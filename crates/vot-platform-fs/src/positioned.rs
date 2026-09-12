use std::fs::File;
use std::io;

/// Reads exactly the requested range without allocating a payload buffer.
/// Windows callers must own the file cursor or use only positioned operations.
///
/// # Errors
/// Returns I/O errors, including a short file or repeated interruption.
pub fn read_exact_at(file: &File, bytes: &mut [u8], offset: u64) -> io::Result<()> {
    read_exact_with(bytes, offset, |bytes, offset| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;
            file.read_at(bytes, offset)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt as _;
            file.seek_read(bytes, offset)
        }
    })
}

/// Writes a borrowed range completely without allocating a payload buffer.
/// Windows callers must own the file cursor or use only positioned operations.
///
/// # Errors
/// Returns I/O errors, including a zero write or repeated interruption.
pub fn write_all_at(file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
    write_all_with(bytes, offset, |bytes, offset| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;
            file.write_at(bytes, offset)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt as _;
            file.seek_write(bytes, offset)
        }
    })
}

fn retry<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    for _ in 0..32 {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
    Err(io::ErrorKind::Interrupted.into())
}

fn read_exact_with(
    mut bytes: &mut [u8],
    mut offset: u64,
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let count = std::num::NonZeroUsize::new(retry(|| read(bytes, offset))?)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .get();
        offset = offset
            .checked_add(count as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        bytes = bytes.get_mut(count..).ok_or(io::ErrorKind::InvalidData)?;
    }
    Ok(())
}

fn write_all_with(
    mut bytes: &[u8],
    mut offset: u64,
    mut write: impl FnMut(&[u8], u64) -> io::Result<usize>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let count = std::num::NonZeroUsize::new(retry(|| write(bytes, offset))?)
            .ok_or(io::ErrorKind::WriteZero)?
            .get();
        offset = offset
            .checked_add(count as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        bytes = bytes.get(count..).ok_or(io::ErrorKind::InvalidData)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_io_preserves_offsets_bytes_and_errors() {
        let mut offsets = Vec::new();
        let mut bytes = [0; 5];
        read_exact_with(&mut bytes, 17, |out, offset| {
            offsets.push(offset);
            let count = out.len().min(2);
            out[..count].fill(u8::try_from(offset).unwrap());
            Ok(count)
        })
        .unwrap();
        assert_eq!(offsets, [17, 19, 21]);
        assert_eq!(bytes, [17, 17, 19, 19, 21]);
        offsets.clear();
        let mut written = Vec::new();
        write_all_with(&bytes, 17, |input, offset| {
            offsets.push(offset);
            let count = input.len().min(2);
            written.extend_from_slice(&input[..count]);
            Ok(count)
        })
        .unwrap();
        assert_eq!(offsets, [17, 19, 21]);
        assert_eq!(written, bytes);
        for (offset, count, expected_read, expected_write) in [
            (0, 0, io::ErrorKind::UnexpectedEof, io::ErrorKind::WriteZero),
            (
                u64::MAX,
                1,
                io::ErrorKind::InvalidInput,
                io::ErrorKind::InvalidInput,
            ),
            (0, 2, io::ErrorKind::InvalidData, io::ErrorKind::InvalidData),
        ] {
            assert_eq!(
                read_exact_with(&mut [0], offset, |_, _| Ok(count))
                    .unwrap_err()
                    .kind(),
                expected_read
            );
            assert_eq!(
                write_all_with(&[0], offset, |_, _| Ok(count))
                    .unwrap_err()
                    .kind(),
                expected_write
            );
        }
        assert_eq!(
            read_exact_with(&mut [0], 0, |_, _| Err(
                io::ErrorKind::PermissionDenied.into()
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            write_all_with(&[0], 0, |_, _| Err(io::ErrorKind::PermissionDenied.into()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        read_exact_with(&mut [], u64::MAX, |_, _| panic!("empty read issued I/O")).unwrap();
        write_all_with(&[], u64::MAX, |_, _| panic!("empty write issued I/O")).unwrap();
    }

    #[test]
    fn interrupted_io_has_a_bounded_retry_budget() {
        let mut calls = 0;
        assert_eq!(
            retry(|| {
                calls += 1;
                if calls == 32 {
                    Ok(17)
                } else {
                    Err(io::ErrorKind::Interrupted.into())
                }
            })
            .unwrap(),
            17
        );
        assert_eq!(calls, 32);
        calls = 0;
        let result: io::Result<()> = retry(|| {
            calls += 1;
            Err(io::ErrorKind::Interrupted.into())
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(calls, 32);
    }

    #[test]
    fn native_positioned_io_preserves_the_surrounding_file() {
        let path = std::env::temp_dir().join(format!("vot-positioned-{}", std::process::id()));
        crate::create_private_directory(&path).unwrap();
        let directory = crate::Directory::open(&path).unwrap();
        directory.require_private().unwrap();
        let location = directory.entry(std::ffi::OsStr::new("data")).unwrap();
        let file = location.create_owned().unwrap();
        let expected = location.identity().unwrap();
        assert_eq!(crate::file_identity(&file).unwrap(), expected);
        assert_eq!(crate::identity_and_links(&file).unwrap(), (expected, 1));
        write_all_at(&file, b"abcdefghijkl", 0).unwrap();
        write_all_at(&file, b"XYZ", 4).unwrap();
        let mut bytes = [0; 12];
        read_exact_at(&file, &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"abcdXYZhijkl");
        read_exact_at(&file, &mut bytes[..3], 4).unwrap();
        assert_eq!(&bytes[..3], b"XYZ");
        assert_eq!(
            read_exact_at(&file, &mut bytes, 1).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        #[cfg(unix)]
        {
            std::fs::hard_link(location.path(), path.join("alias")).unwrap();
            assert_eq!(crate::identity_and_links(&file).unwrap(), (expected, 2));
        }
        drop(file);
        drop(location);
        drop(directory);
        std::fs::remove_dir_all(path).unwrap();
    }
}
