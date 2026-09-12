use std::fs::File;
use std::io;

/// Returns the next offset that may contain file data, or end of file.
/// Unsupported sparse-file queries conservatively return the requested offset.
/// The file cursor may change; callers must use positional I/O or own the cursor.
///
/// # Errors
/// Propagates I/O errors other than an unsupported query or end of file.
pub fn next_file_data_offset(file: &File, offset: u64) -> io::Result<Option<u64>> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos"
    ))]
    {
        data_result(
            rustix::fs::seek(file, rustix::fs::SeekFrom::Data(offset)),
            offset,
        )
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos"
    )))]
    {
        let _ = file;
        Ok(Some(offset))
    }
}

fn data_result(result: Result<u64, rustix::io::Errno>, offset: u64) -> io::Result<Option<u64>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(rustix::io::Errno::NXIO) => Ok(None),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP) => Ok(Some(offset)),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_query_finds_written_bytes_on_an_owned_file() {
        use std::os::unix::fs::FileExt as _;
        let path = std::env::temp_dir().join(format!("vot-sparse-query-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        file.write_all_at(&[17], 8192).unwrap();
        assert_eq!(next_file_data_offset(&file, 8192).unwrap(), Some(8192));
    }

    #[test]
    fn sparse_query_errors_never_skip_unexamined_data() {
        assert_eq!(data_result(Ok(123), 17).unwrap(), Some(123));
        assert_eq!(data_result(Err(rustix::io::Errno::NXIO), 17).unwrap(), None);
        for error in [rustix::io::Errno::INVAL, rustix::io::Errno::OPNOTSUPP] {
            assert_eq!(data_result(Err(error), 17).unwrap(), Some(17));
        }
        assert!(data_result(Err(rustix::io::Errno::IO), 17).is_err());
    }
}
