//! Small, isolated platform filesystem operations that require native FFI.

#![deny(unsafe_code)]

use std::io;
use std::path::Path;

#[cfg(unix)]
/// Reports whether two paths are regular hard links to the same file.
///
/// Symlinks are inspected without following them and are never accepted.
///
/// # Errors
/// Returns an operating-system error other than a missing destination.
pub fn same_file_regular(source: &Path, destination: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let source = std::fs::symlink_metadata(source)?;
    let destination = match std::fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !source.file_type().is_file() {
        return Ok(false);
    }
    if !destination.file_type().is_file() {
        return Ok(false);
    }
    Ok(source.dev() == destination.dev() && source.ino() == destination.ino())
}

#[cfg(windows)]
#[allow(unsafe_code)]
/// Reports whether two paths are regular hard links to the same file.
///
/// Reparse points are opened without traversal and are never accepted.
///
/// # Errors
/// Returns an operating-system error other than a missing destination.
pub fn same_file_regular_windows(source: &Path, destination: &Path) -> io::Result<bool> {
    use std::fs::{File, OpenOptions};
    use std::mem::MaybeUninit;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle,
    };

    fn open(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    fn identity(file: &File) -> io::Result<Option<(u32, u64)>> {
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: the raw handle remains owned by `file` and valid for the
        // call, and `information` points to writable storage of the exact
        // structure required by GetFileInformationByHandle.
        let result =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful GetFileInformationByHandle call initializes
        // every field in the output structure.
        let information = unsafe { information.assume_init() };
        if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        {
            return Ok(None);
        }
        let index =
            u64::from(information.nFileIndexHigh) << 32 | u64::from(information.nFileIndexLow);
        Ok(Some((information.dwVolumeSerialNumber, index)))
    }

    let source = open(source)?;
    let destination = match open(destination) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let Some(source) = identity(&source)? else {
        return Ok(false);
    };
    let Some(destination) = identity(&destination)? else {
        return Ok(false);
    };
    Ok(source == destination)
}

#[cfg(windows)]
pub use same_file_regular_windows as same_file_regular;

#[cfg(windows)]
#[allow(unsafe_code)]
/// Frees a preallocated file from valid-data tracking, so positional
/// writes may land at any offset without the filesystem zero-filling
/// everything below them first.
///
/// NTFS keeps a valid data length per file: a write past it zero-fills
/// the whole gap under the file's resources, which serializes concurrent
/// out-of-order writers and writes the gap twice. A sparse file has no
/// gap to fill, because unwritten regions read as zeros by construction.
///
/// # Errors
/// Returns the operating system's refusal, filesystems without the
/// attribute among them; the caller loses nothing but the saving.
pub fn allow_unordered_writes_windows(file: &std::fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;

    let mut returned: u32 = 0;
    // SAFETY: the raw handle remains owned by `file` and valid for the
    // call; FSCTL_SET_SPARSE takes no input buffer (null and zero select
    // setting the attribute), and `returned` points to writable storage.
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
pub use allow_unordered_writes_windows as allow_unordered_writes;

#[cfg(not(windows))]
/// Positional writes already land at any offset without penalty here;
/// the signature stands so callers need no platform of their own.
///
/// # Errors
/// None here; the Windows half surfaces the platform's refusal.
pub fn allow_unordered_writes(_file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
/// Reports whether two paths are regular hard links to the same file.
///
/// # Errors
/// Always returns `Unsupported` on unsupported platforms.
pub fn same_file_regular_unsupported(_source: &Path, _destination: &Path) -> io::Result<bool> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(not(any(unix, windows)))]
pub use same_file_regular_unsupported as same_file_regular;

#[cfg(not(windows))]
/// Replaces `destination` with `source` atomically on the same filesystem.
///
/// # Errors
/// Returns the operating-system filesystem error when replacement fails.
pub fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
#[allow(unsafe_code)]
/// Replaces `destination` with `source` atomically on the same filesystem.
///
/// # Errors
/// Returns an invalid-path or operating-system error when replacement fails.
pub fn atomic_replace_windows(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if value.contains(&0) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        value.push(0);
        Ok(value)
    }

    let source = wide(source)?;
    let destination = wide(destination)?;
    // SAFETY: both pointers reference live, NUL-terminated UTF-16 buffers for
    // the duration of the call. The buffers do not alias mutable Rust memory.
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub use atomic_replace_windows as atomic_replace;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn replacement_overwrites_existing_file_atomically() {
        let directory =
            std::env::temp_dir().join(format!("vot-platform-fs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let source = directory.join("source");
        let destination = directory.join("destination");
        fs::write(&source, b"new").unwrap();
        fs::write(&destination, b"old").unwrap();
        atomic_replace(&source, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert!(!source.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn regular_identity_rejects_symlinks_and_other_files() {
        let directory =
            std::env::temp_dir().join(format!("vot-platform-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let source = directory.join("source");
        let linked = directory.join("linked");
        let other = directory.join("other");
        let symlink = directory.join("symlink");
        fs::write(&source, b"source").unwrap();
        fs::hard_link(&source, &linked).unwrap();
        fs::write(&other, b"other").unwrap();
        std::os::unix::fs::symlink(&source, &symlink).unwrap();

        assert!(same_file_regular(&source, &linked).unwrap());
        assert!(!same_file_regular(&source, &other).unwrap());
        assert!(!same_file_regular(&source, &symlink).unwrap());
        assert!(!same_file_regular(&source, &directory.join("missing")).unwrap());
        assert!(same_file_regular(&source, &source.join("child")).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
