//! Small, isolated platform filesystem operations that require native FFI.

#![deny(unsafe_code)]

use std::io;
use std::path::Path;

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
}
