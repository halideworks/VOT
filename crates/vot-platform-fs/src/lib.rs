//! Small, isolated platform filesystem operations that require native FFI.

#![deny(unsafe_code)]

use std::fs::File;
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

#[cfg(unix)]
/// Reports whether `path` is a regular name for the file held by `file`.
///
/// Symlinks are inspected without following them and are never accepted.
///
/// # Errors
/// Returns an operating-system error other than a missing path.
pub fn same_file_handle(file: &File, path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let held = file.metadata()?;
    let named = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !named.file_type().is_file() {
        return Ok(false);
    }
    Ok(held.dev() == named.dev() && held.ino() == named.ino())
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
/// Reports whether `path` is a regular name for the file held by `file`.
///
/// Reparse points are opened without traversal and are never accepted.
///
/// # Errors
/// Returns an operating-system error other than a missing path.
pub fn same_file_regular_windows_handle(file: &File, path: &Path) -> io::Result<bool> {
    use std::mem::MaybeUninit;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle,
    };

    fn identity(file: &File) -> io::Result<Option<(u32, u64)>> {
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: the raw handle remains valid for the call and the output
        // points to storage for the exact structure the API initializes.
        let result =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: success initializes every field in the output structure.
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

    let named = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let Some(held) = identity(file)? else {
        return Ok(false);
    };
    let Some(named) = identity(&named)? else {
        return Ok(false);
    };
    Ok(held == named)
}

#[cfg(windows)]
pub use same_file_regular_windows_handle as same_file_handle;

#[cfg(windows)]
/// Opens an existing staging file while preventing rename or deletion.
///
/// # Errors
/// Returns the operating-system refusal to open and guard the file.
pub fn same_file_regular_windows_guard(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    std::fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path)
}

#[cfg(windows)]
pub use same_file_regular_windows_guard as guard_staging_file;

#[cfg(not(windows))]
/// Opens an existing staging file for identity retention.
///
/// # Errors
/// Returns the operating-system refusal to open the file.
pub fn guard_staging_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
/// Exclusively creates staging with delete access while preventing path swaps.
///
/// # Errors
/// Returns the operating-system refusal to create and guard the file.
pub fn same_file_regular_windows_create(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path)
}

#[cfg(windows)]
pub use same_file_regular_windows_create as create_staging_file;

#[cfg(not(windows))]
/// Exclusively creates a staging file.
///
/// # Errors
/// Returns the operating-system refusal to create the file.
pub fn create_staging_file(path: &Path) -> io::Result<File> {
    validate_removal_parent(path)?;
    std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
}

#[cfg(unix)]
/// Verifies the portable Unix precondition for later name removal.
///
/// The parent must be a real directory owned by this effective user and must
/// not be writable by group or others. Callers must also serialize mutation
/// by other processes running as the same user.
///
/// # Errors
/// Returns metadata errors or `PermissionDenied` for an unsafe parent.
pub fn validate_removal_parent(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::symlink_metadata(parent)?;
    if !parent.file_type().is_dir()
        || parent.uid() != rustix::process::geteuid().as_raw()
        || parent.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file removal requires an owner-matched, non-writable parent",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
/// Unix parent-removal validation is unnecessary on this platform.
///
/// # Errors
/// Never returns an error.
pub fn validate_removal_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
/// Creates a no-replace hard link from `file` relative to the destination's
/// opened parent directory, without resolving the staging name.
///
/// # Errors
/// Returns invalid-leaf, directory-open, or native link errors.
pub fn same_file_regular_windows_link(
    file: &File,
    _source: &Path,
    destination: &Path,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_LINK_INFORMATION, FileLinkInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let leaf = destination
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
        .encode_wide()
        .collect::<Vec<_>>();
    if leaf.is_empty() || leaf.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let leaf_bytes = leaf
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = std::fs::OpenOptions::new()
        .access_mode(FILE_ADD_FILE | FILE_TRAVERSE | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent)?;
    let header = std::mem::offset_of!(FILE_LINK_INFORMATION, FileName);
    let bytes = header
        .checked_add(leaf_bytes as usize)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let words = bytes.div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    let information = buffer.as_mut_ptr().cast::<FILE_LINK_INFORMATION>();
    // SAFETY: `buffer` is usize-aligned and large enough for the fixed header
    // plus every UTF-16 leaf byte. All pointers stay live for the native call.
    unsafe {
        (*information).Anonymous.ReplaceIfExists = false;
        (*information).RootDirectory = parent.as_raw_handle();
        (*information).FileNameLength = leaf_bytes;
        std::ptr::copy_nonoverlapping(
            leaf.as_ptr(),
            std::ptr::addr_of_mut!((*information).FileName).cast::<u16>(),
            leaf.len(),
        );
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the retained file and parent handles remain valid, and the
    // initialized variable-length buffer matches FILE_LINK_INFORMATION.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            information.cast(),
            u32::try_from(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
            FileLinkInformation,
        )
    };
    if status < 0 {
        // SAFETY: this pure conversion accepts every NTSTATUS value.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(
            code.to_ne_bytes(),
        )));
    }
    Ok(())
}

#[cfg(windows)]
pub use same_file_regular_windows_link as link_file_handle;

#[cfg(not(windows))]
/// Creates a no-replace hard link from `source` to `destination`.
///
/// # Errors
/// Returns the operating-system link error.
pub fn link_file_handle(_file: &File, source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::hard_link(source, destination)
}

#[cfg(windows)]
#[allow(unsafe_code)]
/// Removes the file held by `file` without resolving its path again.
///
/// # Errors
/// Returns an identity mismatch or operating-system disposition failure.
pub fn same_file_regular_windows_remove(file: &File, path: &Path) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx,
        SetFileInformationByHandle,
    };

    if !same_file_regular_windows_handle(file, path)? {
        return Err(io::Error::other(
            "file name no longer identifies the held file",
        ));
    }
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: the handle remains owned by `file`, and the pointer and size
    // describe a live FILE_DISPOSITION_INFO_EX value for the duration.
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            std::ptr::from_ref(&disposition).cast(),
            u32::try_from(std::mem::size_of_val(&disposition)).expect("small Windows structure"),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
pub use same_file_regular_windows_remove as remove_file_handle;

#[cfg(unix)]
/// Removes `path` only while `file` still proves ownership of that name and
/// its parent is owned by the file owner and not writable by group or others.
///
/// The parent restriction is the portable Unix precondition that excludes
/// concurrent namespace mutation by a different user between identity check
/// and unlink. Callers must also serialize same-owner mutation of the parent.
///
/// # Errors
/// Returns an unsafe-parent, identity-mismatch, or removal failure.
pub fn remove_file_handle(file: &File, path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    validate_removal_parent(path)?;
    let held = file.metadata()?;
    if held.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file removal requires ownership of the held file",
        ));
    }
    if !same_file_handle(file, path)? {
        return Err(io::Error::other(
            "file name no longer identifies the held file",
        ));
    }
    std::fs::remove_file(path)
}

#[cfg(not(any(unix, windows)))]
/// File removal by retained handle is unavailable on this platform.
///
/// # Errors
/// Always returns `Unsupported`.
pub fn same_file_regular_unsupported_remove(_file: &File, _path: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(not(any(unix, windows)))]
pub use same_file_regular_unsupported_remove as remove_file_handle;

#[cfg(windows)]
#[allow(unsafe_code)]
/// Marks a file as sparse so positional writes skip valid-data-length
/// zero-filling, which otherwise serializes out-of-order writers.
///
/// # Errors
/// Returns the OS refusal; callers without the attribute lose only the saving.
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

#[cfg(not(any(unix, windows)))]
/// Reports whether `path` is a regular name for the file held by `file`.
///
/// # Errors
/// Always returns `Unsupported` on unsupported platforms.
pub fn same_file_regular_unsupported_handle(_file: &File, _path: &Path) -> io::Result<bool> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(not(any(unix, windows)))]
pub use same_file_regular_unsupported_handle as same_file_handle;

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

    #[cfg(unix)]
    #[test]
    fn handle_identity_survives_a_swapped_name() {
        let directory =
            std::env::temp_dir().join(format!("vot-platform-handle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("held");
        let alias = directory.join("alias");
        fs::write(&path, b"trusted").unwrap();
        let held = File::open(&path).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(same_file_handle(&held, &path).unwrap());
        assert!(same_file_handle(&held, &alias).unwrap());
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(!same_file_handle(&held, &path).unwrap());
        assert!(same_file_handle(&held, &alias).unwrap());
        assert!(!same_file_handle(&held, &directory.join("missing")).unwrap());
        assert!(same_file_handle(&held, &path.join("child")).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn retained_handle_removes_only_its_own_name() {
        let directory =
            std::env::temp_dir().join(format!("vot-platform-remove-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("held");
        let published = directory.join("published");
        let file = create_staging_file(&path).unwrap();
        assert!(same_file_handle(&file, &path).unwrap());
        link_file_handle(&file, &path, &published).unwrap();
        remove_file_handle(&file, &path).unwrap();
        drop(file);
        assert!(!path.exists());
        assert!(published.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_staging_handle_denies_namespace_swaps() {
        let directory =
            std::env::temp_dir().join(format!("vot-platform-guard-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("held");
        let renamed = directory.join("renamed");
        let file = create_staging_file(&path).unwrap();
        assert!(fs::rename(&path, &renamed).is_err());
        assert!(fs::remove_file(&path).is_err());
        remove_file_handle(&file, &path).unwrap();
        drop(file);
        assert!(!path.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn removal_refuses_a_parent_writable_by_other_users() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory =
            std::env::temp_dir().join(format!("vot-platform-parent-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("held");
        let file = create_staging_file(&path).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            remove_file_handle(&file, &path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(path.exists());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        remove_file_handle(&file, &path).unwrap();
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn removal_parent_must_be_a_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory =
            std::env::temp_dir().join(format!("vot-platform-parent-file-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let parent = directory.join("not-a-directory");
        fs::write(&parent, b"not a directory").unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            validate_removal_parent(&parent.join("child"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
