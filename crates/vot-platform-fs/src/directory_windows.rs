//! Retained local NTFS directories and handle-relative child operations.

#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
    FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, GetFileInformationByHandle,
    GetVolumeInformationByHandleW, READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

#[path = "private_windows.rs"]
mod security;

#[derive(Clone, Debug)]
pub struct Directory {
    file: Arc<File>,
    path: PathBuf,
    owner: security::Owner,
}

impl Directory {
    /// Retains a non-reparse directory on local NTFS.
    ///
    /// # Errors
    /// Refuses remote volumes, other filesystems, and inaccessible directories.
    pub fn open(path: &Path) -> io::Result<Self> {
        let path = if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path
        };
        let file = OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let info = information(&file)?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != FILE_ATTRIBUTE_DIRECTORY
        {
            return Err(io::Error::other("expected a non-reparse directory"));
        }
        require_local_ntfs(&file)?;
        Ok(Self {
            file: Arc::new(file),
            path: path.to_owned(),
            owner: security::current_owner()?,
        })
    }

    /// Selects one native filename relative to the retained directory.
    ///
    /// # Errors
    /// Refuses separators, streams, device names, and Win32 name aliases.
    pub fn entry(&self, name: &OsStr) -> io::Result<FileLocation> {
        validate_leaf(name)?;
        Ok(FileLocation {
            directory: self.clone(),
            name: name.to_owned(),
        })
    }

    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Flushes the held NTFS directory, including its persistent namespace metadata.
    ///
    /// # Errors
    /// Propagates the directory flush failure.
    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Verifies ownership and a private access-control list.
    ///
    /// # Errors
    /// Refuses access granted outside the owner, administrators, and `LocalSystem`.
    pub fn require_private(&self) -> io::Result<()> {
        security::check(&self.file, &self.owner, true)
    }

    fn require_removal_parent(&self) -> io::Result<()> {
        security::check(&self.file, &self.owner, false)
    }
}

#[derive(Clone, Debug)]
pub struct FileLocation {
    directory: Directory,
    name: OsString,
}

impl FileLocation {
    /// Retains the named file's parent.
    ///
    /// # Errors
    /// Returns a filename or directory-admission error.
    pub fn from_path(path: &Path) -> io::Result<Self> {
        let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
        Directory::open(path.parent().unwrap_or_else(|| Path::new(".")))?.entry(name)
    }

    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.directory.path.join(&self.name)
    }
    #[must_use]
    pub const fn directory(&self) -> &Directory {
        &self.directory
    }
    #[must_use]
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    /// Selects another name in the same retained directory.
    ///
    /// # Errors
    /// Returns a filename validation error.
    pub fn sibling(&self, name: &OsStr) -> io::Result<Self> {
        self.directory.entry(name)
    }

    /// Opens a regular, non-reparse file for reading.
    ///
    /// # Errors
    /// Propagates native open errors.
    pub fn open_read(&self) -> io::Result<File> {
        self.open(FILE_OPEN, FILE_GENERIC_READ, SHARED)
    }

    /// Opens a replaceable regular file for a journal writer.
    ///
    /// # Errors
    /// Propagates native open errors.
    pub fn open_write(&self) -> io::Result<File> {
        self.open(
            FILE_OPEN,
            READ_WRITE_DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )
    }

    /// Creates a new replaceable regular file, refusing existing names.
    ///
    /// # Errors
    /// Propagates native creation errors.
    pub fn create(&self) -> io::Result<File> {
        self.open(
            FILE_CREATE,
            READ_WRITE_DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )
    }

    /// Creates a capture file while excluding other writers and namespace mutation.
    ///
    /// # Errors
    /// Refuses an existing name or a failed sparse-file setup.
    pub fn create_owned(&self) -> io::Result<File> {
        let file = self.open(FILE_CREATE, READ_WRITE_DELETE, FILE_SHARE_READ)?;
        if let Err(error) = crate::allow_unordered_writes(&file) {
            let _ = self.remove_owned(&file);
            return Err(error);
        }
        Ok(file)
    }

    /// Opens a capture file while excluding other writers and namespace mutation.
    ///
    /// # Errors
    /// Propagates native open errors.
    pub fn open_owned(&self) -> io::Result<File> {
        self.open(FILE_OPEN, READ_WRITE_DELETE, FILE_SHARE_READ)
    }

    fn open(&self, disposition: u32, access: u32, sharing: u32) -> io::Result<File> {
        self.open_information(disposition, access, sharing)
            .map(|(file, _)| file)
    }

    fn open_information(
        &self,
        disposition: u32,
        access: u32,
        sharing: u32,
    ) -> io::Result<(File, BY_HANDLE_FILE_INFORMATION)> {
        let descriptor = if disposition == FILE_CREATE {
            Some(security::descriptor(&self.directory.owner)?)
        } else {
            None
        };
        let mut name: Vec<_> = self.name.encode_wide().collect();
        let length = u16::try_from(name.len() * 2).map_err(|_| io::ErrorKind::InvalidInput)?;
        let name = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: name.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).unwrap(),
            RootDirectory: self.directory.file.as_raw_handle(),
            ObjectName: &raw const name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: descriptor
                .as_ref()
                .map_or(std::ptr::null_mut(), |s| s.0.cast()),
            ..OBJECT_ATTRIBUTES::default()
        };
        let mut handle = std::ptr::null_mut();
        let mut status = IO_STATUS_BLOCK::default();
        // SAFETY: all input buffers and the retained parent outlive this synchronous call.
        let result = unsafe {
            NtCreateFile(
                &raw mut handle,
                access | SYNCHRONIZE | FILE_READ_ATTRIBUTES | READ_CONTROL,
                &raw const attributes,
                &raw mut status,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                sharing,
                disposition,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        nt_result(result)?;
        // SAFETY: successful NtCreateFile transfers a new owned handle to this File.
        let file = unsafe { File::from_raw_handle(handle) };
        let info = information(&file)?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(io::Error::other("expected a regular non-reparse file"));
        }
        if access & FILE_WRITE_DATA != 0 {
            security::check(&file, &self.directory.owner, true)?;
        }
        Ok((file, info))
    }

    /// Returns the volume and file ID through a metadata-only handle.
    ///
    /// # Errors
    /// Returns native lookup or file-type errors.
    pub fn identity(&self) -> io::Result<(u64, u64)> {
        let (_, info) = self.open_information(FILE_OPEN, FILE_READ_ATTRIBUTES, SHARED)?;
        Ok(identity(&info))
    }

    /// Tests whether this name still identifies the retained file.
    ///
    /// # Errors
    /// Propagates lookup errors other than a missing name.
    pub fn same_file(&self, file: &File) -> io::Result<bool> {
        match self.identity() {
            Ok(named) => Ok(named == file_identity(file)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Removes only the file identified by the retained handle.
    ///
    /// # Errors
    /// Refuses changed identity, an unprotected parent, or native deletion failure.
    pub fn remove_owned(&self, file: &File) -> io::Result<()> {
        self.require_removal_parent()?;
        if !self.same_file(file)? {
            return Err(io::Error::other("file identity changed"));
        }
        crate::remove_owned_handle_windows(file)
    }

    /// Atomically replaces a name relative to retained directories.
    ///
    /// # Errors
    /// Refuses unprotected parents and native rename errors.
    pub fn replace_private(&self, destination: &Self) -> io::Result<()> {
        self.require_removal_parent()?;
        destination.require_removal_parent()?;
        let source = self.open(FILE_OPEN, DELETE, SHARED)?;
        let leaf: Vec<_> = destination.name.encode_wide().collect();
        let name_length = u32::try_from(leaf.len() * 2).map_err(|_| io::ErrorKind::InvalidInput)?;
        let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let size = (header + leaf.len() * 2).max(std::mem::size_of::<FILE_RENAME_INFORMATION>());
        let native_size = u32::try_from(size).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut buffer = vec![0_usize; size.div_ceil(std::mem::size_of::<usize>())];
        let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        // SAFETY: the aligned allocation covers the header and every UTF-16 name byte.
        unsafe {
            (*information).Anonymous.Flags =
                FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
            (*information).RootDirectory = destination.directory.file.as_raw_handle();
            (*information).FileNameLength = name_length;
            std::ptr::copy_nonoverlapping(
                leaf.as_ptr(),
                std::ptr::addr_of_mut!((*information).FileName).cast(),
                leaf.len(),
            );
        }
        let mut status = IO_STATUS_BLOCK::default();
        // SAFETY: both handles and the initialized variable-length buffer stay live.
        let result = unsafe {
            NtSetInformationFile(
                source.as_raw_handle(),
                &raw mut status,
                information.cast(),
                native_size,
                FileRenameInformationEx,
            )
        };
        nt_result(result)
    }

    /// Requires a parent protected from other users' writes.
    ///
    /// # Errors
    /// Returns ownership or ACL errors.
    pub fn require_removal_parent(&self) -> io::Result<()> {
        self.directory.require_removal_parent()
    }

    /// Flushes the retained parent directory.
    ///
    /// # Errors
    /// Propagates the native flush error.
    pub fn sync_parent(&self) -> io::Result<()> {
        self.directory.sync()
    }
}

const SHARED: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const READ_WRITE_DELETE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE;

fn nt_result(status: i32) -> io::Result<()> {
    if status < 0 {
        // SAFETY: this conversion accepts any NTSTATUS and retains no pointers.
        Err(io::Error::from_raw_os_error(i32::from_ne_bytes(
            unsafe { RtlNtStatusToDosError(status) }.to_ne_bytes(),
        )))
    } else {
        Ok(())
    }
}

fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the owned handle and correctly sized output remain valid for this call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// Returns the volume and 64-bit file ID; callers needing uniqueness must admit NTFS.
///
/// # Errors
/// Returns the native metadata query error.
pub fn file_identity(file: &File) -> io::Result<(u64, u64)> {
    Ok(identity_and_links(file)?.0)
}

/// Returns the NTFS identity and link count from one native query.
///
/// # Errors
/// Returns the native metadata query error.
pub fn identity_and_links(file: &File) -> io::Result<((u64, u64), u64)> {
    let info = information(file)?;
    Ok((identity(&info), u64::from(info.nNumberOfLinks)))
}

fn identity(info: &BY_HANDLE_FILE_INFORMATION) -> (u64, u64) {
    (
        u64::from(info.dwVolumeSerialNumber),
        u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
    )
}

fn require_local_ntfs(file: &File) -> io::Result<()> {
    use windows_sys::Wdk::Storage::FileSystem::{
        FileFsDeviceInformation, NtQueryVolumeInformationFile,
    };
    use windows_sys::Wdk::System::SystemServices::{
        FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE,
    };
    let mut filesystem = [0_u16; 32];
    // SAFETY: the handle and output array remain valid; optional outputs are null.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem.as_mut_ptr(),
            32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: the output is exactly the native FileFsDeviceInformation structure.
    nt_result(unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &raw mut status,
            (&raw mut device).cast(),
            u32::try_from(std::mem::size_of_val(&device)).unwrap(),
            FileFsDeviceInformation,
        )
    })?;
    if filesystem[..5] != [78, 84, 70, 83, 0] || device.Characteristics & FILE_REMOTE_DEVICE != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "capture durability requires local NTFS",
        ));
    }
    Ok(())
}

fn validate_leaf(name: &OsStr) -> io::Result<()> {
    let wide: Vec<_> = name.encode_wide().collect();
    if wide.is_empty()
        || wide.len() > 255
        || wide
            .iter()
            .any(|c| *c < 32 || [34, 42, 47, 58, 60, 62, 63, 92, 124].contains(c))
        || wide.last().is_some_and(|c| [32, 46].contains(c))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let stem: String = name
        .to_string_lossy()
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&stem.as_str())
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.chars().count() == 4
            && stem
                .chars()
                .last()
                .is_some_and(|c| "123456789¹²³".contains(c)))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

/// Creates a new directory with an explicit private, inheritable ACL.
///
/// # Errors
/// Refuses existing entries and propagates native security or creation errors.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    security::create(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{next_file_data_offset, read_exact_at, write_all_at};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "vot-ntfs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            create_private_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn replacement_keeps_both_handles_and_writer_exclusion() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0).unwrap();
        directory.require_private().unwrap();
        let old = directory.entry(OsStr::new("old")).unwrap();
        let new = directory.entry(OsStr::new("new")).unwrap();
        let old_file = old.create().unwrap();
        let new_file = new.create().unwrap();
        write_all_at(&old_file, b"before", 0).unwrap();
        write_all_at(&new_file, b"after!", 0).unwrap();
        new_file.sync_all().unwrap();
        new.replace_private(&old).unwrap();
        directory.sync().unwrap();
        assert!(old.same_file(&new_file).unwrap());
        assert!(!old.same_file(&old_file).unwrap());
        assert!(old.open_write().is_err());
        assert_eq!(std::fs::read(old.path()).unwrap(), b"after!");
        let mut bytes = [0; 6];
        read_exact_at(&old_file, &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"before");
        assert!(new.identity().is_err());
        assert!(old.remove_owned(&old_file).is_err());
        old.remove_owned(&new_file).unwrap();
        drop(new_file);
        directory.sync().unwrap();
        assert!(!old.path().exists());
    }

    #[test]
    fn owned_sparse_files_deny_writers_and_namespace_mutation() {
        let temp = Temp::new();
        let directory = Directory::open(&temp.0).unwrap();
        let location = directory.entry(OsStr::new("payload")).unwrap();
        let file = location.create_owned().unwrap();
        assert!(location.create_owned().is_err());
        assert!(location.open_owned().is_err());
        assert!(std::fs::rename(location.path(), temp.0.join("moved")).is_err());
        assert!(std::fs::remove_file(location.path()).is_err());
        file.set_len(4 * 1024 * 1024).unwrap();
        assert_eq!(next_file_data_offset(&file, 0).unwrap(), None);
        for offset in [1024 * 1024, 3 * 1024 * 1024] {
            write_all_at(&file, &[7; 4096], offset).unwrap();
        }
        file.sync_all().unwrap();
        let first = next_file_data_offset(&file, 0).unwrap().unwrap();
        assert!(first > 0 && first <= 1024 * 1024);
        assert_eq!(
            next_file_data_offset(&file, 1024 * 1024).unwrap(),
            Some(1024 * 1024)
        );
        let second = next_file_data_offset(&file, 2 * 1024 * 1024)
            .unwrap()
            .unwrap();
        assert!((2 * 1024 * 1024..=3 * 1024 * 1024).contains(&second));
        assert_eq!(next_file_data_offset(&file, 4 * 1024 * 1024).unwrap(), None);
        assert_eq!(next_file_data_offset(&file, u64::MAX).unwrap(), None);
        drop(file);
        location.open_owned().unwrap();
    }

    #[test]
    fn children_are_private_without_inheritance_and_permissive_files_are_refused() {
        let temp = Temp::new();
        security::set_test_acl(&temp.0, false, false);
        let directory = Directory::open(&temp.0).unwrap();
        directory.require_private().unwrap();
        for owned in [false, true] {
            let location = directory
                .entry(OsStr::new(if owned { "owned" } else { "journal" }))
                .unwrap();
            let file = if owned {
                location.create_owned()
            } else {
                location.create()
            }
            .unwrap();
            security::check(&file, &directory.owner, true).unwrap();
            write_all_at(&file, b"private", 0).unwrap();
            drop(file);
            location.open_owned().unwrap();
            security::set_test_acl(&location.path(), true, false);
            assert!(location.open_owned().is_err());
            assert!(location.open_write().is_err());
        }
        security::set_test_acl(&temp.0, true, true);
        assert!(directory.require_private().is_err());
        assert!(directory.require_removal_parent().is_err());
    }

    #[test]
    fn native_leaf_admission_refuses_windows_aliases_and_streams() {
        for name in [
            "",
            ".",
            "..",
            "XML:EDL",
            "file:stream",
            "a/b",
            "a\\b",
            "a\0b",
            "a?b",
            "a*b",
            "a<b",
            "a>b",
            "a|b",
            "a\"b",
            "trailing.",
            "trailing ",
            "CON",
            "con.txt",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "lpt9.ext",
            "COM¹",
            "LPT²",
            "COM³",
            "CONIN$",
            "CONOUT$",
        ] {
            assert!(validate_leaf(OsStr::new(name)).is_err(), "{name:?}");
        }
        assert!(validate_leaf(OsStr::new(&"a".repeat(256))).is_err());
        for name in [
            "XML_EDL",
            "日本語.mov",
            "é.mov",
            "e\u{301}.mov",
            "COM0",
            "LPT10",
        ] {
            validate_leaf(OsStr::new(name)).unwrap();
        }
        validate_leaf(OsStr::new(&"a".repeat(255))).unwrap();
        let temp = Temp::new();
        let directory = Directory::open(&temp.0).unwrap();
        std::fs::create_dir(temp.0.join("folder")).unwrap();
        assert!(
            directory
                .entry(OsStr::new("folder"))
                .unwrap()
                .open_read()
                .is_err()
        );
    }
}
