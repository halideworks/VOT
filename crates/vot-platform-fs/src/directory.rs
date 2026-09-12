//! Directory-relative operations for publication into a shared namespace.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

#[derive(Clone, Debug)]
pub struct Directory {
    file: Arc<File>,
    path: PathBuf,
    nas_contract: crate::NasContract,
}

impl Directory {
    /// Retains a local directory. Remote filesystems require an explicit contract.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be opened without following a final symlink.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_nas(path, crate::NasContract::Unqualified)
    }

    /// Admits a NAS only under the caller's explicit server qualification.
    /// CIFS path operations require server-enforced namespace protection; the
    /// retained Linux directory descriptor does not provide that protection.
    ///
    /// # Errors
    /// Refuses an unqualified NAS, a missing mount, or unsupported client options.
    pub fn open_with_nas(path: &Path, contract: crate::NasContract) -> io::Result<Self> {
        let path = if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path
        };
        let file = File::from(rustix::fs::open(path, directory_flags(), Mode::empty())?);
        #[cfg(target_os = "linux")]
        match (crate::is_smb_or_nfs(&file)?, contract) {
            (true, crate::NasContract::Unqualified) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "NAS receiving requires an explicit server durability and namespace qualification",
                ));
            }
            (_, crate::NasContract::ServerAcknowledged) => crate::validate_nas_mount(&file)?,
            (false, crate::NasContract::Unqualified) => {}
        }
        validate_platform_contract(contract, cfg!(target_os = "linux"))?;
        Ok(Self {
            file: Arc::new(file),
            path: path.to_path_buf(),
            nas_contract: contract,
        })
    }

    /// Creates or opens a private child without changing the selected parent's permissions.
    /// The child remains in place; unlinking it in a shared parent is not identity-conditional.
    ///
    /// # Errors
    /// Returns an error if creation, ownership, private access or filesystem validation fails.
    pub fn private_child(&self, name: &OsStr) -> io::Result<Self> {
        let child = self.create_child_with_mode(name, Mode::from_raw_mode(0o700))?;
        child.require_private()?;
        Ok(child)
    }

    /// Creates a child with the filesystem's normal inherited permissions.
    ///
    /// # Errors
    /// Refuses symlinks, another filesystem, or failed namespace operations.
    pub fn create_child(&self, name: &OsStr) -> io::Result<Self> {
        self.create_child_with_mode(name, Mode::from_raw_mode(0o777))
    }

    fn create_child_with_mode(&self, name: &OsStr, mode: Mode) -> io::Result<Self> {
        validate_leaf(name)?;
        let created = match rustix::fs::mkdirat(&*self.file, name, mode) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => return Err(error.into()),
        };
        let child = self.open_child(name)?;
        if created {
            self.sync()?;
        }
        Ok(child)
    }

    /// Opens one descendant through the retained directory, without following symlinks.
    ///
    /// # Errors
    /// Refuses a missing child, symlinks, or a different filesystem.
    pub fn open_child(&self, name: &OsStr) -> io::Result<Self> {
        validate_leaf(name)?;
        let file = File::from(rustix::fs::openat(
            &*self.file,
            name,
            directory_flags(),
            Mode::empty(),
        )?);
        let child = Self {
            file: Arc::new(file),
            path: self.path.join(name),
            nas_contract: self.nas_contract,
        };
        if self.file.metadata()?.dev() != child.file.metadata()?.dev() {
            return Err(io::Error::other("receiving directory crosses a filesystem"));
        }
        Ok(child)
    }

    #[must_use]
    pub const fn nas_contract(&self) -> crate::NasContract {
        self.nas_contract
    }

    ///
    /// # Errors
    /// Returns an error unless the name is a single non-special filename.
    pub fn entry(&self, name: &OsStr) -> io::Result<FileLocation> {
        validate_leaf(name)?;
        Ok(FileLocation {
            directory: self.clone(),
            name: name.to_owned(),
        })
    }

    ///
    /// # Errors
    /// Returns an error if the directory flush fails.
    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    ///
    /// # Errors
    /// Returns an error unless the held directory is owner-matched and owner-only.
    pub fn require_private(&self) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        if !protected_directory(
            metadata.is_dir(),
            metadata.uid(),
            rustix::process::geteuid().as_raw(),
            metadata.mode(),
            0o077,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "temporary directory requires owner-only access enforced by the filesystem",
            ));
        }
        Ok(())
    }

    fn require_removal_parent(&self) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        if !protected_directory(
            metadata.is_dir(),
            metadata.uid(),
            rustix::process::geteuid().as_raw(),
            metadata.mode(),
            0o022,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file removal requires an owner-matched, non-writable parent",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FileLocation {
    directory: Directory,
    name: OsString,
}

impl FileLocation {
    ///
    /// # Errors
    /// Returns an error if the parent or filename cannot be admitted.
    pub fn from_path(path: &Path) -> io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Directory::open(path.parent().unwrap_or_else(|| Path::new(".")))?.entry(name)
    }

    /// This path is for persisted location information, not live namespace operations.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.directory.path.join(&self.name)
    }

    #[must_use]
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    ///
    /// # Errors
    /// Returns an error unless the name is a single non-special filename.
    pub fn sibling(&self, name: &OsStr) -> io::Result<Self> {
        self.directory.entry(name)
    }

    #[must_use]
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    ///
    /// # Errors
    /// Returns an error if opening fails or the name is not a regular non-symlink file.
    pub fn open(&self, flags: OFlags, mode: Mode) -> io::Result<File> {
        let descriptor = rustix::fs::openat(
            &*self.directory.file,
            &self.name,
            flags
                .union(OFlags::NOFOLLOW)
                .union(OFlags::CLOEXEC)
                .union(OFlags::NONBLOCK),
            mode,
        )?;
        let file = File::from(descriptor);
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("location is not a regular file"));
        }
        Ok(file)
    }

    /// Opens an existing regular file for reads only.
    ///
    /// # Errors
    /// Returns an error if no regular non-symlink file can be opened.
    pub fn open_read(&self) -> io::Result<File> {
        self.open(OFlags::RDONLY, Mode::empty())
    }

    /// Opens an existing regular file for reads and writes.
    ///
    /// # Errors
    /// Returns an error if no regular non-symlink file can be opened.
    pub fn open_write(&self) -> io::Result<File> {
        self.open(OFlags::RDWR, Mode::empty())
    }

    /// Creates a new regular file, refusing any existing entry.
    ///
    /// # Errors
    /// Returns an error if exclusive creation fails.
    pub fn create(&self) -> io::Result<File> {
        self.open(
            OFlags::RDWR.union(OFlags::CREATE).union(OFlags::EXCL),
            Mode::from_raw_mode(0o666),
        )
    }

    /// Creates a new capture file; the caller must acquire its writer lock.
    ///
    /// # Errors
    /// Propagates exclusive creation errors.
    pub fn create_owned(&self) -> io::Result<File> {
        self.create()
    }

    /// Opens a capture file; the caller must acquire its writer lock.
    ///
    /// # Errors
    /// Propagates open errors.
    pub fn open_owned(&self) -> io::Result<File> {
        self.open_write()
    }

    ///
    /// # Errors
    /// Returns an error if lookup fails or the name is not a regular file.
    pub fn identity(&self) -> io::Result<(u64, u64)> {
        let stat =
            rustix::fs::statat(&*self.directory.file, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "location is occupied by a non-regular entry",
            ));
        }
        #[allow(clippy::unnecessary_cast)]
        Ok((stat.st_dev as u64, stat.st_ino as u64))
    }

    ///
    /// # Errors
    /// Returns an error for lookup failures other than a missing name.
    pub fn same_file(&self, file: &File) -> io::Result<bool> {
        let metadata = file.metadata()?;
        match self.identity() {
            Ok(identity) => Ok(identity == (metadata.dev(), metadata.ino())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// The protected source name cannot be substituted by a different filesystem user.
    /// Same-user mutations must remain serialized by the caller.
    ///
    /// # Errors
    /// Returns an error if the protected source check or no-replace link fails.
    pub fn link_to(&self, file: &File, destination: &Self) -> io::Result<()> {
        self.directory.require_removal_parent()?;
        if !self.same_file(file)? {
            return Err(io::Error::other(
                "source name no longer identifies the held file",
            ));
        }
        rustix::fs::linkat(
            &*self.directory.file,
            &self.name,
            &*destination.directory.file,
            &destination.name,
            AtFlags::empty(),
        )?;
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if ownership, protected-parent or retained-identity checks fail, or unlink fails.
    pub fn remove_owned(&self, file: &File) -> io::Result<()> {
        self.directory.require_removal_parent()?;
        if file.metadata()?.uid() != rustix::process::geteuid().as_raw() || !self.same_file(file)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file name no longer identifies an owned file",
            ));
        }
        rustix::fs::unlinkat(&*self.directory.file, &self.name, AtFlags::empty())?;
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if either parent is unprotected or rename fails.
    pub fn replace_private(&self, destination: &Self) -> io::Result<()> {
        self.directory.require_removal_parent()?;
        destination.directory.require_removal_parent()?;
        rustix::fs::renameat(
            &*self.directory.file,
            &self.name,
            &*destination.directory.file,
            &destination.name,
        )?;
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if the directory permits other users to replace its entries.
    pub fn require_removal_parent(&self) -> io::Result<()> {
        self.directory.require_removal_parent()
    }

    ///
    /// # Errors
    /// Returns an error if the parent directory flush fails.
    pub fn sync_parent(&self) -> io::Result<()> {
        self.directory.sync()
    }
}

fn validate_platform_contract(contract: crate::NasContract, supported: bool) -> io::Result<()> {
    if !supported && contract != crate::NasContract::Unqualified {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NAS qualification is Linux-only",
        ));
    }
    Ok(())
}

fn protected_directory(
    is_directory: bool,
    owner: u32,
    service: u32,
    mode: u32,
    forbidden: u32,
) -> bool {
    is_directory && owner == service && mode & forbidden == 0
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
}

fn validate_leaf(name: &OsStr) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected one filename",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn protection_and_platform_contracts_cover_each_boundary() {
        for supported in [false, true] {
            for contract in [
                crate::NasContract::Unqualified,
                crate::NasContract::ServerAcknowledged,
            ] {
                assert_eq!(
                    validate_platform_contract(contract, supported).is_ok(),
                    supported || contract == crate::NasContract::Unqualified
                );
            }
        }
        for forbidden in [0o022, 0o077] {
            for mode in 0..0o1000 {
                for is_directory in [false, true] {
                    for owner in [10, 11] {
                        let expected = is_directory && owner == 10 && mode & forbidden == 0;
                        assert_eq!(
                            protected_directory(is_directory, owner, 10, mode, forbidden),
                            expected
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn locations_propagate_errors_and_replace_only_private_names() {
        let root = std::env::temp_dir().join(format!(
            "vot-dir-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let _cleanup = Cleanup(root.clone());
        let directory = Directory::open(&root).unwrap();
        let source = directory.entry(OsStr::new("source")).unwrap();
        assert_eq!(source.path(), root.join("source"));
        let mut file = source.create().unwrap();
        file.write_all(b"retained").unwrap();
        assert!(source.create().is_err());
        let destination = source.sibling(OsStr::new("destination")).unwrap();
        assert!(!destination.same_file(&file).unwrap());
        source.replace_private(&destination).unwrap();
        assert!(!source.path().exists());
        assert!(destination.same_file(&file).unwrap());
        assert_eq!(std::fs::read(destination.path()).unwrap(), b"retained");
        std::fs::create_dir(source.path()).unwrap();
        assert!(source.same_file(&file).is_err());
        let shared = directory.create_child(OsStr::new("shared")).unwrap();
        std::fs::set_permissions(root.join("shared"), std::fs::Permissions::from_mode(0o770))
            .unwrap();
        let entry = shared.entry(OsStr::new("blocked")).unwrap();
        assert!(entry.require_removal_parent().is_err());
        assert!(destination.replace_private(&entry).is_err());
        // /dev/null supplies a deterministic rejected fsync without a filesystem fault.
        let invalid = Directory {
            file: Arc::new(File::open("/dev/null").unwrap()),
            path: root,
            nas_contract: crate::NasContract::Unqualified,
        };
        assert!(invalid.sync().is_err());
        assert!(
            invalid
                .entry(OsStr::new("unused"))
                .unwrap()
                .sync_parent()
                .is_err()
        );
        assert!(invalid.require_private().is_err());
        assert!(invalid.require_removal_parent().is_err());
    }

    #[test]
    fn publication_retains_directories_and_never_copies_or_overwrites() {
        let root = std::env::temp_dir().join(format!(
            "vot-dir-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let _cleanup = Cleanup(root.clone());
        let selected = root.join("selected");
        std::fs::create_dir(&selected).unwrap();
        std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o775)).unwrap();
        let directory = Directory::open(&selected).unwrap();
        for name in ["", ".", "..", "a/b", "a\0b"] {
            assert!(directory.entry(OsStr::new(name)).is_err());
            assert!(directory.private_child(OsStr::new(name)).is_err());
            assert!(directory.open_child(OsStr::new(name)).is_err());
            assert!(directory.create_child(OsStr::new(name)).is_err());
        }
        let private = directory.private_child(OsStr::new(".vot-stage")).unwrap();
        let nested = directory.create_child(OsStr::new("nested")).unwrap();
        assert_eq!(nested.nas_contract(), crate::NasContract::Unqualified);
        let reopened = directory.open_child(OsStr::new("nested")).unwrap();
        assert_eq!(
            nested.file().metadata().unwrap().ino(),
            reopened.file().metadata().unwrap().ino()
        );
        assert_eq!(std::fs::metadata(&selected).unwrap().mode() & 0o777, 0o775);
        let location = private.entry(OsStr::new("payload")).unwrap();
        let mut file = location
            .open(
                OFlags::RDWR.union(OFlags::CREATE).union(OFlags::EXCL),
                Mode::from_raw_mode(0o600),
            )
            .unwrap();
        file.write_all(&[7; 4096]).unwrap();
        let original = file.metadata().unwrap();
        assert!(
            location
                .open(
                    OFlags::RDWR.union(OFlags::CREATE).union(OFlags::EXCL),
                    Mode::empty()
                )
                .is_err()
        );
        let moved = root.join("moved");
        std::fs::rename(&selected, &moved).unwrap();
        std::fs::create_dir(&selected).unwrap();
        std::fs::write(selected.join("delivered"), b"unrelated").unwrap();
        let final_name = directory.entry(OsStr::new("delivered")).unwrap();
        location.link_to(&file, &final_name).unwrap();
        let final_metadata = std::fs::metadata(moved.join("delivered")).unwrap();
        assert_eq!(
            (original.dev(), original.ino()),
            (final_metadata.dev(), final_metadata.ino())
        );
        assert!(location.link_to(&file, &final_name).is_err());
        assert!(final_name.remove_owned(&file).is_err());
        location.remove_owned(&file).unwrap();
        assert!(final_name.same_file(&file).unwrap());
        assert_eq!(
            std::fs::read(selected.join("delivered")).unwrap(),
            b"unrelated"
        );
        assert!(!moved.join(".vot-stage/payload").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_children_and_regular_names_reject_substitution() {
        let root = std::env::temp_dir().join(format!(
            "vot-dir-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let _cleanup = Cleanup(root.clone());
        let directory = Directory::open(&root).unwrap();
        std::fs::create_dir(root.join("shared")).unwrap();
        std::fs::set_permissions(root.join("shared"), std::fs::Permissions::from_mode(0o770))
            .unwrap();
        assert!(directory.private_child(OsStr::new("shared")).is_err());
        std::os::unix::fs::symlink(root.join("shared"), root.join("alias")).unwrap();
        assert!(directory.private_child(OsStr::new("alias")).is_err());
        assert!(directory.open_child(OsStr::new("alias")).is_err());
        assert!(directory.create_child(OsStr::new("alias")).is_err());
        assert!(Directory::open(&root.join("alias")).is_err());
        let location = directory.entry(OsStr::new("a")).unwrap();
        let file = location
            .open(
                OFlags::RDWR.union(OFlags::CREATE).union(OFlags::EXCL),
                Mode::from_raw_mode(0o600),
            )
            .unwrap();
        std::fs::rename(root.join("a"), root.join("saved")).unwrap();
        std::fs::write(root.join("a"), b"replacement").unwrap();
        assert!(!location.same_file(&file).unwrap());
        assert!(location.remove_owned(&file).is_err());
        assert!(
            location
                .link_to(&file, &directory.entry(OsStr::new("out")).unwrap())
                .is_err()
        );
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"replacement");
        let alias = directory.entry(OsStr::new("alias")).unwrap();
        assert!(alias.identity().is_err());
        assert!(alias.open(OFlags::RDONLY, Mode::empty()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
