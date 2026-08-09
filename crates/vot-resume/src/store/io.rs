//! Store file operations: append, truncation, locks, and signatures.

use crate::{
    Error, File, MAGIC, OpenOptions, Path, PathBuf, Read, Seek, SeekFrom, Write, append_fits,
    append_header_length, encode_record, fs, io,
};

pub(crate) fn truncate_torn_tail(path: &Path, valid_length: usize) -> Result<(), Error> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(u64::try_from(valid_length).map_err(|_| Error::TooLarge)?)?;
    file.sync_all()?;
    #[cfg(unix)]
    File::open(path.parent().ok_or(Error::InvalidConfiguration)?)?.sync_all()?;
    Ok(())
}

pub(crate) fn append_record(path: &Path, payload: &[u8]) -> Result<(), Error> {
    let record = encode_record(payload)?;
    let record_length = u64::try_from(record.len()).map_err(|_| Error::TooLarge)?;
    let current_length = file_len(path)?;
    let header_length = append_header_length(current_length);
    if !append_fits(current_length, header_length, record_length) {
        return Err(Error::TooLarge);
    }
    let created = current_length == 0;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if created {
        file.write_all(MAGIC)?;
    }
    file.write_all(&record)?;
    file.sync_all()?;
    #[cfg(unix)]
    if created {
        File::open(path.parent().ok_or(Error::InvalidConfiguration)?)?.sync_all()?;
    }
    Ok(())
}

pub(crate) fn read_bounded_store(path: &Path, maximum: u64) -> Result<Vec<u8>, Error> {
    let mut input = File::open(path)?.take(maximum.saturating_add(1));
    let mut output = Vec::with_capacity(4096);
    input.read_to_end(&mut output)?;
    if u64::try_from(output.len()).map_err(|_| Error::TooLarge)? > maximum {
        return Err(Error::TooLarge);
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileSignature {
    length: u64,
    tail: [u8; 8],
}

pub(crate) fn file_len(path: &Path) -> Result<u64, Error> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(Error::Io(error)),
    }
}

pub(crate) fn file_signature(path: &Path) -> Result<FileSignature, Error> {
    let length = file_len(path)?;
    if length == 0 {
        return Ok(FileSignature {
            length,
            tail: [0; 8],
        });
    }
    let mut file = File::open(path)?;
    let mut tail = [0; 8];
    let count = usize::try_from(length.min(8)).map_err(|_| Error::TooLarge)?;
    file.seek(SeekFrom::Start(length.saturating_sub(8)))?;
    file.read_exact(&mut tail[..count])?;
    Ok(FileSignature { length, tail })
}

pub(crate) fn temporary_path(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or(Error::InvalidConfiguration)?;
    let mut temporary = name.to_os_string();
    temporary.push(".tmp");
    Ok(path.with_file_name(temporary))
}

pub(crate) fn lock_path(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or(Error::InvalidConfiguration)?;
    let mut lock = name.to_os_string();
    lock.push(".lock");
    Ok(path.with_file_name(lock))
}

/// Removes a store's files without opening it.
///
/// The lock is taken only when there is a lock file to take, because
/// creating one in order to remove a store would both mint the file this
/// declines to delete and fail outright when the containing directory has
/// already gone. Nothing can be holding a store whose lock file does not
/// exist.
///
/// # Errors
/// Surfaces anything but a name that is already gone.
pub fn remove_files(path: &Path, lock_file_too: bool) -> Result<(), Error> {
    let lock_file = lock_path(path)?;
    let Some(lock) = held_lock(&lock_file)? else {
        return remove_if_present(path).and_then(|()| remove_if_present(&temporary_path(path)?));
    };
    let removal = remove_if_present(path).and_then(|()| remove_if_present(&temporary_path(path)?));
    if !lock_file_too || removal.is_err() {
        drop(lock);
        return removal;
    }
    remove_lock_file(lock, &lock_file)
}

/// Unlinks a lock file this thread holds.
///
/// On Unix the name goes while the lock is still held, so no waiter can
/// acquire the inode in between and end up holding a lock nothing else can
/// reach. Windows refuses to unlink an open file, so there the lock is
/// released first.
pub(crate) fn remove_lock_file(lock: File, lock_file: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    return remove_lock_file_unix(lock, lock_file);
    #[cfg(not(unix))]
    return remove_lock_file_other(lock, lock_file);
}

#[cfg(unix)]
pub(crate) fn remove_lock_file_unix(lock: File, lock_file: &Path) -> Result<(), Error> {
    let removal = remove_if_present(lock_file);
    drop(lock);
    removal
}

#[cfg(not(unix))]
pub(crate) fn remove_lock_file_other(lock: File, lock_file: &Path) -> Result<(), Error> {
    drop(lock);
    remove_if_present(lock_file)
}

/// The store's lock, or nothing when there is no lock file to hold.
pub(crate) fn held_lock(lock_file: &Path) -> Result<Option<File>, Error> {
    let lock = match OpenOptions::new().read(true).write(true).open(lock_file) {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::Io(error)),
    };
    fs4::FileExt::lock(&lock)?;
    Ok(Some(lock))
}

/// Removes a name, treating one that is already gone as the outcome wanted.
/// Every other failure surfaces.
pub(crate) fn remove_if_present(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

pub(crate) fn lock_store(path: &Path) -> Result<File, Error> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path(path)?)?;
    fs4::FileExt::lock(&lock)?;
    Ok(lock)
}
