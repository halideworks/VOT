//! Native temporary-file storage for retained proof nodes.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(not(any(unix, windows)))]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use vot_journal::{CRC32C_EMPTY, crc32c_update};
use vot_proof_store::{ProofNode, ProofNodeStorage, StoreError};

const NODE_BYTES: usize = 32;
const CHECKSUM_BYTES: usize = 4;
const RECORD_BYTES: usize = NODE_BYTES + CHECKSUM_BYTES;
const RECORD_BYTES_U64: u64 = RECORD_BYTES as u64;
const MAX_RECORD_ORDINAL: u64 = 512_409_557_603_043_099;
const MAX_CONSECUTIVE_INTERRUPTS: usize = 16;
const CHECKSUM_DOMAIN: &[u8] = b"VOT proof spill node v0";

/// A proof-node store owned through an exclusively created temporary file.
pub struct TemporaryFileNodeStorage {
    file: Option<File>,
    path: Option<PathBuf>,
    len: u64,
    #[cfg(not(any(unix, windows)))]
    cursor: std::sync::Mutex<()>,
}

impl TemporaryFileNodeStorage {
    /// Exclusively creates an empty store at a caller-selected path.
    /// The caller must keep the parent directory private and must not rename or
    /// replace the path while the store is alive.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] when the path already exists or
    /// the file cannot be created with private permissions.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);

        let file = options.open(path).map_err(|_| StoreError::Unavailable)?;
        #[cfg(unix)]
        if file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .is_err()
        {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(StoreError::Unavailable);
        }

        Ok(Self {
            file: Some(file),
            path: Some(path.to_path_buf()),
            len: 0,
            #[cfg(not(any(unix, windows)))]
            cursor: std::sync::Mutex::new(()),
        })
    }

    /// Closes and removes the backing file, reporting cleanup failure.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] when the file cannot be removed.
    pub fn discard(mut self) -> Result<(), StoreError> {
        self.close();
        let path = self.path.take().ok_or(StoreError::Unavailable)?;
        fs::remove_file(path).map_err(|_| StoreError::Unavailable)
    }

    fn file(&self) -> Result<&File, StoreError> {
        self.file.as_ref().ok_or(StoreError::Unavailable)
    }

    fn close(&mut self) {
        drop(self.file.take());
    }
}

impl ProofNodeStorage for TemporaryFileNodeStorage {
    fn len(&self) -> Result<u64, StoreError> {
        Ok(self.len)
    }

    fn append(&mut self, node: ProofNode) -> Result<(), StoreError> {
        let ordinal = self.len;
        let offset = record_offset(ordinal)?;
        let following = ordinal.checked_add(1).ok_or(StoreError::Capacity)?;
        let record = encode_record(ordinal, &node);
        write_all_at(self.file()?, &record, offset).map_err(|_| StoreError::Unavailable)?;
        self.len = following;
        Ok(())
    }

    fn read(&self, ordinal: u64) -> Result<ProofNode, StoreError> {
        if ordinal >= self.len {
            return Err(StoreError::Corrupt);
        }
        let offset = record_offset(ordinal)?;
        #[cfg(not(any(unix, windows)))]
        let _cursor = self.cursor.lock().map_err(|_| StoreError::Unavailable)?;
        let mut record = [0_u8; RECORD_BYTES];
        read_exact_at(self.file()?, &mut record, offset).map_err(|error| map_read_error(&error))?;

        let mut node = [0_u8; NODE_BYTES];
        node.copy_from_slice(&record[..NODE_BYTES]);
        let stored = u32::from_be_bytes([
            record[NODE_BYTES],
            record[NODE_BYTES + 1],
            record[NODE_BYTES + 2],
            record[NODE_BYTES + 3],
        ]);
        if stored != node_checksum(ordinal, &node) {
            return Err(StoreError::Corrupt);
        }
        Ok(node)
    }
}

impl Drop for TemporaryFileNodeStorage {
    fn drop(&mut self) {
        self.close();
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn record_offset(ordinal: u64) -> Result<u64, StoreError> {
    if ordinal > MAX_RECORD_ORDINAL {
        return Err(StoreError::Capacity);
    }
    ordinal
        .checked_mul(RECORD_BYTES_U64)
        .ok_or(StoreError::Capacity)
}

fn node_checksum(ordinal: u64, node: &ProofNode) -> u32 {
    let checksum = crc32c_update(CRC32C_EMPTY, CHECKSUM_DOMAIN);
    let checksum = crc32c_update(checksum, &ordinal.to_be_bytes());
    crc32c_update(checksum, node)
}

fn encode_record(ordinal: u64, node: &ProofNode) -> [u8; RECORD_BYTES] {
    let mut record = [0_u8; RECORD_BYTES];
    record[..NODE_BYTES].copy_from_slice(node);
    record[NODE_BYTES..].copy_from_slice(&node_checksum(ordinal, node).to_be_bytes());
    record
}

fn map_read_error(error: &io::Error) -> StoreError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        StoreError::Corrupt
    } else {
        StoreError::Unavailable
    }
}

fn read_some_at(file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
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
    #[cfg(not(any(unix, windows)))]
    {
        let mut file = file.try_clone()?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(bytes)
    }
}

fn read_exact_at(file: &File, bytes: &mut [u8], offset: u64) -> io::Result<()> {
    read_exact_with(bytes, offset, |bytes, offset| {
        read_some_at(file, bytes, offset)
    })
}

fn retry_interrupted<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut last_error = io::Error::from(io::ErrorKind::Interrupted);
    for _ in 0..=MAX_CONSECUTIVE_INTERRUPTS {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => last_error = error,
            result => return result,
        }
    }
    Err(last_error)
}

fn read_exact_with(
    mut bytes: &mut [u8],
    mut offset: u64,
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let read = retry_interrupted(|| read(bytes, offset))?;
        let read = std::num::NonZeroUsize::new(read)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .get();
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| io::ErrorKind::InvalidInput)?)
            .ok_or(io::ErrorKind::InvalidInput)?;
        bytes = bytes.get_mut(read..).ok_or(io::ErrorKind::InvalidData)?;
    }
    Ok(())
}

fn write_some_at(file: &File, bytes: &[u8], offset: u64) -> io::Result<usize> {
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
    #[cfg(not(any(unix, windows)))]
    {
        let mut file = file.try_clone()?;
        file.seek(SeekFrom::Start(offset))?;
        file.write(bytes)
    }
}

fn write_all_at(file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
    write_all_with(bytes, offset, |bytes, offset| {
        write_some_at(file, bytes, offset)
    })
}

fn write_all_with(
    mut bytes: &[u8],
    mut offset: u64,
    mut write: impl FnMut(&[u8], u64) -> io::Result<usize>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = retry_interrupted(|| write(bytes, offset))?;
        let written = std::num::NonZeroUsize::new(written)
            .ok_or(io::ErrorKind::WriteZero)?
            .get();
        offset = offset
            .checked_add(u64::try_from(written).map_err(|_| io::ErrorKind::InvalidInput)?)
            .ok_or(io::ErrorKind::InvalidInput)?;
        bytes = bytes.get(written..).ok_or(io::ErrorKind::InvalidData)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::panic::{RefUnwindSafe, UnwindSafe};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestPath(PathBuf);

    impl Deref for TestPath {
        type Target = Path;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn test_path(name: &str) -> TestPath {
        let root = std::env::var_os("VOT_TEST_TEMP")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("CARGO_TARGET_TMPDIR").map(PathBuf::from))
            .or_else(|| {
                std::env::var_os("CARGO_TARGET_DIR")
                    .map(|target| PathBuf::from(target).join("vot-test-temp"))
            })
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/vot-test-temp")
            });
        fs::create_dir_all(&root).unwrap_or_else(|error| {
            panic!(
                "cannot create test temporary directory {}: {error}",
                root.display()
            )
        });
        TestPath(root.join(format!(
            "vot-proof-store-file-{}-{}-{name}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn assert_auto_traits<T: Send + Sync + UnwindSafe + RefUnwindSafe + Unpin>() {}

    #[test]
    fn storage_keeps_required_auto_traits() {
        assert_auto_traits::<TemporaryFileNodeStorage>();
    }

    #[test]
    fn create_is_exclusive_and_preserves_the_existing_file() {
        let path = test_path("collision");
        fs::write(&*path, b"occupied").unwrap();
        assert!(matches!(
            TemporaryFileNodeStorage::create(&*path),
            Err(StoreError::Unavailable)
        ));
        assert_eq!(fs::read(&*path).unwrap(), b"occupied");
    }

    #[test]
    fn records_have_fixed_bytes_private_permissions_and_exact_readback() {
        let path = test_path("record-bytes");
        let mut storage = TemporaryFileNodeStorage::create(&*path).unwrap();
        let first = [0x11; NODE_BYTES];
        let second = [0xa7; NODE_BYTES];
        storage.append(first).unwrap();
        storage.append(second).unwrap();

        assert_eq!(storage.len(), Ok(2));
        assert_eq!(storage.read(0), Ok(first));
        assert_eq!(storage.read(1), Ok(second));
        assert_eq!(storage.read(2), Err(StoreError::Corrupt));
        assert_eq!(storage.read(u64::MAX), Err(StoreError::Corrupt));

        let mut actual = [0_u8; 2 * RECORD_BYTES];
        read_exact_at(storage.file().unwrap(), &mut actual, 0).unwrap();
        let mut expected = [0_u8; 2 * RECORD_BYTES];
        expected[..RECORD_BYTES].copy_from_slice(&encode_record(0, &first));
        expected[RECORD_BYTES..].copy_from_slice(&encode_record(1, &second));
        assert_eq!(actual, expected);
        assert_eq!(storage.file().unwrap().metadata().unwrap().len(), 72);

        #[cfg(unix)]
        assert_eq!(
            storage
                .file()
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn every_short_record_is_corrupt() {
        for length in 0..RECORD_BYTES {
            let path = test_path(&format!("short-{length}"));
            let mut storage = TemporaryFileNodeStorage::create(&*path).unwrap();
            storage.append([0x33; NODE_BYTES]).unwrap();
            storage
                .file()
                .unwrap()
                .set_len(u64::try_from(length).unwrap())
                .unwrap();
            assert_eq!(storage.read(0), Err(StoreError::Corrupt), "{length}");
        }
    }

    #[test]
    fn node_checksum_and_record_order_corruption_are_rejected() {
        let node_path = test_path("node-corrupt");
        let mut node_store = TemporaryFileNodeStorage::create(&*node_path).unwrap();
        node_store.append([0x44; NODE_BYTES]).unwrap();
        write_all_at(node_store.file().unwrap(), &[0x45], 0).unwrap();
        assert_eq!(node_store.read(0), Err(StoreError::Corrupt));

        let checksum_path = test_path("checksum-corrupt");
        let mut checksum_store = TemporaryFileNodeStorage::create(&*checksum_path).unwrap();
        checksum_store.append([0x55; NODE_BYTES]).unwrap();
        let mut checksum_byte = [0];
        read_exact_at(
            checksum_store.file().unwrap(),
            &mut checksum_byte,
            RECORD_BYTES_U64 - 1,
        )
        .unwrap();
        checksum_byte[0] ^= 1;
        write_all_at(
            checksum_store.file().unwrap(),
            &checksum_byte,
            RECORD_BYTES_U64 - 1,
        )
        .unwrap();
        assert_eq!(checksum_store.read(0), Err(StoreError::Corrupt));

        let order_path = test_path("order-corrupt");
        let mut order_store = TemporaryFileNodeStorage::create(&*order_path).unwrap();
        order_store.append([0x66; NODE_BYTES]).unwrap();
        order_store.append([0x77; NODE_BYTES]).unwrap();
        let mut records = [0_u8; 2 * RECORD_BYTES];
        read_exact_at(order_store.file().unwrap(), &mut records, 0).unwrap();
        records.rotate_left(RECORD_BYTES);
        write_all_at(order_store.file().unwrap(), &records, 0).unwrap();
        assert_eq!(order_store.read(0), Err(StoreError::Corrupt));
        assert_eq!(order_store.read(1), Err(StoreError::Corrupt));
    }

    #[test]
    fn exact_io_retries_interruptions_and_advances_short_operations() {
        let source = encode_record(7, &[0x6d; NODE_BYTES]);
        let mut actual = [0_u8; RECORD_BYTES];
        let mut read_calls = 0;
        let mut read_bytes = 0;
        read_exact_with(&mut actual, 91, |output, offset| {
            read_calls += 1;
            if read_calls % 2 == 1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            assert_eq!(offset, 91 + read_bytes as u64);
            output[0] = source[read_bytes];
            read_bytes += 1;
            Ok(1)
        })
        .unwrap();
        assert_eq!(actual, source);
        assert_eq!(read_calls, 2 * RECORD_BYTES);

        let mut written = Vec::new();
        let mut write_calls = 0;
        write_all_with(&source, 173, |input, offset| {
            write_calls += 1;
            if write_calls % 2 == 1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            assert_eq!(offset, 173 + written.len() as u64);
            written.push(input[0]);
            Ok(1)
        })
        .unwrap();
        assert_eq!(written, source);
        assert_eq!(write_calls, 2 * RECORD_BYTES);
    }

    #[test]
    fn exact_io_bounds_consecutive_interruptions() {
        let mut read_calls = 0;
        let read_error = read_exact_with(&mut [0], 0, |_, _| {
            read_calls += 1;
            Err(io::ErrorKind::Interrupted.into())
        })
        .unwrap_err();
        assert_eq!(read_error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(read_calls, MAX_CONSECUTIVE_INTERRUPTS + 1);

        let mut write_calls = 0;
        let write_error = write_all_with(&[0], 0, |_, _| {
            write_calls += 1;
            Err(io::ErrorKind::Interrupted.into())
        })
        .unwrap_err();
        assert_eq!(write_error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(write_calls, MAX_CONSECUTIVE_INTERRUPTS + 1);

        let mut denied_calls = 0;
        let denied_error = read_exact_with(&mut [0], 0, |_, _| {
            denied_calls += 1;
            Err(io::ErrorKind::PermissionDenied.into())
        })
        .unwrap_err();
        assert_eq!(denied_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(denied_calls, 1);
    }

    #[test]
    fn record_offsets_accept_the_last_complete_record_only() {
        assert_eq!(record_offset(0), Ok(0));
        assert_eq!(record_offset(1), Ok(RECORD_BYTES_U64));
        assert_eq!(record_offset(2), Ok(2 * RECORD_BYTES_U64));
        assert_eq!(
            record_offset(MAX_RECORD_ORDINAL),
            Ok(MAX_RECORD_ORDINAL * RECORD_BYTES_U64)
        );
        assert_eq!(
            record_offset(MAX_RECORD_ORDINAL + 1),
            Err(StoreError::Capacity)
        );
    }

    #[test]
    fn drop_and_discard_close_before_removing_the_file() {
        let drop_path = test_path("drop");
        {
            let storage = TemporaryFileNodeStorage::create(&*drop_path).unwrap();
            assert!(drop_path.exists());
            drop(storage);
        }
        assert!(!drop_path.exists());

        let discard_path = test_path("discard");
        let storage = TemporaryFileNodeStorage::create(&*discard_path).unwrap();
        storage.discard().unwrap();
        assert!(!discard_path.exists());
    }

    #[test]
    fn failed_append_and_unwind_remove_the_file() {
        let failed_path = test_path("failed-append");
        {
            let mut storage = TemporaryFileNodeStorage::create(&*failed_path).unwrap();
            storage.close();
            assert_eq!(
                storage.append([0x81; NODE_BYTES]),
                Err(StoreError::Unavailable)
            );
        }
        assert!(!failed_path.exists());

        let unwind_path = test_path("unwind");
        let outcome = std::panic::catch_unwind(|| {
            let _storage = TemporaryFileNodeStorage::create(&*unwind_path).unwrap();
            panic!("exercise unwind cleanup");
        });
        assert!(outcome.is_err());
        assert!(!unwind_path.exists());
    }

    #[test]
    fn discard_reports_cleanup_failure() {
        let path = test_path("discard-failure");
        let mut storage = TemporaryFileNodeStorage::create(&*path).unwrap();
        storage.close();
        fs::remove_file(&*path).unwrap();
        fs::create_dir(&*path).unwrap();
        assert_eq!(storage.discard(), Err(StoreError::Unavailable));
        assert!(path.is_dir());
    }
}
