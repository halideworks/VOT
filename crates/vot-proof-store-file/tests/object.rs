use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use vot_object::{ObjectBuilder, PreparedObject, Suite};
use vot_proof_catalog::encode;
use vot_proof_store_file::TemporaryFileNodeStorage;

const GROUP_SIZE: usize = 65_536;
const RECORD_SIZE: u64 = 36;
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
    fs::create_dir_all(&root).unwrap();
    TestPath(root.join(format!(
        "vot-proof-object-{}-{}-{name}",
        std::process::id(),
        NEXT_PATH.fetch_add(1, Ordering::Relaxed)
    )))
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index.wrapping_mul(17) % 251).unwrap())
        .collect()
}

fn prepare_memory(suite: Suite, data: &[u8]) -> PreparedObject {
    let mut builder = ObjectBuilder::new(suite, Some(data.len() as u64)).unwrap();
    for chunk in data.chunks(131_071) {
        builder.update(chunk).unwrap();
    }
    builder.finish().unwrap()
}

fn prepare_file(suite: Suite, data: &[u8], path: &Path) -> PreparedObject {
    let storage = TemporaryFileNodeStorage::create(path).unwrap();
    let mut builder =
        ObjectBuilder::with_proof_storage(suite, Some(data.len() as u64), Box::new(storage))
            .unwrap();
    for chunk in data.chunks(131_071) {
        builder.update(chunk).unwrap();
    }
    builder.finish().unwrap()
}

#[test]
fn file_backing_preserves_identity_proofs_catalogs_and_cleanup() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        for length in [
            0, 1, 65_535, 65_536, 65_537, 4_194_303, 4_194_304, 4_194_305,
        ] {
            let data = pattern(length);
            let memory = prepare_memory(suite, &data);
            let path = test_path(&format!("{suite:?}-{length}"));
            let stored = prepare_file(suite, &data, &path);
            assert!(path.exists());
            assert_eq!(stored.object_id(), memory.object_id());
            assert_eq!(encode(&stored).unwrap(), encode(&memory).unwrap());
            if !data.is_empty() {
                for (offset, request) in
                    [(0, 1), (data.len() as u64 - 1, 1), (0, data.len() as u64)]
                {
                    assert_eq!(stored.prove(offset, request), memory.prove(offset, request));
                }
                assert!(stored.holds(0, &data));
            }
            drop(stored);
            assert!(!path.exists());
        }
    }
}

#[test]
fn unfinished_and_failed_builders_remove_their_backing() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        let unfinished_path = test_path(&format!("unfinished-{suite:?}"));
        {
            let storage = TemporaryFileNodeStorage::create(&*unfinished_path).unwrap();
            let mut builder =
                ObjectBuilder::with_proof_storage(suite, None, Box::new(storage)).unwrap();
            builder.update(b"partial").unwrap();
        }
        assert!(!unfinished_path.exists());

        let mismatch_path = test_path(&format!("mismatch-{suite:?}"));
        let storage = TemporaryFileNodeStorage::create(&*mismatch_path).unwrap();
        let mut builder =
            ObjectBuilder::with_proof_storage(suite, Some(8), Box::new(storage)).unwrap();
        builder.update(b"short").unwrap();
        assert!(builder.finish().is_err());
        assert!(!mismatch_path.exists());
    }
}

#[test]
#[ignore = "streams at least one GiB to measure the spill model"]
fn bounded_spill_scale_reports_exact_node_storage() {
    let groups = std::env::var("VOT_SCALE_GROUPS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(16_384);
    assert!(groups >= 16_384);
    let object_length = groups.checked_mul(GROUP_SIZE as u64).unwrap();
    let group = vec![0x5a; GROUP_SIZE].into_boxed_slice();

    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        let path = test_path(&format!("scale-{suite:?}"));
        let storage = TemporaryFileNodeStorage::create(&*path).unwrap();
        let mut builder =
            ObjectBuilder::with_proof_storage(suite, Some(object_length), Box::new(storage))
                .unwrap();
        for _ in 0..groups {
            builder.update(&group).unwrap();
        }
        let prepared = builder.finish().unwrap();
        let spill_bytes = fs::metadata(&*path).unwrap().len();
        assert_eq!(spill_bytes % RECORD_SIZE, 0);
        let nodes = spill_bytes / RECORD_SIZE;
        assert!(nodes >= groups);
        assert!(nodes < groups.checked_mul(2).unwrap() + 64);
        println!(
            "suite={suite:?} object_bytes={object_length} pending_byte_ceiling={GROUP_SIZE} node_count={nodes} spill_bytes={spill_bytes} record_bytes={RECORD_SIZE}"
        );
        drop(prepared);
        assert!(!path.exists());
    }
}
