use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use vot_sdk::object::{InMemoryObjectBuilder, Suite};
use vot_sdk::verify::{VerifiedSlice, verify_range};
use vot_sdk_file::{CommitProfile, ErrorKind, NativeFile, RangeStatus};

const GROUP: usize = 65_536;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "vot-sdk-file-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700).create(&path).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn entry_count(&self) -> usize {
        fs::read_dir(&self.0).unwrap().count()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn prepared(bytes: &[u8]) -> vot_sdk::object::InMemoryPreparedObject {
    let mut builder = InMemoryObjectBuilder::new(
        Suite::Blake3Bao64,
        Some(bytes.len() as u64),
        bytes.len() as u64,
    )
    .unwrap();
    builder.update(bytes).unwrap();
    builder.finish().unwrap()
}

fn verified<'a>(
    object: &vot_sdk::object::InMemoryPreparedObject,
    bytes: &'a [u8],
    offset: u64,
    requested: u64,
) -> VerifiedSlice<'a> {
    let proof = object.prove(offset, requested).unwrap();
    let start = usize::try_from(proof.covered_offset()).unwrap();
    let end = start + usize::try_from(proof.covered_length()).unwrap();
    verify_range(
        object.object_id(),
        proof.covered_offset(),
        &bytes[start..end],
        proof.proof(),
    )
    .unwrap()
}

#[test]
fn out_of_order_verified_ranges_publish_with_exact_progress() {
    let directory = TestDirectory::new("out-of-order");
    let destination = directory.join("object");
    let bytes = vec![0x41; GROUP * 2];
    let object = prepared(&bytes);
    let first = verified(&object, &bytes, 0, 1);
    let second = verified(&object, &bytes, GROUP as u64, 1);
    let mut file = NativeFile::create(object.object_id(), &destination, CommitProfile::Fast)
        .expect("exclusive staging");

    let progress = file.accept(&second).expect("second range");
    assert_eq!(progress.status, RangeStatus::Accepted);
    assert_eq!(progress.progress.covered_bytes, GROUP as u64);
    assert_eq!(progress.progress.total_bytes, (GROUP * 2) as u64);
    assert_eq!(progress.progress.fragments, 1);
    let replay = file.accept(&second).expect("replay");
    assert_eq!(replay.status, RangeStatus::Replay);
    assert_eq!(replay.progress.covered_bytes, GROUP as u64);
    assert_eq!(
        file.accept(&first).unwrap().progress.covered_bytes,
        (GROUP * 2) as u64
    );

    file.publish().expect("atomic publication");
    assert_eq!(fs::read(destination).unwrap(), bytes);
    assert_eq!(directory.entry_count(), 1, "temporary names were removed");
}

#[test]
fn identity_and_completeness_precede_publication() {
    let directory = TestDirectory::new("identity");
    let destination = directory.join("object");
    let bytes = b"the expected object";
    let object = prepared(bytes);
    let other_bytes = b"another object";
    let other = prepared(other_bytes);
    let foreign = verified(&other, other_bytes, 0, 1);
    let expected = verified(&object, bytes, 0, 1);
    let mut file = NativeFile::create(object.object_id(), &destination, CommitProfile::Fast)
        .expect("receiver");

    assert_eq!(
        file.accept(&foreign).unwrap_err().kind(),
        ErrorKind::IdentityMismatch
    );
    assert_eq!(file.progress().covered_bytes, 0);
    assert_eq!(file.publish().unwrap_err().kind(), ErrorKind::Incomplete);
    file.accept(&expected).expect("expected object");
    file.publish().expect("complete publication");
    assert_eq!(fs::read(destination).unwrap(), bytes);
}

#[test]
fn cancellation_and_drop_remove_unpublished_staging() {
    let directory = TestDirectory::new("cancel");
    let object = prepared(b"cancelled");
    let file = NativeFile::create(
        object.object_id(),
        directory.join("cancelled"),
        CommitProfile::Fast,
    )
    .unwrap();
    assert!(directory.entry_count() >= 1);
    file.cancel().expect("explicit cleanup");
    assert_eq!(directory.entry_count(), 0);

    let file = NativeFile::create(
        object.object_id(),
        directory.join("dropped"),
        CommitProfile::Fast,
    )
    .unwrap();
    assert!(directory.entry_count() >= 1);
    drop(file);
    assert_eq!(directory.entry_count(), 0);
}

#[test]
fn an_existing_destination_is_never_replaced() {
    let directory = TestDirectory::new("no-overwrite");
    let destination = directory.join("object");
    let bytes = b"new bytes";
    let object = prepared(bytes);
    let range = verified(&object, bytes, 0, 1);
    let mut file = NativeFile::create(object.object_id(), &destination, CommitProfile::Fast)
        .expect("receiver before conflict");
    file.accept(&range).unwrap();
    fs::write(&destination, b"existing bytes").unwrap();

    assert_eq!(file.publish().unwrap_err().kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&destination).unwrap(), b"existing bytes");
    drop(file);
    assert_eq!(directory.entry_count(), 1, "only the destination remains");
}

#[test]
fn concurrent_publication_has_one_winner_and_a_cleanable_loser() {
    let directory = TestDirectory::new("publication-race");
    let destination = directory.join("object");
    let bytes = b"verified race bytes";
    let object = prepared(bytes);
    let range = verified(&object, bytes, 0, 1);
    let mut winner =
        NativeFile::create(object.object_id(), &destination, CommitProfile::Fast).expect("winner");
    let mut loser =
        NativeFile::create(object.object_id(), &destination, CommitProfile::Fast).expect("loser");
    winner.accept(&range).unwrap();
    loser.accept(&range).unwrap();
    let start = Arc::new(Barrier::new(2));
    let publish = |mut file: NativeFile| {
        let start = Arc::clone(&start);
        std::thread::spawn(move || {
            start.wait();
            let result = file.publish();
            (file, result)
        })
    };
    let winner = publish(winner);
    let loser = publish(loser);
    let outcomes = [winner.join().unwrap(), loser.join().unwrap()];
    let mut winners = 0;
    let mut losers = 0;
    for (file, result) in outcomes {
        match result {
            Ok(()) => winners += 1,
            Err(error) => {
                losers += 1;
                assert_eq!(error.kind(), ErrorKind::AlreadyExists);
                assert!(!file.recovery_required());
                file.cancel().unwrap();
            }
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(losers, 1);
    assert_eq!(fs::read(destination).unwrap(), bytes);
    assert_eq!(directory.entry_count(), 1);
}

#[cfg(unix)]
#[test]
fn balanced_profile_publishes_verified_bytes() {
    let directory = TestDirectory::new("balanced");
    let destination = directory.join("object");
    let bytes = b"balanced verified bytes";
    let object = prepared(bytes);
    let range = verified(&object, bytes, 0, 1);
    let mut file = NativeFile::create(object.object_id(), &destination, CommitProfile::Balanced)
        .expect("balanced receiver");
    file.accept(&range).unwrap();
    file.publish().unwrap();
    assert_eq!(fs::read(destination).unwrap(), bytes);
}

#[cfg(target_os = "linux")]
#[test]
fn strict_profile_publishes_one_verified_group() {
    let directory = TestDirectory::new("strict");
    let destination = directory.join("object");
    let bytes = vec![0x5a; GROUP];
    let object = prepared(&bytes);
    let range = verified(&object, &bytes, 0, 1);
    let mut file = NativeFile::create(object.object_id(), &destination, CommitProfile::Strict)
        .expect("strict receiver");
    file.accept(&range).unwrap();
    file.publish().unwrap();
    assert_eq!(fs::read(destination).unwrap(), bytes);
}
