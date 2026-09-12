use super::*;
use std::fs;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vot_sdk::object::{InMemoryObjectBuilder, InMemoryPreparedObject};

static NEXT: AtomicU64 = AtomicU64::new(0);
const INCARNATION: [u8; 16] = [23; 16];
const G: usize = 65_536;

pub(super) struct Temp(pub(super) PathBuf);
impl Temp {
    pub(super) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vot-capture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        vot_platform_fs::create_private_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn object(suite: Suite, bytes: &[u8]) -> InMemoryPreparedObject {
    let mut builder =
        InMemoryObjectBuilder::new(suite, Some(bytes.len() as u64), bytes.len() as u64).unwrap();
    builder.update(bytes).unwrap();
    builder.finish().unwrap()
}

fn accept(
    capture: &mut CaptureFile,
    object: &InMemoryPreparedObject,
    bytes: &[u8],
    offset: usize,
) -> Result<CaptureProgress, Error> {
    let proof = object.prove(offset as u64, 1).unwrap();
    let end = offset + usize::try_from(proof.covered_length()).unwrap();
    let verified = vot_sdk::verify::verify_range(
        object.object_id(),
        offset as u64,
        &bytes[offset..end],
        proof.proof(),
    )
    .unwrap();
    capture.accept(&verified)
}

fn filled(path: &Path, suite: Suite, bytes: &[u8]) -> (CaptureFile, InMemoryPreparedObject) {
    let object = object(suite, bytes);
    let mut capture = CaptureFile::create(path, INCARNATION, object.object_id(), 8).unwrap();
    for offset in (0..bytes.len()).step_by(G) {
        accept(&mut capture, &object, bytes, offset).unwrap();
    }
    (capture, object)
}

#[test]
fn disk_groups_reuse_across_checkpoints_and_survive_compaction_and_reopen() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        let dir = Temp::new();
        let mut bytes = vec![7; 3 * G + 17];
        let (mut capture, old) = filled(&dir.0, suite, &bytes);
        assert_eq!(
            capture.progress().unwrap().covered_bytes,
            bytes.len() as u64
        );
        bytes[G] = 9;
        let new = object(suite, &bytes);
        assert_eq!(capture.select(new.object_id()).unwrap().covered_bytes, 0);
        let old_proof = old.prove(0, 1).unwrap();
        assert!(capture.reuse(0, old_proof.proof()).is_err());
        for offset in [0, 2 * G, 3 * G] {
            let proof = new.prove(offset as u64, 1).unwrap();
            capture.reuse(offset as u64, proof.proof()).unwrap();
        }
        let changed = new.prove(G as u64, 1).unwrap();
        assert!(capture.reuse(G as u64, changed.proof()).is_err());
        let completed = accept(&mut capture, &new, &bytes, G).unwrap();
        assert_eq!(completed.object, *new.object_id());
        assert_eq!(completed.covered_bytes, bytes.len() as u64);
        assert_eq!(completed.cached_groups, 4);
        assert_eq!(capture.checkpoint().unwrap(), completed);
        assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
        drop(capture);
        for _ in 0..2 {
            let mut reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
            assert_eq!(reopened.progress().unwrap(), completed);
            assert_eq!(
                reopened.trace,
                [
                    Boundary::JournalSynced,
                    Boundary::BeforeParentSync,
                    Boundary::ParentSynced,
                    Boundary::Resized,
                    Boundary::BeforeDataSync,
                    Boundary::DataSynced
                ]
            );
            let mut assembled = Vec::new();
            for offset in (0..bytes.len()).step_by(G) {
                let proof = new.prove(offset as u64, 1).unwrap();
                let retained = reopened.read(offset as u64, proof.proof()).unwrap();
                assert_eq!(retained.as_slice().object_id(), *new.object_id());
                assembled.extend_from_slice(retained.as_slice().data());
            }
            assert_eq!(assembled, bytes);
            assert_eq!(object(suite, &assembled).object_id(), new.object_id());
        }
    }
}

#[test]
fn partial_tails_grow_and_shrink_without_reusing_a_different_length() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        let dir = Temp::new();
        let (mut capture, _) = filled(&dir.0, suite, &[7; 17]);
        let bytes = vec![7; G + 19];
        let larger = object(suite, &bytes);
        capture.select(larger.object_id()).unwrap();
        assert!(
            capture
                .reuse(0, larger.prove(0, 1).unwrap().proof())
                .is_err()
        );
        accept(&mut capture, &larger, &bytes, 0).unwrap();
        accept(&mut capture, &larger, &bytes, G).unwrap();
        let full_group = object(suite, &bytes[..G]);
        capture.select(full_group.object_id()).unwrap();
        assert_eq!(capture.reuse(0, &[]).unwrap().covered_bytes, GROUP);
        let shorter = object(suite, &bytes[..16_385]);
        assert_eq!(
            capture.select(shorter.object_id()).unwrap().cached_groups,
            0
        );
        assert!(capture.reuse(0, &[]).is_err());
        accept(&mut capture, &shorter, &bytes[..16_385], 0).unwrap();
        drop(capture);
        let mut reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
        assert_eq!(
            reopened.read(0, &[]).unwrap().as_slice().data(),
            &bytes[..16_385]
        );
        let empty = object(suite, &[]);
        let progress = reopened.select(empty.object_id()).unwrap();
        assert_eq!(progress.covered_bytes, 0);
        assert_eq!(progress.cached_groups, 0);
        assert_eq!(fs::metadata(dir.0.join("capture.data")).unwrap().len(), 0);
        drop(reopened);
        assert_eq!(
            CaptureFile::open(&dir.0, INCARNATION)
                .unwrap()
                .progress()
                .unwrap(),
            progress
        );
    }
}

#[test]
fn capacity_and_evidence_refusals_happen_before_invalidation() {
    let dir = Temp::new();
    let bytes = vec![3; 2 * G];
    let prepared = object(Suite::Blake3Bao64, &bytes);
    let mut capture = CaptureFile::create(&dir.0, INCARNATION, prepared.object_id(), 1).unwrap();
    accept(&mut capture, &prepared, &bytes, 0).unwrap();
    let before = capture.progress().unwrap();
    let journal = fs::read(dir.0.join("capture.journal")).unwrap();
    let data = fs::read(dir.0.join("capture.data")).unwrap();
    assert_eq!(
        accept(&mut capture, &prepared, &bytes, G)
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceExhausted
    );
    assert!(capture.invalidate(1).is_err());
    assert!(capture.reuse(0, &[0]).is_err());
    let other = object(Suite::Sha256Bep52, &bytes);
    assert!(capture.select(other.object_id()).is_err());
    assert_eq!(
        accept(&mut capture, &other, &bytes, 0).unwrap_err().kind(),
        ErrorKind::IdentityMismatch
    );
    let full = prepared.prove(0, bytes.len() as u64).unwrap();
    let verified =
        vot_sdk::verify::verify_range(prepared.object_id(), 0, &bytes, full.proof()).unwrap();
    assert!(capture.accept(&verified).is_err());
    assert_eq!(capture.progress().unwrap(), before);
    assert_eq!(fs::read(dir.0.join("capture.journal")).unwrap(), journal);
    assert_eq!(fs::read(dir.0.join("capture.data")).unwrap(), data);
    accept(&mut capture, &prepared, &bytes, 0).unwrap();
    capture.invalidate(0).unwrap();
    assert_eq!(
        accept(&mut capture, &prepared, &bytes, G)
            .unwrap()
            .covered_bytes,
        GROUP
    );
}

#[test]
fn replacement_failures_retire_coverage_and_acknowledgments_follow_both_barriers() {
    let boundaries = [
        Boundary::BeforeRecord(INVALIDATE),
        Boundary::Recorded(INVALIDATE),
        Boundary::PartialWrite,
        Boundary::Written,
        Boundary::BeforeDataSync,
        Boundary::DataSynced,
        Boundary::BeforeRecord(COMMIT),
        Boundary::Recorded(COMMIT),
    ];
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        for fault in boundaries {
            let dir = Temp::new();
            let old = vec![1; 2 * G];
            let (mut capture, _) = filled(&dir.0, suite, &old);
            let mut bytes = old;
            bytes[..G].fill(5);
            let target = object(suite, &bytes);
            capture.select(target.object_id()).unwrap();
            capture
                .reuse(GROUP, target.prove(GROUP, 1).unwrap().proof())
                .unwrap();
            capture.fault = Some(fault);
            assert!(
                accept(&mut capture, &target, &bytes, 0).is_err(),
                "{fault:?}"
            );
            assert!(capture.progress().is_err());
            assert!(capture.checkpoint().is_err());
            assert!(accept(&mut capture, &target, &bytes, G).is_err());
            drop(capture);
            let mut reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
            let expected = if fault == Boundary::Recorded(COMMIT) {
                2 * GROUP
            } else {
                GROUP
            };
            assert_eq!(
                reopened.progress().unwrap().covered_bytes,
                expected,
                "{fault:?}"
            );
            reopened.trace.clear();
            accept(&mut reopened, &target, &bytes, 0).unwrap();
            assert_eq!(
                reopened.trace,
                [
                    Boundary::BeforeRecord(INVALIDATE),
                    Boundary::JournalAppended(INVALIDATE),
                    Boundary::BeforeMetadataWrite,
                    Boundary::MetadataWritten,
                    Boundary::Recorded(INVALIDATE),
                    Boundary::Written,
                    Boundary::BeforeDataSync,
                    Boundary::DataSynced,
                    Boundary::BeforeRecord(COMMIT),
                    Boundary::JournalAppended(COMMIT),
                    Boundary::BeforeMetadataWrite,
                    Boundary::MetadataWritten,
                    Boundary::Recorded(COMMIT)
                ]
            );
            assert_eq!(reopened.progress().unwrap().covered_bytes, 2 * GROUP);
            assert_eq!(fs::read(dir.0.join("capture.data")).unwrap(), bytes);
        }
    }
}

#[test]
fn interrupted_selection_cannot_restore_truncated_groups() {
    for fault in [
        Boundary::Recorded(SELECT),
        Boundary::Resized,
        Boundary::BeforeDataSync,
        Boundary::DataSynced,
    ] {
        let dir = Temp::new();
        let bytes = vec![4; 2 * G];
        let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &bytes);
        let smaller = object(Suite::Blake3Bao64, &bytes[..G + 17]);
        capture.fault = Some(fault);
        assert!(capture.select(smaller.object_id()).is_err());
        drop(capture);
        let mut reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
        assert_eq!(reopened.progress().unwrap().object, *smaller.object_id());
        assert_eq!(reopened.progress().unwrap().cached_groups, 1);
        assert_eq!(reopened.progress().unwrap().covered_bytes, 0);
        assert_eq!(
            fs::metadata(dir.0.join("capture.data")).unwrap().len(),
            GROUP + 17
        );
        reopened
            .reuse(0, smaller.prove(0, 1).unwrap().proof())
            .unwrap();
        assert!(
            reopened
                .reuse(GROUP, smaller.prove(GROUP, 1).unwrap().proof())
                .is_err()
        );
        accept(&mut reopened, &smaller, &bytes[..G + 17], G).unwrap();
    }
}

#[test]
fn recovery_invalidates_corrupt_or_missing_bytes_but_preserves_other_groups() {
    for truncate in [false, true] {
        let dir = Temp::new();
        let bytes = vec![2; 2 * G];
        let (capture, target) = filled(&dir.0, Suite::Sha256Bep52, &bytes);
        drop(capture);
        let data = fs::OpenOptions::new()
            .write(true)
            .open(dir.0.join("capture.data"))
            .unwrap();
        if truncate {
            data.set_len(GROUP).unwrap();
        } else {
            write_all_at(&data, &[99], GROUP).unwrap();
        }
        drop(data);
        let mut reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
        assert_eq!(reopened.progress().unwrap().covered_bytes, GROUP);
        assert_eq!(reopened.progress().unwrap().cached_groups, 1);
        assert!(
            reopened
                .reuse(GROUP, target.prove(GROUP, 1).unwrap().proof())
                .is_err()
        );
        drop(reopened);
        assert_eq!(
            CaptureFile::open(&dir.0, INCARNATION)
                .unwrap()
                .progress()
                .unwrap()
                .covered_bytes,
            GROUP
        );
    }
}

#[test]
fn reading_detected_corruption_retires_its_persisted_coverage() {
    for truncate in [false, true] {
        let dir = Temp::new();
        let (mut capture, target) = filled(&dir.0, Suite::Blake3Bao64, &[7; 17]);
        if truncate {
            capture.file.set_len(1).unwrap();
        } else {
            write_all_at(&capture.file, &[9], 0).unwrap();
        }
        assert!(
            capture
                .read(0, target.prove(0, 1).unwrap().proof())
                .is_err()
        );
        assert_eq!(capture.progress().unwrap().covered_bytes, 0);
        drop(capture);
        assert_eq!(
            CaptureFile::open(&dir.0, INCARNATION)
                .unwrap()
                .progress()
                .unwrap()
                .cached_groups,
            0
        );
    }
}

#[cfg(unix)]
#[test]
fn ownership_refuses_aliases_substitution_and_second_writers() {
    let dir = Temp::new();
    let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[8; 17]);
    assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
    capture.checkpoint().unwrap();
    assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
    let data = dir.0.join("capture.data");
    let alias = dir.0.join("alias");
    fs::hard_link(&data, &alias).unwrap();
    assert!(capture.progress().is_err());
    drop(capture);
    assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
    fs::remove_file(&alias).unwrap();
    assert!(CaptureFile::open(&dir.0, [0; 16]).is_err());
    let mut capture = CaptureFile::open(&dir.0, INCARNATION).unwrap();
    fs::rename(&data, &alias).unwrap();
    fs::write(&data, b"unrelated").unwrap();
    assert!(capture.checkpoint().is_err());
    drop(capture);
    assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
    assert_eq!(fs::read(data).unwrap(), b"unrelated");
}

#[cfg(unix)]
#[test]
fn journal_substitution_and_insecure_directories_are_refused() {
    let dir = Temp::new();
    let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[8; 17]);
    let journal = dir.0.join("capture.journal");
    fs::rename(&journal, dir.0.join("old-journal")).unwrap();
    fs::write(&journal, b"unrelated").unwrap();
    assert!(capture.invalidate(0).is_err());
    assert_eq!(fs::read(&journal).unwrap(), b"unrelated");
    drop(capture);
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
    let empty = object(Suite::Blake3Bao64, &[]);
    assert!(CaptureFile::create(&dir.0, INCARNATION, empty.object_id(), 1).is_err());
}

#[test]
fn torn_commit_and_complete_unsynced_invalidation_recover_conservatively() {
    let dir = Temp::new();
    let (capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[7; 17]);
    drop(capture);
    let journal_path = dir.0.join("capture.journal");
    let original = fs::read(&journal_path).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&journal_path)
        .unwrap()
        .set_len(original.len() as u64 - 2)
        .unwrap();
    let mut reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
    assert_eq!(reopened.progress().unwrap().covered_bytes, 0);
    let target = object(Suite::Blake3Bao64, &[7; 17]);
    accept(&mut reopened, &target, &[7; 17], 0).unwrap();
    drop(reopened);
    let before = fs::metadata(&journal_path).unwrap().len();
    let (mut journal, _) = Journal::open_current(&journal_path, INCARNATION).unwrap();
    journal
        .append_durable(INVALIDATE, &0_u64.to_le_bytes())
        .unwrap();
    drop(journal);
    let encoded = fs::read(&journal_path)
        .unwrap()
        .split_off(usize::try_from(before).unwrap());
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&journal_path)
        .unwrap();
    file.set_len(before).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::OpenOptions::new()
        .append(true)
        .open(&journal_path)
        .unwrap()
        .write_all(&encoded)
        .unwrap();
    let reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
    assert_eq!(reopened.trace[0], Boundary::JournalSynced);
    assert_eq!(reopened.progress().unwrap().covered_bytes, 0);
    drop(reopened);
    let mut corrupt = fs::read(&journal_path).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    fs::write(&journal_path, &corrupt).unwrap();
    assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
    assert_eq!(fs::read(&journal_path).unwrap(), corrupt);
}

#[test]
fn snapshots_preserve_pending_operations_and_reject_malformed_records() {
    let target = object(Suite::Blake3Bao64, &vec![7; 2 * G]);
    let mut state = State::new([2, 3, 5, 7, 11, 13], 2, target.object_id().clone()).unwrap();
    state.apply(1, INVALIDATE, &0_u64.to_le_bytes()).unwrap();
    let group = Group::from_bytes(Suite::Blake3Bao64, 0, &vec![7; G], 0).unwrap();
    state.apply(2, COMMIT, &group.encode()).unwrap();
    state
        .apply(3, SELECT, &encode_object(target.object_id()))
        .unwrap();
    state.apply(4, INVALIDATE, &GROUP.to_le_bytes()).unwrap();
    let record = vot_journal::Record {
        incarnation: INCARNATION,
        sequence: 4,
        state: SNAPSHOT,
        payload: state.snapshot(),
        checkpoint: true,
    };
    let mut restored = State::restore(&record).unwrap();
    assert_eq!(restored.snapshot(), state.snapshot());
    assert_eq!(restored.sequence, 4);
    assert_eq!(restored.generation, 3);
    let group = Group::from_bytes(Suite::Blake3Bao64, GROUP, &vec![7; G], 3).unwrap();
    assert!(matches!(
        restored.apply(5, COMMIT, &group.encode()).unwrap(),
        Effect::Store {
            offset: GROUP,
            group: Some(_)
        }
    ));
    for (sequence, kind, payload) in [
        (6, COMMIT, group.encode()),
        (7, INVALIDATE, 0_u64.to_le_bytes().to_vec()),
        (6, REUSE, 1_u64.to_le_bytes().to_vec()),
        (6, SELECT, vec![0; 42]),
        (6, 99, vec![]),
        (6, REUSE, vec![0; 9]),
    ] {
        assert!(restored.apply(sequence, kind, &payload).is_err());
    }
    for length in 0..record.payload.len() {
        let mut short = record.clone();
        short.payload.truncate(length);
        assert!(State::restore(&short).is_err());
    }
    let mut trailing = record.clone();
    trailing.payload.push(0);
    assert!(State::restore(&trailing).is_err());
    let mut wrong = record.clone();
    wrong.state = SELECT;
    assert!(State::restore(&wrong).is_err());
    wrong = record.clone();
    wrong.checkpoint = false;
    assert!(State::restore(&wrong).is_err());
    wrong = record;
    wrong.payload[0] ^= 1;
    assert!(State::restore(&wrong).is_err());
}

#[test]
fn snapshot_budget_has_a_fixed_upper_bound_and_invalid_admission_creates_nothing() {
    let prepared = object(Suite::Blake3Bao64, &[7; 17]);
    for limit in [0, MAX_CAPTURE_GROUPS + 1] {
        let dir = Temp::new();
        assert!(CaptureFile::create(&dir.0, INCARNATION, prepared.object_id(), limit).is_err());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }
    let mut id = prepared.object_id().clone();
    id.length = vot_sdk::object::MAX_OBJECT_LENGTH;
    let state = State::new([2, 3, 5, 7, 11, 13], MAX_CAPTURE_GROUPS, id).unwrap();
    let record = vot_journal::Record {
        incarnation: INCARNATION,
        sequence: 0,
        state: SNAPSHOT,
        payload: state.snapshot(),
        checkpoint: true,
    };
    assert_eq!(record.payload.len(), 122);
    assert_eq!(State::restore(&record).unwrap().limit, MAX_CAPTURE_GROUPS);
    for (suite, length) in [(0, 17), (1, u64::MAX), (1, 0)] {
        let dir = Temp::new();
        let id = ObjectId {
            suite,
            root: [9; 32],
            length,
        };
        assert!(CaptureFile::create(&dir.0, INCARNATION, &id, 1).is_err());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }
}

#[test]
fn full_journal_compacts_pending_invalidation_before_retrying_commit() {
    let dir = Temp::new();
    let (mut capture, target) = filled(&dir.0, Suite::Blake3Bao64, &[7; 17]);
    capture.fault = Some(Boundary::JournalFull(COMMIT));
    let progress = accept(&mut capture, &target, &[7; 17], 0).unwrap();
    let replay = vot_journal::replay(&dir.0.join("capture.journal"), INCARNATION).unwrap();
    assert_eq!(replay.records.len(), 2);
    assert!(replay.records[0].checkpoint);
    assert_eq!(replay.records[1].state, COMMIT);
    drop(capture);
    assert_eq!(
        CaptureFile::open(&dir.0, INCARNATION)
            .unwrap()
            .progress()
            .unwrap(),
        progress
    );
}

#[test]
fn only_short_reads_invalidate_missing_payload() {
    assert!(complete_read(Ok(())).unwrap());
    assert!(!complete_read(Err(io::Error::from(io::ErrorKind::UnexpectedEof))).unwrap());
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Interrupted,
        io::ErrorKind::Other,
        io::ErrorKind::NotFound,
    ] {
        assert!(complete_read(Err(io::Error::from(kind))).is_err());
    }
}

#[test]
fn cached_group_shapes_and_small_proofs_are_strict() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        for (offset, length) in [(0, 0), (0, G + 1), (1, 17), (u64::MAX, 17)] {
            assert!(Group::from_bytes(suite, offset, &vec![7; length], 0).is_err());
        }
        let target = object(suite, &[7; 17]);
        let group = Group::from_bytes(suite, 0, &[7; 17], 0).unwrap();
        assert!(group.verify(target.object_id(), &[0]).is_err());
        let wrong = object(suite, &[8; 17]);
        assert!(group.verify(wrong.object_id(), &[]).is_err());
    }
    let target = object(Suite::Blake3Bao64, &vec![7; 2 * G]);
    let mut state = State::new([2, 3, 5, 7, 11, 13], 2, target.object_id().clone()).unwrap();
    state.generation = 2;
    state.sequence = 2;
    let valid = Group::from_bytes(Suite::Blake3Bao64, GROUP, &vec![7; G], 2).unwrap();
    for (length, generation, small_root) in [
        (0, 2, [0; 32]),
        (GROUP + 1, 1, [0; 32]),
        (GROUP, 3, [0; 32]),
        (GROUP - 1, 2, [0; 32]),
        (GROUP, 2, [1; 32]),
        (GROUP, 1, [0; 32]),
    ] {
        let mut group = valid.clone();
        group.length = length;
        group.generation = generation;
        group.small_root = small_root;
        assert_eq!(
            group.validate(&state).is_ok(),
            length == GROUP && generation == 1
        );
    }
    let mut state = State::new([2, 3, 5, 7, 11, 13], 1, target.object_id().clone()).unwrap();
    state
        .apply(1, SELECT, &encode_object(target.object_id()))
        .unwrap();
    state.apply(2, INVALIDATE, &GROUP.to_le_bytes()).unwrap();
    let mut old = valid.clone();
    old.generation = 0;
    assert!(state.apply(3, COMMIT, &old.encode()).is_err());
    let mut current = valid;
    current.generation = 1;
    state.apply(3, COMMIT, &current.encode()).unwrap();
    let mut maximum = target.object_id().clone();
    maximum.length = vot_sdk::object::MAX_OBJECT_LENGTH;
    assert!(validate_object(&maximum).is_ok());
    maximum.length += 1;
    assert!(validate_object(&maximum).is_err());
}

#[test]
fn recovery_parent_sync_failure_cannot_admit_coverage() {
    let dir = Temp::new();
    let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[7; 17]);
    capture.checkpoint().unwrap();
    capture.poisoned = true;
    capture.trace.clear();
    capture.fault = Some(Boundary::BeforeParentSync);
    assert!(capture.sync_recovery_journal().is_err());
    assert_eq!(
        capture.trace,
        [Boundary::JournalSynced, Boundary::BeforeParentSync]
    );
    assert!(capture.progress().is_err());
    drop(capture);
    let capture = CaptureFile::open(&dir.0, INCARNATION).unwrap();
    assert_eq!(
        capture.trace[..3],
        [
            Boundary::JournalSynced,
            Boundary::BeforeParentSync,
            Boundary::ParentSynced
        ]
    );
    assert_eq!(capture.progress().unwrap().covered_bytes, 17);
}

#[cfg(unix)]
#[test]
fn payload_lock_remains_held_across_journal_replacement() {
    let dir = Temp::new();
    let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[7; 17]);
    let second = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.0.join("capture.data"))
        .unwrap();
    assert!(matches!(second.try_lock(), Err(TryLockError::WouldBlock)));
    capture.checkpoint().unwrap();
    assert!(matches!(second.try_lock(), Err(TryLockError::WouldBlock)));
    drop(capture);
    second.try_lock().unwrap();
}

#[test]
fn repeated_replay_restores_newer_metadata_after_historical_shrink() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        for torn in [false, true] {
            let dir = Temp::new();
            let bytes = vec![7; 3 * G + 17];
            let (mut capture, original) = filled(&dir.0, suite, &bytes);
            capture.checkpoint().unwrap();
            let short = object(suite, &bytes[..G + 3]);
            capture.select(short.object_id()).unwrap();
            capture.select(original.object_id()).unwrap();
            capture
                .reuse(0, original.prove(0, 1).unwrap().proof())
                .unwrap();
            for offset in [G, 2 * G, 3 * G] {
                accept(&mut capture, &original, &bytes, offset).unwrap();
            }
            let expected = capture.progress().unwrap();
            capture.table.file.sync_all().unwrap();
            let journal = fs::read(dir.0.join("capture.journal")).unwrap();
            if torn {
                write_all_at(&capture.table.file, &[0xff; 80], 96 + 8).unwrap();
            }
            drop(capture);
            let directory = Directory::open(&dir.0).unwrap();
            let location = directory.entry(OsStr::new("capture.groups")).unwrap();
            let mut table = Table::new(location.open_write().unwrap(), location);
            table.select(short.object_id().length).unwrap();
            table.file.sync_all().unwrap();
            drop(table);
            assert_eq!(fs::read(dir.0.join("capture.journal")).unwrap(), journal);
            let mut reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
            assert_eq!(reopened.progress().unwrap(), expected);
            for offset in [0, G, 2 * G, 3 * G] {
                let proof = original.prove(offset as u64, 1).unwrap();
                assert!(reopened.read(offset as u64, proof.proof()).is_ok());
            }
            drop(reopened);
            assert_eq!(
                CaptureFile::open(&dir.0, INCARNATION)
                    .unwrap()
                    .progress()
                    .unwrap(),
                expected
            );
        }
    }
}

#[test]
fn durable_afterimages_repair_torn_commit_and_reuse_slots() {
    for kind in [COMMIT, REUSE] {
        let dir = Temp::new();
        let (mut capture, target) = filled(&dir.0, Suite::Blake3Bao64, &[7; 17]);
        capture.checkpoint().unwrap();
        capture.select(target.object_id()).unwrap();
        capture.fault = Some(Boundary::JournalAppended(kind));
        let result = if kind == COMMIT {
            accept(&mut capture, &target, &[7; 17], 0)
        } else {
            capture.reuse(0, &[])
        };
        assert!(result.is_err());
        assert!(capture.progress().is_err());
        capture.table.file.set_len(91).unwrap();
        write_all_at(&capture.table.file, &[0xff; 19], 8).unwrap();
        drop(capture);
        let capture = CaptureFile::open(&dir.0, INCARNATION).unwrap();
        assert_eq!(capture.progress().unwrap().covered_bytes, 17);
        assert_eq!(capture.progress().unwrap().cached_groups, 1);
    }
}

#[test]
fn metadata_flush_precedes_compaction_and_failed_flush_preserves_redo() {
    for fault in [Boundary::BeforeMetadataSync, Boundary::MetadataSynced] {
        let dir = Temp::new();
        let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[7; 17]);
        let expected = capture.progress().unwrap();
        let journal = fs::read(dir.0.join("capture.journal")).unwrap();
        capture.trace.clear();
        capture.fault = Some(fault);
        assert!(capture.checkpoint().is_err());
        assert!(capture.progress().is_err());
        assert_eq!(fs::read(dir.0.join("capture.journal")).unwrap(), journal);
        drop(capture);
        let mut reopened = CaptureFile::open(&dir.0, INCARNATION).unwrap();
        assert_eq!(reopened.progress().unwrap(), expected);
        reopened.trace.clear();
        reopened.checkpoint().unwrap();
        assert_eq!(
            reopened.trace,
            [Boundary::BeforeMetadataSync, Boundary::MetadataSynced]
        );
        let replay = vot_journal::replay(&dir.0.join("capture.journal"), INCARNATION).unwrap();
        assert_eq!(replay.records.len(), 1);
        assert_eq!(replay.records[0].payload.len(), 122);
    }
}

#[test]
fn metadata_identity_corruption_and_reserved_names_are_refused() {
    for action in [0, 1, 2, 3] {
        let dir = Temp::new();
        let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[7; 17]);
        capture.checkpoint().unwrap();
        let path = dir.0.join("capture.groups");
        #[cfg(windows)]
        if action == 0 {
            assert!(fs::rename(&path, dir.0.join("old-groups")).is_err());
            capture.progress().unwrap();
            drop(capture);
            CaptureFile::open(&dir.0, INCARNATION).unwrap();
            continue;
        }
        match action {
            0 => {
                fs::rename(&path, dir.0.join("old-groups")).unwrap();
                fs::write(&path, []).unwrap();
                assert!(capture.progress().is_err());
            }
            1 => {
                fs::hard_link(&path, dir.0.join("alias")).unwrap();
                assert!(capture.progress().is_err());
            }
            2 => {
                write_all_at(&capture.table.file, &[19], 32).unwrap();
            }
            _ => {
                capture.table.file.set_len(95).unwrap();
            }
        }
        drop(capture);
        assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
    }
    let dir = Temp::new();
    fs::write(dir.0.join("capture.groups"), b"unrelated").unwrap();
    let target = object(Suite::Blake3Bao64, &[7; 17]);
    assert!(CaptureFile::create(&dir.0, INCARNATION, target.object_id(), 1).is_err());
    assert_eq!(
        fs::read(dir.0.join("capture.groups")).unwrap(),
        b"unrelated"
    );
    assert!(!dir.0.join("capture.data").exists());
}

#[test]
fn interrupted_tail_clear_is_repaired_from_the_durable_selection() {
    let dir = Temp::new();
    let bytes = vec![7; 2 * G];
    let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &bytes);
    capture.checkpoint().unwrap();
    let before = fs::read(dir.0.join("capture.groups")).unwrap();
    let short = object(Suite::Blake3Bao64, &bytes[..G + 17]);
    let expected = capture.select(short.object_id()).unwrap();
    write_all_at(&capture.table.file, &before[96..], 96).unwrap();
    write_all_at(&capture.table.file, &[0; 16], 96).unwrap();
    drop(capture);
    let recovered = CaptureFile::open(&dir.0, INCARNATION).unwrap();
    assert_eq!(recovered.progress().unwrap(), expected);
}

#[cfg(windows)]
#[test]
fn windows_writer_exclusion_survives_compaction_and_rejects_existing_aliases() {
    let dir = Temp::new();
    let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[8; 17]);
    for compact in [false, true] {
        if compact {
            capture.checkpoint().unwrap();
        }
        assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
        for leaf in ["capture.data", "capture.groups", "capture.journal"] {
            assert!(
                fs::OpenOptions::new()
                    .write(true)
                    .open(dir.0.join(leaf))
                    .is_err()
            );
        }
        for leaf in ["capture.data", "capture.groups"] {
            let path = dir.0.join(leaf);
            assert!(fs::rename(&path, dir.0.join("substitution")).is_err());
            assert!(fs::remove_file(&path).is_err());
        }
        capture.progress().unwrap();
    }
    let alias = dir.0.join("alias");
    fs::hard_link(dir.0.join("capture.data"), &alias).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&alias).is_err());
    assert!(capture.progress().is_err());
    drop(capture);
    assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
    fs::remove_file(alias).unwrap();
    assert!(CaptureFile::open(&dir.0, [0; 16]).is_err());
    CaptureFile::open(&dir.0, INCARNATION).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_journal_substitution_is_detected_before_payload_mutation() {
    let dir = Temp::new();
    let (mut capture, _) = filled(&dir.0, Suite::Blake3Bao64, &[8; 17]);
    let journal = dir.0.join("capture.journal");
    fs::rename(&journal, dir.0.join("old-journal")).unwrap();
    fs::write(&journal, b"unrelated").unwrap();
    assert!(capture.invalidate(0).is_err());
    assert_eq!(fs::read(&journal).unwrap(), b"unrelated");
    drop(capture);
    assert!(CaptureFile::open(&dir.0, INCARNATION).is_err());
}
