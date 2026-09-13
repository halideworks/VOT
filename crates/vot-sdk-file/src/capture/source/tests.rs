use super::*;
use crate::capture::tests::Temp;
use std::fs::{self, OpenOptions};
use vot_platform_fs::write_all_at;

const G: usize = GROUP_BYTES;
const INCARNATION: [u8; 16] = [63; 16];

fn identity(suite: Suite, bytes: &[u8]) -> ObjectId {
    ObjectId {
        suite: suite.identifier(),
        root: vot_verifier::root(suite, bytes).unwrap(),
        length: bytes.len() as u64,
    }
}

fn writer(path: &Path, bytes: &[u8]) -> File {
    fs::write(path, bytes).unwrap();
    OpenOptions::new().write(true).open(path).unwrap()
}

fn check(capture: &mut CaptureSource, suite: Suite, bytes: &[u8]) {
    assert_eq!(
        capture.checkpoint().unwrap().object_id(),
        &identity(suite, bytes)
    );
    for offset in (0..bytes.len()).step_by(G) {
        assert_eq!(
            capture.read(offset as u64).unwrap().as_slice().data(),
            &bytes[offset..bytes.len().min(offset + G)]
        );
    }
}

#[test]
fn appends_headers_tails_truncation_and_completion_match_fresh_hashing() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        let source_dir = Temp::new();
        let stage = Temp::new();
        let path = source_dir.0.join("clip.mov");
        let producer = writer(&path, &[]);
        let mut capture =
            CaptureSource::create(File::open(&path).unwrap(), &stage.0, INCARNATION, suite, 16)
                .unwrap();
        let mut bytes = Vec::new();
        for length in [
            0,
            1,
            16_384,
            16_385,
            G,
            G + 1,
            3 * G + 17,
            4 * G,
            3 * G,
            2 * G,
            G + 19,
            G,
            17,
            0,
            5 * G + 1,
        ] {
            bytes.resize(length, 7);
            producer.set_len(length as u64).unwrap();
            write_all_at(&producer, &bytes, 0).unwrap();
            capture.refresh(0..0).unwrap();
            check(&mut capture, suite, &bytes);
            capture.refresh(0..length as u64).unwrap();
            check(&mut capture, suite, &bytes);
            assert!(!capture.is_finished());
        }
        bytes[0] = 9;
        write_all_at(&producer, &[9], 0).unwrap();
        // A same-length rewrite is not inferred from a stat or a quiet interval.
        capture.refresh(0..0).unwrap();
        assert_eq!(
            capture.finish().unwrap_err().kind(),
            ErrorKind::IdentityMismatch
        );
        assert!(!capture.is_finished());
        capture.refresh(0..1).unwrap();
        check(&mut capture, suite, &bytes);
        assert_eq!(capture.finish().unwrap(), identity(suite, &bytes));
        assert!(capture.is_finished());
        assert_eq!(
            capture.capture.progress().unwrap().covered_bytes,
            bytes.len() as u64
        );
        assert!(capture.refresh(0..0).is_err());
        assert!(capture.finish().is_err());
        drop(capture);
        let mut recovered =
            CaptureSource::open(File::open(&path).unwrap(), &stage.0, INCARNATION).unwrap();
        assert!(!recovered.is_finished());
        check(&mut recovered, suite, &bytes);
        recovered.finish().unwrap();
    }
}

#[test]
fn replacement_is_explicit_and_does_not_follow_a_new_path_entry() {
    let source_dir = Temp::new();
    let stage = Temp::new();
    let path = source_dir.0.join("clip.mov");
    let renamed = source_dir.0.join("old.mov");
    fs::write(&path, [1; 17]).unwrap();
    let suite = Suite::Blake3Bao64;
    let mut capture =
        CaptureSource::create(File::open(&path).unwrap(), &stage.0, INCARNATION, suite, 8).unwrap();
    let old_identity = capture.source_identity().unwrap();
    capture.refresh(0..0).unwrap();
    fs::rename(&path, &renamed).unwrap();
    fs::write(&path, [2; 33]).unwrap();
    assert_eq!(capture.source_identity().unwrap(), old_identity);
    capture.refresh(0..0).unwrap();
    check(&mut capture, suite, &[1; 17]);
    capture.finish().unwrap();
    capture.replace(File::open(&path).unwrap()).unwrap();
    assert_ne!(capture.source_identity().unwrap(), old_identity);
    assert!(!capture.is_finished());
    assert_eq!(capture.checkpoint().unwrap().object_id().length, 0);
    assert!(capture.read(0).is_err());
    capture.refresh(0..0).unwrap();
    check(&mut capture, suite, &[2; 33]);
}

#[test]
fn input_limits_noops_and_disjoint_growth_preserve_the_previous_draft() {
    let source_dir = Temp::new();
    let stage = Temp::new();
    let path = source_dir.0.join("clip.mov");
    let producer = writer(&path, &vec![1; 2 * G]);
    let suite = Suite::Sha256Bep52;
    let mut capture =
        CaptureSource::create(File::open(&path).unwrap(), &stage.0, INCARNATION, suite, 4).unwrap();
    capture.refresh(0..0).unwrap();
    let before = capture.capture.progress().unwrap();
    capture.refresh(1..1).unwrap();
    assert_eq!(capture.capture.progress().unwrap(), before);
    for range in [
        Range { start: 1, end: 0 },
        0..(2 * GROUP + 1),
        u64::MAX..u64::MAX,
    ] {
        assert!(capture.refresh(range).is_err());
        assert_eq!(capture.capture.progress().unwrap(), before);
    }
    producer.set_len(4 * GROUP + 1).unwrap();
    assert_eq!(
        capture.refresh(0..0).unwrap_err().kind(),
        ErrorKind::ResourceExhausted
    );
    assert_eq!(capture.capture.progress().unwrap(), before);
    let mut bytes = vec![1; 2 * G];
    bytes.resize(4 * G, 2);
    bytes[1] = 3;
    producer.set_len(bytes.len() as u64).unwrap();
    write_all_at(&producer, &bytes, 0).unwrap();
    capture.refresh(1..2).unwrap();
    check(&mut capture, suite, &bytes);
    // One SELECT for the batch, rather than one per appended group.
    assert_eq!(
        capture
            .capture
            .trace
            .iter()
            .filter(|b| **b == crate::capture::Boundary::Recorded(super::super::state::SELECT))
            .count(),
        2
    );
    assert_eq!(capture.buffer.len(), WINDOW);
    assert_eq!(capture.finish().unwrap(), identity(suite, &bytes));
}

#[test]
fn incomplete_installation_and_corrupt_recovery_force_full_reconciliation() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        let source_dir = Temp::new();
        let stage = Temp::new();
        let path = source_dir.0.join("clip.mov");
        let producer = writer(&path, &vec![1; 3 * G]);
        let mut capture =
            CaptureSource::create(File::open(&path).unwrap(), &stage.0, INCARNATION, suite, 8)
                .unwrap();
        capture.refresh(0..0).unwrap();
        write_all_at(&producer, &[9], 0).unwrap();
        capture.capture.fault = Some(crate::capture::Boundary::Written);
        assert!(capture.refresh(0..1).is_err());
        assert!(capture.checkpoint().is_err());
        assert!(capture.read(0).is_err());
        assert!(capture.refresh(0..1).is_err());
        drop(capture);
        let mut capture =
            CaptureSource::open(File::open(&path).unwrap(), &stage.0, INCARNATION).unwrap();
        assert!(capture.checkpoint().is_err());
        // A later hint for a different group cannot drop the interrupted update.
        write_all_at(&producer, &[8], GROUP).unwrap();
        capture.refresh(GROUP..GROUP + 1).unwrap();
        let mut bytes = vec![1; 3 * G];
        bytes[0] = 9;
        bytes[G] = 8;
        check(&mut capture, suite, &bytes);
        drop(capture);
        let stage_writer = OpenOptions::new()
            .write(true)
            .open(stage.0.join("capture.data"))
            .unwrap();
        write_all_at(&stage_writer, &[0], 2 * GROUP).unwrap();
        drop(stage_writer);
        let mut capture =
            CaptureSource::open(File::open(&path).unwrap(), &stage.0, INCARNATION).unwrap();
        assert!(capture.checkpoint().is_err());
        capture.refresh(0..0).unwrap();
        check(&mut capture, suite, &bytes);
        capture.finish().unwrap();
    }
}

#[test]
fn plans_cover_exact_groups_without_scanning_the_unchanged_prefix() {
    for (previous, length, dirty, expected) in [
        (0, 0, 0..0, [0..0, 0..0]),
        (GROUP, GROUP, 0..0, [0..0, 0..0]),
        (GROUP, GROUP + 1, 0..0, [0..GROUP + 1, 0..0]),
        (
            3 * GROUP,
            3 * GROUP + 1,
            0..0,
            [0..0, 3 * GROUP..3 * GROUP + 1],
        ),
        (
            3 * GROUP + 1,
            4 * GROUP,
            0..1,
            [0..GROUP, 3 * GROUP..4 * GROUP],
        ),
        (4 * GROUP, 3 * GROUP, 0..0, [0..0, 3 * GROUP..3 * GROUP]),
        (
            4 * GROUP,
            2 * GROUP + 1,
            2 * GROUP..2 * GROUP + 1,
            [2 * GROUP..2 * GROUP + 1, 0..0],
        ),
        (
            4 * GROUP,
            4 * GROUP,
            GROUP + 1..2 * GROUP + 1,
            [0..0, GROUP..3 * GROUP],
        ),
        (4 * GROUP, 4 * GROUP, 0..1, [0..GROUP, 0..0]),
    ] {
        assert_eq!(plan(previous, length, dirty).unwrap(), expected);
    }
    assert!(
        plan(
            vot_object::MAX_OBJECT_LENGTH,
            vot_object::MAX_OBJECT_LENGTH,
            0..0
        )
        .is_ok()
    );
    assert!(plan(0, vot_object::MAX_OBJECT_LENGTH + 1, 0..0).is_err());
    assert!(plan(0, u64::MAX, 0..0).is_err());
    for invalid in [Range { start: 1, end: 0 }, 0..5, 5..5] {
        assert!(plan(4, 4, invalid).is_err());
    }
}

#[test]
fn source_changes_between_preparation_and_installation_cannot_commit_a_false_root() {
    for truncate in [false, true] {
        let source_dir = Temp::new();
        let stage = Temp::new();
        let path = source_dir.0.join("clip.mov");
        let producer = writer(&path, &vec![1; 3 * G]);
        let suite = Suite::Blake3Bao64;
        let mut capture =
            CaptureSource::create(File::open(&path).unwrap(), &stage.0, INCARNATION, suite, 8)
                .unwrap();
        capture.after_read = Some(Box::new(move || {
            if truncate {
                producer.set_len(0).unwrap();
            } else {
                write_all_at(&producer, &[2], 0).unwrap();
            }
        }));
        assert!(capture.refresh(0..0).is_err());
        assert!(capture.checkpoint().is_err());
        assert!(capture.finish().is_err());
        assert!(!capture.is_finished());
        let bytes = fs::read(&path).unwrap();
        capture.refresh(0..0).unwrap();
        check(&mut capture, suite, &bytes);
        capture.finish().unwrap();
    }
}

#[test]
fn missing_source_bytes_and_non_files_are_refused_without_changing_staging() {
    let source_dir = Temp::new();
    let stage = Temp::new();
    let path = source_dir.0.join("clip.mov");
    fs::write(&path, [7]).unwrap();
    let source = File::open(&path).unwrap();
    let mut scratch = [0; 2];
    assert!(read_group(&source, 0, 3, &mut scratch).is_err());
    assert!(read_group(&source, 0, u64::MAX, &mut scratch).is_err());
    assert!(read_group(&source, 0, 2, &mut scratch).is_err());
    assert!(read_group(&source, 1, 1, &mut scratch).is_err());
    assert_eq!(read_group(&source, 0, 1, &mut scratch).unwrap(), &[7]);
    let mut capture =
        CaptureSource::create(source, &stage.0, INCARNATION, Suite::Blake3Bao64, 1).unwrap();
    // A deleted source name does not revoke the retained regular handle.
    fs::remove_file(&path).unwrap();
    capture.refresh(0..0).unwrap();
    capture.finish().unwrap();
    #[cfg(unix)]
    {
        let before = capture.capture.progress().unwrap();
        assert!(capture.replace(File::open(&source_dir.0).unwrap()).is_err());
        assert!(
            CaptureSource::open(File::open(&source_dir.0).unwrap(), &stage.0, INCARNATION).is_err()
        );
        assert!(
            CaptureSource::create(
                File::open(&source_dir.0).unwrap(),
                &stage.0,
                INCARNATION,
                Suite::Blake3Bao64,
                1
            )
            .is_err()
        );
        assert_eq!(capture.capture.progress().unwrap(), before);
    }
}

#[test]
fn staging_cannot_be_rebound_as_its_own_source() {
    let source_dir = Temp::new();
    let stage = Temp::new();
    let path = source_dir.0.join("clip.mov");
    fs::write(&path, [7; 17]).unwrap();
    let mut capture = CaptureSource::create(
        File::open(&path).unwrap(),
        &stage.0,
        INCARNATION,
        Suite::Blake3Bao64,
        1,
    )
    .unwrap();
    capture.refresh(0..0).unwrap();
    let before = capture.capture.progress().unwrap();
    for name in ["capture.data", "capture.groups", "capture.journal"] {
        assert!(
            capture
                .replace(File::open(stage.0.join(name)).unwrap())
                .is_err()
        );
        assert_eq!(capture.capture.progress().unwrap(), before);
    }
    drop(capture);
    for name in ["capture.data", "capture.groups", "capture.journal"] {
        assert!(
            CaptureSource::open(
                File::open(stage.0.join(name)).unwrap(),
                &stage.0,
                INCARNATION
            )
            .is_err()
        );
    }
}

#[test]
fn a_zero_extended_old_tail_is_incomplete_even_when_payload_has_the_new_root() {
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        let source_dir = Temp::new();
        let stage = Temp::new();
        let path = source_dir.0.join("clip.mov");
        let producer = writer(&path, &[7; 17]);
        let mut capture =
            CaptureSource::create(File::open(&path).unwrap(), &stage.0, INCARNATION, suite, 1)
                .unwrap();
        capture.refresh(0..0).unwrap();
        producer.set_len(33).unwrap();
        let mut bytes = vec![7; 17];
        bytes.resize(33, 0);
        capture.capture.select(&identity(suite, &bytes)).unwrap();
        drop(capture);
        let mut capture =
            CaptureSource::open(File::open(&path).unwrap(), &stage.0, INCARNATION).unwrap();
        assert!(capture.checkpoint().is_err());
        capture.refresh(0..0).unwrap();
        check(&mut capture, suite, &bytes);
        capture.finish().unwrap();
    }
}

#[test]
fn a_failed_staged_read_forces_reconciliation_and_final_growth_refuses_completion() {
    let source_dir = Temp::new();
    let stage = Temp::new();
    let path = source_dir.0.join("clip.mov");
    let producer = writer(&path, &[7; 17]);
    let mut capture = CaptureSource::create(
        File::open(&path).unwrap(),
        &stage.0,
        INCARNATION,
        Suite::Blake3Bao64,
        1,
    )
    .unwrap();
    capture.refresh(0..0).unwrap();
    capture.finish().unwrap();
    write_all_at(&capture.capture.file, &[8], 0).unwrap();
    assert!(capture.read(0).is_err());
    assert!(!capture.is_finished());
    assert!(capture.checkpoint().is_err());
    capture.refresh(0..0).unwrap();
    check(&mut capture, Suite::Blake3Bao64, &[7; 17]);
    capture.after_read = Some(Box::new(move || producer.set_len(18).unwrap()));
    assert_eq!(
        capture.finish().unwrap_err().kind(),
        ErrorKind::IdentityMismatch
    );
    assert!(!capture.is_finished());
}

#[test]
fn refresh_io_is_bounded_by_dirty_groups_and_does_not_reread_a_quiet_tail() {
    let source_dir = Temp::new();
    let stage = Temp::new();
    let path = source_dir.0.join("clip.mov");
    let producer = writer(&path, &vec![7; 8 * G + 17]);
    let mut capture = CaptureSource::create(
        File::open(&path).unwrap(),
        &stage.0,
        INCARNATION,
        Suite::Blake3Bao64,
        16,
    )
    .unwrap();
    capture.refresh(0..0).unwrap();
    READ_BYTES.set(0);
    capture.refresh(0..0).unwrap();
    assert_eq!(READ_BYTES.get(), 0);
    write_all_at(&producer, &[8], 0).unwrap();
    capture.refresh(0..1).unwrap();
    assert_eq!(READ_BYTES.get(), 2 * GROUP);
    READ_BYTES.set(0);
    write_all_at(&producer, &[9], 0).unwrap();
    capture.refresh(0..8 * GROUP + 17).unwrap();
    assert_eq!(READ_BYTES.get(), 9 * GROUP + 17);
    READ_BYTES.set(0);
    producer.set_len(9 * GROUP + 1).unwrap();
    capture.refresh(0..0).unwrap();
    assert_eq!(READ_BYTES.get(), 2 * (GROUP + 1));
    READ_BYTES.set(0);
    producer.set_len(7 * GROUP).unwrap();
    capture.refresh(0..0).unwrap();
    assert_eq!(READ_BYTES.get(), 0);
}
