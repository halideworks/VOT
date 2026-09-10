#![cfg(unix)]

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use vot_sdk::object::{InMemoryObjectBuilder, Suite};
use vot_sdk::verify::verify_range;
use vot_sdk_file::{CommitProfile, ErrorKind, NasContract, ReceiveDirectory};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self::at("VOT_TEST_DIRECTORY")
    }
    fn at(variable: &str) -> Self {
        let root = std::env::var_os(variable).map_or_else(std::env::temp_dir, PathBuf::from);
        let path = root.join(format!(
            "vot-shared-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn selected(&self) -> PathBuf {
        let path = self.0.join("selected");
        fs::DirBuilder::new().mode(0o775).create(&path).unwrap();
        path
    }
    fn contract(&self) -> NasContract {
        #[cfg(target_os = "linux")]
        if vot_platform_fs::is_smb_or_nfs(&File::open(&self.0).unwrap()).unwrap() {
            return NasContract::ServerAcknowledged;
        }
        NasContract::Unqualified
    }
}
impl Drop for Fixture {
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

#[test]
fn shared_receiving_resumes_and_publishes_the_same_allocation() {
    let fixture = Fixture::new();
    let selected = fixture.selected();
    let original_mode = fs::metadata(&selected).unwrap().mode();
    let namespace = ReceiveDirectory::open(&selected, fixture.contract()).unwrap();
    let bytes = vec![0x51; 131_072];
    let object = prepared(&bytes);
    let first = object.prove(0, 65_536).unwrap();
    let second = object.prove(65_536, 65_536).unwrap();
    let first = verify_range(object.object_id(), 0, &bytes[..65_536], first.proof()).unwrap();
    let second =
        verify_range(object.object_id(), 65_536, &bytes[65_536..], second.proof()).unwrap();
    let file = namespace
        .create(
            object.object_id(),
            OsStr::new("frame.exr"),
            CommitProfile::Balanced,
        )
        .unwrap();
    file.accept(&first).unwrap();
    let staged = fs::metadata(file.staging_path()).unwrap();
    let state = file.resume_state().unwrap();
    let mut reader = file.read_staging().unwrap();
    assert!(reader.write_all(b"must remain read only").is_err());
    let mut prefix = vec![0; 65_536];
    reader.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix, bytes[..65_536]);
    drop(reader);
    file.abandon();
    assert!(!selected.join("frame.exr").exists());

    let mut wrong = state.clone();
    wrong.profile = CommitProfile::Fast;
    assert!(
        matches!(namespace.resume(object.object_id(), OsStr::new("frame.exr"), &wrong), Err(error) if error.kind() == ErrorKind::StateConflict)
    );
    wrong = state.clone();
    wrong.staging_name = "../frame.exr".into();
    assert!(
        namespace
            .resume(object.object_id(), OsStr::new("frame.exr"), &wrong)
            .is_err()
    );
    assert!(
        namespace
            .resume(object.object_id(), OsStr::new("other.exr"), &state)
            .is_err()
    );

    let mut resumed = namespace
        .resume(object.object_id(), OsStr::new("frame.exr"), &state)
        .unwrap();
    assert_eq!(resumed.progress().covered_bytes, 65_536);
    resumed.accept(&second).unwrap();
    let before_publish = fs::metadata(resumed.staging_path()).unwrap();
    resumed.publish().unwrap();
    let published = fs::metadata(selected.join("frame.exr")).unwrap();
    assert_eq!(
        (staged.dev(), staged.ino()),
        (published.dev(), published.ino())
    );
    assert_eq!(before_publish.blocks(), published.blocks());
    assert_eq!(fs::read(selected.join("frame.exr")).unwrap(), bytes);
    assert_eq!(fs::metadata(&selected).unwrap().mode(), original_mode);
    assert_eq!(
        fs::read_dir(selected.join(".vot-stage")).unwrap().count(),
        0
    );
    assert!(
        namespace
            .create(
                object.object_id(),
                OsStr::new("frame.exr"),
                CommitProfile::Balanced
            )
            .is_err()
    );
    for name in [".vot-stage", ".VOT-STAGE", "../outside", "a/b", "", "."] {
        assert!(
            namespace
                .create(object.object_id(), OsStr::new(name), CommitProfile::Fast)
                .is_err()
        );
    }
    let cancelled = namespace
        .create(
            object.object_id(),
            OsStr::new("cancelled.exr"),
            CommitProfile::Fast,
        )
        .unwrap();
    cancelled.cancel().unwrap();
    assert!(!selected.join("cancelled.exr").exists());
    assert_eq!(
        fs::read_dir(selected.join(".vot-stage")).unwrap().count(),
        0
    );
}

#[test]
fn local_and_nfs_ancestor_rename_preserves_publication_and_journal_cleanup() {
    // CIFS qualifies server-enforced ancestor protection, not relative-handle rename semantics.
    let fixture = Fixture::at("VOT_TEST_RENAME_DIRECTORY");
    let selected = fixture.selected();
    let namespace = ReceiveDirectory::open(&selected, fixture.contract()).unwrap();
    let bytes = b"one verified payload";
    let object = prepared(bytes);
    let proof = object.prove(0, bytes.len() as u64).unwrap();
    let range = verify_range(object.object_id(), 0, bytes, proof.proof()).unwrap();
    let mut file = namespace
        .create(
            object.object_id(),
            OsStr::new("frame.exr"),
            CommitProfile::Balanced,
        )
        .unwrap();
    file.accept(&range).unwrap();
    let moved = fixture.0.join("moved");
    fs::rename(&selected, &moved).unwrap();
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("frame.exr"), b"unrelated").unwrap();
    file.publish().unwrap();
    assert_eq!(fs::read(moved.join("frame.exr")).unwrap(), bytes);
    assert_eq!(fs::read(selected.join("frame.exr")).unwrap(), b"unrelated");
    assert_eq!(fs::read_dir(moved.join(".vot-stage")).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn nas_qualification_does_not_silently_fall_back_to_local_storage() {
    let fixture = Fixture::new();
    if fixture.contract() == NasContract::Unqualified {
        assert!(ReceiveDirectory::open(&fixture.0, NasContract::ServerAcknowledged).is_err());
    } else {
        let namespace = ReceiveDirectory::open(&fixture.0, fixture.contract()).unwrap();
        let object = prepared(b"verified");
        assert!(
            matches!(namespace.create(object.object_id(), OsStr::new("strict"), CommitProfile::Strict), Err(error) if error.kind() == ErrorKind::UnsupportedProfile)
        );
        assert!(ReceiveDirectory::open(&fixture.0, NasContract::Unqualified).is_err());
        assert_eq!(
            fs::read_dir(fixture.0.join(".vot-stage")).unwrap().count(),
            0
        );
    }
}

struct LostReply(Option<vot_commit_posix::FaultPoint>);
impl vot_commit_posix::FaultInjector for LostReply {
    fn check(&mut self, point: vot_commit_posix::FaultPoint) -> std::io::Result<()> {
        if self.0 == Some(point) {
            self.0 = None;
            return Err(std::io::Error::other("lost publication acknowledgment"));
        }
        Ok(())
    }
}

#[test]
fn interrupted_publication_rechecks_content_and_preserves_conflicts() {
    use vot_commit_posix::{FaultPoint, PosixCommit};
    for fault in [
        Some(FaultPoint::NamespaceLink),
        Some(FaultPoint::DirectoryFlush),
        None,
    ] {
        let fixture = Fixture::new();
        let selected = fixture.selected();
        let contract = fixture.contract();
        let namespace = ReceiveDirectory::open(&selected, contract).unwrap();
        let bytes = b"verified recovery payload";
        let object = prepared(bytes);
        let proof = object.prove(0, bytes.len() as u64).unwrap();
        let verified = verify_range(object.object_id(), 0, bytes, proof.proof()).unwrap();
        let file = namespace
            .create(
                object.object_id(),
                OsStr::new("frame.exr"),
                CommitProfile::Balanced,
            )
            .unwrap();
        file.accept(&verified).unwrap();
        let state = file.resume_state().unwrap();
        file.abandon();
        let directory = vot_platform_fs::Directory::open_with_nas(&selected, contract).unwrap();
        let temporary = directory.private_child(OsStr::new(".vot-stage")).unwrap();
        let mut commit = PosixCommit::reattach_at(
            vot_commit_model::Profile::Balanced,
            state.incarnation,
            temporary.entry(&state.staging_name).unwrap(),
            directory.entry(OsStr::new("frame.exr")).unwrap(),
            temporary.entry(&state.journal_name).unwrap(),
            contract,
            LostReply(fault),
        )
        .unwrap();
        commit.finish_transit_verified().unwrap();
        assert_eq!(commit.publish().is_err(), fault.is_some());
        drop(commit);
        let identity = fs::metadata(selected.join("frame.exr")).unwrap();
        let wrong = prepared(&vec![0; bytes.len()]);
        assert!(
            matches!(namespace.recover_publication(wrong.object_id(), OsStr::new("frame.exr"), &state),
            Err(error) if error.kind() == ErrorKind::IdentityMismatch)
        );
        assert!(
            selected
                .join(".vot-stage")
                .join(&state.journal_name)
                .exists()
        );
        let mut wrong = state.clone();
        wrong.profile = CommitProfile::Fast;
        assert!(
            namespace
                .recover_publication(object.object_id(), OsStr::new("frame.exr"), &wrong)
                .is_err()
        );
        let observation = namespace
            .recover_publication(object.object_id(), OsStr::new("frame.exr"), &state)
            .unwrap();
        assert_eq!(observation.incarnation, state.incarnation);
        assert!(observation.sequence > 0);
        assert_eq!(fs::read(selected.join("frame.exr")).unwrap(), bytes);
        let recovered = fs::metadata(selected.join("frame.exr")).unwrap();
        // CIFS refreshes allocated blocks after recovery flushes delayed writes.
        assert_eq!(
            (identity.dev(), identity.ino()),
            (recovered.dev(), recovered.ino())
        );
        let again = namespace
            .recover_publication(object.object_id(), OsStr::new("frame.exr"), &state)
            .unwrap();
        assert_eq!(again.incarnation, observation.incarnation);
        assert_eq!(again.sequence, observation.sequence);
        namespace
            .forget_publication(OsStr::new("frame.exr"), &state)
            .unwrap();
        assert_eq!(
            fs::read_dir(selected.join(".vot-stage")).unwrap().count(),
            0
        );
    }
}

#[test]
fn non_regular_final_collision_does_not_preserve_cancelled_payload() {
    let fixture = Fixture::at("VOT_TEST_RENAME_DIRECTORY");
    let namespace = ReceiveDirectory::open(&fixture.0, fixture.contract()).unwrap();
    let object = prepared(b"verified");
    let proof = object.prove(0, 8).unwrap();
    let verified = verify_range(object.object_id(), 0, b"verified", proof.proof()).unwrap();
    for kind in ["directory", "symlink"] {
        let mut file = namespace
            .create(
                object.object_id(),
                OsStr::new(kind),
                CommitProfile::Balanced,
            )
            .unwrap();
        file.accept(&verified).unwrap();
        if kind == "directory" {
            fs::create_dir(fixture.0.join(kind)).unwrap();
        } else {
            std::os::unix::fs::symlink("missing", fixture.0.join(kind)).unwrap();
        }
        assert_eq!(file.publish().unwrap_err().kind(), ErrorKind::AlreadyExists);
        assert!(!file.recovery_required());
        file.cancel().unwrap();
        assert!(fs::symlink_metadata(fixture.0.join(kind)).is_ok());
        assert_eq!(
            fs::read_dir(fixture.0.join(".vot-stage")).unwrap().count(),
            0
        );
    }
}

#[test]
fn publication_journal_survives_until_the_application_checkpoint() {
    let fixture = Fixture::new();
    let namespace = ReceiveDirectory::open(&fixture.0, fixture.contract()).unwrap();
    let object = prepared(b"checkpoint");
    let proof = object.prove(0, 10).unwrap();
    let verified = verify_range(object.object_id(), 0, b"checkpoint", proof.proof()).unwrap();
    let name = OsStr::new("checkpoint.exr");
    let mut file = namespace
        .create(object.object_id(), name, CommitProfile::Balanced)
        .unwrap();
    file.accept(&verified).unwrap();
    let state = file.resume_state().unwrap();
    assert!(namespace.forget_publication(name, &state).is_err());
    file.publish_retaining_journal().unwrap();
    let journal = file.journal_path().to_owned();
    let observation = file.publish_observation().unwrap();
    drop(file);
    assert!(journal.is_file());
    assert_eq!(fs::read(fixture.0.join(name)).unwrap(), b"checkpoint");
    let mut wrong = state.clone();
    wrong.incarnation = [0; 16];
    assert!(namespace.forget_publication(name, &wrong).is_err());
    assert!(journal.is_file());
    namespace.forget_publication(name, &state).unwrap();
    assert!(!journal.exists());
    assert_eq!(observation.incarnation, state.incarnation);
    assert_eq!(fs::read(fixture.0.join(name)).unwrap(), b"checkpoint");
}
