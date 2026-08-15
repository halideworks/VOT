use std::sync::atomic::{AtomicU64, Ordering};

use vot_commit_model::{Event, Machine, Profile};
use vot_journal::{Error as JournalError, Journal, replay};
use vot_manifest::{
    EntryKind, Error as ManifestError, ManifestEntry, ManifestPage, ObjectId, PackagePath,
    PathProfile, ProgressiveIngest, StorageRef,
};
use vot_transport_sim::{Failure, NegativeControl, Outcome, Scenario, Simulator};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TemporaryJournal {
    directory: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl TemporaryJournal {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "vot-sim-negative-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&directory).unwrap();
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&directory).unwrap();

        let path = directory.join("journal");
        Self { directory, path }
    }
}

impl Drop for TemporaryJournal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn file(name: &str) -> ManifestEntry {
    ManifestEntry {
        path: PackagePath::portable([name]).unwrap(),
        kind: EntryKind::File,
        length: Some(1),
        storage: Some(StorageRef::Direct(ObjectId {
            suite: 1,
            root: [1; 32],
            length: 1,
        })),
        metadata: None,
    }
}

#[test]
fn broken_transport_defects_are_detected() {
    let scenario =
        Scenario::parse(include_str!("../../../sim/failures/drop-reliable.vot")).unwrap();
    let drop_trace =
        Simulator::run_negative_control(&scenario, NegativeControl::DropFirstReliableFrame);
    assert_eq!(
        drop_trace.outcome,
        Outcome::Failed(Failure::IncompleteReliable { missing: 1 })
    );
    assert_eq!(
        drop_trace.canonical(),
        include_str!("../../../sim/failures/drop-reliable.trace")
    );

    let first = ManifestPage {
        manifest_id: [3; 16],
        index: 0,
        total: None,
        previous_digest: [0; 32],
        profile: PathProfile::Portable,
        entries: vec![file("a")],
    };
    let mut ingest = ProgressiveIngest::new([3; 16], PathProfile::Portable);
    assert_eq!(
        ingest.accept(&ManifestPage {
            index: 1,
            entries: vec![file("b")],
            ..first.clone()
        }),
        Err(ManifestError::WrongPageIndex)
    );

    let fixture = TemporaryJournal::new();
    let mut journal = Journal::create(&fixture.path, [4; 16]).unwrap();
    journal.append_durable(1, b"prior").unwrap();
    drop(journal);
    assert!(matches!(
        replay(&fixture.path, [5; 16]),
        Err(JournalError::StaleIncarnation)
    ));

    let mut machine = Machine::new(Profile::Strict);
    machine.apply(Event::Admit).unwrap();
    machine.apply(Event::TransitVerified).unwrap();
    assert!(machine.apply(Event::NamespaceLinked).is_err());
}
