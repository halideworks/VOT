use std::sync::atomic::{AtomicU64, Ordering};

use vot_commit_model::{Event, Machine, Profile};
use vot_journal::{Error as JournalError, Journal, replay};
use vot_manifest::{
    Component, EntryKind, Error as ManifestError, ManifestEntry, ManifestPage, ObjectId,
    PathProfile, ProgressiveIngest, StorageRef,
};
use vot_transport_sim::{Failure, NegativeControl, Outcome, Scenario, Simulator};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn file(name: &str) -> ManifestEntry {
    ManifestEntry {
        path: vec![Component::Text(name.to_owned())],
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

    let path = std::env::temp_dir().join(format!(
        "vot-sim-negative-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut journal = Journal::create(&path, [4; 16]).unwrap();
    journal.append_durable(1, b"prior").unwrap();
    drop(journal);
    assert!(matches!(
        replay(&path, [5; 16]),
        Err(JournalError::StaleIncarnation)
    ));
    std::fs::remove_file(path).unwrap();

    let mut machine = Machine::new(Profile::Strict);
    machine.apply(Event::Admit).unwrap();
    machine.apply(Event::TransitVerified).unwrap();
    assert!(machine.apply(Event::NamespaceLinked).is_err());
}
