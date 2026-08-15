use std::path::{Path, PathBuf};

use vot_resume::{ResumeStore, ResumeTracker};
use vot_resume_core::{ResumeIdentity, ResumeState, UnitRanges};
use vot_transport_api::SubjectId;

fn subject() -> SubjectId {
    SubjectId::new(1, [0x72; 32], 6 * 65_536).unwrap()
}

struct TempStore(PathBuf);

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = vot_resume::remove_files(&self.0, true);
    }
}

impl AsRef<Path> for TempStore {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

#[test]
fn native_tracker_matches_the_persistence_neutral_state() {
    let path = TempStore(
        std::env::temp_dir().join(format!("vot-resume-core-parity-{}", std::process::id())),
    );
    let subject = subject();
    let mut store = ResumeStore::open(path.0.clone()).unwrap();
    let mut native = ResumeTracker::discover(&mut store, subject, 6, 2).unwrap();
    let identity = ResumeIdentity::new(subject.suite(), subject.root(), subject.length());
    let mut core = ResumeState::new(identity, 6, 2, UnitRanges::new()).unwrap();

    for unit in 0..5 {
        assert_eq!(
            native.begin_unit(unit).unwrap(),
            core.begin_unit(unit).unwrap()
        );
        let native_due = native.complete_unit(unit).unwrap();
        let core_due = core.complete_unit(unit).unwrap();
        assert_eq!(native_due, core_due);
        if native_due {
            let plan = core.prepare_checkpoint();
            native.checkpoint(&mut store).unwrap();
            let durable = store.checkpointed(subject).unwrap().clone();
            core.commit_checkpoint(plan, durable).unwrap();
        }
        assert_eq!(
            native.retransmission_units_after_crash(),
            core.retransmission_units_after_crash()
        );
        assert_eq!(native.retransmission_bound(), core.retransmission_bound());
        assert_eq!(
            native.missing_units().collect::<Vec<_>>(),
            core.missing_units().collect::<Vec<_>>()
        );
    }
}
