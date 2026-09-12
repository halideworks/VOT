//! Bounded overwrite crash model, not a filesystem durability qualification.
//! Journal records are atomic or rejected; unsynced data bytes may persist independently.

use vot_resume_core::{ResumeIdentity, ResumeState, UnitRanges};

const BEFORE: [u8; 3] = [1, 2, 3];
const AFTER: [u8; 3] = [4, 5, 3];

#[derive(Clone, Copy, Debug)]
enum Step {
    Invalidate,
    SyncJournal,
    WriteFirst,
    WriteSecond,
    SyncData,
    Checkpoint,
    Acknowledge,
}

const STEPS: [Step; 8] = [
    Step::Invalidate,
    Step::SyncJournal,
    Step::WriteFirst,
    Step::WriteSecond,
    Step::SyncData,
    Step::Checkpoint,
    Step::SyncJournal,
    Step::Acknowledge,
];

#[derive(Clone, Debug)]
struct Record {
    sequence: u64,
    expected: [u8; 3],
    coverage: UnitRanges,
}

struct Store {
    durable: [u8; 3],
    visible: [u8; 3],
    record: Record,
    pending: Option<Record>,
    acknowledged: bool,
}

struct Recovered {
    data: [u8; 3],
    record: Record,
}

fn all_units() -> UnitRanges {
    UnitRanges::from_runs([(0, 3)]).unwrap()
}

impl Store {
    fn new() -> Self {
        Self {
            durable: BEFORE,
            visible: BEFORE,
            record: Record {
                sequence: 0,
                expected: BEFORE,
                coverage: all_units(),
            },
            pending: None,
            acknowledged: false,
        }
    }

    fn step(&mut self, step: Step) {
        match step {
            Step::Invalidate => {
                let replaced = UnitRanges::from_runs([(0, 2)]).unwrap();
                self.pending = Some(Record {
                    sequence: 1,
                    expected: AFTER,
                    coverage: self.record.coverage.difference(&replaced),
                });
            }
            Step::SyncJournal => {
                if let Some(record) = self.pending.take() {
                    self.record = record;
                }
            }
            Step::WriteFirst => self.visible[0] = AFTER[0],
            Step::WriteSecond => self.visible[1] = AFTER[1],
            Step::SyncData => self.durable = self.visible,
            Step::Checkpoint => {
                let identity = ResumeIdentity::new(1, [1; 32], 3);
                let mut resume =
                    ResumeState::new(identity, 3, 2, self.record.coverage.clone()).unwrap();
                for unit in [0, 1] {
                    assert!(resume.begin_unit(unit).unwrap());
                    resume.complete_unit(unit).unwrap();
                }
                let plan = resume.prepare_checkpoint();
                self.pending = Some(Record {
                    sequence: 1,
                    expected: AFTER,
                    coverage: plan.checkpointed().clone(),
                });
            }
            Step::Acknowledge => self.acknowledged = true,
        }
    }

    fn crashes(&self) -> Vec<Recovered> {
        let mut states = Vec::new();
        for record in std::iter::once(&self.record).chain(self.pending.iter()) {
            for mask in 0..8 {
                let mut data = self.durable;
                for (index, byte) in data.iter_mut().enumerate() {
                    if mask & (1 << index) != 0 {
                        *byte = self.visible[index];
                    }
                }
                states.push(Recovered {
                    data,
                    record: record.clone(),
                });
            }
        }
        states
    }
}

impl Recovered {
    fn valid(&self) -> bool {
        self.record.coverage.units().all(|unit| {
            let index = usize::try_from(unit).unwrap();
            self.data[index] == self.record.expected[index]
        })
    }

    fn complete(&self) -> bool {
        self.record.sequence == 1 && self.record.coverage == all_units()
    }
}

fn exercise() -> usize {
    let mut store = Store::new();
    let mut checked = 0;
    for boundary in 0..=STEPS.len() {
        for state in store.crashes() {
            assert!(
                state.valid(),
                "false coverage at boundary {boundary}: {:?}",
                state.record
            );
            if store.acknowledged {
                assert!(
                    state.complete(),
                    "acknowledgment preceded a durable checkpoint"
                );
                assert_eq!(state.data, AFTER);
            }
            checked += 1;
        }
        if let Some(step) = STEPS.get(boundary) {
            store.step(*step);
        }
    }
    assert!(store.acknowledged);
    checked
}

fn main() {
    println!(
        "{} crash outcomes checked across {} boundaries",
        exercise(),
        STEPS.len() + 1
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_crash_boundary_preserves_truthful_coverage() {
        assert_eq!(exercise(), 88);
    }

    #[test]
    fn invalidation_supersedes_the_old_checkpoint_before_replacement() {
        let mut store = Store::new();
        store.step(Step::Invalidate);
        store.step(Step::SyncJournal);
        store.step(Step::WriteFirst);
        for state in store.crashes() {
            assert_eq!(state.record.sequence, 1);
            assert_eq!(
                state.record.coverage,
                UnitRanges::from_runs([(2, 1)]).unwrap()
            );
            assert_eq!(state.record.coverage.missing(3).collect::<Vec<_>>(), [0, 1]);
            assert!(state.valid());
            assert!(!state.complete());
        }
    }

    #[test]
    fn lost_acknowledgment_can_query_the_completed_operation() {
        let mut store = Store::new();
        assert!(store.crashes().iter().all(|state| !state.complete()));
        for step in &STEPS[..STEPS.len() - 1] {
            store.step(*step);
        }
        assert!(!store.acknowledged);
        for state in store.crashes() {
            assert!(state.valid());
            assert!(state.complete());
            assert_eq!(state.data, AFTER);
        }
    }

    #[test]
    fn omitted_barriers_have_concrete_counterexamples() {
        for omitted in [1, 4, 6] {
            let mut store = Store::new();
            let mut unsafe_state = false;
            for (index, step) in STEPS.iter().enumerate() {
                if index != omitted {
                    store.step(*step);
                }
                unsafe_state |= store
                    .crashes()
                    .iter()
                    .any(|state| !state.valid() || (store.acknowledged && !state.complete()));
                if unsafe_state {
                    break;
                }
            }
            assert!(unsafe_state, "missing barrier {omitted} was not detected");
        }
    }
}
