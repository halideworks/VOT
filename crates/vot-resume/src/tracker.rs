//! Transfer tracking over the store.

use crate::{BTreeSet, Error, ResumeStore, SubjectId, UnitRanges, validate_total_units};

/// Per-object bounded-waste tracker. Active and post-checkpoint units are volatile by design.
pub struct ResumeTracker {
    subject: SubjectId,
    total_units: u64,
    checkpoint_window: usize,
    checkpointed: UnitRanges,
    completed_since_checkpoint: BTreeSet<u64>,
    active: BTreeSet<u64>,
}

impl ResumeTracker {
    pub fn discover(
        store: &mut ResumeStore,
        subject: SubjectId,
        total_units: u64,
        checkpoint_window: usize,
    ) -> Result<Self, Error> {
        validate_total_units(total_units)?;
        validate_checkpoint_window(total_units, checkpoint_window)?;
        let checkpointed = store.reserve_object(subject, total_units)?;
        Ok(Self {
            subject,
            total_units,
            checkpoint_window,
            checkpointed,
            completed_since_checkpoint: BTreeSet::new(),
            active: BTreeSet::new(),
        })
    }

    pub fn begin_unit(&mut self, unit: u64) -> Result<bool, Error> {
        self.validate_unit(unit)?;
        if self.checkpointed.contains(unit) || self.completed_since_checkpoint.contains(&unit) {
            return Ok(false);
        }
        if !self.active.insert(unit) {
            return Err(Error::UnitAlreadyActive);
        }
        Ok(true)
    }

    /// Returns true when the checkpoint window is full and should be persisted.
    pub fn complete_unit(&mut self, unit: u64) -> Result<bool, Error> {
        self.validate_unit(unit)?;
        if !self.active.contains(&unit) {
            return Err(Error::UnitNotActive);
        }
        if self.completed_since_checkpoint.len() >= self.checkpoint_window {
            return Err(Error::CheckpointRequired);
        }
        self.active.remove(&unit);
        self.completed_since_checkpoint.insert(unit);
        Ok(self.completed_since_checkpoint.len() >= self.checkpoint_window)
    }

    pub fn checkpoint(&mut self, store: &mut ResumeStore) -> Result<(), Error> {
        // Merge pending and checkpointed runs in one pass to avoid per-unit shifts.
        let mut pending = UnitRanges::new();
        pending.extend_units(self.completed_since_checkpoint.iter().copied());
        let mut checkpointed = self.checkpointed.clone();
        checkpointed.union(&pending);
        let checkpointed = store.save_object(self.subject, self.total_units, &checkpointed)?;
        self.checkpointed = checkpointed;
        self.completed_since_checkpoint.clear();
        Ok(())
    }

    #[must_use]
    pub fn retransmission_units_after_crash(&self) -> usize {
        self.completed_since_checkpoint.len() + self.active.len()
    }

    #[must_use]
    pub fn retransmission_bound(&self) -> usize {
        self.checkpoint_window + self.active.len()
    }

    #[must_use]
    pub fn is_checkpointed(&self, unit: u64) -> bool {
        self.checkpointed.contains(unit)
    }

    pub fn missing_units(&self) -> impl Iterator<Item = u64> + '_ {
        self.checkpointed.missing(self.total_units)
    }

    fn validate_unit(&self, unit: u64) -> Result<(), Error> {
        if unit >= self.total_units {
            Err(Error::InvalidUnit)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn validate_checkpoint_window(
    total_units: u64,
    checkpoint_window: usize,
) -> Result<(), Error> {
    let checkpoint_window =
        u64::try_from(checkpoint_window).map_err(|_| Error::InvalidConfiguration)?;
    if checkpoint_window == 0 || checkpoint_window > total_units {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}
