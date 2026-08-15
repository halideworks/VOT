//! Transfer tracking over the store.

use crate::{Error, ResumeStore, SubjectId, validate_total_units};
use vot_resume_core::{Error as CoreError, ResumeIdentity, ResumeState};

/// Per-object bounded-waste tracker. Active and post-checkpoint units are volatile by design.
pub struct ResumeTracker {
    subject: SubjectId,
    state: ResumeState,
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
        let identity = ResumeIdentity::new(subject.suite(), subject.root(), subject.length());
        let state = ResumeState::new(identity, total_units, checkpoint_window, checkpointed)
            .map_err(map_core_error)?;
        Ok(Self { subject, state })
    }

    pub fn begin_unit(&mut self, unit: u64) -> Result<bool, Error> {
        self.state.begin_unit(unit).map_err(map_core_error)
    }

    /// Returns true when the checkpoint window is full and should be persisted.
    pub fn complete_unit(&mut self, unit: u64) -> Result<bool, Error> {
        self.state.complete_unit(unit).map_err(map_core_error)
    }

    pub fn checkpoint(&mut self, store: &mut ResumeStore) -> Result<(), Error> {
        let plan = self.state.prepare_checkpoint();
        let checkpointed =
            store.save_object(self.subject, self.state.total_units(), plan.checkpointed())?;
        self.state
            .commit_checkpoint(plan, checkpointed)
            .map_err(map_core_error)
    }

    #[must_use]
    pub fn retransmission_units_after_crash(&self) -> usize {
        self.state.retransmission_units_after_crash()
    }

    #[must_use]
    pub fn retransmission_bound(&self) -> usize {
        self.state.retransmission_bound()
    }

    #[must_use]
    pub fn is_checkpointed(&self, unit: u64) -> bool {
        self.state.is_checkpointed(unit)
    }

    pub fn missing_units(&self) -> impl Iterator<Item = u64> + '_ {
        self.state.missing_units()
    }
}

pub(crate) fn validate_checkpoint_window(
    total_units: u64,
    checkpoint_window: usize,
) -> Result<(), Error> {
    vot_resume_core::validate_checkpoint_window(total_units, checkpoint_window)
        .map_err(map_core_error)
}

fn map_core_error(error: CoreError) -> Error {
    match error {
        CoreError::InvalidConfiguration => Error::InvalidConfiguration,
        CoreError::InvalidUnit => Error::InvalidUnit,
        CoreError::UnitAlreadyActive => Error::UnitAlreadyActive,
        CoreError::UnitNotActive => Error::UnitNotActive,
        CoreError::CheckpointRequired => Error::CheckpointRequired,
        CoreError::InvalidCheckpoint
        | CoreError::StaleCheckpointPlan
        | CoreError::CheckpointGenerationExhausted => Error::Corrupt,
    }
}
