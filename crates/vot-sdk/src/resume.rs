//! Bounded persistence-neutral resume state.

use crate::Error;
use crate::error;
use crate::object::ObjectId;

/// Canonical completed-unit runs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnitRanges {
    inner: vot_resume_core::UnitRanges,
}

impl UnitRanges {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: vot_resume_core::UnitRanges::new(),
        }
    }

    pub fn from_runs<I>(runs: I, max_input_runs: usize) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (u64, u64)>,
    {
        vot_resume_core::UnitRanges::from_runs_bounded(runs, max_input_runs)
            .map(|inner| Self { inner })
            .map_err(error::resume_run)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[must_use]
    pub fn run_count(&self) -> usize {
        self.inner.run_count()
    }

    #[must_use]
    pub fn count(&self) -> u64 {
        self.inner.count()
    }

    #[must_use]
    pub fn contains(&self, unit: u64) -> bool {
        self.inner.contains(unit)
    }

    pub fn runs(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.inner.runs()
    }
}

/// Identity binding checkpoint state to one object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeIdentity {
    inner: vot_resume_core::ResumeIdentity,
}

impl ResumeIdentity {
    #[must_use]
    pub const fn for_object(object: &ObjectId) -> Self {
        Self {
            inner: vot_resume_core::ResumeIdentity::new(object.suite, object.root, object.length),
        }
    }
}

/// Immutable checkpoint proposal for host persistence.
#[must_use]
pub struct CheckpointPlan {
    inner: vot_resume_core::CheckpointPlan,
}

impl CheckpointPlan {
    pub fn checkpointed_runs(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.inner.checkpointed().runs()
    }

    #[must_use]
    pub fn checkpointed_count(&self) -> u64 {
        self.inner.checkpointed().count()
    }
}

/// Per-object bounded-waste resume accounting.
pub struct ResumeState {
    inner: vot_resume_core::ResumeState,
}

impl ResumeState {
    pub fn new(
        identity: ResumeIdentity,
        total_units: u64,
        checkpoint_window: usize,
        checkpointed: UnitRanges,
    ) -> Result<Self, Error> {
        vot_resume_core::ResumeState::new(
            identity.inner,
            total_units,
            checkpoint_window,
            checkpointed.inner,
        )
        .map(|inner| Self { inner })
        .map_err(error::resume)
    }

    #[must_use]
    pub const fn total_units(&self) -> u64 {
        self.inner.total_units()
    }

    pub fn begin_unit(&mut self, unit: u64) -> Result<bool, Error> {
        self.inner.begin_unit(unit).map_err(error::resume)
    }

    pub fn complete_unit(&mut self, unit: u64) -> Result<bool, Error> {
        self.inner.complete_unit(unit).map_err(error::resume)
    }

    pub fn prepare_checkpoint(&self) -> CheckpointPlan {
        CheckpointPlan {
            inner: self.inner.prepare_checkpoint(),
        }
    }

    pub fn commit_checkpoint(
        &mut self,
        plan: CheckpointPlan,
        durable: UnitRanges,
    ) -> Result<(), Error> {
        self.inner
            .commit_checkpoint(plan.inner, durable.inner)
            .map_err(error::resume)
    }

    #[must_use]
    pub fn retransmission_units_after_crash(&self) -> usize {
        self.inner.retransmission_units_after_crash()
    }

    #[must_use]
    pub fn retransmission_bound(&self) -> usize {
        self.inner.retransmission_bound()
    }

    #[must_use]
    pub fn is_checkpointed(&self, unit: u64) -> bool {
        self.inner.is_checkpointed(unit)
    }

    pub fn missing_units(&self) -> impl Iterator<Item = u64> + '_ {
        self.inner.missing_units()
    }
}
