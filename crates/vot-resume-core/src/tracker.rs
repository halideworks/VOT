//! Logical resume state and its persistence handoff.

use std::collections::BTreeSet;
use std::fmt;

use crate::UnitRanges;

/// Logical resume-state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfiguration,
    InvalidUnit,
    UnitAlreadyActive,
    UnitNotActive,
    CheckpointRequired,
    InvalidCheckpoint,
    StaleCheckpointPlan,
    CheckpointGenerationExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid resume configuration",
            Self::InvalidUnit => "invalid resume unit",
            Self::UnitAlreadyActive => "resume unit is already active",
            Self::UnitNotActive => "resume unit is not active",
            Self::CheckpointRequired => "resume checkpoint is required",
            Self::InvalidCheckpoint => "invalid durable resume checkpoint",
            Self::StaleCheckpointPlan => "stale resume checkpoint plan",
            Self::CheckpointGenerationExhausted => "resume checkpoint generation exhausted",
        })
    }
}

impl std::error::Error for Error {}

/// Host-supplied identity that prevents checkpoint plans crossing objects.
///
/// The fields are compared exactly and otherwise remain uninterpreted by the
/// resume core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeIdentity {
    discriminator: u16,
    digest: [u8; 32],
    length: u64,
}

impl ResumeIdentity {
    #[must_use]
    pub const fn new(discriminator: u16, digest: [u8; 32], length: u64) -> Self {
        Self {
            discriminator,
            digest,
            length,
        }
    }
}

/// An immutable checkpoint proposal bound to one logical-state generation.
///
/// The host persists the proposed checkpoint and returns its durable result to
/// `ResumeState::commit_checkpoint`.
#[must_use]
pub struct CheckpointPlan {
    identity: ResumeIdentity,
    generation: u64,
    total_units: u64,
    baseline: UnitRanges,
    checkpointed: UnitRanges,
    pending: UnitRanges,
}

impl CheckpointPlan {
    /// Checkpoint state for the host to persist.
    #[must_use]
    pub const fn checkpointed(&self) -> &UnitRanges {
        &self.checkpointed
    }
}

/// Per-object bounded-waste resume state without a persistence backend.
pub struct ResumeState {
    identity: ResumeIdentity,
    total_units: u64,
    checkpoint_window: usize,
    checkpointed: UnitRanges,
    completed_since_checkpoint: BTreeSet<u64>,
    active: BTreeSet<u64>,
    checkpoint_generation: u64,
}

impl ResumeState {
    pub fn new(
        identity: ResumeIdentity,
        total_units: u64,
        checkpoint_window: usize,
        checkpointed: UnitRanges,
    ) -> Result<Self, Error> {
        validate_checkpoint_window(total_units, checkpoint_window)?;
        validate_durable(total_units, &checkpointed)?;
        Ok(Self {
            identity,
            total_units,
            checkpoint_window,
            checkpointed,
            completed_since_checkpoint: BTreeSet::new(),
            active: BTreeSet::new(),
            checkpoint_generation: 0,
        })
    }

    #[must_use]
    pub const fn total_units(&self) -> u64 {
        self.total_units
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

    /// Builds the state to persist without changing logical state.
    pub fn prepare_checkpoint(&self) -> CheckpointPlan {
        let mut pending = UnitRanges::new();
        pending.extend_units(self.completed_since_checkpoint.iter().copied());
        let mut checkpointed = self.checkpointed.clone();
        checkpointed.union(&pending);
        CheckpointPlan {
            identity: self.identity,
            generation: self.checkpoint_generation,
            total_units: self.total_units,
            baseline: self.checkpointed.clone(),
            checkpointed,
            pending,
        }
    }

    /// Commits a host-confirmed durable checkpoint.
    ///
    /// The durable state may be a superset of the proposal when another host
    /// writer merged checkpoints while this plan was being persisted.
    pub fn commit_checkpoint(
        &mut self,
        plan: CheckpointPlan,
        durable: UnitRanges,
    ) -> Result<(), Error> {
        let CheckpointPlan {
            identity,
            generation,
            total_units,
            baseline,
            checkpointed,
            pending,
        } = plan;
        if identity != self.identity
            || generation != self.checkpoint_generation
            || total_units != self.total_units
            || baseline != self.checkpointed
            || pending
                .units()
                .any(|unit| !self.completed_since_checkpoint.contains(&unit))
        {
            return Err(Error::StaleCheckpointPlan);
        }
        validate_durable(self.total_units, &durable)?;
        if !checkpointed.difference(&durable).is_empty() {
            return Err(Error::InvalidCheckpoint);
        }
        let next_generation = self
            .checkpoint_generation
            .checked_add(1)
            .ok_or(Error::CheckpointGenerationExhausted)?;

        self.completed_since_checkpoint
            .retain(|unit| !durable.contains(*unit));
        self.active.retain(|unit| !durable.contains(*unit));
        self.checkpointed = durable;
        self.checkpoint_generation = next_generation;
        Ok(())
    }

    #[must_use]
    pub fn retransmission_units_after_crash(&self) -> usize {
        self.completed_since_checkpoint
            .len()
            .saturating_add(self.active.len())
    }

    #[must_use]
    pub fn retransmission_bound(&self) -> usize {
        self.checkpoint_window.saturating_add(self.active.len())
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

pub fn validate_checkpoint_window(total_units: u64, checkpoint_window: usize) -> Result<(), Error> {
    let checkpoint_window =
        u64::try_from(checkpoint_window).map_err(|_| Error::InvalidConfiguration)?;
    if checkpoint_window == 0 || checkpoint_window > total_units {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn validate_durable(total_units: u64, checkpointed: &UnitRanges) -> Result<(), Error> {
    if checkpointed.max().is_some_and(|unit| unit >= total_units) {
        Err(Error::InvalidCheckpoint)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ResumeIdentity, ResumeState, validate_checkpoint_window};
    use crate::UnitRanges;

    fn ranges(units: impl IntoIterator<Item = u64>) -> UnitRanges {
        let mut set = UnitRanges::new();
        set.extend_units(units);
        set
    }

    fn identity(tag: u8) -> ResumeIdentity {
        ResumeIdentity::new(u16::from_be_bytes([tag, tag]), [tag; 32], u64::from(tag))
    }

    fn state(
        total_units: u64,
        checkpoint_window: usize,
        checkpointed: UnitRanges,
    ) -> Result<ResumeState, Error> {
        ResumeState::new(identity(1), total_units, checkpoint_window, checkpointed)
    }

    fn state_with_pending(
        id: ResumeIdentity,
        total_units: u64,
        checkpointed: UnitRanges,
        pending: u64,
    ) -> ResumeState {
        let mut state = ResumeState::new(id, total_units, 2, checkpointed).unwrap();
        state.begin_unit(pending).unwrap();
        state.complete_unit(pending).unwrap();
        state
    }

    #[test]
    fn configuration_and_initial_checkpoint_are_validated() {
        assert_eq!(
            validate_checkpoint_window(0, 1),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            validate_checkpoint_window(1, 0),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            validate_checkpoint_window(1, 2),
            Err(Error::InvalidConfiguration)
        );
        assert!(validate_checkpoint_window(1, 1).is_ok());
        assert!(matches!(
            state(2, 1, ranges([2])),
            Err(Error::InvalidCheckpoint)
        ));
        let state = state(2, 1, ranges([0])).unwrap();
        assert!(state.is_checkpointed(0));
        assert_eq!(state.missing_units().collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn active_pending_and_checkpointed_units_stay_distinct() {
        let mut state = state(4, 2, UnitRanges::new()).unwrap();
        assert!(state.begin_unit(0).unwrap());
        assert_eq!(state.begin_unit(0), Err(Error::UnitAlreadyActive));
        assert_eq!(state.complete_unit(1), Err(Error::UnitNotActive));
        assert!(!state.complete_unit(0).unwrap());
        assert!(!state.begin_unit(0).unwrap());
        assert!(!state.is_checkpointed(0));
        assert_eq!(state.retransmission_units_after_crash(), 1);
        assert_eq!(state.retransmission_bound(), 2);
        assert_eq!(state.begin_unit(4), Err(Error::InvalidUnit));
    }

    #[test]
    fn a_full_window_rejects_completion_without_mutation() {
        let mut state = state(3, 1, UnitRanges::new()).unwrap();
        state.begin_unit(0).unwrap();
        state.begin_unit(1).unwrap();
        assert!(state.complete_unit(0).unwrap());
        assert_eq!(state.complete_unit(1), Err(Error::CheckpointRequired));
        assert_eq!(state.retransmission_units_after_crash(), 2);
        assert_eq!(state.retransmission_bound(), 2);
    }

    #[test]
    fn preparing_and_rejecting_a_checkpoint_are_atomic() {
        let mut state = state(3, 2, UnitRanges::new()).unwrap();
        state.begin_unit(0).unwrap();
        state.complete_unit(0).unwrap();
        let plan = state.prepare_checkpoint();
        assert_eq!(state.retransmission_units_after_crash(), 1);
        assert_eq!(
            state.commit_checkpoint(plan, UnitRanges::new()),
            Err(Error::InvalidCheckpoint)
        );
        assert_eq!(state.retransmission_units_after_crash(), 1);
        assert!(!state.is_checkpointed(0));

        let plan = state.prepare_checkpoint();
        assert_eq!(
            state.commit_checkpoint(plan, ranges([0, 3])),
            Err(Error::InvalidCheckpoint)
        );
        assert_eq!(state.retransmission_units_after_crash(), 1);
    }

    #[test]
    fn a_stale_writer_superset_becomes_the_durable_view() {
        let mut state = state(3, 1, UnitRanges::new()).unwrap();
        state.begin_unit(1).unwrap();
        state.complete_unit(1).unwrap();
        let plan = state.prepare_checkpoint();
        assert_eq!(plan.checkpointed(), &ranges([1]));
        state.commit_checkpoint(plan, ranges([0, 1])).unwrap();
        assert!(state.is_checkpointed(0));
        assert!(state.is_checkpointed(1));
        assert_eq!(state.retransmission_units_after_crash(), 0);
    }

    #[test]
    fn work_completed_after_prepare_remains_pending() {
        let mut state = state(4, 3, UnitRanges::new()).unwrap();
        state.begin_unit(0).unwrap();
        state.complete_unit(0).unwrap();
        let plan = state.prepare_checkpoint();
        state.begin_unit(1).unwrap();
        state.complete_unit(1).unwrap();
        state.commit_checkpoint(plan, ranges([0])).unwrap();
        assert!(state.is_checkpointed(0));
        assert!(!state.is_checkpointed(1));
        assert_eq!(state.retransmission_units_after_crash(), 1);
        assert_eq!(state.prepare_checkpoint().checkpointed(), &ranges([0, 1]));
    }

    #[test]
    fn a_durable_superset_reconciles_new_pending_and_active_work() {
        let mut state = state(4, 3, UnitRanges::new()).unwrap();
        state.begin_unit(0).unwrap();
        state.complete_unit(0).unwrap();
        let plan = state.prepare_checkpoint();
        state.begin_unit(1).unwrap();
        state.complete_unit(1).unwrap();
        state.begin_unit(2).unwrap();

        state.commit_checkpoint(plan, ranges([0, 1, 2])).unwrap();

        assert_eq!(state.retransmission_units_after_crash(), 0);
        assert_eq!(state.complete_unit(2), Err(Error::UnitNotActive));
        assert_eq!(state.retransmission_units_after_crash(), 0);
        assert_eq!(state.missing_units().collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn a_committed_generation_invalidates_other_plans() {
        let mut state = state(2, 1, UnitRanges::new()).unwrap();
        state.begin_unit(0).unwrap();
        state.complete_unit(0).unwrap();
        let first = state.prepare_checkpoint();
        let second = state.prepare_checkpoint();
        state.commit_checkpoint(first, ranges([0])).unwrap();
        assert_eq!(
            state.commit_checkpoint(second, ranges([0])),
            Err(Error::StaleCheckpointPlan)
        );
    }

    #[test]
    fn every_plan_binding_field_is_checked_independently() {
        let plan = state_with_pending(identity(1), 3, UnitRanges::new(), 0).prepare_checkpoint();
        let mut wrong_identity = state_with_pending(identity(2), 3, UnitRanges::new(), 0);
        assert_eq!(
            wrong_identity.commit_checkpoint(plan, ranges([0])),
            Err(Error::StaleCheckpointPlan)
        );

        let plan = state_with_pending(identity(1), 3, UnitRanges::new(), 0).prepare_checkpoint();
        let mut wrong_total = state_with_pending(identity(1), 4, UnitRanges::new(), 0);
        assert_eq!(
            wrong_total.commit_checkpoint(plan, ranges([0])),
            Err(Error::StaleCheckpointPlan)
        );

        let plan = state_with_pending(identity(1), 3, UnitRanges::new(), 0).prepare_checkpoint();
        let mut wrong_baseline = state_with_pending(identity(1), 3, ranges([2]), 0);
        assert_eq!(
            wrong_baseline.commit_checkpoint(plan, ranges([0, 2])),
            Err(Error::StaleCheckpointPlan)
        );

        let plan = state_with_pending(identity(1), 3, UnitRanges::new(), 0).prepare_checkpoint();
        let mut wrong_pending = state_with_pending(identity(1), 3, UnitRanges::new(), 1);
        assert_eq!(
            wrong_pending.commit_checkpoint(plan, ranges([0])),
            Err(Error::StaleCheckpointPlan)
        );

        let plan = state_with_pending(identity(1), 3, UnitRanges::new(), 0).prepare_checkpoint();
        let mut wrong_generation = state_with_pending(identity(1), 3, UnitRanges::new(), 0);
        wrong_generation.checkpoint_generation = 1;
        assert_eq!(
            wrong_generation.commit_checkpoint(plan, ranges([0])),
            Err(Error::StaleCheckpointPlan)
        );
    }

    #[test]
    fn generation_exhaustion_does_not_commit() {
        let mut state = state(1, 1, UnitRanges::new()).unwrap();
        state.begin_unit(0).unwrap();
        state.complete_unit(0).unwrap();
        state.checkpoint_generation = u64::MAX;
        let plan = state.prepare_checkpoint();
        assert_eq!(
            state.commit_checkpoint(plan, ranges([0])),
            Err(Error::CheckpointGenerationExhausted)
        );
        assert_eq!(state.retransmission_units_after_crash(), 1);
        assert!(!state.is_checkpointed(0));
    }

    #[test]
    fn public_state_contracts_report_exact_values() {
        let partial = state(7, 3, ranges([0, 2, 3])).unwrap();
        assert_eq!(partial.total_units(), 7);
        assert_eq!(
            partial.missing_units().collect::<Vec<_>>(),
            vec![1, 4, 5, 6]
        );

        let complete = state(3, 1, ranges(0..3)).unwrap();
        assert_eq!(complete.missing_units().next(), None);

        let messages = [
            (Error::InvalidConfiguration, "invalid resume configuration"),
            (Error::InvalidUnit, "invalid resume unit"),
            (Error::UnitAlreadyActive, "resume unit is already active"),
            (Error::UnitNotActive, "resume unit is not active"),
            (Error::CheckpointRequired, "resume checkpoint is required"),
            (
                Error::InvalidCheckpoint,
                "invalid durable resume checkpoint",
            ),
            (Error::StaleCheckpointPlan, "stale resume checkpoint plan"),
            (
                Error::CheckpointGenerationExhausted,
                "resume checkpoint generation exhausted",
            ),
        ];
        for (error, message) in messages {
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn retransmission_bound_saturates_at_the_platform_limit() {
        let mut state = state(u64::MAX, usize::MAX, UnitRanges::new()).unwrap();
        state.begin_unit(0).unwrap();
        assert_eq!(state.retransmission_units_after_crash(), 1);
        assert_eq!(state.retransmission_bound(), usize::MAX);
    }
}
