//! Persistence-neutral resume accounting.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

pub mod units;
pub use units::UnitRanges;

mod tracker;
pub use tracker::{CheckpointPlan, Error, ResumeIdentity, ResumeState, validate_checkpoint_window};
