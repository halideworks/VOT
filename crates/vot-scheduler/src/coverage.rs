//! Scheduler ownership and error mapping around pure range coverage.

use super::{Error, RangeSink};

pub(super) use vot_coverage::Check;

pub(super) struct RangeState {
    pub(super) coverage: vot_coverage::Coverage,
    pub(super) sink: Box<dyn RangeSink>,
}

impl RangeState {
    pub(super) fn new(sink: Box<dyn RangeSink>) -> Self {
        Self {
            coverage: vot_coverage::Coverage::new(),
            sink,
        }
    }
}

pub(super) const fn coverage_error(error: vot_coverage::Error) -> Error {
    match error {
        vot_coverage::Error::EmptyRange | vot_coverage::Error::PartialOverlap => {
            Error::LengthMismatch
        }
        vot_coverage::Error::LengthExceeded => Error::LengthExceeded,
        vot_coverage::Error::FragmentsExhausted => Error::RangeFragmentsExhausted,
    }
}
