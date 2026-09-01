//! Scheduler ownership and error mapping around pure range coverage.

use super::{Error, RangeSink};

pub(super) use vot_coverage::Check;

pub(super) struct RangeState {
    pub(super) coverage: vot_coverage::Coverage,
    pub(super) sink: Box<dyn RangeSink>,
    #[expect(dead_code, reason = "owns the verifier reservation until drop")]
    pub(super) reservation: vot_transport_api::Permit,
}

impl RangeState {
    /// The object's length decides how many extents its arrival order may
    /// leave outstanding, so it is taken here rather than defaulted.
    pub(super) fn new(
        object_len: u64,
        sink: Box<dyn RangeSink>,
        reservation: vot_transport_api::Permit,
    ) -> Self {
        Self {
            coverage: vot_coverage::Coverage::for_object(object_len),
            sink,
            reservation,
        }
    }
}

pub(super) const fn coverage_error(error: vot_coverage::Error) -> Error {
    match error {
        vot_coverage::Error::EmptyRange
        | vot_coverage::Error::PartialOverlap
        | vot_coverage::Error::ReservedOverlap => Error::LengthMismatch,
        vot_coverage::Error::LengthExceeded => Error::LengthExceeded,
        vot_coverage::Error::FragmentsExhausted => Error::RangeFragmentsExhausted,
    }
}
