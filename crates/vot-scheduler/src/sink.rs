//! Where verified ranges go.

use super::Error;

#[cfg(feature = "file-sink")]
mod file_sink;
#[cfg(feature = "file-sink")]
pub use file_sink::FileSink;

/// A sink's refusal. It carries no cause because the receiver's answer is
/// the same whatever it was: the range is refused and stays retryable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinkError;

impl From<SinkError> for Error {
    fn from(_: SinkError) -> Self {
        Self::Sink
    }
}

/// Where a subject's verified bytes go. `write_at` takes `&self` because
/// accepted writes commute (disjoint or identical), so sinks are thread-safe.
pub trait RangeSink: Send + Sync {
    /// # Errors
    /// Refuses a write it cannot take; the receiver keeps the range retryable.
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), SinkError>;
}

/// A sink that drops what it is given, for measurements and tests whose
/// subject is transport and verification rather than the bytes' destination.
pub struct DiscardSink;

impl RangeSink for DiscardSink {
    fn write_at(&self, _covered_offset: u64, _data: &[u8]) -> Result<(), SinkError> {
        Ok(())
    }
}

/// A shared sink is a sink, which is what lets a caller keep a handle to
/// the destination it registered.
impl<S: RangeSink + ?Sized> RangeSink for std::sync::Arc<S> {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), SinkError> {
        (**self).write_at(covered_offset, data)
    }
}
