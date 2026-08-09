//! The pre-readiness event buffer and its accounting.

use super::{Error, ErrorKind, Event, VecDeque, error_code};

/// Peer records held while this endpoint finishes negotiating.
///
/// A conforming peer can have data in flight before it learns this side is ready.
pub const DEFAULT_PENDING_RECORD_BYTES: usize = 4 * vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES;

/// The same bound by count, since bytes alone do not limit per-record
/// overhead.
pub const DEFAULT_PENDING_RECORD_COUNT: usize = 64;

/// The pre-readiness event buffer with its own accounting: an event's cost is
/// computed once on hold and released exactly once on pop, so the queue and
/// its byte total cannot drift.
pub(super) struct PendingEvents {
    pub(super) events: VecDeque<Event>,
    pub(super) bytes: usize,
    pub(super) byte_limit: usize,
    pub(super) count_limit: usize,
}

impl Default for PendingEvents {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            bytes: 0,
            byte_limit: DEFAULT_PENDING_RECORD_BYTES,
            count_limit: DEFAULT_PENDING_RECORD_COUNT,
        }
    }
}

impl PendingEvents {
    fn cost(event: &Event) -> usize {
        match event {
            Event::Reliable { bytes, .. } => bytes.len(),
            _ => 0,
        }
    }

    pub(super) fn try_hold(&mut self, event: Event) -> Result<(), Error> {
        let next = self
            .bytes
            .checked_add(Self::cost(&event))
            .ok_or_else(|| self.exhausted_error())?;
        if next > self.byte_limit || self.events.len() >= self.count_limit {
            return Err(self.exhausted_error());
        }
        self.bytes = next;
        self.events.push_back(event);
        self.assert_accounted();
        Ok(())
    }

    pub(super) fn pop_front(&mut self) -> Option<Event> {
        let event = self.events.pop_front()?;
        self.bytes = self.bytes.saturating_sub(Self::cost(&event));
        self.assert_accounted();
        Some(event)
    }

    fn exhausted_error(&self) -> Error {
        Error::new(
            ErrorKind::PendingRecordsExhausted {
                bytes: self.bytes,
                count: self.events.len(),
            },
            error_code::RESOURCE_LIMIT,
        )
    }

    /// The charged bytes recomputed from the events, in tests and debug builds.
    pub(super) fn assert_accounted(&self) {
        debug_assert_eq!(
            self.bytes,
            self.events.iter().map(Self::cost).sum::<usize>()
        );
    }
}
