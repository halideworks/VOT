//! Backend-neutral VOT transport contract and bounded receiver credit.

#![forbid(unsafe_code)]

pub const ALPN: &[u8] = b"vot-draft-03";
pub const MAX_DATA_RECORD_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StreamId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubjectId {
    pub suite: u16,
    pub root: [u8; 32],
    pub length: u64,
}

/// A transport acknowledgement is delivery evidence only.
///
/// ```compile_fail
/// use vot_journal::DurableWitness;
/// use vot_transport_api::TransportAck;
///
/// let durable: DurableWitness = TransportAck::new(1, 10).into();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportAck {
    stream: StreamId,
    sequence: u64,
}

impl TransportAck {
    #[must_use]
    pub const fn new(stream: u64, sequence: u64) -> Self {
        Self {
            stream: StreamId(stream),
            sequence,
        }
    }

    #[must_use]
    pub const fn stream(self) -> StreamId {
        self.stream
    }

    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramSendState {
    Queued,
    Sent,
    Acknowledged,
    SuspectedLost,
    Canceled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    Connected(ConnectionId),
    Disconnected(ConnectionId),
    Control(Vec<u8>),
    Reliable {
        stream: StreamId,
        sequence: u64,
        bytes: Vec<u8>,
    },
    Acknowledged(TransportAck),
    DatagramState {
        context: u64,
        state: DatagramSendState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfiguration,
    RecordTooLarge,
    OutboundQueueFull,
    InboundQueueFull,
    StagingExhausted,
    ArithmeticOverflow,
    Backend,
}

pub trait TransportAdapter {
    /// # Errors
    /// Reports a backend or protocol limit failure.
    fn send_control(&mut self, frame: &[u8]) -> Result<(), Error>;

    /// # Errors
    /// Rejects records larger than 256 KiB and backend failures.
    fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error>;

    /// Returns the next backend event without blocking.
    fn poll(&mut self) -> Option<Event>;

    /// # Errors
    /// Reports a backend failure. Credit is absolute, not additive.
    fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error>;
}

/// Sole source of truth for receiver staging usage and advertised credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagingCapacity {
    limit: u64,
    used: u64,
    bdp_target: u64,
    configured_max: u64,
}

impl StagingCapacity {
    /// # Errors
    /// Rejects zero limits or a configured maximum above the staging limit.
    pub const fn new(limit: u64, bdp_target: u64, configured_max: u64) -> Result<Self, Error> {
        if limit == 0 || configured_max == 0 || configured_max > limit {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            limit,
            used: 0,
            bdp_target,
            configured_max,
        })
    }

    /// # Errors
    /// Rejects arithmetic overflow or a reservation beyond the hard limit.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), Error> {
        let next = self
            .used
            .checked_add(bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        if next > self.limit {
            return Err(Error::StagingExhausted);
        }
        self.used = next;
        Ok(())
    }

    pub fn release(&mut self, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
    }

    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.limit - self.used
    }

    /// Credit is a pure function of the current staging state.
    #[must_use]
    pub fn advertised_credit(&self) -> u64 {
        let target = self.bdp_target.min(self.configured_max);
        self.remaining().min(target)
    }
}

/// # Errors
/// Rejects data records above the frozen protocol limit.
pub fn validate_data_record(record: &[u8]) -> Result<(), Error> {
    if record.len() > MAX_DATA_RECORD_BYTES {
        Err(Error::RecordTooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_credit_is_derived_from_remaining_staging() {
        let mut staging = StagingCapacity::new(1024, 800, 900).unwrap();
        assert_eq!(staging.advertised_credit(), 800);
        staging.reserve(400).unwrap();
        assert_eq!(staging.used(), 400);
        assert_eq!(staging.advertised_credit(), 624);
        staging.reserve(600).unwrap();
        assert_eq!(staging.advertised_credit(), 24);
        assert_eq!(staging.reserve(25), Err(Error::StagingExhausted));
        assert_eq!(staging.used(), 1000);
        staging.release(600);
        assert_eq!(staging.advertised_credit(), 624);
        staging.release(400);
        assert_eq!(staging.advertised_credit(), 800);

        let mut exact = StagingCapacity::new(10, 10, 10).unwrap();
        exact.reserve(10).unwrap();
        assert_eq!(exact.used(), 10);
        assert_eq!(exact.advertised_credit(), 0);
    }

    #[test]
    fn records_are_bounded_before_a_backend_sees_them() {
        assert_eq!(MAX_DATA_RECORD_BYTES, 262_144);
        assert_eq!(
            validate_data_record(&vec![0; MAX_DATA_RECORD_BYTES]),
            Ok(())
        );
        assert_eq!(
            validate_data_record(&vec![0; MAX_DATA_RECORD_BYTES + 1]),
            Err(Error::RecordTooLarge)
        );
    }

    #[test]
    fn invalid_capacity_configuration_is_rejected() {
        assert_eq!(
            StagingCapacity::new(0, 1, 1),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            StagingCapacity::new(10, 1, 11),
            Err(Error::InvalidConfiguration)
        );
    }

    #[test]
    fn transport_ack_retains_delivery_coordinates() {
        let ack = TransportAck::new(17, 42);
        assert_eq!(ack.stream(), StreamId(17));
        assert_eq!(ack.sequence(), 42);
    }
}
