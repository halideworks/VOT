//! Reliable single-rail transfer planning and root-verified receive state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use vot_transport_api::{ConnectionId, StagingCapacity, SubjectId, TransportAck};
use vot_verifier::{GROUP_SIZE, StreamVerifier, Suite};

const VERIFIER_RESERVATION: u64 = GROUP_SIZE as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownObject,
    AlreadyReceiving,
    RecordTooLarge,
    LengthExceeded,
    LengthMismatch,
    RootMismatch,
    Staging(vot_transport_api::Error),
    Verification(vot_verifier::VerifyError),
}

impl From<vot_transport_api::Error> for Error {
    fn from(error: vot_transport_api::Error) -> Self {
        Self::Staging(error)
    }
}

impl From<vot_verifier::VerifyError> for Error {
    fn from(error: vot_verifier::VerifyError) -> Self {
        Self::Verification(error)
    }
}

struct ActiveObject {
    verifier: StreamVerifier,
    received: u64,
}

/// Receiver state is keyed by subject identity and outlives connections.
pub struct ReliableReceiver {
    staging: StagingCapacity,
    active: BTreeMap<SubjectId, ActiveObject>,
    verified: BTreeSet<SubjectId>,
    connections: BTreeSet<ConnectionId>,
    ack_count: u64,
    peak_staging: u64,
}

impl ReliableReceiver {
    /// # Errors
    /// Rejects invalid staging configuration.
    pub fn new(staging_limit: u64, bdp_target: u64, configured_max: u64) -> Result<Self, Error> {
        Ok(Self {
            staging: StagingCapacity::new(staging_limit, bdp_target, configured_max)?,
            active: BTreeMap::new(),
            verified: BTreeSet::new(),
            connections: BTreeSet::new(),
            ack_count: 0,
            peak_staging: 0,
        })
    }

    pub fn connected(&mut self, connection: ConnectionId) {
        self.connections.insert(connection);
    }

    pub fn disconnected(&mut self, connection: ConnectionId) {
        self.connections.remove(&connection);
    }

    /// # Errors
    /// Rejects duplicate active objects. Verified objects are idempotent.
    pub fn begin(&mut self, subject: SubjectId) -> Result<(), Error> {
        if self.verified.contains(&subject) {
            return Ok(());
        }
        if self.active.contains_key(&subject) {
            return Err(Error::AlreadyReceiving);
        }
        let verifier = StreamVerifier::new(suite(subject.suite)?);
        self.staging.reserve(VERIFIER_RESERVATION)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        self.active.insert(
            subject,
            ActiveObject {
                verifier,
                received: 0,
            },
        );
        Ok(())
    }

    /// # Errors
    /// Rejects oversized records, unknown objects, bounds violations, or hash errors.
    pub fn receive(&mut self, subject: SubjectId, record: &[u8]) -> Result<(), Error> {
        vot_transport_api::validate_data_record(record).map_err(|error| match error {
            vot_transport_api::Error::RecordTooLarge => Error::RecordTooLarge,
            other => Error::Staging(other),
        })?;
        let bytes = u64::try_from(record.len()).map_err(|_| Error::LengthExceeded)?;
        self.staging.reserve(bytes)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        let result = self.receive_reserved(subject, record, bytes);
        self.staging.release(bytes);
        result
    }

    fn receive_reserved(
        &mut self,
        subject: SubjectId,
        record: &[u8],
        bytes: u64,
    ) -> Result<(), Error> {
        let active = self.active.get_mut(&subject).ok_or(Error::UnknownObject)?;
        let received = active
            .received
            .checked_add(bytes)
            .ok_or(Error::LengthExceeded)?;
        if received > subject.length {
            return Err(Error::LengthExceeded);
        }
        active.verifier.update(record)?;
        active.received = received;
        Ok(())
    }

    /// # Errors
    /// Rejects incomplete content or a root mismatch.
    pub fn finish(&mut self, subject: SubjectId) -> Result<(), Error> {
        if self.verified.contains(&subject) {
            return Ok(());
        }
        let active = self.active.remove(&subject).ok_or(Error::UnknownObject)?;
        self.staging.release(VERIFIER_RESERVATION);
        if active.received != subject.length {
            return Err(Error::LengthMismatch);
        }
        if active.verifier.finish()? != subject.root {
            return Err(Error::RootMismatch);
        }
        self.verified.insert(subject);
        Ok(())
    }

    /// ACKs are transport telemetry only and cannot alter object state.
    pub fn acknowledged(&mut self, _ack: TransportAck) {
        self.ack_count = self.ack_count.saturating_add(1);
    }

    #[must_use]
    pub fn is_verified(&self, subject: SubjectId) -> bool {
        self.verified.contains(&subject)
    }

    #[must_use]
    pub fn advertised_credit(&self) -> u64 {
        self.staging.advertised_credit()
    }

    #[must_use]
    pub const fn peak_staging(&self) -> u64 {
        self.peak_staging
    }

    #[must_use]
    pub const fn ack_count(&self) -> u64 {
        self.ack_count
    }

    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

fn suite(id: u16) -> Result<Suite, Error> {
    match id {
        1 => Ok(Suite::Blake3Bao64),
        2 => Ok(Suite::Sha256Bep52),
        _ => Err(Error::UnknownObject),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Job {
    pub priority: u8,
    pub sequence: u64,
    pub subject: SubjectId,
}

/// Deterministic highest-priority-first planner with FIFO tie breaking.
#[derive(Default)]
pub struct Planner {
    jobs: BTreeSet<Job>,
}

impl Planner {
    pub fn push(&mut self, job: Job) {
        self.jobs.insert(job);
    }

    pub fn pop(&mut self) -> Option<Job> {
        let selected = self
            .jobs
            .iter()
            .min_by_key(|job| (u8::MAX - job.priority, job.sequence))
            .copied()?;
        self.jobs.remove(&selected);
        Some(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_transport_sim::{Action, ExpectedOutcome, Scenario, ScheduledAction, Simulator};

    fn subject(bytes: &[u8]) -> SubjectId {
        SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, bytes).unwrap(),
            length: bytes.len() as u64,
        }
    }

    #[test]
    fn complete_transfer_over_simulator() {
        let bytes = vec![0x5a; 700_000];
        let subject = subject(&bytes);
        let scenario = Scenario {
            name: "wave4-reliable".to_owned(),
            seed: 19,
            expected: ExpectedOutcome::Complete,
            expected_trace: None,
            actions: vec![
                ScheduledAction {
                    at: 0,
                    action: Action::AddPath {
                        path: 1,
                        mtu: 1500,
                        latency: 2,
                    },
                },
                ScheduledAction {
                    at: 1,
                    action: Action::Send {
                        path: 1,
                        transfer: 7,
                        bytes: subject.length,
                    },
                },
            ],
        };
        assert!(matches!(
            Simulator::run(&scenario).outcome,
            vot_transport_sim::Outcome::Complete { published: 1 }
        ));

        let mut receiver = ReliableReceiver::new(400_000, 256_000, 400_000).unwrap();
        assert_eq!(receiver.advertised_credit(), 256_000);
        receiver.connected(ConnectionId(1));
        assert_eq!(receiver.connection_count(), 1);
        receiver.begin(subject).unwrap();
        for record in bytes.chunks(256 * 1024) {
            receiver.receive(subject, record).unwrap();
        }
        receiver.finish(subject).unwrap();
        assert!(receiver.is_verified(subject));
        assert_eq!(receiver.peak_staging(), 256 * 1024 + VERIFIER_RESERVATION);
    }

    #[test]
    fn verified_state_survives_disconnect_and_ack_has_no_assurance_effect() {
        let bytes = b"verified object";
        let subject = subject(bytes);
        let mut receiver = ReliableReceiver::new(2 * VERIFIER_RESERVATION, 1024, 1024).unwrap();
        receiver.connected(ConnectionId(1));
        assert_eq!(receiver.connection_count(), 1);
        receiver.begin(subject).unwrap();
        assert_eq!(receiver.ack_count(), 0);
        receiver.acknowledged(TransportAck::new(4, 99));
        assert!(!receiver.is_verified(subject));
        receiver.receive(subject, bytes).unwrap();
        receiver.finish(subject).unwrap();
        receiver.disconnected(ConnectionId(1));
        assert_eq!(receiver.connection_count(), 0);
        receiver.connected(ConnectionId(2));
        assert_eq!(receiver.connection_count(), 1);
        assert!(receiver.is_verified(subject));
        assert_eq!(receiver.ack_count(), 1);
    }

    #[test]
    fn mismatched_root_and_overrun_are_rejected() {
        let bytes = b"expected";
        let mut wrong = subject(bytes);
        wrong.root[0] ^= 1;
        let mut receiver = ReliableReceiver::new(2 * VERIFIER_RESERVATION, 1024, 1024).unwrap();
        receiver.begin(wrong).unwrap();
        receiver.receive(wrong, bytes).unwrap();
        assert_eq!(receiver.finish(wrong), Err(Error::RootMismatch));

        let short = SubjectId {
            length: 2,
            ..subject(b"ab")
        };
        receiver.begin(short).unwrap();
        assert_eq!(receiver.receive(short, b"abc"), Err(Error::LengthExceeded));
    }

    #[test]
    fn planner_is_priority_then_fifo() {
        let first = subject(b"a");
        let second = subject(b"b");
        let mut planner = Planner::default();
        planner.push(Job {
            priority: 0,
            sequence: 0,
            subject: first,
        });
        planner.push(Job {
            priority: 9,
            sequence: 1,
            subject: second,
        });
        assert_eq!(planner.pop().unwrap().subject, second);
        assert_eq!(planner.pop().unwrap().subject, first);
    }

    #[test]
    fn sha256_suite_transfer_is_verified() {
        let bytes = b"sha256 tree content";
        let subject = SubjectId {
            suite: 2,
            root: vot_verifier::root(Suite::Sha256Bep52, bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let mut receiver = ReliableReceiver::new(2 * VERIFIER_RESERVATION, 1024, 1024).unwrap();
        receiver.begin(subject).unwrap();
        receiver.receive(subject, bytes).unwrap();
        receiver.finish(subject).unwrap();
        assert!(receiver.is_verified(subject));
    }

    #[test]
    fn active_verifiers_are_bounded_by_staging_capacity() {
        let first = subject(b"first");
        let second = subject(b"second");
        let mut receiver = ReliableReceiver::new(
            VERIFIER_RESERVATION,
            VERIFIER_RESERVATION,
            VERIFIER_RESERVATION,
        )
        .unwrap();
        receiver.begin(first).unwrap();
        assert_eq!(receiver.advertised_credit(), 0);
        assert_eq!(
            receiver.begin(second),
            Err(Error::Staging(vot_transport_api::Error::StagingExhausted))
        );
        receiver.receive(first, b"first").unwrap_err();
        assert_eq!(receiver.finish(first), Err(Error::LengthMismatch));
        receiver.begin(second).unwrap();
    }
}
