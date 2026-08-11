//! Reliable single-rail transfer planning and root-verified receive state.

#![forbid(unsafe_code)]

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet};

use vot_transport_api::{ConnectionId, PathStats, StagingCapacity, SubjectId, TransportAck};

pub mod session;
use vot_verifier::{GROUP_SIZE, StreamVerifier, Suite};

/// Max bytes one proof-bearing range may cover. Also sizes receiver staging.
pub const MAX_PROOF_RANGE_BYTES: u64 = vot_verified_range::MAX_PROOF_RANGE_BYTES;
/// Range granularity a proof covers, from spec/proofs.md.
pub const RANGE_UNIT_BYTES: u64 = vot_verified_range::RANGE_UNIT_BYTES;

const VERIFIER_RESERVATION: u64 = GROUP_SIZE as u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownObject,
    AlreadyReceiving,
    RecordTooLarge,
    LengthExceeded,
    LengthMismatch,
    RootMismatch,
    Staging(vot_transport_api::Error),
    Verification(vot_verifier::VerifyError),
    ProofInvalid,
    UnsupportedCompression,
    /// The session failed before a frame could be interpreted.
    Session(vot_session::Error),
    /// More incomplete bundle state than this receiver will hold.
    PendingBundlesExhausted,
    /// The subject's sink refused a verified range; the range stays retryable.
    Sink,
    /// More disjoint covered runs than this receiver will track.
    RangeFragmentsExhausted,
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

mod coverage;
mod planner;
mod proof;
mod receiver;
mod sink;

#[cfg(test)]
use coverage::MAX_RANGE_FRAGMENTS;
use coverage::RangeState;
pub use planner::*;
use proof::{
    assemble_ordered, check_range_proof, subject_id, suite, validate_typed_bundle,
    verify_typed_bundle,
};
pub use receiver::*;
pub use sink::*;

#[cfg(test)]
mod tests {
    use super::*;
    use vot_transport_api::{Event, StreamId, TransportAdapter};
    use vot_transport_sim::{Impairment, SimulatorAdapter};

    #[test]
    fn a_poisoned_ledger_recovers_only_with_nothing_in_flight() {
        let mut receiver = ReliableReceiver::new(1 << 20, 800, 900).unwrap();
        assert!(
            !receiver.recover_accounting(),
            "a healthy ledger has nothing to recover"
        );

        let held = subject(b"in flight");
        receiver.begin(held).unwrap();
        receiver.staging.release(u64::MAX);
        assert!(receiver.staging.is_poisoned());
        assert!(
            !receiver.recover_accounting(),
            "rebuilt while an object was still in flight"
        );

        receiver.active.clear();
        assert!(receiver.recover_accounting());
        assert!(!receiver.staging.is_poisoned());
        assert!(!receiver.recover_accounting(), "and only once");
    }
    fn subject(bytes: &[u8]) -> SubjectId {
        SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, bytes).unwrap(),
            length: bytes.len() as u64,
        }
    }

    /// Retains what it is written, for test assertions.
    #[derive(Default)]
    struct MemorySink(std::sync::Mutex<BTreeMap<u64, Vec<u8>>>);

    impl MemorySink {
        fn assembled(&self) -> Vec<u8> {
            let writes = self.0.lock().unwrap();
            let mut assembled = Vec::new();
            for (offset, data) in writes.iter() {
                assert_eq!(*offset, assembled.len() as u64, "a gap in sink writes");
                assembled.extend_from_slice(data);
            }
            assembled
        }
    }

    impl RangeSink for MemorySink {
        fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), SinkError> {
            let replaced = self.0.lock().unwrap().insert(covered_offset, data.to_vec());
            assert!(replaced.is_none(), "a range was written twice");
            Ok(())
        }
    }

    /// Refuses its first write and takes the second, the shape of a
    /// transient refusal downstream.
    struct FlakySink(std::sync::atomic::AtomicBool);

    impl RangeSink for FlakySink {
        fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<(), SinkError> {
            if self.0.swap(false, std::sync::atomic::Ordering::Relaxed) {
                Err(SinkError)
            } else {
                Ok(())
            }
        }
    }

    fn assert_typed_bundle_error(
        subject: SubjectId,
        bundle: &vot_codec::frames::ProofBundle,
        records: &[vot_codec::frames::DataRecord],
        expected: Error,
    ) {
        let staging_limit = VERIFIER_RESERVATION + bundle.covered_length;
        let mut receiver =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        receiver
            .begin_ranges(subject, Box::new(DiscardSink))
            .unwrap();
        assert_eq!(
            receiver.receive_typed_bundle(subject, bundle, records),
            Err(expected)
        );
    }

    #[test]
    fn reliable_transfer_uses_transport_adapter_contract() {
        let bytes = vec![0x5a; 700_000];
        let subject = subject(&bytes);
        let mut adapter = SimulatorAdapter::default();
        adapter.set_receive_credit(400_000).unwrap();
        for record in bytes.chunks(256 * 1024) {
            adapter.send_reliable(StreamId(7), record).unwrap();
        }
        assert_eq!(adapter.pending_submissions(), 4);
        adapter.flush().unwrap();
        assert_eq!(adapter.receive_credit(), 400_000);

        let mut receiver = ReliableReceiver::new(400_000, 256_000, 400_000).unwrap();
        assert_eq!(receiver.advertised_credit(), 256_000);
        receiver.connected(ConnectionId(1));
        assert_eq!(receiver.connection_count(), 1);
        receiver.begin(subject).unwrap();
        let mut events = Vec::new();
        assert_eq!(adapter.poll_batch(&mut events, 8), 3);
        for event in events {
            let Event::Reliable { bytes, .. } = event else {
                panic!("simulator emitted a non-reliable event");
            };
            receiver.receive(subject, &bytes).unwrap();
        }
        receiver.finish(subject).unwrap();
        assert!(receiver.is_verified(subject));
        assert_eq!(receiver.peak_staging(), 256 * 1024 + VERIFIER_RESERVATION);
    }

    #[test]
    fn reordered_and_duplicated_delivery_still_verifies_every_range() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let mut bytes = Vec::with_capacity(unit * 3);
        for index in 0..3_u8 {
            bytes.extend(std::iter::repeat_n(index, unit));
        }
        let subject = subject(&bytes);

        let mut adapter = SimulatorAdapter::with_impairment(Impairment {
            reorder_depth: 2,
            duplicate_every: 2,
            ..Impairment::default()
        })
        .unwrap();
        for (index, record) in bytes.chunks(unit).enumerate() {
            adapter
                .send_reliable(StreamId(7 + index as u64), record)
                .unwrap();
        }
        adapter.flush().unwrap();

        let staging = 4 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION;
        let mut receiver = ReliableReceiver::new(staging, RANGE_UNIT_BYTES, staging).unwrap();
        let sink = std::sync::Arc::new(MemorySink::default());
        receiver
            .begin_ranges(subject, Box::new(sink.clone()))
            .unwrap();
        let mut arrivals = Vec::new();
        while let Some(event) = adapter.poll() {
            let Event::Reliable { bytes: record, .. } = event else {
                panic!("simulator emitted a non-reliable event");
            };
            let index = u64::from(record[0]);
            let offset = index * RANGE_UNIT_BYTES;
            let proof = vot_proof_blake3::prove(&bytes, offset, RANGE_UNIT_BYTES).unwrap();
            receiver
                .receive_range(subject, offset, &record, &proof.proof)
                .unwrap();
            arrivals.push(index);
        }
        assert_eq!(arrivals.len(), 4);
        assert_ne!(arrivals, vec![0, 1, 2, 2], "delivery was not reordered");
        assert_eq!(
            {
                let mut sorted = arrivals.clone();
                sorted.sort_unstable();
                sorted.dedup();
                sorted
            },
            vec![0, 1, 2]
        );
        receiver.finish_ranges(subject).unwrap();
        assert!(receiver.is_verified(subject));
        assert_eq!(sink.assembled(), bytes);
        assert_eq!(
            receiver.peak_staging(),
            RANGE_UNIT_BYTES + VERIFIER_RESERVATION
        );
    }

    #[test]
    fn duplicate_begin_modes_are_rejected_while_active() {
        let object = subject(b"duplicate");
        let mut sequential =
            ReliableReceiver::new(4 * VERIFIER_RESERVATION, 1, 4 * VERIFIER_RESERVATION).unwrap();
        sequential.begin(object).unwrap();
        assert_eq!(sequential.begin(object), Err(Error::AlreadyReceiving));

        let mut ranged =
            ReliableReceiver::new(4 * VERIFIER_RESERVATION, 1, 4 * VERIFIER_RESERVATION).unwrap();
        ranged.begin_ranges(object, Box::new(DiscardSink)).unwrap();
        assert_eq!(
            ranged.begin_ranges(object, Box::new(DiscardSink)),
            Err(Error::AlreadyReceiving)
        );
    }

    #[test]
    fn an_abandoned_range_transfer_releases_its_room_and_can_begin_again() {
        let object = subject(b"abandoned");
        let other = subject(b"another");
        let mut receiver =
            ReliableReceiver::new(VERIFIER_RESERVATION, 1, VERIFIER_RESERVATION).unwrap();
        assert!(!receiver.abandon_ranges(object), "nothing to forget yet");
        receiver
            .begin_ranges(object, Box::new(DiscardSink))
            .unwrap();
        assert!(
            receiver.begin_ranges(other, Box::new(DiscardSink)).is_err(),
            "the one reservation of room is held"
        );
        assert!(receiver.abandon_ranges(object));
        assert!(!receiver.abandon_ranges(object), "forgotten once");
        receiver.begin_ranges(other, Box::new(DiscardSink)).unwrap();
        receiver.abandon_ranges(other);
        receiver
            .begin_ranges(object, Box::new(DiscardSink))
            .unwrap();
    }

    #[test]
    fn finish_ranges_requires_every_byte_of_the_object() {
        let object = SubjectId {
            suite: 1,
            root: [0; 32],
            length: 2 * RANGE_UNIT_BYTES,
        };
        let mut receiver =
            ReliableReceiver::new(4 * VERIFIER_RESERVATION, 1, 4 * VERIFIER_RESERVATION).unwrap();
        receiver.range_active.insert(
            object,
            RangeState {
                extents: BTreeMap::new(),
                bytes: RANGE_UNIT_BYTES,
                sink: Box::new(DiscardSink),
            },
        );
        assert_eq!(receiver.finish_ranges(object), Err(Error::LengthMismatch));
        receiver.range_active.insert(
            object,
            RangeState {
                extents: BTreeMap::new(),
                bytes: 2 * RANGE_UNIT_BYTES,
                sink: Box::new(DiscardSink),
            },
        );
        receiver.finish_ranges(object).unwrap();
        assert!(receiver.is_verified(object));
    }

    #[test]
    fn a_partial_unit_cannot_stand_in_for_a_whole_one() {
        let bytes = vec![0x11; usize::try_from(2 * RANGE_UNIT_BYTES).unwrap()];
        let object = subject(&bytes);
        let prefix = vot_proof_blake3::prove(&bytes, 0, 1024).unwrap();
        let staging = 4 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION;
        let mut receiver = ReliableReceiver::new(staging, RANGE_UNIT_BYTES, staging).unwrap();
        receiver
            .begin_ranges(object, Box::new(DiscardSink))
            .unwrap();
        assert_eq!(
            receiver.receive_range(object, 0, &bytes[..1024], &prefix.proof),
            Err(Error::LengthExceeded)
        );

        let short = vec![0x22; usize::try_from(RANGE_UNIT_BYTES).unwrap() + 7];
        let short_object = subject(&short);
        let tail_offset = RANGE_UNIT_BYTES;
        let tail = vot_proof_blake3::prove(&short, tail_offset, 7).unwrap();
        let mut tail_receiver = ReliableReceiver::new(staging, RANGE_UNIT_BYTES, staging).unwrap();
        tail_receiver
            .begin_ranges(short_object, Box::new(DiscardSink))
            .unwrap();
        tail_receiver
            .receive_range(
                short_object,
                tail_offset,
                &short[usize::try_from(tail_offset).unwrap()..],
                &tail.proof,
            )
            .unwrap();
    }

    #[test]
    fn path_stats_update_staging_bdp_target() {
        let mut receiver = ReliableReceiver::new(4096, 1, 4096).unwrap();
        assert_eq!(receiver.advertised_credit(), 1);
        receiver.observe_path_stats(PathStats {
            pacing_rate_bps: Some(8_000_000),
            lost_packets: None,
            spurious_lost_packets: None,
            packets_sent: None,
            packets_received: None,
            smoothed_rtt_us: Some(1_000),
            congestion_window_bytes: None,
            mtu_bytes: Some(1500),
        });
        assert_eq!(receiver.advertised_credit(), 1_000);
        receiver.observe_path_stats(PathStats {
            pacing_rate_bps: None,
            lost_packets: None,
            spurious_lost_packets: None,
            packets_sent: None,
            packets_received: None,
            smoothed_rtt_us: None,
            congestion_window_bytes: Some(2_048),
            mtu_bytes: Some(1500),
        });
        assert_eq!(receiver.advertised_credit(), 2_048);

        let mut zero_bdp = ReliableReceiver::new(4096, 1, 4096).unwrap();
        zero_bdp.observe_path_stats(PathStats {
            pacing_rate_bps: Some(1),
            lost_packets: None,
            spurious_lost_packets: None,
            packets_sent: None,
            packets_received: None,
            smoothed_rtt_us: Some(1),
            congestion_window_bytes: None,
            mtu_bytes: None,
        });
        assert_eq!(zero_bdp.advertised_credit(), 1);
        zero_bdp.observe_path_stats(PathStats {
            pacing_rate_bps: None,
            lost_packets: None,
            spurious_lost_packets: None,
            packets_sent: None,
            packets_received: None,
            smoothed_rtt_us: None,
            congestion_window_bytes: Some(0),
            mtu_bytes: None,
        });
        assert_eq!(zero_bdp.advertised_credit(), 1);
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
        let higher = Job {
            priority: 9,
            sequence: 1,
            subject: second,
        };
        let lower = Job {
            priority: 0,
            sequence: 0,
            subject: first,
        };
        assert_eq!(higher.partial_cmp(&lower), Some(Ordering::Less));
        assert_eq!(planner.pop().unwrap().subject, second);
        assert_eq!(planner.pop().unwrap().subject, first);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn range_validation_and_ownership_boundaries_are_explicit() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let bytes = vec![0x5a; unit * 3];
        let range_subject = subject(&bytes);
        let make_receiver = || {
            ReliableReceiver::new(
                8 * VERIFIER_RESERVATION,
                8 * VERIFIER_RESERVATION,
                8 * VERIFIER_RESERVATION,
            )
            .unwrap()
        };

        let mut receiver = make_receiver();
        receiver
            .begin_ranges(range_subject, Box::new(DiscardSink))
            .unwrap();
        assert_eq!(
            receiver.receive_range(range_subject, 0, &[], &[]),
            Err(Error::RecordTooLarge)
        );
        let too_large = vec![0; usize::try_from(MAX_PROOF_RANGE_BYTES + 1).unwrap()];
        assert_eq!(
            receiver.receive_range(range_subject, 0, &too_large, &[]),
            Err(Error::RecordTooLarge)
        );

        let large_range_subject = SubjectId {
            suite: 1,
            root: [0; 32],
            length: MAX_PROOF_RANGE_BYTES,
        };
        let exact_max = vec![0; usize::try_from(MAX_PROOF_RANGE_BYTES).unwrap()];
        let mut exact_receiver = make_receiver();
        exact_receiver
            .begin_ranges(large_range_subject, Box::new(DiscardSink))
            .unwrap();
        assert_eq!(
            exact_receiver.receive_range(large_range_subject, 0, &exact_max, &[]),
            Err(Error::ProofInvalid)
        );

        let one = &bytes[..unit];
        let first_proof = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        let mut misaligned = make_receiver();
        misaligned
            .begin_ranges(range_subject, Box::new(DiscardSink))
            .unwrap();
        assert_eq!(
            misaligned.receive_range(range_subject, 1, one, &[]),
            Err(Error::LengthExceeded)
        );

        let exact_range_subject = subject(one);
        let exact_proof = vot_proof_blake3::prove(one, 0, RANGE_UNIT_BYTES).unwrap();
        let mut exact_end = make_receiver();
        exact_end
            .begin_ranges(exact_range_subject, Box::new(DiscardSink))
            .unwrap();
        exact_end
            .receive_range(exact_range_subject, 0, one, &exact_proof.proof)
            .unwrap();

        let mut duplicate = make_receiver();
        duplicate
            .begin_ranges(range_subject, Box::new(DiscardSink))
            .unwrap();
        duplicate
            .receive_range(range_subject, 0, one, &first_proof.proof)
            .unwrap();
        duplicate
            .receive_range(range_subject, 0, one, &first_proof.proof)
            .unwrap();

        let first_two = &bytes[..unit * 2];
        let overlap_data = &bytes[unit..unit * 2];
        let first_two_proof = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES * 2).unwrap();
        let overlap_proof =
            vot_proof_blake3::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let mut overlap = make_receiver();
        overlap
            .begin_ranges(range_subject, Box::new(DiscardSink))
            .unwrap();
        overlap
            .receive_range(range_subject, 0, first_two, &first_two_proof.proof)
            .unwrap();
        overlap
            .receive_range(
                range_subject,
                RANGE_UNIT_BYTES,
                overlap_data,
                &overlap_proof.proof,
            )
            .unwrap();
        assert_eq!(
            overlap.range_active[&range_subject].bytes,
            2 * RANGE_UNIT_BYTES
        );

        let mut overlap_from_below = make_receiver();
        overlap_from_below
            .begin_ranges(range_subject, Box::new(DiscardSink))
            .unwrap();
        overlap_from_below
            .receive_range(
                range_subject,
                RANGE_UNIT_BYTES,
                overlap_data,
                &overlap_proof.proof,
            )
            .unwrap();
        assert_eq!(
            overlap_from_below.receive_range(range_subject, 0, first_two, &first_two_proof.proof),
            Err(Error::LengthMismatch)
        );

        let second_proof =
            vot_proof_blake3::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let mut adjacent = make_receiver();
        adjacent
            .begin_ranges(range_subject, Box::new(DiscardSink))
            .unwrap();
        adjacent
            .receive_range(range_subject, 0, one, &first_proof.proof)
            .unwrap();
        adjacent
            .receive_range(
                range_subject,
                RANGE_UNIT_BYTES,
                &bytes[unit..unit * 2],
                &second_proof.proof,
            )
            .unwrap();

        let mut middle = make_receiver();
        middle
            .begin_ranges(range_subject, Box::new(DiscardSink))
            .unwrap();
        middle
            .receive_range(
                range_subject,
                RANGE_UNIT_BYTES,
                &bytes[unit..unit * 2],
                &second_proof.proof,
            )
            .unwrap();
        assert_eq!(middle.range_active[&range_subject].bytes, RANGE_UNIT_BYTES);
        assert_eq!(
            middle.range_active[&range_subject]
                .extents
                .iter()
                .map(|(start, end)| (*start, *end))
                .collect::<Vec<_>>(),
            vec![(RANGE_UNIT_BYTES, 2 * RANGE_UNIT_BYTES)]
        );
        assert_eq!(
            middle.finish_ranges(range_subject),
            Err(Error::LengthMismatch)
        );
    }

    #[test]
    fn a_file_sink_places_ranges_at_their_offsets() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let mut bytes = Vec::with_capacity(unit * 3);
        for index in 0..3_u8 {
            bytes.extend(std::iter::repeat_n(index + 1, unit));
        }
        let path = std::env::temp_dir().join(format!(
            "vot-file-sink-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        let sink = FileSink::create(&path, bytes.len() as u64).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes.len() as u64);
        sink.write_at(2 * RANGE_UNIT_BYTES, &bytes[unit * 2..])
            .unwrap();
        sink.write_at(0, &bytes[..unit]).unwrap();
        sink.write_at(RANGE_UNIT_BYTES, &bytes[unit..unit * 2])
            .unwrap();
        sink.write_at(0, &bytes[..unit]).unwrap();
        drop(sink);
        let written = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(written, bytes);
    }

    #[test]
    fn a_resumed_sink_keeps_what_the_last_fetch_placed() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vot-file-sink-resume-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        let length = 3 * RANGE_UNIT_BYTES;
        let first = FileSink::create(&path, length).unwrap();
        first.write_at(RANGE_UNIT_BYTES, &vec![0x42; unit]).unwrap();
        drop(first);

        assert!(
            FileSink::resume(std::path::Path::new("/vot-missing/none"), length).is_err(),
            "resume opens what exists, never invents it"
        );
        let resumed = FileSink::resume(&path, length).unwrap();
        resumed.write_at(0, &vec![0x41; unit]).unwrap();
        drop(resumed);
        let written = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(written.len() as u64, length, "sized on reopen");
        assert!(
            written[unit..unit * 2].iter().all(|byte| *byte == 0x42),
            "the last fetch's bytes survived the reopen"
        );
        assert!(written[..unit].iter().all(|byte| *byte == 0x41));
    }

    #[test]
    fn extents_coalesce_and_a_covered_range_is_a_replay() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let bytes = vec![0x77; unit * 3];
        let object = subject(&bytes);
        let staging = 4 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION;
        let sink = std::sync::Arc::new(MemorySink::default());
        let mut receiver = ReliableReceiver::new(staging, RANGE_UNIT_BYTES, staging).unwrap();
        receiver
            .begin_ranges(object, Box::new(sink.clone()))
            .unwrap();
        let prove = |offset| vot_proof_blake3::prove(&bytes, offset, RANGE_UNIT_BYTES).unwrap();
        let range = |offset: u64| {
            let start = usize::try_from(offset).unwrap();
            &bytes[start..start + unit]
        };
        receiver
            .receive_range(object, 0, range(0), &prove(0).proof)
            .unwrap();
        receiver
            .receive_range(
                object,
                2 * RANGE_UNIT_BYTES,
                range(2 * RANGE_UNIT_BYTES),
                &prove(2 * RANGE_UNIT_BYTES).proof,
            )
            .unwrap();
        assert_eq!(receiver.range_active[&object].extents.len(), 2);
        receiver
            .receive_range(
                object,
                RANGE_UNIT_BYTES,
                range(RANGE_UNIT_BYTES),
                &prove(RANGE_UNIT_BYTES).proof,
            )
            .unwrap();
        assert_eq!(
            receiver.range_active[&object]
                .extents
                .iter()
                .map(|(start, end)| (*start, *end))
                .collect::<Vec<_>>(),
            vec![(0, 3 * RANGE_UNIT_BYTES)]
        );
        receiver
            .receive_range(
                object,
                RANGE_UNIT_BYTES,
                range(RANGE_UNIT_BYTES),
                &prove(RANGE_UNIT_BYTES).proof,
            )
            .unwrap();
        receiver
            .receive_range(
                object,
                2 * RANGE_UNIT_BYTES,
                range(2 * RANGE_UNIT_BYTES),
                &prove(2 * RANGE_UNIT_BYTES).proof,
            )
            .unwrap();
        receiver.finish_ranges(object).unwrap();
        assert_eq!(sink.assembled(), bytes);
    }

    #[test]
    fn a_refused_write_leaves_the_range_retryable() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let bytes = vec![0x88; unit];
        let object = subject(&bytes);
        let proof = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        let staging = 2 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION;
        let mut receiver = ReliableReceiver::new(staging, staging, staging).unwrap();
        receiver
            .begin_ranges(
                object,
                Box::new(FlakySink(std::sync::atomic::AtomicBool::new(true))),
            )
            .unwrap();
        let credit = receiver.advertised_credit();
        assert_eq!(
            receiver.receive_range(object, 0, &bytes, &proof.proof),
            Err(Error::Sink)
        );
        assert_eq!(receiver.advertised_credit(), credit);
        assert_eq!(receiver.range_active[&object].bytes, 0);
        receiver
            .receive_range(object, 0, &bytes, &proof.proof)
            .unwrap();
        receiver.finish_ranges(object).unwrap();
        assert!(receiver.is_verified(object));
    }

    #[test]
    fn a_panicking_sink_does_not_strand_staging() {
        struct PanickingSink;
        impl RangeSink for PanickingSink {
            fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<(), SinkError> {
                panic!("a sink is caller code and may do this");
            }
        }
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let bytes = vec![0xaa; unit];
        let object = subject(&bytes);
        let proof = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        let staging = 2 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION;
        let mut receiver = ReliableReceiver::new(staging, staging, staging).unwrap();
        receiver
            .begin_ranges(object, Box::new(PanickingSink))
            .unwrap();
        let credit = receiver.advertised_credit();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            receiver.receive_range(object, 0, &bytes, &proof.proof)
        }));
        assert!(outcome.is_err(), "the sink's panic reached the caller");
        assert_eq!(receiver.advertised_credit(), credit);
    }

    #[test]
    fn fragments_are_bounded_but_a_merging_range_is_not_refused() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let bytes = vec![0x99; unit * 3];
        let object = subject(&bytes);
        let staging = 4 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION;
        let mut receiver = ReliableReceiver::new(staging, staging, staging).unwrap();
        receiver
            .begin_ranges(object, Box::new(DiscardSink))
            .unwrap();
        {
            let active = receiver.range_active.get_mut(&object).unwrap();
            for index in 0..u64::try_from(MAX_RANGE_FRAGMENTS).unwrap() {
                let start = (10 + 2 * index) * RANGE_UNIT_BYTES;
                active.extents.insert(start, start + RANGE_UNIT_BYTES);
            }
        }
        let first = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        assert_eq!(
            receiver.receive_range(object, 0, &bytes[..unit], &first.proof),
            Err(Error::RangeFragmentsExhausted)
        );
        {
            let active = receiver.range_active.get_mut(&object).unwrap();
            active.extents.remove(&(10 * RANGE_UNIT_BYTES));
            active
                .extents
                .insert(RANGE_UNIT_BYTES, 2 * RANGE_UNIT_BYTES);
        }
        receiver
            .receive_range(object, 0, &bytes[..unit], &first.proof)
            .unwrap();
        assert_eq!(
            receiver.range_active[&object].extents.len(),
            MAX_RANGE_FRAGMENTS
        );
        assert_eq!(
            receiver.range_active[&object].extents[&0],
            2 * RANGE_UNIT_BYTES
        );
        let third =
            vot_proof_blake3::prove(&bytes, 2 * RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        receiver
            .receive_range(
                object,
                2 * RANGE_UNIT_BYTES,
                &bytes[unit * 2..],
                &third.proof,
            )
            .unwrap();
        assert_eq!(
            receiver.range_active[&object].extents.len(),
            MAX_RANGE_FRAGMENTS
        );
        assert_eq!(
            receiver.range_active[&object].extents[&0],
            3 * RANGE_UNIT_BYTES
        );
    }

    #[test]
    fn proof_bearing_ranges_accept_out_of_order_for_both_suites() {
        let bytes = vec![0x5a; usize::try_from(RANGE_UNIT_BYTES * 2).unwrap()];

        let blake_subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let second_blake =
            vot_proof_blake3::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let first_blake = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        let mut blake_receiver = ReliableReceiver::new(
            4 * VERIFIER_RESERVATION,
            2 * VERIFIER_RESERVATION,
            4 * VERIFIER_RESERVATION,
        )
        .unwrap();
        blake_receiver
            .begin_ranges(blake_subject, Box::new(DiscardSink))
            .unwrap();
        blake_receiver
            .receive_range(
                blake_subject,
                second_blake.covered_offset,
                &second_blake.data,
                &second_blake.proof,
            )
            .unwrap();
        blake_receiver
            .receive_range(
                blake_subject,
                first_blake.covered_offset,
                &first_blake.data,
                &first_blake.proof,
            )
            .unwrap();
        blake_receiver.finish_ranges(blake_subject).unwrap();
        assert!(blake_receiver.is_verified(blake_subject));

        let sha_subject = SubjectId {
            suite: 2,
            root: vot_verifier::root(Suite::Sha256Bep52, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let second_sha =
            vot_proof_sha256::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let first_sha = vot_proof_sha256::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        let mut sha_receiver = ReliableReceiver::new(
            4 * VERIFIER_RESERVATION,
            2 * VERIFIER_RESERVATION,
            4 * VERIFIER_RESERVATION,
        )
        .unwrap();
        sha_receiver
            .begin_ranges(sha_subject, Box::new(DiscardSink))
            .unwrap();
        sha_receiver
            .receive_range(
                sha_subject,
                second_sha.covered_offset,
                &second_sha.data,
                &second_sha.proof,
            )
            .unwrap();
        sha_receiver
            .receive_range(
                sha_subject,
                first_sha.covered_offset,
                &first_sha.data,
                &first_sha.proof,
            )
            .unwrap();
        sha_receiver.finish_ranges(sha_subject).unwrap();
        assert!(sha_receiver.is_verified(sha_subject));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn typed_wire_bundle_reassembles_records_before_root_verification() {
        let bytes = vec![0x3c; usize::try_from(RANGE_UNIT_BYTES * 2).unwrap()];
        let subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
        let bundle = vot_codec::frames::ProofBundle {
            request_id: [3; 16],
            bundle_id: [4; 16],
            object: vot_codec::frames::ObjectId {
                suite: subject.suite,
                root: subject.root,
                length: subject.length,
            },
            requested_offset: 0,
            requested_length: subject.length,
            covered_offset: proof.covered_offset,
            covered_length: proof.data.len() as u64,
            data_record_count: 2,
            total_plaintext_length: proof.data.len() as u64,
            proof: proof.proof,
        };
        let records = [
            vot_codec::frames::DataRecord {
                bundle_id: [4; 16],
                record_index: 1,
                plaintext_offset: RANGE_UNIT_BYTES,
                plaintext_length: RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[usize::try_from(RANGE_UNIT_BYTES).unwrap()..].to_vec(),
            },
            vot_codec::frames::DataRecord {
                bundle_id: [4; 16],
                record_index: 0,
                plaintext_offset: 0,
                plaintext_length: RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[..usize::try_from(RANGE_UNIT_BYTES).unwrap()].to_vec(),
            },
        ];
        let mut bundle_wire = Vec::new();
        vot_codec::frames::encode(
            &vot_codec::frames::TypedFrame::ProofBundle(bundle.clone()),
            &mut bundle_wire,
        )
        .unwrap();
        let (bundle_frame, bundle_used) =
            vot_codec::frames::decode(&bundle_wire, vot_codec::DecodeLimits::default()).unwrap();
        assert_eq!(bundle_used, bundle_wire.len());
        let vot_codec::frames::TypedFrame::ProofBundle(bundle) = bundle_frame else {
            panic!("wire frame was not a proof bundle");
        };
        let mut decoded_records = Vec::with_capacity(records.len());
        for record in &records {
            let mut record_wire = Vec::new();
            vot_codec::frames::encode(
                &vot_codec::frames::TypedFrame::DataRecord(record.clone()),
                &mut record_wire,
            )
            .unwrap();
            let (record_frame, record_used) =
                vot_codec::frames::decode(&record_wire, vot_codec::DecodeLimits::default())
                    .unwrap();
            assert_eq!(record_used, record_wire.len());
            let vot_codec::frames::TypedFrame::DataRecord(record) = record_frame else {
                panic!("wire frame was not a data record");
            };
            decoded_records.push(record);
        }

        let staging_limit = VERIFIER_RESERVATION + bytes.len() as u64;
        let mut receiver =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        receiver
            .begin_ranges(subject, Box::new(DiscardSink))
            .unwrap();
        assert_eq!(receiver.advertised_credit(), bytes.len() as u64);
        receiver
            .receive_typed_bundle(subject, &bundle, &decoded_records)
            .unwrap();
        assert_eq!(receiver.advertised_credit(), bytes.len() as u64);
        assert_eq!(receiver.peak_staging(), staging_limit);
        receiver.finish_ranges(subject).unwrap();
        assert!(receiver.is_verified(subject));
        assert_eq!(receiver.advertised_credit(), staging_limit);

        let mut bad_bundle = bundle.clone();
        bad_bundle.object.suite = 2;
        assert_typed_bundle_error(subject, &bad_bundle, &records, Error::LengthMismatch);
        bad_bundle = bundle.clone();
        bad_bundle.object.root[0] ^= 1;
        assert_typed_bundle_error(subject, &bad_bundle, &records, Error::LengthMismatch);
        bad_bundle = bundle.clone();
        bad_bundle.object.length += 1;
        assert_typed_bundle_error(subject, &bad_bundle, &records, Error::LengthMismatch);
        bad_bundle = bundle.clone();
        bad_bundle.data_record_count -= 1;
        assert_typed_bundle_error(subject, &bad_bundle, &records[..1], Error::LengthMismatch);

        let mut bad_records = records.to_vec();
        bad_records[1].plaintext_offset = RANGE_UNIT_BYTES;
        assert_typed_bundle_error(subject, &bundle, &bad_records, Error::LengthMismatch);

        let duplicate_limit = VERIFIER_RESERVATION + 2 * bundle.covered_length;
        let mut duplicate_receiver =
            ReliableReceiver::new(duplicate_limit, duplicate_limit, duplicate_limit).unwrap();
        duplicate_receiver
            .begin_ranges(subject, Box::new(DiscardSink))
            .unwrap();
        duplicate_receiver
            .receive_typed_bundle(subject, &bundle, &decoded_records)
            .unwrap();
        let credit_before_duplicate = duplicate_receiver.advertised_credit();
        duplicate_receiver
            .receive_typed_bundle(subject, &bundle, &decoded_records)
            .unwrap();
        assert_eq!(
            duplicate_receiver.advertised_credit(),
            credit_before_duplicate
        );
    }

    #[test]
    fn a_witness_verifies_off_thread_and_admits_on_it() {
        let bytes = vec![0x3c; usize::try_from(RANGE_UNIT_BYTES * 2).unwrap()];
        let subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
        let bundle = vot_codec::frames::ProofBundle {
            request_id: [3; 16],
            bundle_id: [4; 16],
            object: vot_codec::frames::ObjectId {
                suite: subject.suite,
                root: subject.root,
                length: subject.length,
            },
            requested_offset: 0,
            requested_length: subject.length,
            covered_offset: proof.covered_offset,
            covered_length: proof.data.len() as u64,
            data_record_count: 1,
            total_plaintext_length: proof.data.len() as u64,
            proof: proof.proof,
        };
        let records = [vot_codec::frames::DataRecord {
            bundle_id: [4; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: bytes.len() as u64,
            compression: 0,
            encoded: bytes.clone(),
        }];

        let range = std::thread::scope(|scope| {
            scope
                .spawn(|| ReliableReceiver::verify_typed_bundle(subject, &bundle, &records))
                .join()
                .expect("a verifier thread")
        })
        .expect("a verified range");
        assert_eq!(range.len(), bytes.len() as u64);
        assert!(!range.is_empty());
        assert_eq!(
            format!("{range:?}"),
            format!("VerifiedRange {{ subject: {subject:?}, covered_offset: 0, data: {bytes:?} }}")
        );

        let staging_limit = VERIFIER_RESERVATION + bytes.len() as u64;
        let mut receiver =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        receiver
            .begin_ranges(subject, Box::new(DiscardSink))
            .unwrap();
        let credit_before = receiver.advertised_credit();
        receiver.admit_verified_range(range).unwrap();
        assert_eq!(receiver.advertised_credit(), credit_before);
        assert_eq!(receiver.peak_staging(), staging_limit);
        receiver.finish_ranges(subject).unwrap();
        assert!(receiver.is_verified(subject));

        let mut bad_records = records.to_vec();
        bad_records[0].encoded[0] ^= 1;
        assert!(matches!(
            ReliableReceiver::verify_typed_bundle(subject, &bundle, &bad_records),
            Err(Error::ProofInvalid)
        ));

        let stray = ReliableReceiver::verify_typed_bundle(subject, &bundle, &records).unwrap();
        let mut closed =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        assert!(matches!(
            closed.admit_verified_range(stray),
            Err(Error::UnknownObject)
        ));

        let again = ReliableReceiver::verify_typed_bundle(subject, &bundle, &records).unwrap();
        let credit_verified = receiver.advertised_credit();
        receiver.admit_verified_range(again).unwrap();
        assert_eq!(receiver.advertised_credit(), credit_verified);
    }

    #[test]
    fn a_written_range_admits_without_the_bytes() {
        let bytes = vec![0x3c; usize::try_from(RANGE_UNIT_BYTES * 2).unwrap()];
        let subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
        let bundle = vot_codec::frames::ProofBundle {
            request_id: [3; 16],
            bundle_id: [4; 16],
            object: vot_codec::frames::ObjectId {
                suite: subject.suite,
                root: subject.root,
                length: subject.length,
            },
            requested_offset: 0,
            requested_length: subject.length,
            covered_offset: proof.covered_offset,
            covered_length: proof.data.len() as u64,
            data_record_count: 1,
            total_plaintext_length: proof.data.len() as u64,
            proof: proof.proof,
        };
        let records = [vot_codec::frames::DataRecord {
            bundle_id: [4; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: bytes.len() as u64,
            compression: 0,
            encoded: bytes.clone(),
        }];
        let range = ReliableReceiver::verify_typed_bundle(subject, &bundle, &records).unwrap();

        let sink = std::sync::Arc::new(MemorySink::default());
        let staging_limit = VERIFIER_RESERVATION + bytes.len() as u64;
        let mut receiver =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        receiver
            .begin_ranges(subject, Box::new(sink.clone()))
            .unwrap();
        let credit = receiver.advertised_credit();
        let written = range.write_to(sink.as_ref()).unwrap();
        drop(range);
        receiver.admit_written_range(written).unwrap();
        assert_eq!(receiver.advertised_credit(), credit);
        assert_eq!(receiver.range_active[&subject].bytes, bytes.len() as u64);
        receiver.finish_ranges(subject).unwrap();
        assert!(receiver.is_verified(subject));
        assert_eq!(sink.assembled(), bytes);

        receiver
            .admit_written_range(WrittenRange {
                subject,
                covered_offset: 0,
                bytes: bytes.len() as u64,
            })
            .unwrap();

        let mut closed =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        assert!(matches!(
            closed.admit_written_range(WrittenRange {
                subject,
                covered_offset: 0,
                bytes: 1,
            }),
            Err(Error::UnknownObject)
        ));

        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let second = vot_proof_blake3::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let mut straddled =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        straddled
            .begin_ranges(subject, Box::new(DiscardSink))
            .unwrap();
        straddled
            .receive_range(subject, RANGE_UNIT_BYTES, &bytes[unit..], &second.proof)
            .unwrap();
        assert_eq!(
            straddled.admit_written_range(WrittenRange {
                subject,
                covered_offset: 0,
                bytes: bytes.len() as u64,
            }),
            Err(Error::LengthMismatch)
        );
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
