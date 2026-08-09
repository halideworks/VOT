//! Stream reassembly for VOT frames.
//!
//! QUIC and TLS deliver byte streams, not messages. Frames may be split across
//! reads or coalesced in one. Bounded reassembly prevents memory growth from
//! partial frames. The budget comes from the backend.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use vot_transport_api::Error;

/// Largest partial frame held on a reliable lane while waiting for the rest.
pub const MAX_PARTIAL_FRAME: usize = vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES;

/// Default control-lane reassembly bound (compiled ceiling).
pub const MAX_PARTIAL_CONTROL_FRAME: usize = vot_transport_api::MAX_CONTROL_FRAME_WIRE_BYTES;

/// Which kind of stream is being read. Carried explicitly so an application
/// stream is never mistaken for the control stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    /// The negotiation stream `spec/wire.md` reserves.
    Control,
    /// An application lane, reported under `lane`.
    Reliable { lane: u64 },
}

impl StreamKind {
    /// Largest payload a frame on this kind of stream may declare.
    ///
    /// `control` is what this endpoint advertised, which is at most the
    /// compiled-in ceiling and may be less.
    #[must_use]
    pub const fn payload_limit(self, control: usize) -> usize {
        match self {
            Self::Control => control,
            Self::Reliable { .. } => vot_transport_api::MAX_DATA_RECORD_BYTES,
        }
    }

    /// Largest partial frame this kind of stream may hold, envelope included.
    #[must_use]
    pub const fn partial_frame_limit(self, control: usize) -> usize {
        match self {
            Self::Control => control.saturating_add(vot_transport_api::MAX_FRAME_ENVELOPE_BYTES),
            Self::Reliable { .. } => MAX_PARTIAL_FRAME,
        }
    }
}

/// A stream's bytes could not be framed, with the code the session closes under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameFault {
    error: Error,
    close: u16,
}

impl FrameFault {
    /// A frame larger than this stream can carry.
    #[must_use]
    pub const fn too_large() -> Self {
        Self {
            error: Error::RecordTooLarge,
            close: vot_codec::error_code::FRAME_TOO_LARGE,
        }
    }

    /// A decoder error, closing under the code the registry gives it.
    #[must_use]
    pub fn from_decode(error: &vot_codec::DecodeError) -> Self {
        Self {
            error: Error::Backend,
            close: error.protocol_code(),
        }
    }

    /// The budget for frames still arriving, or for events, is spent.
    #[must_use]
    pub const fn exhausted() -> Self {
        Self {
            error: Error::InboundQueueFull,
            close: vot_codec::error_code::RESOURCE_LIMIT,
        }
    }

    /// A frame that ended when the carrier did.
    #[must_use]
    pub const fn truncated() -> Self {
        Self {
            error: Error::Backend,
            close: vot_codec::error_code::MALFORMED_FRAME,
        }
    }

    /// What this endpoint reports to its own caller.
    #[must_use]
    pub const fn error(self) -> Error {
        self.error
    }

    /// The registered code `spec/wire.md` requires the session to close under.
    #[must_use]
    pub const fn close(self) -> u16 {
        self.close
    }
}

/// Shared budget for partial-frame storage across all streams. The backend
/// decides what it shares with.
pub trait AssemblyBudget {
    /// Charges more partial-frame storage. False when the budget is spent.
    fn reserve(&self, bytes: usize) -> bool;

    /// Returns partial-frame storage to the budget.
    fn release(&self, bytes: usize);
}

/// A budget of its own, for a backend whose reassembly shares memory with
/// nothing else.
#[derive(Debug)]
pub struct StandaloneBudget {
    held: AtomicUsize,
    limit: usize,
}

impl StandaloneBudget {
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            held: AtomicUsize::new(0),
            limit,
        }
    }

    /// Bytes currently charged across every stream.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Relaxed)
    }
}

impl AssemblyBudget for StandaloneBudget {
    fn reserve(&self, bytes: usize) -> bool {
        // CAS, not fetch-add: avoids overspend and phantom charges on refusal.
        let mut held = self.held.load(Ordering::Relaxed);
        loop {
            let Some(next) = held.checked_add(bytes) else {
                return false;
            };
            if next > self.limit {
                return false;
            }
            match self
                .held
                .compare_exchange_weak(held, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(current) => held = current,
            }
        }
    }

    fn release(&self, bytes: usize) {
        let mut held = self.held.load(Ordering::Relaxed);
        loop {
            let next = held.saturating_sub(bytes);
            match self
                .held
                .compare_exchange_weak(held, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(current) => held = current,
            }
        }
    }
}

impl<T: AssemblyBudget> AssemblyBudget for Arc<T> {
    fn reserve(&self, bytes: usize) -> bool {
        T::reserve(self, bytes)
    }

    fn release(&self, bytes: usize) {
        T::release(self, bytes);
    }
}

/// Per-stream reassembly state. Each stream has its own buffer.
#[derive(Debug)]
pub struct Framing<B: AssemblyBudget> {
    pending: Vec<u8>,
    /// The control bound this stream reassembles under. A frame already
    /// part-way through keeps the bound its envelope was read under.
    control_limit: Arc<AtomicUsize>,
    /// Payload bytes of a skipped frame still to arrive. Dropped as they land.
    discarding: usize,
    /// What `pending` currently costs against the shared budget.
    reserved: usize,
    budget: B,
    kind: StreamKind,
}

impl<B: AssemblyBudget> Framing<B> {
    pub fn new(kind: StreamKind, budget: B, control_limit: Arc<AtomicUsize>) -> Self {
        Self {
            pending: Vec::new(),
            control_limit,
            discarding: 0,
            reserved: 0,
            budget,
            kind,
        }
    }

    /// Buffers bytes of a frame still arriving, against the shared budget.
    ///
    /// # Errors
    /// Reports a budget the peer has already spent, which is a resource limit
    /// rather than a malformed frame.
    fn hold(&mut self, bytes: &[u8]) -> Result<(), FrameFault> {
        if !bytes.is_empty() {
            if !self.budget.reserve(bytes.len()) {
                return Err(FrameFault::exhausted());
            }
            self.reserved += bytes.len();
        }
        self.pending.extend_from_slice(bytes);
        debug_assert_eq!(self.reserved, self.pending.len());
        Ok(())
    }

    /// Returns the buffer's whole charge to the budget. `hold` and this are
    /// the only places the reservation moves; everything that empties the
    /// buffer settles through here so the two cannot drift.
    fn settle_charge(&mut self) {
        if self.reserved != 0 {
            self.budget.release(self.reserved);
            self.reserved = 0;
        }
        debug_assert_eq!(self.reserved, self.pending.len());
    }

    /// Hands over the completed frame with its charge already returned, so a
    /// frame is never both charged and emitted.
    fn take_pending(&mut self) -> Vec<u8> {
        let complete = std::mem::take(&mut self.pending);
        self.settle_charge();
        complete
    }

    /// Drops the buffered frame and returns its cost to the budget. The
    /// buffer keeps its capacity for the next partial frame.
    pub fn release(&mut self) {
        self.pending.clear();
        self.settle_charge();
    }

    /// Feeds received bytes to `emit`, one complete frame at a time. Only
    /// trailing incomplete frames are buffered.
    ///
    /// # Errors
    /// Reports malformed, oversized, or uncompletable frames. Propagates
    /// whatever `emit` reports.
    pub fn accept(
        &mut self,
        bytes: &[u8],
        mut emit: impl FnMut(&[u8]) -> Result<(), FrameFault>,
    ) -> Result<(), FrameFault> {
        let control = self.control_limit.load(Ordering::Relaxed);
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: self.kind.payload_limit(control),
            max_frames: 1,
        };
        let mut input = bytes;
        loop {
            // Bytes belonging to a frame being skipped never reach the buffer at
            // all.
            if self.discarding != 0 {
                let dropped = self.discarding.min(input.len());
                self.discarding -= dropped;
                input = &input[dropped..];
                if self.discarding != 0 {
                    return Ok(());
                }
            }
            if input.is_empty() {
                return Ok(());
            }

            // A frame already part-way through is completed from the buffer,
            // which is the only place bytes accumulate.
            if !self.pending.is_empty() {
                let Some(envelope) = self.envelope(limits, control, None)? else {
                    // Header incomplete: take one byte and retry.
                    self.hold(&input[..1])?;
                    input = &input[1..];
                    continue;
                };
                let needed = envelope.total_length - self.pending.len();
                let taken = needed.min(input.len());
                if envelope.skipped {
                    self.discarding = needed - taken;
                    self.release();
                    input = &input[taken..];
                    continue;
                }
                self.hold(&input[..taken])?;
                input = &input[taken..];
                if self.pending.len() < envelope.total_length {
                    return Ok(());
                }
                // Release budget before queueing to avoid double charge. The
                // loop's progress depends on the buffer emptying here: were it
                // left full, this branch would repeat forever.
                let complete = self.take_pending();
                debug_assert!(self.pending.is_empty(), "take_pending left bytes behind");
                emit(&complete)?;
                continue;
            }

            let Some(envelope) = self.envelope(limits, control, Some(input))? else {
                self.hold(input)?;
                return Ok(());
            };
            if input.len() < envelope.total_length {
                if envelope.skipped {
                    self.discarding = envelope.total_length - input.len();
                    return Ok(());
                }
                self.hold(input)?;
                return Ok(());
            }
            if !envelope.skipped {
                emit(&input[..envelope.total_length])?;
            }
            input = &input[envelope.total_length..];
        }
    }

    /// Reads the next envelope from `input`, or from the buffer when `input` is
    /// `None`, applying this stream's bound to it.
    ///
    /// Returns `None` while the header is still arriving.
    fn envelope(
        &self,
        limits: vot_codec::DecodeLimits,
        control: usize,
        input: Option<&[u8]>,
    ) -> Result<Option<vot_codec::FrameEnvelope>, FrameFault> {
        match vot_codec::peek_envelope(input.unwrap_or(&self.pending), limits) {
            Ok(envelope) => {
                // Reject frames whose registered limit exceeds the lane bound,
                // before they reach the adapter and retry forever.
                if envelope.total_length > self.kind.partial_frame_limit(control) {
                    return Err(FrameFault::too_large());
                }
                Ok(Some(envelope))
            }
            Err(vot_codec::DecodeError::Incomplete { .. }) => Ok(None),
            Err(error) => Err(FrameFault::from_decode(&error)),
        }
    }

    /// Bytes currently held for a frame still being assembled.
    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Whether a frame is part-way through arriving, whether it is being
    /// assembled or discarded.
    #[must_use]
    pub const fn is_assembling(&self) -> bool {
        !self.pending.is_empty() || self.discarding != 0
    }
}

impl<B: AssemblyBudget> Drop for Framing<B> {
    fn drop(&mut self) {
        // Return the reservation on reset so partial frames are uncharged.
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_limit() -> Arc<AtomicUsize> {
        Arc::new(AtomicUsize::new(
            vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
        ))
    }

    fn budget() -> Arc<StandaloneBudget> {
        Arc::new(StandaloneBudget::new(MAX_PARTIAL_CONTROL_FRAME))
    }

    /// A `SETTINGS` frame with `payload_len` bytes of payload.
    ///
    /// A frame whose registered limit is larger than any bound under test, so
    /// what refuses it here is the stream's bound rather than the registry's.
    fn frame(payload_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        vot_codec::encode_frame(
            vot_codec::frame_type::SETTINGS,
            &vec![0x5a; payload_len],
            &mut out,
        )
        .expect("a frame the codec accepts");
        out
    }

    /// Every frame `bytes` completes, and what is left held.
    fn collect(
        framing: &mut Framing<Arc<StandaloneBudget>>,
        bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>, FrameFault> {
        let mut frames = Vec::new();
        framing.accept(bytes, |frame| {
            frames.push(frame.to_vec());
            Ok(())
        })?;
        Ok(frames)
    }

    #[test]
    fn a_frame_split_across_reads_arrives_once_and_whole() {
        let mut framing = Framing::new(StreamKind::Control, budget(), control_limit());
        let whole = frame(64);
        for split in 1..whole.len() {
            let mut framing = Framing::new(StreamKind::Control, budget(), control_limit());
            assert_eq!(
                collect(&mut framing, &whole[..split]),
                Ok(Vec::new()),
                "nothing is delivered from a partial frame at {split}"
            );
            assert!(framing.is_assembling(), "{split}");
            assert_eq!(
                collect(&mut framing, &whole[split..]),
                Ok(vec![whole.clone()]),
                "the whole frame, split at {split}"
            );
            assert!(!framing.is_assembling(), "{split}");
            assert_eq!(framing.buffered(), 0, "{split}");
        }

        let mut coalesced = Vec::new();
        for payload in [1_usize, 2, 3] {
            coalesced.extend_from_slice(&frame(payload));
        }
        assert_eq!(
            collect(&mut framing, &coalesced),
            Ok(vec![frame(1), frame(2), frame(3)])
        );
    }

    #[test]
    fn one_byte_at_a_time_still_yields_the_frame() {
        let mut framing = Framing::new(StreamKind::Reliable { lane: 4 }, budget(), control_limit());
        let whole = frame(300);
        let mut delivered = Vec::new();
        for byte in &whole {
            framing
                .accept(std::slice::from_ref(byte), |frame| {
                    delivered.push(frame.to_vec());
                    Ok(())
                })
                .expect("a frame arriving a byte at a time");
        }
        assert_eq!(delivered, vec![whole]);
        assert_eq!(framing.buffered(), 0);
    }

    #[test]
    fn a_frame_larger_than_the_stream_carries_is_refused_before_it_is_held() {
        let mut framing = Framing::new(StreamKind::Reliable { lane: 4 }, budget(), control_limit());
        let mut oversized = Vec::new();
        vot_codec::encode_varint(vot_codec::frame_type::PROOF_BUNDLE, &mut oversized).unwrap();
        vot_codec::encode_varint(MAX_PARTIAL_FRAME as u64, &mut oversized).unwrap();
        assert_eq!(
            collect(&mut framing, &oversized),
            Err(FrameFault::too_large())
        );
        assert_eq!(
            FrameFault::too_large().close(),
            vot_codec::error_code::FRAME_TOO_LARGE
        );
        assert_eq!(FrameFault::too_large().error(), Error::RecordTooLarge);
        assert_eq!(framing.buffered(), 0, "nothing refused was held");
    }

    #[test]
    fn the_control_bound_is_the_one_this_endpoint_advertised() {
        const ENVELOPE: usize = vot_transport_api::MAX_FRAME_ENVELOPE_BYTES;
        let narrow = Arc::new(AtomicUsize::new(2_048));
        let mut framing = Framing::new(StreamKind::Control, budget(), Arc::clone(&narrow));
        assert_eq!(
            collect(&mut framing, &frame(2_048)),
            Ok(vec![frame(2_048)]),
            "a frame at the advertised bound"
        );
        assert_eq!(
            collect(&mut framing, &frame(2_048 + ENVELOPE + 1)),
            Err(FrameFault::too_large()),
            "and one byte past what it may weigh"
        );

        let mut lane = Framing::new(StreamKind::Reliable { lane: 4 }, budget(), narrow);
        assert_eq!(
            collect(&mut lane, &frame(4_096)),
            Ok(vec![frame(4_096)]),
            "a record past the control bound"
        );
    }

    #[test]
    fn held_bytes_are_charged_and_returned() {
        let shared = budget();
        let mut framing = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        let whole = frame(1_024);
        collect(&mut framing, &whole[..100]).expect("a partial frame");
        assert_eq!(shared.held(), 100, "what is held is charged");
        assert_eq!(framing.buffered(), 100);

        collect(&mut framing, &whole[100..]).expect("the rest of the frame");
        assert_eq!(shared.held(), 0, "and returned once the frame completes");

        let mut reset = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        collect(&mut reset, &whole[..50]).expect("a partial frame");
        assert_eq!(shared.held(), 50);
        drop(reset);
        assert_eq!(shared.held(), 0);
    }

    #[test]
    fn a_peer_cannot_hold_more_than_the_budget_across_streams() {
        let shared = Arc::new(StandaloneBudget::new(128));
        let whole = frame(1_024);
        let mut first = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        let mut second = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        collect(&mut first, &whole[..100]).expect("a partial frame");
        assert_eq!(
            collect(&mut second, &whole[..100]),
            Err(FrameFault::exhausted()),
            "the second stream is refused by the budget the first spent"
        );
        assert_eq!(
            FrameFault::exhausted().close(),
            vot_codec::error_code::RESOURCE_LIMIT
        );
        assert_eq!(FrameFault::exhausted().error(), Error::InboundQueueFull);

        first.release();
        assert_eq!(shared.held(), 0);
        assert_eq!(collect(&mut second, &whole[..100]), Ok(Vec::new()));
        assert_eq!(shared.held(), 100);
    }

    #[test]
    fn a_budget_admits_what_it_has_room_for_and_no_more() {
        let budget = StandaloneBudget::new(10);
        assert!(budget.reserve(10), "exactly the budget");
        assert!(!budget.reserve(1), "and nothing past it");
        assert_eq!(budget.held(), 10);
        budget.release(4);
        assert_eq!(budget.held(), 6);
        assert!(budget.reserve(4));
        assert!(!budget.reserve(1));
        budget.release(1_000);
        assert_eq!(budget.held(), 0);
        assert!(!budget.reserve(usize::MAX), "an overflow is not room");
    }

    #[test]
    fn an_optional_frame_nobody_reads_is_discarded_rather_than_buffered() {
        let shared = budget();
        let mut framing = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        let mut skipped = Vec::new();
        vot_codec::encode_frame(0x1f00, &vec![0x11; 4_000], &mut skipped)
            .expect("an unknown optional frame");

        assert_eq!(collect(&mut framing, &skipped[..3]), Ok(Vec::new()));
        assert_eq!(
            collect(&mut framing, &skipped[3..]),
            Ok(Vec::new()),
            "nothing is delivered for a frame that is skipped"
        );
        assert_eq!(shared.held(), 0, "and nothing was held for it");
        assert!(!framing.is_assembling());

        let following = frame(8);
        let mut both = skipped.clone();
        both.extend_from_slice(&following);
        let mut fresh = Framing::new(StreamKind::Control, shared, control_limit());
        assert_eq!(collect(&mut fresh, &both), Ok(vec![following]));
    }

    #[test]
    fn a_discarded_frame_is_counted_down_exactly_across_reads() {
        let shared = budget();
        let mut framing = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        let mut skipped = Vec::new();
        vot_codec::encode_frame(0x1f00, &vec![0x11; 4_000], &mut skipped)
            .expect("an unknown optional frame");
        let header = skipped.len() - 4_000;
        let following = frame(8);

        assert_eq!(collect(&mut framing, &skipped[..header]), Ok(Vec::new()));
        assert!(framing.is_assembling(), "a frame is part-way through");
        assert_eq!(shared.held(), 0, "a skipped frame is never held");

        assert_eq!(
            collect(&mut framing, &skipped[header..header + 100]),
            Ok(Vec::new())
        );
        assert!(framing.is_assembling());
        assert_eq!(shared.held(), 0);

        let mut rest = skipped[header + 100..].to_vec();
        rest.extend_from_slice(&following);
        assert_eq!(collect(&mut framing, &rest), Ok(vec![following]));
        assert!(!framing.is_assembling());
        assert_eq!(shared.held(), 0);
    }

    #[test]
    fn a_frame_at_exactly_the_reassembly_bound_is_carried() {
        const ENVELOPE: usize = vot_transport_api::MAX_FRAME_ENVELOPE_BYTES;
        let control = 2_048;
        let bound = control + ENVELOPE;
        let exact = (1..=bound)
            .rev()
            .find(|payload| frame(*payload).len() == bound)
            .expect("some payload reaches the bound exactly");
        let mut framing = Framing::new(
            StreamKind::Control,
            budget(),
            Arc::new(AtomicUsize::new(control)),
        );
        assert_eq!(
            collect(&mut framing, &frame(exact)),
            Ok(vec![frame(exact)]),
            "a frame weighing exactly what the stream may hold"
        );
        assert_eq!(
            collect(&mut framing, &frame(exact + 1)),
            Err(FrameFault::too_large()),
            "and one byte more"
        );
    }

    #[test]
    fn the_budget_charge_always_equals_the_bytes_held() {
        // Characterization for the accounting refactor: after every accept,
        // whatever its outcome, the shared budget holds exactly what the
        // framer buffers. A skipped frame charges nothing at any point.
        let mut stream = Vec::new();
        stream.extend_from_slice(&frame(64));
        vot_codec::encode_frame(0x1f00, &vec![0x11; 900], &mut stream)
            .expect("an unknown optional frame");
        stream.extend_from_slice(&frame(1));
        stream.extend_from_slice(&frame(700));
        vot_codec::encode_frame(0x1ffe, &[], &mut stream).expect("an empty grease frame");
        stream.extend_from_slice(&frame(0));
        stream.extend_from_slice(&frame(333));

        let expected = vec![frame(64), frame(1), frame(700), frame(0), frame(333)];
        for chunk in [1_usize, 2, 3, 5, 16, 64, 641, stream.len()] {
            let shared = budget();
            let mut framing =
                Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
            let mut delivered = Vec::new();
            for piece in stream.chunks(chunk) {
                framing
                    .accept(piece, |frame| {
                        delivered.push(frame.to_vec());
                        Ok(())
                    })
                    .expect("a well-formed stream");
                assert_eq!(shared.held(), framing.buffered(), "chunk size {chunk}");
            }
            assert_eq!(delivered, expected, "chunk size {chunk}");
            assert_eq!(shared.held(), 0, "chunk size {chunk}");
        }
        // A refused frame leaves the charge equal to what is still held, and
        // release returns every charged byte.
        let narrow = Arc::new(StandaloneBudget::new(100));
        let mut framing = Framing::new(StreamKind::Control, Arc::clone(&narrow), control_limit());
        let whole = frame(400);
        assert_eq!(
            collect(&mut framing, &whole[..300]),
            Err(FrameFault::exhausted())
        );
        assert_eq!(narrow.held(), framing.buffered());
        framing.release();
        assert_eq!(narrow.held(), 0);
        assert_eq!(framing.buffered(), 0);

        // An emit refusal mid-batch keeps the invariant too.
        let shared = budget();
        let mut framing = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        let mut coalesced = frame(8);
        coalesced.extend_from_slice(&frame(16));
        coalesced.extend_from_slice(&frame(24)[..10]);
        let outcome = framing.accept(&coalesced, |_| Err(FrameFault::exhausted()));
        assert_eq!(outcome, Err(FrameFault::exhausted()));
        assert_eq!(shared.held(), framing.buffered());
    }

    #[test]
    fn a_malformed_frame_closes_under_the_code_the_registry_gives_it() {
        let mut framing = Framing::new(StreamKind::Control, budget(), control_limit());
        let mut malformed = Vec::new();
        vot_codec::encode_varint(vot_codec::frame_type::SETTINGS, &mut malformed).unwrap();
        vot_codec::encode_varint(20_000, &mut malformed).unwrap();
        let fault = collect(&mut framing, &malformed).expect_err("a malformed frame");
        assert_eq!(fault.error(), Error::Backend);
        assert_ne!(fault.close(), 0, "a registered close code");
    }

    #[test]
    fn what_emit_refuses_is_what_the_caller_hears() {
        let mut framing = Framing::new(StreamKind::Control, budget(), control_limit());
        let mut coalesced = frame(1);
        coalesced.extend_from_slice(&frame(2));
        let mut seen = 0;
        let outcome = framing.accept(&coalesced, |_| {
            seen += 1;
            Err(FrameFault::exhausted())
        });
        assert_eq!(outcome, Err(FrameFault::exhausted()));
        assert_eq!(seen, 1, "the second frame is not offered after the first");
    }

    #[test]
    fn a_stream_that_ends_mid_frame_is_a_truncated_one() {
        assert_eq!(FrameFault::truncated().error(), Error::Backend);
        assert_eq!(
            FrameFault::truncated().close(),
            vot_codec::error_code::MALFORMED_FRAME
        );
        let mut framing = Framing::new(StreamKind::Control, budget(), control_limit());
        collect(&mut framing, &frame(64)[..4]).expect("a partial frame");
        assert!(
            framing.is_assembling(),
            "which is what a carrier checks when it declares end of stream"
        );
    }

    #[test]
    fn the_bounds_a_stream_reassembles_under_are_the_ones_the_wire_states() {
        assert_eq!(
            MAX_PARTIAL_FRAME,
            vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES
        );
        assert_eq!(
            MAX_PARTIAL_CONTROL_FRAME,
            vot_transport_api::MAX_CONTROL_FRAME_WIRE_BYTES
        );
        assert_eq!(
            StreamKind::Reliable { lane: 1 }.payload_limit(64),
            vot_transport_api::MAX_DATA_RECORD_BYTES,
            "a lane's bound is the record bound whatever the control one is"
        );
        assert_eq!(StreamKind::Control.payload_limit(64), 64);
        assert_eq!(
            StreamKind::Control.partial_frame_limit(64),
            64 + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
        );
        assert_eq!(
            StreamKind::Reliable { lane: 1 }.partial_frame_limit(64),
            MAX_PARTIAL_FRAME
        );
        assert_eq!(
            StreamKind::Control.partial_frame_limit(usize::MAX),
            usize::MAX
        );
    }
}
