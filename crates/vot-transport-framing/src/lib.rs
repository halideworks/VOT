//! Reading VOT frames out of a stream that carries bytes.
//!
//! QUIC and TLS both deliver a byte stream, not messages, and `spec/wire.md`
//! permits a frame to be split across reads or several to arrive in one.
//! Treating a read as a record delivers truncated or combined ones, so every
//! stream needs its own reassembly, and reassembly a peer can grow without
//! limit is a way to spend an endpoint's memory without sending a valid frame.
//!
//! None of that depends on the carrier, so it is here rather than in a backend.
//! What each backend supplies is the budget the held bytes are charged to,
//! because how many streams exist at once and what else shares that memory is
//! the backend's to know.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use vot_transport_api::Error;

/// Largest partial frame held on a reliable lane while waiting for the rest.
pub const MAX_PARTIAL_FRAME: usize = vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES;

/// Default control-lane reassembly bound.
///
/// The ceiling, not the bound in force: an assembled transport takes the limit
/// it advertises at construction and holds every stream to that.
pub const MAX_PARTIAL_CONTROL_FRAME: usize = vot_transport_api::MAX_CONTROL_FRAME_WIRE_BYTES;

/// Which kind of stream is being read, and so which bound applies.
///
/// Carried explicitly rather than inferred from the lane number, so an
/// application stream can never be mistaken for the control stream.
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

/// What partial frames are charged against.
///
/// A lane bound covers one stream. A peer that opens many and leaves a nearly
/// complete record on each multiplies that by the stream count, which no
/// per-stream bound can see, so the budget is shared and the backend decides
/// what it is shared with.
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
        // Compare and exchange rather than fetch and add: adding first would
        // let two streams past a budget that only had room for one, and
        // subtracting afterwards leaves the refusal charged in between.
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

/// Per-stream reassembly state.
///
/// Each stream owns its own, because bytes from two streams share no ordering
/// and combining them would build frames that were never sent.
#[derive(Debug)]
pub struct Framing<B: AssemblyBudget> {
    pending: Vec<u8>,
    /// The control bound this stream reassembles under. A frame already
    /// part-way through keeps the bound its envelope was read under.
    control_limit: Arc<AtomicUsize>,
    /// Payload bytes of a skipped frame still to arrive. They are dropped as
    /// they land rather than buffered, which `spec/wire.md` requires and which
    /// also keeps a peer from parking a lane's worth of memory per stream by
    /// fragmenting a frame nobody will read.
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
        Ok(())
    }

    /// Drops the buffered frame and returns its cost to the budget.
    pub fn release(&mut self) {
        self.pending.clear();
        if self.reserved != 0 {
            self.budget.release(self.reserved);
            self.reserved = 0;
        }
    }

    /// Feeds received bytes to `emit`, one complete frame at a time.
    ///
    /// Frames are handed over as they are parsed rather than collected, and only
    /// a trailing incomplete frame is ever copied into the buffer. A coalesced
    /// read can carry many valid frames at once, so returning them together
    /// would let one read hold the whole read plus a copy of every frame in it
    /// before the bounded queue saw any of them.
    ///
    /// # Errors
    /// Reports a frame this stream cannot carry, either because it is malformed,
    /// because it is larger than the stream allows, or because it can never
    /// complete, all of which would otherwise stall the stream. Propagates
    /// whatever `emit` reports.
    pub fn accept(
        &mut self,
        bytes: &[u8],
        mut emit: impl FnMut(&[u8]) -> Result<(), FrameFault>,
    ) -> Result<(), FrameFault> {
        // Once per call, so one carrier read uses one bound.
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
                    // Not even the header is complete. It is at most a couple of
                    // varints, so take one byte and look again.
                    self.hold(&input[..1])?;
                    input = &input[1..];
                    continue;
                };
                let needed = envelope.total_length - self.pending.len();
                let taken = needed.min(input.len());
                if envelope.skipped {
                    // The header is buffered but the payload is not, so only the
                    // remainder has to be counted down.
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
                // Released before the frame is queued, so its bytes are charged
                // once rather than to both accounts at the handover.
                let complete = std::mem::take(&mut self.pending);
                self.release();
                emit(&complete)?;
                continue;
            }

            // Nothing buffered, so parse straight out of the read.
            let Some(envelope) = self.envelope(limits, control, Some(input))? else {
                // Only a partial header is left. That is bounded by the envelope
                // size, not by the payload it describes.
                self.hold(input)?;
                return Ok(());
            };
            if input.len() < envelope.total_length {
                if envelope.skipped {
                    // spec/wire.md step 6: stream-discard exactly the declared
                    // length and never size a buffer from it.
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
                // The codec bounds a known frame by its registered limit, which
                // for PROOF_BUNDLE and HAVE is larger than this lane carries.
                // Without this the frame decodes, reaches the adapter, is refused
                // there as oversized, and is retried for ever at the head of the
                // queue.
                if envelope.total_length > self.kind.partial_frame_limit(control) {
                    return Err(FrameFault::too_large());
                }
                Ok(Some(envelope))
            }
            // The type and length have not both arrived yet.
            Err(vot_codec::DecodeError::Incomplete { .. }) => Ok(None),
            // The decoder already knows which registered error this is, and
            // spec/wire.md requires the session to close under that code rather
            // than under a generic transport abort.
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
        // A peer that resets a stream part-way through a frame destroys this
        // without the frame ever completing. Without returning the reservation
        // those bytes stay charged for ever, and enough resets refuse streams
        // that have done nothing wrong.
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
        // The reason this exists: a read is not a record. A frame handed over per
        // read would be delivered truncated and then again as a fragment.
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

        // And a read carrying several frames delivers all of them, in order.
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
        // The envelope itself can be split, which is the case the buffer has to
        // handle without a bound of its own to grow.
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
        // The codec bounds a known frame by its registered limit, which for some
        // frames is larger than a lane carries. Without this bound the frame
        // decodes, reaches the adapter, is refused there, and is retried for ever
        // at the head of the queue.
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
        // A narrower advertised bound is the bound in force, not the ceiling the
        // crate was compiled with.
        const ENVELOPE: usize = vot_transport_api::MAX_FRAME_ENVELOPE_BYTES;
        let narrow = Arc::new(AtomicUsize::new(2_048));
        let mut framing = Framing::new(StreamKind::Control, budget(), Arc::clone(&narrow));
        assert_eq!(
            collect(&mut framing, &frame(2_048)),
            Ok(vec![frame(2_048)]),
            "a frame at the advertised bound"
        );
        // The bound is on the whole frame, envelope included, so one past it is
        // stated that way rather than by payload.
        assert_eq!(
            collect(&mut framing, &frame(2_048 + ENVELOPE + 1)),
            Err(FrameFault::too_large()),
            "and one byte past what it may weigh"
        );

        // A lane is bounded by the record limit rather than by the control one,
        // so the same narrow advertisement does not narrow it.
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

        // A stream reset part-way through a frame returns its charge too. Without
        // that, enough resets refuse streams that have done nothing wrong.
        let mut reset = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        collect(&mut reset, &whole[..50]).expect("a partial frame");
        assert_eq!(shared.held(), 50);
        drop(reset);
        assert_eq!(shared.held(), 0);
    }

    #[test]
    fn a_peer_cannot_hold_more_than_the_budget_across_streams() {
        // A per-stream bound covers one stream. A peer that opens many and leaves
        // a nearly complete frame on each multiplies it by the stream count,
        // which no per-stream bound can see.
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

        // What the first stream returns is what the second may then hold.
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
        // A release past what is held leaves nothing charged rather than
        // wrapping.
        budget.release(1_000);
        assert_eq!(budget.held(), 0);
        assert!(!budget.reserve(usize::MAX), "an overflow is not room");
    }

    #[test]
    fn an_optional_frame_nobody_reads_is_discarded_rather_than_buffered() {
        // spec/wire.md step 6: stream-discard exactly the declared length and
        // never size a buffer from it. A peer that fragments a frame it knows
        // will be skipped would otherwise park a lane's worth of memory per
        // stream.
        let shared = budget();
        let mut framing = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        let mut skipped = Vec::new();
        // An unknown optional frame type: even, and not registered.
        vot_codec::encode_frame(0x1f00, &vec![0x11; 4_000], &mut skipped)
            .expect("an unknown optional frame");

        // Split so the header arrives without its payload.
        assert_eq!(collect(&mut framing, &skipped[..3]), Ok(Vec::new()));
        assert_eq!(
            collect(&mut framing, &skipped[3..]),
            Ok(Vec::new()),
            "nothing is delivered for a frame that is skipped"
        );
        assert_eq!(shared.held(), 0, "and nothing was held for it");
        assert!(!framing.is_assembling());

        // The frame after it is still read, which is what says the discard
        // counted the right number of bytes.
        let following = frame(8);
        let mut both = skipped.clone();
        both.extend_from_slice(&following);
        let mut fresh = Framing::new(StreamKind::Control, shared, control_limit());
        assert_eq!(collect(&mut fresh, &both), Ok(vec![following]));
    }

    #[test]
    fn a_discarded_frame_is_counted_down_exactly_across_reads() {
        // The declared length is counted down as the bytes land, and the frame
        // after it has to line up. A count that drifts either eats the next
        // frame's bytes or hands a skipped frame's payload to the parser as
        // frames.
        let shared = budget();
        let mut framing = Framing::new(StreamKind::Control, Arc::clone(&shared), control_limit());
        let mut skipped = Vec::new();
        vot_codec::encode_frame(0x1f00, &vec![0x11; 4_000], &mut skipped)
            .expect("an unknown optional frame");
        let header = skipped.len() - 4_000;
        let following = frame(8);

        // The header alone, which is where the countdown is set.
        assert_eq!(collect(&mut framing, &skipped[..header]), Ok(Vec::new()));
        assert!(framing.is_assembling(), "a frame is part-way through");
        assert_eq!(shared.held(), 0, "a skipped frame is never held");

        // Part of the payload, so the countdown has to survive a read that
        // neither starts nor finishes it.
        assert_eq!(
            collect(&mut framing, &skipped[header..header + 100]),
            Ok(Vec::new())
        );
        assert!(framing.is_assembling());
        assert_eq!(shared.held(), 0);

        // The rest of the payload and the next frame in one read. The next frame
        // is delivered whole, which is what says the countdown ended on the right
        // byte.
        let mut rest = skipped[header + 100..].to_vec();
        rest.extend_from_slice(&following);
        assert_eq!(collect(&mut framing, &rest), Ok(vec![following]));
        assert!(!framing.is_assembling());
        assert_eq!(shared.held(), 0);
    }

    #[test]
    fn a_frame_at_exactly_the_reassembly_bound_is_carried() {
        // The bound is what a stream may hold, so a frame weighing exactly that
        // is inside it. Refusing it would close a session over a frame the
        // advertisement allowed.
        const ENVELOPE: usize = vot_transport_api::MAX_FRAME_ENVELOPE_BYTES;
        let control = 2_048;
        let bound = control + ENVELOPE;
        // Found rather than assumed: the header width depends on the payload it
        // describes, so the payload that reaches the bound is measured.
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
    fn a_malformed_frame_closes_under_the_code_the_registry_gives_it() {
        let mut framing = Framing::new(StreamKind::Control, budget(), control_limit());
        // A declared payload past what the registry allows that frame. The
        // decoder already knows which registered error that is, and spec/wire.md
        // requires the session to close under that code rather than under a
        // generic transport abort.
        let mut malformed = Vec::new();
        vot_codec::encode_varint(vot_codec::frame_type::SETTINGS, &mut malformed).unwrap();
        vot_codec::encode_varint(20_000, &mut malformed).unwrap();
        let fault = collect(&mut framing, &malformed).expect_err("a malformed frame");
        assert_eq!(fault.error(), Error::Backend);
        assert_ne!(fault.close(), 0, "a registered close code");
    }

    #[test]
    fn what_emit_refuses_is_what_the_caller_hears() {
        // The backend's queue is the one that refuses, and its reason has to
        // reach the caller rather than being turned into a framing fault.
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
        // A control bound at the top of the range cannot overflow the envelope
        // addition.
        assert_eq!(
            StreamKind::Control.partial_frame_limit(usize::MAX),
            usize::MAX
        );
    }
}
