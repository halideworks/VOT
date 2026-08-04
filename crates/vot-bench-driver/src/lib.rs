//! Measured backend driver for the Wave 5.5 benchmark contract.
//!
//! `tools/run_benchmark.py` runs one process per matrix case, hands it the case
//! through `VOT_BENCH_*`, and reads a single JSON object from stdout. The runner
//! deliberately refuses to invent a measurement, and this driver holds the same
//! line in the other direction: a case it cannot run honestly is an error, not
//! an approximation.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use vot_scheduler::ReliableReceiver;
use vot_transport_api::{
    Event, MAX_FRAME_ENVELOPE_BYTES, Payload, StreamId, SubjectId, TransportAdapter, shared_payload,
};
use vot_transport_sim::{Impairment, SimulatorAdapter};
use vot_verifier::{StreamVerifier, Suite};

#[cfg(feature = "msquic")]
mod backend_msquic;
#[cfg(feature = "quiche")]
mod backend_quiche;
#[cfg(any(feature = "msquic", feature = "quiche"))]
pub mod role;

mod cycles;

/// Suite identifiers as the benchmark contract spells them.
const SUITE_BLAKE3: &str = "blake3-bao64";
const SUITE_SHA256: &str = "sha256-bep52";

/// Verifier group size, and the receiver's per-object staging reservation.
const GROUP_BYTES: u64 = vot_verifier::GROUP_SIZE as u64;

/// Records submitted between flushes, so neither the adapter queue nor the
/// receiver's staging grows with object size.
const SUBMIT_BATCH_RECORDS: usize = 16;

/// Bytes drawn from the generator at a time.
const WORD_BYTES: usize = 8;

/// The lane the sequential transfer uses.
///
/// One lane, because the case describes one object. A second would measure how
/// the carrier schedules between lanes, which is a different question from the
/// one the sequential matrix asks; the ranged path asks exactly that question
/// and numbers its lanes from here up (ADR-0025).
const TRANSFER_LANE: StreamId = StreamId(1);

/// The shortest wait after a delivery that moved nothing, and the longest.
///
/// How long the driver waits changes what it measures, which is why this backs
/// off rather than picking one interval. Polling a carrier that has nothing to
/// give contends with the thread that would be filling it: measured over a
/// 512 MB object, a fixed 200 microsecond wait reported a median of about 1000
/// Mbit/s with a 31 percent spread, and fixed waits of 1 to 5 milliseconds
/// reported about 1500 with a 9 percent spread. Waiting less made the carrier
/// slower and the result noisier.
///
/// A fixed long wait would then distort the small cases, where one wait is most
/// of the run. Backing off from the short end gives a small object its answer
/// without a millisecond of padding and a long one the interval where the
/// driver is out of the carrier's way.
const IDLE_WAIT_MIN: Duration = Duration::from_micros(16);
const IDLE_WAIT_MAX: Duration = Duration::from_micros(1024);

/// Doublings from [`IDLE_WAIT_MIN`] that reach [`IDLE_WAIT_MAX`].
const IDLE_WAIT_DOUBLINGS: u32 = 6;
const _: () =
    assert!(IDLE_WAIT_MIN.as_micros() << IDLE_WAIT_DOUBLINGS == IDLE_WAIT_MAX.as_micros());

/// Deliveries a transfer may make beyond one per record before its carrier is
/// called stopped.
///
/// A count rather than a deadline, so the transfer ends by construction rather
/// than only because a clock advanced. A run that reaches it is an error,
/// because a partial transfer reported as a measurement is exactly what the
/// benchmark contract exists to prevent.
///
/// Per record, with a floor, rather than a flat allowance. The budget is also
/// how long a stopped carrier takes to be called stopped, at [`IDLE_WAIT_MAX`]
/// a round, so a flat allowance made a one-record transfer wait as long as a
/// gigabyte one. That is invisible in a healthy run and costs twenty seconds
/// apiece under the mutation gate, where every test's carrier is stopped on
/// purpose.
///
/// Both numbers are about eight times what was measured: 512 MB over loopback
/// spends a few thousand rounds against a budget of 65,536, and a single record
/// spends six to eight against 256.
const ROUNDS_PER_RECORD: u64 = 8;
const MIN_ROUNDS: u64 = 256;

#[derive(Debug)]
pub enum Error {
    /// A `VOT_BENCH_*` variable was absent, empty, or not a number.
    Environment(&'static str),
    /// A value parsed but is outside what the contract allows.
    Value(&'static str),
    /// The case is valid but this driver has no honest implementation for it.
    Unsupported(String),
    Transport(vot_transport_api::Error),
    Receive(vot_scheduler::Error),
    Verify(vot_verifier::VerifyError),
    /// No measured source for a required metric on this platform.
    Unmeasurable(&'static str),
    /// A delivered record was not the frame it was submitted as. Only a carrier
    /// that changed or truncated it on the way can produce this.
    Corrupt,
    /// The carrier used up its delivery budget with the object incomplete.
    Stalled,
    /// The carrier reported the connection gone before the object was whole.
    Disconnected,
    /// The endpoints did not connect, so nothing was carried at all.
    ///
    /// Separate from [`Error::Stalled`] because the two are found in different
    /// places: a transfer that stops is the carrier's business, and a pair that
    /// never connects is the case's configuration or the address it was given.
    Handshake,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment(name) => write!(formatter, "{name} is missing or not a number"),
            Self::Value(name) => write!(formatter, "{name} is outside the allowed range"),
            Self::Unsupported(detail) => write!(formatter, "unsupported case: {detail}"),
            Self::Transport(error) => write!(formatter, "transport error: {error:?}"),
            Self::Receive(error) => write!(formatter, "receive error: {error:?}"),
            Self::Verify(error) => write!(formatter, "verification error: {error:?}"),
            Self::Unmeasurable(metric) => {
                write!(
                    formatter,
                    "{metric} has no measured source on this platform"
                )
            }
            Self::Corrupt => write!(
                formatter,
                "a delivered record was not the frame it was submitted as"
            ),
            Self::Stalled => write!(formatter, "the carrier stopped delivering"),
            Self::Disconnected => write!(
                formatter,
                "the carrier reported the connection gone before the object was whole"
            ),
            Self::Handshake => write!(formatter, "the endpoints did not connect"),
        }
    }
}

impl From<vot_transport_api::Error> for Error {
    fn from(error: vot_transport_api::Error) -> Self {
        Self::Transport(error)
    }
}

impl From<vot_scheduler::Error> for Error {
    fn from(error: vot_scheduler::Error) -> Self {
        Self::Receive(error)
    }
}

impl From<vot_verifier::VerifyError> for Error {
    fn from(error: vot_verifier::VerifyError) -> Self {
        Self::Verify(error)
    }
}

/// The impairment case, as the runner describes it.
///
/// Every field is carried even when a backend cannot apply it, so
/// [`Measurement::notes`] can say which ones went unmodelled rather than
/// leaving a reader to assume the path was shaped as the file describes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImpairmentCase {
    pub mtu_bytes: u64,
    pub rtt_us: u64,
    pub loss_ppm: u64,
    pub reorder_window: u64,
    pub bandwidth_bps: u64,
    pub queue_bytes: u64,
}

/// How the ranged path reaches the carrier: every worker on one shared
/// connection, or one connection per worker. The spine hypothesis compares
/// the two (ruling 6), so the case names its arrangement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rails {
    Shared,
    Provisioned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub backend: String,
    pub suite: Suite,
    pub workers: usize,
    pub seed: u64,
    pub object_bytes: u64,
    pub record_bytes: usize,
    pub rails: Rails,
    pub impairment: ImpairmentCase,
}

/// Reads one case variable. An empty value is as absent as a missing one; the
/// runner never sets a field it has no value for.
fn variable(lookup: &dyn Fn(&str) -> Option<String>, name: &'static str) -> Result<String, Error> {
    lookup(name)
        .filter(|value| !value.is_empty())
        .ok_or(Error::Environment(name))
}

fn number(lookup: &dyn Fn(&str) -> Option<String>, name: &'static str) -> Result<u64, Error> {
    variable(lookup, name)?
        .parse()
        .map_err(|_| Error::Environment(name))
}

impl Config {
    /// Reads one benchmark case from the process environment.
    ///
    /// # Errors
    /// Rejects a missing, unparsable, or out-of-range variable.
    pub fn from_env() -> Result<Self, Error> {
        Self::from_lookup(&|name| std::env::var(name).ok())
    }

    /// Reads one benchmark case from an arbitrary variable source.
    ///
    /// # Errors
    /// Rejects a missing, unparsable, or out-of-range variable.
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let suite = match variable(lookup, "VOT_BENCH_SUITE")?.as_str() {
            SUITE_BLAKE3 => Suite::Blake3Bao64,
            SUITE_SHA256 => Suite::Sha256Bep52,
            _ => return Err(Error::Value("VOT_BENCH_SUITE")),
        };
        let workers = usize::try_from(number(lookup, "VOT_BENCH_WORKERS")?)
            .map_err(|_| Error::Value("VOT_BENCH_WORKERS"))?;
        if workers == 0 {
            return Err(Error::Value("VOT_BENCH_WORKERS"));
        }
        let object_bytes = number(lookup, "VOT_BENCH_OBJECT_BYTES")?;
        if object_bytes == 0 {
            return Err(Error::Value("VOT_BENCH_OBJECT_BYTES"));
        }
        let record_bytes = usize::try_from(number(lookup, "VOT_BENCH_RECORD_BYTES")?)
            .map_err(|_| Error::Value("VOT_BENCH_RECORD_BYTES"))?;
        if record_bytes == 0 || record_bytes > vot_transport_api::MAX_DATA_RECORD_BYTES {
            return Err(Error::Value("VOT_BENCH_RECORD_BYTES"));
        }
        // Absent is the shared arrangement every landed number was taken on;
        // the runner only names what it means to vary.
        let rails = match lookup("VOT_BENCH_RAILS").filter(|value| !value.is_empty()) {
            None => Rails::Shared,
            Some(value) if value == "shared" => Rails::Shared,
            Some(value) if value == "provisioned" => Rails::Provisioned,
            Some(_) => return Err(Error::Value("VOT_BENCH_RAILS")),
        };
        if rails == Rails::Provisioned && workers == 1 {
            // One worker has nothing to provision; a case that asks anyway is
            // asking for a number this driver would have to invent.
            return Err(Error::Value("VOT_BENCH_RAILS"));
        }
        Ok(Self {
            backend: variable(lookup, "VOT_BENCH_BACKEND")?,
            suite,
            workers,
            seed: number(lookup, "VOT_BENCH_SEED")?,
            object_bytes,
            record_bytes,
            rails,
            impairment: ImpairmentCase {
                mtu_bytes: number(lookup, "VOT_BENCH_IMPAIRMENT_MTU_BYTES")?,
                rtt_us: number(lookup, "VOT_BENCH_IMPAIRMENT_RTT_US")?,
                loss_ppm: number(lookup, "VOT_BENCH_IMPAIRMENT_LOSS_PPM")?,
                reorder_window: number(lookup, "VOT_BENCH_IMPAIRMENT_REORDER_WINDOW")?,
                bandwidth_bps: number(lookup, "VOT_BENCH_IMPAIRMENT_BANDWIDTH_BPS")?,
                queue_bytes: number(lookup, "VOT_BENCH_IMPAIRMENT_QUEUE_BYTES")?,
            },
        })
    }

    /// Bandwidth-delay product in bytes, which becomes the receiver's advertised
    /// credit target. Saturates rather than wrapping on an absurd impairment.
    #[must_use]
    pub const fn bandwidth_delay_bytes(&self) -> u64 {
        let bytes_per_second = self.impairment.bandwidth_bps / 8;
        bytes_per_second.saturating_mul(self.impairment.rtt_us) / 1_000_000
    }
}

/// One measured run. Every field is observed; none is defaulted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Measurement {
    pub bytes_sent: u64,
    pub verified_bytes: u64,
    pub elapsed_ns: u64,
    pub memory_high_water_bytes: u64,
    /// `None` whenever no cycle counter was read. The benchmark README is
    /// explicit that a missing counter cannot satisfy the Wave 6 cycle metric,
    /// so this is never filled in with an estimate.
    pub cycles: Option<u64>,
    pub notes: String,
}

impl Measurement {
    /// Renders the object `run_benchmark.py` reads from stdout.
    #[must_use]
    pub fn to_json(&self) -> String {
        let cycles = self
            .cycles
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        format!(
            concat!(
                r#"{{"bytes_sent":{},"verified_bytes":{},"elapsed_ns":{},"#,
                r#""memory_high_water_bytes":{},"cycles":{},"notes":"{}"}}"#
            ),
            self.bytes_sent,
            self.verified_bytes,
            self.elapsed_ns,
            self.memory_high_water_bytes,
            cycles,
            escape(&self.notes),
        )
    }
}

/// Escapes the note string for JSON. Notes are driver-authored and contain no
/// control characters, but escaping is cheaper than trusting that.
fn escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            control if control.is_control() => vec![' '],
            other => vec![other],
        })
        .collect()
}

/// Deterministic object bytes for a seed.
///
/// The object is generated one record at a time rather than materialised, so a
/// gigabyte case does not put a gigabyte of fixture into the high-water mark
/// that is supposed to describe transport and verification.
struct ObjectSource {
    state: u64,
}

impl ObjectSource {
    fn new(seed: u64) -> Self {
        Self {
            // A zero state is absorbing for xorshift, and seed zero is legal.
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    /// The source advanced to `byte_offset`, exactly as if every preceding
    /// byte had been drawn.
    ///
    /// Range workers start mid-object, and drawing a gigabyte of prefix
    /// sequentially would charge the timed section for bytes nobody sends.
    /// Byte offsets on this path are 64 KiB aligned, so the word alignment
    /// this needs always holds; it is still checked, because a misaligned
    /// start would generate a different object than the sequential path.
    fn at(seed: u64, byte_offset: u64) -> Result<Self, Error> {
        if byte_offset % WORD_BYTES as u64 != 0 {
            return Err(Error::Value("VOT_BENCH_RECORD_BYTES"));
        }
        let mut source = Self::new(seed);
        source.state = advance(source.state, byte_offset / WORD_BYTES as u64);
        Ok(source)
    }

    fn draw(&mut self) -> u64 {
        self.state = step(self.state);
        self.state
    }

    /// Fills `buffer` with the next `take` bytes of the object.
    ///
    /// The source does not decide when the object ends; [`record_lengths`] does.
    /// Nothing in the transfer loop then depends on a signal a mutation could
    /// pin true, which would hang rather than fail.
    fn fill(&mut self, buffer: &mut Vec<u8>, take: usize) {
        buffer.clear();
        buffer.reserve(take);
        for _ in 0..take.div_ceil(WORD_BYTES) {
            buffer.extend_from_slice(&self.draw().to_le_bytes());
        }
        buffer.truncate(take);
    }
}

/// One worker's contiguous slice of the object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerRange {
    offset: u64,
    bytes: u64,
}

/// Disjoint, 64 KiB-aligned slabs covering the object exactly, one per worker.
///
/// Groups are dealt as evenly as they divide, the leading workers taking one
/// more where they do not, and the last slab also takes the object's ragged
/// tail. More workers than groups would leave some with nothing to send,
/// which is a case with nothing honest to measure rather than a smaller one.
fn worker_ranges(object_bytes: u64, workers: usize) -> Result<Vec<WorkerRange>, Error> {
    let groups = object_bytes.div_ceil(GROUP_BYTES);
    let count = workers as u64;
    if workers == 0 || count > groups {
        return Err(Error::Unsupported(format!(
            "worker_count {workers} over a {groups}-group object leaves workers with nothing to send"
        )));
    }
    let per = groups / count;
    let extra = groups % count;
    let mut ranges = Vec::with_capacity(workers);
    let mut offset = 0_u64;
    for index in 0..count {
        let slab_groups = per + u64::from(index < extra);
        let end = offset
            .saturating_add(slab_groups.saturating_mul(GROUP_BYTES))
            .min(object_bytes);
        ranges.push(WorkerRange {
            offset,
            bytes: end - offset,
        });
        offset = end;
    }
    Ok(ranges)
}

/// Records one bundle carries on the ranged path.
///
/// The codec allows 17; 16 keeps a bundle of 64 KiB records at 1 MiB, inside
/// the 4 MiB requested-range cap with room for the record size below.
const RECORDS_PER_BUNDLE: usize = 16;

/// The largest record the ranged path accepts.
///
/// A `DATA_RECORD`'s whole CBOR payload is bounded at 256 KiB, and the map
/// around the bytes costs some of it, so the largest 64 KiB multiple that
/// fits is three groups. The sequential path keeps its own larger bound; the
/// two paths frame differently and say so in `notes`.
const MAX_RANGED_RECORD_BYTES: usize = 3 * 65_536;

/// The record size a ranged case runs at.
///
/// A multiple of the 64 KiB group, because ranges verify in whole groups and
/// a record that straddled a group boundary would make every bundle's cover
/// misaligned. Only a worker slab's final record may be short, so a short
/// record can sit mid-object where two slabs meet.
fn ranged_record_bytes(config: &Config) -> Result<usize, Error> {
    let bytes = config.record_bytes;
    if bytes == 0 || bytes % vot_verifier::GROUP_SIZE != 0 || bytes > MAX_RANGED_RECORD_BYTES {
        return Err(Error::Value("VOT_BENCH_RECORD_BYTES"));
    }
    Ok(bytes)
}

/// The staging the ranged receiver needs: the object it retains until
/// completion, plus the verifier reservation.
///
/// The range path keeps every verified range in memory until the object is
/// whole, so on this path peak staging tracks object size by design and the
/// report reads it as retention, not as a leak.
fn ranged_staging_limit(config: &Config) -> u64 {
    config.object_bytes.saturating_add(GROUP_BYTES)
}

/// Builds the receiver for a ranged case.
fn receiver_for_ranged(config: &Config) -> Result<ReliableReceiver, Error> {
    let limit = ranged_staging_limit(config);
    let window = config.bandwidth_delay_bytes().max(limit.min(GROUP_BYTES));
    Ok(ReliableReceiver::new(limit, window, limit)?)
}

/// The chaining-value layer ranges are proved from, per suite.
///
/// ADR-0025: proving from the object costs a whole-object hash per range, so
/// the sender streams the object once and keeps 32 bytes per 64 KiB group.
enum ProverLayer {
    Blake3(vot_proof_blake3::GroupCvs),
    Sha256(vot_proof_sha256::PieceHashes),
}

/// Streams the generated object once, feeding the subject hash and the prover
/// layer together. Runs before the timed section, as `subject_of` does.
fn prover_layer_and_subject(config: &Config) -> Result<(SubjectId, ProverLayer), Error> {
    let mut verifier = StreamVerifier::new(config.suite);
    let mut layer = match config.suite {
        Suite::Blake3Bao64 => ProverLayer::Blake3(vot_proof_blake3::GroupCvs::new()),
        Suite::Sha256Bep52 => ProverLayer::Sha256(vot_proof_sha256::PieceHashes::new()),
    };
    let mut source = ObjectSource::new(config.seed);
    let mut group = Vec::with_capacity(vot_verifier::GROUP_SIZE);
    for take in record_lengths(config.object_bytes, vot_verifier::GROUP_SIZE)? {
        source.fill(&mut group, take);
        verifier.update(&group)?;
        match &mut layer {
            ProverLayer::Blake3(cvs) => cvs.push(&group).map_err(|_| layer_error())?,
            ProverLayer::Sha256(pieces) => pieces.push(&group).map_err(|_| layer_error())?,
        }
    }
    let subject = SubjectId {
        suite: match config.suite {
            Suite::Blake3Bao64 => 1,
            Suite::Sha256Bep52 => 2,
        },
        root: verifier.finish()?,
        length: config.object_bytes,
    };
    Ok((subject, layer))
}

/// A proving failure with a well-formed schedule, which only a driver defect
/// can produce. Reported rather than panicking, so a run fails with a reason.
fn layer_error() -> Error {
    Error::Unsupported("the range prover refused a scheduled range".to_owned())
}

/// Proves one aligned range from the layer.
fn prove_range(layer: &ProverLayer, offset: u64, length: u64) -> Result<Vec<u8>, Error> {
    let (covered_offset, covered_length, proof) = match layer {
        ProverLayer::Blake3(cvs) => {
            let cover =
                vot_proof_blake3::prove_with(cvs, offset, length).map_err(|_| layer_error())?;
            (cover.covered_offset, cover.covered_length, cover.proof)
        }
        ProverLayer::Sha256(pieces) => {
            let cover =
                vot_proof_sha256::prove_with(pieces, offset, length).map_err(|_| layer_error())?;
            (cover.covered_offset, cover.covered_length, cover.proof)
        }
    };
    // The schedule is group aligned, so the cover must be exactly the request;
    // an expanded cover would desynchronise the receiver's completion count.
    if covered_offset != offset || covered_length != length {
        return Err(layer_error());
    }
    Ok(proof)
}

/// The identifier a bundle travels under: seed, worker, and chunk, so it is
/// unique within a run and reproducible across runs of the same case.
fn bundle_identifier(seed: u64, worker: u32, chunk: u32) -> [u8; 16] {
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&seed.to_le_bytes());
    id[8..12].copy_from_slice(&worker.to_le_bytes());
    id[12..].copy_from_slice(&chunk.to_le_bytes());
    id
}

/// One worker's framing state: walks its slab bundle by bundle, proving and
/// encoding as it goes, so no more than one bundle of bytes exists at a time.
struct BundleProducer {
    subject: SubjectId,
    layer: Arc<ProverLayer>,
    source: ObjectSource,
    record_bytes: usize,
    /// Absolute offset of the next byte this worker will frame.
    cursor: u64,
    /// First byte past this worker's slab.
    end: u64,
    seed: u64,
    worker: u32,
    chunk: u32,
}

impl BundleProducer {
    fn new(
        config: &Config,
        layer: Arc<ProverLayer>,
        subject: SubjectId,
        range: WorkerRange,
        worker: u32,
    ) -> Result<Self, Error> {
        Ok(Self {
            subject,
            layer,
            source: ObjectSource::at(config.seed, range.offset)?,
            record_bytes: ranged_record_bytes(config)?,
            cursor: range.offset,
            end: range.offset.saturating_add(range.bytes),
            seed: config.seed,
            worker,
            chunk: 0,
        })
    }

    /// Frames the next bundle: one `PROOF_BUNDLE`, then its records, each a
    /// whole wire frame. `None` once the slab is spent.
    fn next_bundle(&mut self) -> Option<Result<Vec<RangedFrame>, Error>> {
        if self.cursor >= self.end {
            return None;
        }
        let covered_offset = self.cursor;
        let covered_length = ((self.record_bytes as u64).saturating_mul(RECORDS_PER_BUNDLE as u64))
            .min(self.end - self.cursor);
        let result = self.frame_bundle(covered_offset, covered_length);
        if result.is_ok() {
            self.cursor += covered_length;
            self.chunk = self.chunk.saturating_add(1);
        }
        Some(result)
    }

    fn frame_bundle(
        &mut self,
        covered_offset: u64,
        covered_length: u64,
    ) -> Result<Vec<RangedFrame>, Error> {
        let identifier = bundle_identifier(self.seed, self.worker, self.chunk);
        let proof = prove_range(&self.layer, covered_offset, covered_length)?;
        let mut record = Vec::with_capacity(self.record_bytes);
        let mut frames = Vec::new();
        let mut records = Vec::new();
        let mut offset = covered_offset;
        let bundle_end = covered_offset + covered_length;
        // Counted, not steered: the record count is fixed before the loop, so
        // no arithmetic inside it can keep the loop alive.
        let bundle_records = covered_length.div_ceil(self.record_bytes as u64);
        for _ in 0..bundle_records {
            let take = usize::try_from((self.record_bytes as u64).min(bundle_end - offset))
                .map_err(|_| Error::Value("VOT_BENCH_RECORD_BYTES"))?;
            self.source.fill(&mut record, take);
            records.push(vot_codec::frames::DataRecord {
                bundle_id: identifier,
                record_index: records.len() as u64,
                plaintext_offset: offset,
                plaintext_length: take as u64,
                compression: 0,
                encoded: record.clone(),
            });
            offset += take as u64;
        }
        let bundle = vot_codec::frames::ProofBundle {
            request_id: identifier,
            bundle_id: identifier,
            object: vot_codec::frames::ObjectId {
                suite: self.subject.suite,
                root: self.subject.root,
                length: self.subject.length,
            },
            requested_offset: covered_offset,
            requested_length: covered_length,
            covered_offset,
            covered_length,
            data_record_count: records.len() as u64,
            total_plaintext_length: covered_length,
            proof,
        };
        let mut wire = Vec::new();
        vot_codec::frames::encode(
            &vot_codec::frames::TypedFrame::ProofBundle(bundle),
            &mut wire,
        )
        .map_err(|_| Error::Value("VOT_BENCH_RECORD_BYTES"))?;
        frames.push((shared_payload(&wire), 0));
        for data_record in records {
            let plaintext = data_record.plaintext_length;
            wire.clear();
            vot_codec::frames::encode(
                &vot_codec::frames::TypedFrame::DataRecord(data_record),
                &mut wire,
            )
            .map_err(|_| Error::Value("VOT_BENCH_RECORD_BYTES"))?;
            frames.push((shared_payload(&wire), plaintext));
        }
        Ok(frames)
    }
}

/// A frame ready to submit, with the object bytes it carries, so `bytes_sent`
/// is observed at submission rather than assumed from completion.
type RangedFrame = (Payload, u64);

/// Bundles in flight on the receive side.
///
/// A lane delivers a bundle's header before its records, but lanes interleave
/// between workers, so arrivals are keyed by identifier and held until the
/// bundle's own record count is met. Bounded: per-lane order caps incomplete
/// bundles at one per lane, so pending past the worker count is a carrier
/// defect rather than a state to grow into.
struct BundleReassembly {
    pending: BTreeMap<[u8; 16], PendingBundle>,
    limit: usize,
    /// Bundles verified, for the notes.
    completed: u64,
}

struct PendingBundle {
    bundle: vot_codec::frames::ProofBundle,
    records: Vec<vot_codec::frames::DataRecord>,
}

impl BundleReassembly {
    fn new(limit: usize) -> Self {
        Self {
            pending: BTreeMap::new(),
            limit,
            completed: 0,
        }
    }

    /// Feeds one delivered frame, returning the object bytes newly verified.
    ///
    /// # Errors
    /// Reports [`Error::Corrupt`] for a frame that does not decode to this
    /// path's two types, arrives out of its bundle's order, or overflows the
    /// pending bound, and propagates the receiver's own verdicts.
    fn accept(
        &mut self,
        receiver: &mut ReliableReceiver,
        subject: SubjectId,
        frame: &[u8],
    ) -> Result<u64, Error> {
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: 0,
            max_frames: 1,
        };
        let (typed, consumed) =
            vot_codec::frames::decode(frame, limits).map_err(|_| Error::Corrupt)?;
        if consumed != frame.len() {
            return Err(Error::Corrupt);
        }
        match typed {
            vot_codec::frames::TypedFrame::ProofBundle(bundle) => {
                if self.pending.len() >= self.limit {
                    return Err(Error::Corrupt);
                }
                let identifier = bundle.bundle_id;
                let opened = PendingBundle {
                    bundle,
                    records: Vec::new(),
                };
                if self.pending.insert(identifier, opened).is_some() {
                    return Err(Error::Corrupt);
                }
                Ok(0)
            }
            vot_codec::frames::TypedFrame::DataRecord(record) => {
                let identifier = record.bundle_id;
                let Some(pending) = self.pending.get_mut(&identifier) else {
                    return Err(Error::Corrupt);
                };
                pending.records.push(record);
                if (pending.records.len() as u64) < pending.bundle.data_record_count {
                    return Ok(0);
                }
                let Some(whole) = self.pending.remove(&identifier) else {
                    return Err(Error::Corrupt);
                };
                let covered = whole.bundle.covered_length;
                receiver.receive_typed_bundle(subject, &whole.bundle, &whole.records)?;
                self.completed = self.completed.saturating_add(1);
                Ok(covered)
            }
            _ => Err(Error::Corrupt),
        }
    }
}

/// One draw's state transition, named so [`advance`] provably raises the same
/// map [`ObjectSource::draw`] applies.
const fn step(mut state: u64) -> u64 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}

/// [`step`] applied `draws` times, in logarithmic time.
///
/// `step` is linear over GF(2): shifts and xors distribute over xor, so one
/// draw is a 64x64 bit matrix and `draws` of them are that matrix raised to a
/// power, by square and multiply. At most 64 squarings whatever the count.
fn advance(state: u64, draws: u64) -> u64 {
    // Columns: matrix[i] is the map applied to the basis state 1 << i.
    let mut matrix = [0_u64; 64];
    for (bit, column) in matrix.iter_mut().enumerate() {
        *column = step(1 << bit);
    }
    let mut result = state;
    let mut remaining = draws;
    // One pass per bit of the count, counted rather than steered, so no
    // mutation of the body can keep the loop alive.
    for _ in 0..u64::BITS {
        if remaining & 1 == 1 {
            result = apply(&matrix, result);
        }
        matrix = square(&matrix);
        remaining >>= 1;
    }
    result
}

/// The matrix applied to one state: xor of the columns its set bits select.
fn apply(matrix: &[u64; 64], state: u64) -> u64 {
    let mut out = 0;
    for (bit, column) in matrix.iter().enumerate() {
        if state & (1 << bit) != 0 {
            out ^= column;
        }
    }
    out
}

/// The matrix composed with itself.
fn square(matrix: &[u64; 64]) -> [u64; 64] {
    let mut out = [0_u64; 64];
    for (bit, column) in out.iter_mut().enumerate() {
        *column = apply(matrix, matrix[bit]);
    }
    out
}

/// The record schedule for an object: full records, then a short final one.
///
/// Returning the schedule up front makes every loop over the object bounded by
/// construction.
fn record_lengths(
    object_bytes: u64,
    record_bytes: usize,
) -> Result<impl Iterator<Item = usize>, Error> {
    let record = record_bytes as u64;
    let full = object_bytes / record;
    let tail = object_bytes % record;
    // The schedule must account for exactly the object. Checking that also
    // bounds the record count, so a wrong count cannot quietly turn into a
    // longer transfer than the case asked for.
    let covered = full
        .checked_mul(record)
        .and_then(|bytes| bytes.checked_add(tail));
    if covered != Some(object_bytes) {
        return Err(Error::Value("VOT_BENCH_OBJECT_BYTES"));
    }
    let full = usize::try_from(full).map_err(|_| Error::Value("VOT_BENCH_OBJECT_BYTES"))?;
    let tail = usize::try_from(tail).map_err(|_| Error::Value("VOT_BENCH_OBJECT_BYTES"))?;
    Ok(std::iter::repeat_n(record_bytes, full).chain((tail != 0).then_some(tail)))
}

/// Computes the subject identity by streaming the generated object once.
///
/// This runs before the timed section: a receiver is given an identity it did
/// not derive from the bytes it is about to accept, exactly as a real transfer
/// learns it from a package descriptor.
fn subject_of(config: &Config) -> Result<SubjectId, Error> {
    let mut verifier = StreamVerifier::new(config.suite);
    let mut source = ObjectSource::new(config.seed);
    let mut record = Vec::with_capacity(config.record_bytes);
    for take in record_lengths(config.object_bytes, config.record_bytes)? {
        source.fill(&mut record, take);
        verifier.update(&record)?;
    }
    Ok(SubjectId {
        suite: match config.suite {
            Suite::Blake3Bao64 => 1,
            Suite::Sha256Bep52 => 2,
        },
        root: verifier.finish()?,
        length: config.object_bytes,
    })
}

/// User and system CPU time this process has spent, in nanoseconds.
///
/// `None` where the platform exposes no source, which is reported as unmeasured
/// rather than as zero.
///
/// Worth having because throughput alone does not say where the time went. A
/// carrier that is slower because it makes more syscalls and one that is slower
/// because it hashes more look identical in bytes per second and are told apart
/// at a glance by this split.
#[must_use]
pub fn cpu_times_ns() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        parse_cpu_times(&std::fs::read_to_string("/proc/self/stat").ok()?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Extracts user and system CPU time from `/proc/self/stat`, in nanoseconds.
///
/// Fields are counted from the last `)` rather than from the start, because the
/// second field is the executable name and may itself contain spaces and
/// parentheses. Splitting the whole line on whitespace reads the wrong fields
/// for any process whose name has a space in it.
#[must_use]
pub fn parse_cpu_times(stat: &str) -> Option<(u64, u64)> {
    // `/proc` reports these in USER_HZ, which is 100 on Linux regardless of the
    // kernel's own tick rate, so a tick is ten milliseconds.
    const NANOS_PER_TICK: u64 = 10_000_000;
    let after_name = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    // The field after the name is `state`, which `/proc/[pid]/stat` numbers 3,
    // so field n is at index n - 3: utime is 14 and stime is 15.
    let user: u64 = fields.get(11)?.parse().ok()?;
    let system: u64 = fields.get(12)?.parse().ok()?;
    Some((
        user.checked_mul(NANOS_PER_TICK)?,
        system.checked_mul(NANOS_PER_TICK)?,
    ))
}

/// Reads the process high-water resident set.
///
/// # Errors
/// Reports that the metric has no measured source when the platform exposes
/// none, rather than reporting zero.
pub fn memory_high_water_bytes() -> Result<u64, Error> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|_| Error::Unmeasurable("memory_high_water_bytes"))?;
        parse_vm_hwm(&status).ok_or(Error::Unmeasurable("memory_high_water_bytes"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::Unmeasurable("memory_high_water_bytes"))
    }
}

/// Extracts `VmHWM` from `/proc/self/status`, in bytes.
#[must_use]
pub fn parse_vm_hwm(status: &str) -> Option<u64> {
    let line = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))?
        .strip_prefix("VmHWM:")?;
    let mut fields = line.split_whitespace();
    let value: u64 = fields.next()?.parse().ok()?;
    match fields.next()? {
        "kB" => value.checked_mul(1024),
        _ => None,
    }
}

/// Builds the receiver for a case.
///
/// The staging limit is the bandwidth-delay product, floored so a submission
/// batch always fits and raised by the per-object verifier reservation. That
/// makes the impairment file decide the receiver's window instead of leaving it
/// to an arbitrary constant.
fn receiver_for(config: &Config) -> Result<ReliableReceiver, Error> {
    let batch = (config.record_bytes as u64).saturating_mul(SUBMIT_BATCH_RECORDS as u64);
    let window = config.bandwidth_delay_bytes().max(batch);
    let limit = window.saturating_add(GROUP_BYTES);
    Ok(ReliableReceiver::new(limit, window, limit)?)
}

/// Maps the impairment case onto what `SimulatorAdapter` actually models, and
/// reports what it does not.
fn simulator_impairment(config: &Config) -> Result<(Impairment, Vec<&'static str>), Error> {
    let reorder_depth = usize::try_from(config.impairment.reorder_window)
        .map_err(|_| Error::Value("VOT_BENCH_IMPAIRMENT_REORDER_WINDOW"))?;
    if reorder_depth > vot_transport_sim::MAX_REORDER_DEPTH {
        return Err(Error::Value("VOT_BENCH_IMPAIRMENT_REORDER_WINDOW"));
    }
    let mut unmodelled = Vec::new();
    // The loopback adapter has no packetisation, no pacing, and no queue, so
    // these describe the case without shaping it. Saying so is the difference
    // between a bounded claim and a misleading one.
    if config.impairment.loss_ppm != 0 {
        unmodelled.push("loss_ppm");
    }
    // The transfer uses one stream, and a stream is never reordered against
    // itself. The depth is still range checked, but it changes nothing here, so
    // a result must not read as though the path was reordered.
    if config.impairment.reorder_window != 0 {
        unmodelled.push("reorder_window");
    }
    // Round-trip time sizes the receive window and nothing else. The adapter
    // delivers immediately, so no run waited for it, and `credit_bytes` is
    // where its only effect shows up.
    if config.impairment.rtt_us != 0 {
        unmodelled.push("rtt_us");
    }
    unmodelled.push("mtu_bytes");
    unmodelled.push("bandwidth_bps");
    unmodelled.push("queue_bytes");
    Ok((
        Impairment {
            reorder_depth,
            ..Impairment::default()
        },
        unmodelled,
    ))
}

/// Times generating the object and nothing else.
///
/// The transfer generates each record inside the timed section, because
/// materialising the object first would put the fixture into the high-water
/// mark that is supposed to describe transport and verification. That makes
/// generation part of `elapsed_ns`, so its cost is measured separately and
/// reported. A reader can subtract it; the driver does not subtract it for
/// them and call the difference a transport number.
///
/// # Errors
/// Propagates an invalid record schedule.
fn generator_nanos(config: &Config) -> Result<u64, Error> {
    let mut source = ObjectSource::new(config.seed);
    let mut record = Vec::with_capacity(config.record_bytes);
    let started = Instant::now();
    for take in record_lengths(config.object_bytes, config.record_bytes)? {
        source.fill(&mut record, take);
        std::hint::black_box(&record);
    }
    Ok(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX))
}

/// What the transfer loop needs from a carrier, whether it loops back inside
/// this process or crosses a socket to another endpoint.
///
/// The methods are plumbing on purpose. Everything that decides a number lives
/// in this file, where the mutation gate measures it, so a backend cannot
/// quietly change what a run means by implementing one of these differently.
trait Carrier {
    /// How the report names this carrier.
    fn name(&self) -> &'static str;

    /// Impairment fields this carrier describes but does not shape.
    fn unmodelled(&self) -> &[&'static str];

    /// What this carrier was configured with, when a reader needs it to know
    /// which path the result describes. Appended to `notes` as it is given.
    fn detail(&self) -> Option<String> {
        None
    }

    /// The endpoint whose inbound bound the case's credit applies to.
    ///
    /// The receiving endpoint is the peer on a real carrier and the same object
    /// on the simulator, so it is named rather than assumed.
    fn receiving(&mut self) -> &mut dyn TransportAdapter;

    /// Submits one framed record on the transfer lane.
    ///
    /// # Errors
    /// Reports whatever the backend reports.
    /// [`vot_transport_api::Error::OutboundQueueFull`] is backpressure rather
    /// than a failure, and the caller decides what to do about it.
    fn submit(&mut self, stream: StreamId, frame: &Payload)
    -> Result<(), vot_transport_api::Error>;

    /// Hands submitted records to the carrier.
    ///
    /// # Errors
    /// Reports whatever the backend reports.
    fn flush(&mut self) -> Result<(), vot_transport_api::Error>;

    /// The next event the receiving endpoint has already been given.
    fn poll_received(&mut self) -> Option<Event>;

    /// Discards the sending endpoint's own events.
    ///
    /// A sender reports acknowledgements and connection state that this
    /// transfer does not read. Leaving them queued would make the backend's
    /// inbound bound the ceiling instead of the carrier.
    fn drain_sent(&mut self);

    /// Waits for the receiving endpoint to have something, at most `bound`.
    ///
    /// Costs real time whether or not anything arrives, so a loop counting
    /// rounds still bounds its wall clock. A backend with a wakeup signal
    /// returns as soon as an event lands, which removes the driver's polling
    /// interval from what a run measures; one without a signal sleeps the
    /// bound out, which is exactly the wait this replaced.
    fn wait(&mut self, bound: Duration);
}

/// The object bytes inside a delivered record frame.
///
/// A lane carries `DATA_RECORD` frames, and a carrier hands back the whole
/// frame it was given, envelope included. The receiver verifies object bytes,
/// so the envelope comes off here. Anything that is not exactly the one frame
/// that was submitted came back changed, which is a carrier defect rather than
/// a measurement.
///
/// # Errors
/// Reports [`Error::Corrupt`] for a frame that does not decode, is not a data
/// record, or does not account for the whole delivery.
fn record_payload(frame: &[u8]) -> Result<&[u8], Error> {
    let limits = vot_codec::DecodeLimits {
        max_unknown_payload: 0,
        max_frames: 1,
    };
    let (decoded, consumed) = vot_codec::decode_one(frame, limits).map_err(|_| Error::Corrupt)?;
    match decoded {
        vot_codec::DecodedFrame::Known {
            frame_type: vot_codec::frame_type::DATA_RECORD,
            payload,
        } if consumed == frame.len() => Ok(payload),
        _ => Err(Error::Corrupt),
    }
}

/// Flushes submitted records and feeds every delivered one to the receiver.
///
/// Returns the object bytes delivered, which is what tells a caller whether the
/// carrier is still making progress. It is not the same as the bytes the
/// carrier moved: the envelope is not part of the object.
fn deliver<C: Carrier>(
    carrier: &mut C,
    receiver: &mut ReliableReceiver,
    subject: SubjectId,
) -> Result<u64, Error> {
    carrier.flush()?;
    let mut delivered = 0_u64;
    while let Some(event) = carrier.poll_received() {
        match event {
            Event::Reliable { bytes, .. } => {
                let payload = record_payload(&bytes)?;
                receiver.receive(subject, payload)?;
                delivered = delivered.saturating_add(payload.len() as u64);
            }
            // The rest of this object is never arriving. Reporting it now is
            // the difference between a run that fails with the reason and one
            // that waits out the stall bound and reports a slower carrier.
            Event::Disconnected(_) => return Err(Error::Disconnected),
            _ => {}
        }
    }
    carrier.drain_sent();
    Ok(delivered)
}

/// Delivers once, and waits if that moved nothing.
///
/// The carrier's own thread is what makes progress, so a caller that found
/// nothing has nothing to do until that thread has run. Waiting rather than
/// spinning matters here more than it usually would: a benchmark that burns a
/// core polling takes it from the carrier it is measuring.
///
/// The waits are counted, which is worth reporting. A transfer that spent most
/// of its deliveries finding nothing was waiting on the carrier, and one that
/// never waited was never ahead of it.
///
/// # Errors
/// Propagates delivery failures.
fn deliver_or_wait<C: Carrier>(
    carrier: &mut C,
    receiver: &mut ReliableReceiver,
    subject: SubjectId,
    idle_waits: &mut u64,
) -> Result<u64, Error> {
    let progress = deliver(carrier, receiver, subject)?;
    if progress == 0 {
        *idle_waits = idle_waits.saturating_add(1);
        carrier.wait(idle_wait(*idle_waits));
    }
    Ok(progress)
}

/// How long to wait once this transfer has had `idle_waits` deliveries that
/// moved nothing.
///
/// Doubling from [`IDLE_WAIT_MIN`], and never past [`IDLE_WAIT_MAX`].
///
/// The count is the transfer's total rather than a run of them, so the wait
/// climbs once and stays. Backing off from a run instead was measured and is
/// worse on both counts: deliveries that do find data reset it, this workload
/// arrives in bursts, and the driver spends the transfer in the short waits
/// that measure a slower and noisier carrier. It also leaves the wait free to
/// stay short for an unbounded number of deliveries, which is the only reason
/// the loops' round budget would need a wall clock to go with it.
fn idle_wait(idle_waits: u64) -> Duration {
    let doublings = u32::try_from(idle_waits.saturating_sub(1))
        .unwrap_or(IDLE_WAIT_DOUBLINGS)
        .min(IDLE_WAIT_DOUBLINGS);
    IDLE_WAIT_MIN
        .saturating_mul(1_u32 << doublings)
        .min(IDLE_WAIT_MAX)
}

/// What one transfer spent, beyond the bytes it moved.
///
/// Every field is observed rather than derived, and each answers a question a
/// reader of the result would otherwise have to guess at: how often the driver
/// deliberately handed records over, how often the carrier refused one, how
/// often the driver had nothing to do but wait, and how much more than the
/// object went onto the wire.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Tally {
    flushes: u64,
    backpressure_waits: u64,
    idle_waits: u64,
    wire_bytes: u64,
    /// Rounds of the one budget the ranged loop has spent. The sequential
    /// path counts its own rounds locally and leaves this zero.
    rounds: u64,
    /// User and system CPU nanoseconds the timed section spent, when the
    /// platform exposes them.
    cpu: Option<(u64, u64)>,
}

/// What the timed section spent, from two readings of the process total.
///
/// `None` unless both readings were taken, because a difference against a
/// reading that was never made is not a measurement.
fn cpu_spent(before: Option<(u64, u64)>, after: Option<(u64, u64)>) -> Option<(u64, u64)> {
    let (user_before, system_before) = before?;
    let (user_after, system_after) = after?;
    Some((
        user_after.saturating_sub(user_before),
        system_after.saturating_sub(system_before),
    ))
}

/// Renders what a run measured, in the field order the contract's readers know.
fn transfer_notes(
    carrier: &impl Carrier,
    receiver: &ReliableReceiver,
    credit: Credit,
    tally: Tally,
    generator_ns: u64,
) -> String {
    let mut notes = format!(
        concat!(
            "backend={};path=sequential-reliable;",
            "staging_peak_bytes={};credit_bytes={};credit_mode={};",
            "flushes={};backpressure_waits={};idle_waits={};wire_bytes={};generator_ns={};",
            "cpu_user_ns={};cpu_sys_ns={}"
        ),
        carrier.name(),
        receiver.peak_staging(),
        receiver.advertised_credit(),
        credit.as_str(),
        tally.flushes,
        tally.backpressure_waits,
        tally.idle_waits,
        tally.wire_bytes,
        generator_ns,
        tally
            .cpu
            .map_or_else(|| "unmeasured".to_owned(), |(user, _)| user.to_string()),
        tally
            .cpu
            .map_or_else(|| "unmeasured".to_owned(), |(_, system)| system.to_string()),
    );
    if let Some(detail) = carrier.detail() {
        notes.push(';');
        notes.push_str(&detail);
    }
    if !carrier.unmodelled().is_empty() {
        notes.push_str(";unmodelled_impairment=");
        notes.push_str(&carrier.unmodelled().join(","));
    }
    notes
}

/// The deliveries a transfer may make in a loop whose end depends on the
/// carrier, before that carrier is called stopped.
///
/// One per record, because a healthy transfer may need that many, plus a flat
/// allowance for the deliveries that find nothing while the carrier is still
/// moving bytes. At [`IDLE_WAIT`] each, the allowance is a couple of minutes of
/// a carrier delivering nothing, which no case on any path this benchmark runs
/// reaches while healthy.
///
/// The budget is spent and counted by the loops themselves rather than by
/// anything they call. A loop whose bound lives somewhere else is not bounded:
/// whatever removes the bound leaves a benchmark that hangs, which is worse
/// than one that fails.
fn round_budget(config: &Config) -> u64 {
    let records = config
        .object_bytes
        .div_ceil(config.record_bytes.max(1) as u64);
    records.saturating_mul(ROUNDS_PER_RECORD).max(MIN_ROUNDS)
}

/// Whether the carrier was given the receiver's credit, or bounds what it
/// accepts at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Credit {
    Set,
    Constructed,
}

impl Credit {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Constructed => "constructed",
        }
    }
}

/// Applies the receiver's credit to the endpoint that will enforce it.
///
/// A carrier that fixes its inbound bound at construction reports
/// `Unsupported` rather than accepting a credit it would not apply, which
/// ADR-0024 requires of the quiche backend: accepting the call and doing
/// nothing would let an endpoint advertise a credit no carrier enforces. Which
/// of the two happened is recorded, because the report must never present a
/// bound nothing applied. `credit_bytes` means the same thing either way: what
/// the receiver advertised, which the receiver itself enforces by refusing
/// staging beyond it.
///
/// # Errors
/// Propagates any error other than `Unsupported`.
fn enforced_credit(endpoint: &mut dyn TransportAdapter, credit: u64) -> Result<Credit, Error> {
    match endpoint.set_receive_credit(credit) {
        Ok(()) => Ok(Credit::Set),
        Err(vot_transport_api::Error::Unsupported) => Ok(Credit::Constructed),
        Err(other) => Err(Error::Transport(other)),
    }
}

/// The in-process loopback carrier.
struct SimulatorCarrier {
    adapter: SimulatorAdapter,
    unmodelled: Vec<&'static str>,
}

impl SimulatorCarrier {
    fn new(config: &Config) -> Result<Self, Error> {
        let (impairment, unmodelled) = simulator_impairment(config)?;
        Ok(Self {
            adapter: SimulatorAdapter::with_impairment(impairment)?,
            unmodelled,
        })
    }
}

impl Carrier for SimulatorCarrier {
    fn name(&self) -> &'static str {
        "simulator"
    }

    fn unmodelled(&self) -> &[&'static str] {
        &self.unmodelled
    }

    fn receiving(&mut self) -> &mut dyn TransportAdapter {
        &mut self.adapter
    }

    fn submit(
        &mut self,
        stream: StreamId,
        frame: &Payload,
    ) -> Result<(), vot_transport_api::Error> {
        self.adapter
            .send_reliable_shared(stream, Payload::clone(frame))
    }

    fn flush(&mut self) -> Result<(), vot_transport_api::Error> {
        self.adapter.flush()
    }

    fn poll_received(&mut self) -> Option<Event> {
        self.adapter.poll()
    }

    // The simulator sends and receives through one object, so every event it
    // has was already offered to `poll_received`.
    fn drain_sent(&mut self) {}

    // The simulator delivers before `flush` returns, so a healthy transfer
    // never waits on it. Sleeping the bound out keeps the wait a cost when
    // something is wrong rather than a spin.
    fn wait(&mut self, bound: Duration) {
        std::thread::sleep(bound);
    }
}

/// Runs one case and returns what was measured.
///
/// # Errors
/// Propagates transport, receive, and verification failures, and rejects any
/// case this driver cannot run honestly.
pub fn measure(config: &Config) -> Result<Measurement, Error> {
    // Opened before any carrier or worker thread exists, so inherit covers
    // every thread this measurement creates; the counter's span is the whole
    // case, connection setup included, which is milliseconds against seconds.
    let counter = cycles::CycleCounter::start();
    let mut measured = measure_case(config)?;
    measured.cycles = counter.and_then(cycles::CycleCounter::read);
    note_cycles(&mut measured.notes, measured.cycles);
    Ok(measured)
}

fn measure_case(config: &Config) -> Result<Measurement, Error> {
    // One worker keeps the sequential path every landed number was taken on;
    // more run the ranged path, where workers carry disjoint proof-bearing
    // ranges of the one object (ADR-0025).
    if config.workers == 1 {
        return match config.backend.as_str() {
            "simulator" => transfer(config, SimulatorCarrier::new(config)?),
            #[cfg(feature = "msquic")]
            "msquic" => transfer(config, backend_msquic::MsQuicCarrier::connected(config)?),
            #[cfg(feature = "quiche")]
            "quiche" => transfer(config, backend_quiche::QuicheCarrier::connected(config)?),
            other => Err(Error::Unsupported(format!(
                "backend {other} has no assembled transport in this build"
            ))),
        };
    }
    let budget = round_budget(config);
    // One shared connection, or a connection per worker; the spine loop is
    // the same either way, so the comparison changes only the carrier count.
    let rail_count = match config.rails {
        Rails::Shared => 1,
        Rails::Provisioned => config.workers,
    };
    match config.backend.as_str() {
        "simulator" => {
            let carriers = (0..rail_count)
                .map(|_| SimulatorCarrier::new(config))
                .collect::<Result<Vec<_>, _>>()?;
            transfer_ranged(config, carriers, budget)
        }
        #[cfg(feature = "msquic")]
        "msquic" => {
            let carriers = (0..rail_count)
                .map(|_| backend_msquic::MsQuicCarrier::connected(config))
                .collect::<Result<Vec<_>, _>>()?;
            transfer_ranged(config, carriers, budget)
        }
        #[cfg(feature = "quiche")]
        "quiche" => {
            let carriers = (0..rail_count)
                .map(|_| backend_quiche::QuicheCarrier::connected(config))
                .collect::<Result<Vec<_>, _>>()?;
            transfer_ranged(config, carriers, budget)
        }
        other => Err(Error::Unsupported(format!(
            "backend {other} has no assembled transport in this build"
        ))),
    }
}

/// Carries one object over `carrier` and returns what was measured.
///
/// Every backend runs this same loop, so a difference between two results is a
/// difference between two carriers rather than between two transfer
/// strategies. The carrier is already connected: a handshake inside the timed
/// section would be reported as transfer time.
///
/// # Errors
/// Propagates transport, receive, and verification failures, and reports a
/// carrier that stopped delivering rather than returning a partial transfer.
fn transfer<C: Carrier>(config: &Config, carrier: C) -> Result<Measurement, Error> {
    transfer_within(config, carrier, round_budget(config))
}

/// [`transfer`] with the delivery budget named, so a test can drive a carrier
/// that stops without spending the budget a real run is given.
fn transfer_within<C: Carrier>(
    config: &Config,
    mut carrier: C,
    budget: u64,
) -> Result<Measurement, Error> {
    #[cfg(test)]
    test_guard::arm();
    let subject = subject_of(config)?;
    let generator_ns = generator_nanos(config)?;
    let mut receiver = receiver_for(config)?;
    receiver.begin(subject)?;
    let credit = enforced_credit(carrier.receiving(), receiver.advertised_credit())?;

    let mut source = ObjectSource::new(config.seed);
    let mut record = Vec::with_capacity(config.record_bytes);
    let mut frame = Vec::with_capacity(config.record_bytes + MAX_FRAME_ENVELOPE_BYTES);
    let mut bytes_sent = 0_u64;
    let mut delivered = 0_u64;
    let mut batch = 0_usize;
    let mut tally = Tally::default();
    // The two loops whose end depends on the carrier spend one budget between
    // them, so both are bounded however the carrier behaves.
    let mut rounds = 0_u64;

    let cpu_before = cpu_times_ns();
    let started = Instant::now();
    for take in record_lengths(config.object_bytes, config.record_bytes)? {
        source.fill(&mut record, take);
        frame.clear();
        vot_codec::encode_frame(vot_codec::frame_type::DATA_RECORD, &record, &mut frame)
            .map_err(|_| Error::Value("VOT_BENCH_RECORD_BYTES"))?;
        // Shared once. The submission contract takes a shared payload precisely
        // so a record crosses into the backend without being copied again, and
        // a driver that copied every record would measure itself as much as the
        // carrier.
        let shared = shared_payload(&frame);
        loop {
            match carrier.submit(TRANSFER_LANE, &shared) {
                Ok(()) => break,
                // A full queue is backpressure, not a failure: what is already
                // submitted has to move before more will fit. Delivering is
                // what makes room, so the record is offered again after it.
                Err(vot_transport_api::Error::OutboundQueueFull) => {
                    // This loop ends only when the carrier takes the record, so
                    // it keeps its own bound. Spending it here rather than
                    // inside what it calls is what makes the loop bounded
                    // whatever that call does.
                    rounds = rounds.saturating_add(1);
                    if rounds > budget {
                        return Err(Error::Stalled);
                    }
                    tally.backpressure_waits = tally.backpressure_waits.saturating_add(1);
                    tally.flushes = tally.flushes.saturating_add(1);
                    delivered = delivered.saturating_add(deliver_or_wait(
                        &mut carrier,
                        &mut receiver,
                        subject,
                        &mut tally.idle_waits,
                    )?);
                }
                Err(other) => return Err(Error::Transport(other)),
            }
        }
        bytes_sent = bytes_sent.saturating_add(record.len() as u64);
        tally.wire_bytes = tally.wire_bytes.saturating_add(frame.len() as u64);
        batch = batch.saturating_add(1);
        // Flushing in batches keeps the carrier's queue and the receiver's
        // staging bounded, so peak memory does not track object size.
        if batch >= SUBMIT_BATCH_RECORDS {
            tally.flushes = tally.flushes.saturating_add(1);
            delivered = delivered.saturating_add(deliver(&mut carrier, &mut receiver, subject)?);
            batch = 0;
        }
    }
    if batch != 0 {
        tally.flushes = tally.flushes.saturating_add(1);
        delivered = delivered.saturating_add(deliver(&mut carrier, &mut receiver, subject)?);
    }

    // Every record has been submitted, so whatever has not arrived is in
    // flight. A carrier that delivers immediately leaves this loop without
    // entering it; one that crosses a socket stays here until the object is
    // whole. The budget is what ends it either way, so a slow path is waited
    // out and a stopped one is an error rather than a partial result.
    while delivered < config.object_bytes {
        rounds = rounds.saturating_add(1);
        if rounds > budget {
            return Err(Error::Stalled);
        }
        delivered = delivered.saturating_add(deliver_or_wait(
            &mut carrier,
            &mut receiver,
            subject,
            &mut tally.idle_waits,
        )?);
    }

    receiver.finish(subject)?;
    let elapsed = started.elapsed();
    tally.cpu = cpu_spent(cpu_before, cpu_times_ns());

    if !receiver.is_verified(subject) {
        return Err(Error::Unsupported(
            "receiver did not reach a verified state".to_owned(),
        ));
    }

    let notes = transfer_notes(&carrier, &receiver, credit, tally, generator_ns);

    Ok(Measurement {
        bytes_sent,
        verified_bytes: config.object_bytes,
        // Instant is monotonic, but a case can still complete inside a tick and
        // the contract requires at least one nanosecond.
        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1),
        memory_high_water_bytes: memory_high_water_bytes()?,
        cycles: None,
        notes,
    })
}

/// Carries one object as proof-bearing ranges over one or more carriers.
///
/// W producer threads generate, prove, and frame disjoint slabs; this thread,
/// the spine, is the only one that touches a carrier: it submits, flushes,
/// polls, and verifies. The loop is byte-identical whether the carriers are
/// one connection with a lane per worker or one connection per worker, so the
/// only difference between those cases is the connection count, which is what
/// the spine hypothesis asks about.
///
/// # Errors
/// Propagates transport, proving, and verification failures, and reports a
/// carrier that stopped rather than returning a partial transfer.
#[expect(
    clippy::too_many_lines,
    reason = "one loop, kept whole so the budget it spends is visibly its own"
)]
fn transfer_ranged<C: Carrier>(
    config: &Config,
    mut carriers: Vec<C>,
    budget: u64,
) -> Result<Measurement, Error> {
    #[cfg(test)]
    test_guard::arm();
    let workers = config.workers;
    if carriers.len() != 1 && carriers.len() != workers {
        return Err(Error::Unsupported(format!(
            "{} carriers cannot carry {workers} workers; one shared or one each",
            carriers.len()
        )));
    }
    // Validated before any thread starts, so a bad size is one error rather
    // than a worker's; each producer reads the same value itself.
    ranged_record_bytes(config)?;
    let ranges = worker_ranges(config.object_bytes, workers)?;
    let (subject, layer) = prover_layer_and_subject(config)?;
    let layer = Arc::new(layer);
    let generator_ns = generator_nanos(config)?;
    let mut receiver = receiver_for_ranged(config)?;
    receiver.begin_ranges(subject)?;
    let mut credit = Credit::Constructed;
    for carrier in &mut carriers {
        credit = enforced_credit(carrier.receiving(), receiver.advertised_credit())?;
    }
    let provisioned = carriers.len() > 1;
    // Worker w submits on lane 1 + w of the one connection, or on the transfer
    // lane of its own. Lane numbering starts where the sequential path's does.
    let rail_count = carriers.len();
    let rail_of = move |worker: usize| -> (usize, StreamId) {
        if rail_count == 1 {
            (0, StreamId(1 + worker as u64))
        } else {
            (worker, TRANSFER_LANE)
        }
    };
    let mut reassembly = BundleReassembly::new(workers);
    let mut tally = Tally::default();
    let mut bytes_sent = 0_u64;
    let mut delivered = 0_u64;

    let cpu_before = cpu_times_ns();
    let started = Instant::now();
    std::thread::scope(|scope| -> Result<(), Error> {
        let mut channels = Vec::with_capacity(workers);
        for (index, range) in ranges.iter().enumerate() {
            let (sender, frames) = mpsc::sync_channel::<Result<Vec<RangedFrame>, Error>>(2);
            let mut producer = BundleProducer::new(
                config,
                Arc::clone(&layer),
                subject,
                *range,
                u32::try_from(index).map_err(|_| Error::Value("VOT_BENCH_WORKERS"))?,
            )?;
            channels.push(frames);
            scope.spawn(move || {
                while let Some(bundle) = producer.next_bundle() {
                    let failed = bundle.is_err();
                    // A closed channel means the spine is gone, taking the
                    // transfer's verdict with it; there is no one to tell.
                    if sender.send(bundle).is_err() {
                        return;
                    }
                    // An error is this producer's last word.
                    if failed {
                        return;
                    }
                }
            });
        }

        let mut queued: Vec<VecDeque<RangedFrame>> =
            (0..workers).map(|_| VecDeque::new()).collect();
        while delivered < config.object_bytes {
            // Spent here rather than in anything the loop calls, which is what
            // keeps the loop bounded whatever those calls do.
            tally.rounds = tally.rounds.saturating_add(1);
            if tally.rounds > budget {
                return Err(Error::Stalled);
            }
            let mut progress = false;
            for worker in 0..workers {
                if queued[worker].is_empty() {
                    match channels[worker].try_recv() {
                        Ok(Ok(frames)) => queued[worker].extend(frames),
                        Ok(Err(error)) => return Err(error),
                        // Disconnected is a finished worker; nothing more comes.
                        Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {}
                    }
                }
                let (carrier_index, lane) = rail_of(worker);
                while let Some((frame, plaintext)) = queued[worker].front() {
                    match carriers[carrier_index].submit(lane, frame) {
                        Ok(()) => {
                            bytes_sent = bytes_sent.saturating_add(*plaintext);
                            tally.wire_bytes = tally.wire_bytes.saturating_add(frame.len() as u64);
                            queued[worker].pop_front();
                            progress = true;
                        }
                        Err(vot_transport_api::Error::OutboundQueueFull) => {
                            tally.backpressure_waits = tally.backpressure_waits.saturating_add(1);
                            break;
                        }
                        Err(other) => return Err(Error::Transport(other)),
                    }
                }
            }
            let mut arrived_bytes = 0_u64;
            for carrier in &mut *carriers {
                tally.flushes = tally.flushes.saturating_add(1);
                carrier.flush()?;
                while let Some(event) = carrier.poll_received() {
                    match event {
                        Event::Reliable { bytes, .. } => {
                            arrived_bytes = arrived_bytes.saturating_add(reassembly.accept(
                                &mut receiver,
                                subject,
                                &bytes,
                            )?);
                        }
                        Event::Disconnected(_) => return Err(Error::Disconnected),
                        _ => {}
                    }
                }
                carrier.drain_sent();
            }
            delivered = delivered.saturating_add(arrived_bytes);
            if arrived_bytes != 0 {
                progress = true;
            }
            if !progress {
                tally.idle_waits = tally.idle_waits.saturating_add(1);
                // Rotated across rails: only a carrier's own signal ends its
                // wait, and any rail's event can end an idle round.
                let rail = usize::try_from(tally.idle_waits % rail_count as u64).unwrap_or(0);
                carriers[rail].wait(idle_wait(tally.idle_waits));
            }
        }
        Ok(())
    })?;
    receiver.finish_ranges(subject)?;
    let elapsed = started.elapsed();
    tally.cpu = cpu_spent(cpu_before, cpu_times_ns());

    if !receiver.is_verified(subject) {
        return Err(Error::Unsupported(
            "receiver did not reach a verified state".to_owned(),
        ));
    }

    let notes = ranged_notes(
        &carriers[0],
        &receiver,
        credit,
        tally,
        generator_ns,
        workers,
        reassembly.completed,
        provisioned,
    );
    Ok(Measurement {
        bytes_sent,
        verified_bytes: delivered,
        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1),
        memory_high_water_bytes: memory_high_water_bytes()?,
        cycles: None,
        notes,
    })
}

/// Renders a ranged run's notes: the sequential fields, then what only this
/// path has, so a reader never mistakes one path's numbers for the other's.
#[expect(
    clippy::too_many_arguments,
    reason = "every argument is one observed field of the one note string"
)]
fn ranged_notes(
    carrier: &impl Carrier,
    receiver: &ReliableReceiver,
    credit: Credit,
    tally: Tally,
    generator_ns: u64,
    workers: usize,
    bundles: u64,
    provisioned: bool,
) -> String {
    let mut notes = format!(
        concat!(
            "backend={};path=ranged;workers={};bundles={};",
            "staging_peak_bytes={};credit_bytes={};credit_mode={};",
            "flushes={};backpressure_waits={};idle_waits={};wire_bytes={};generator_ns={};",
            "cpu_user_ns={};cpu_sys_ns={}"
        ),
        carrier.name(),
        workers,
        bundles,
        receiver.peak_staging(),
        receiver.advertised_credit(),
        credit.as_str(),
        tally.flushes,
        tally.backpressure_waits,
        tally.idle_waits,
        tally.wire_bytes,
        generator_ns,
        tally
            .cpu
            .map_or_else(|| "unmeasured".to_owned(), |(user, _)| user.to_string()),
        tally
            .cpu
            .map_or_else(|| "unmeasured".to_owned(), |(_, system)| system.to_string()),
    );
    if provisioned {
        notes.push_str(";rails=provisioned-multi-rail");
    }
    if let Some(detail) = carrier.detail() {
        notes.push(';');
        notes.push_str(&detail);
    }
    if !carrier.unmodelled().is_empty() {
        notes.push_str(";unmodelled_impairment=");
        notes.push_str(&carrier.unmodelled().join(","));
    }
    notes
}

/// Renders the cycle count into the notes, unmeasured where the host refused
/// a counter, so a reader never mistakes a null for a zero.
pub(crate) fn note_cycles(notes: &mut String, cycles: Option<u64>) {
    notes.push_str(";cycles=");
    match cycles {
        Some(count) => notes.push_str(&count.to_string()),
        None => notes.push_str("unmeasured"),
    }
}

/// A mutant that breaks a loop's progress check can turn an allocating loop
/// into a machine-eater; one reached 96 GiB and the OOM kill took the whole
/// terminal session with it. Aborting at a cap makes that mutant caught.
#[cfg(test)]
mod test_guard {
    use std::sync::Once;

    /// Far above any honest test, and low enough that two capped binaries
    /// and their builds fit a CI runner's 16 GiB together.
    const CAP_BYTES: u64 = 2 << 30;

    static ARM: Once = Once::new();

    /// Spawn the watchdog once per test binary. Every transfer entry calls
    /// this, so no test has to remember to.
    pub(crate) fn arm() {
        ARM.call_once(|| {
            std::thread::spawn(|| {
                loop {
                    if resident_bytes().is_some_and(|rss| rss > CAP_BYTES) {
                        eprintln!("test_guard: resident set passed {CAP_BYTES} bytes, aborting");
                        std::process::abort();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            });
        });
    }

    /// Linux is where these tests and the mutation gates run; without procfs
    /// there is no watchdog rather than a false abort.
    fn resident_bytes() -> Option<u64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4096)
    }

    #[test]
    fn the_watchdog_can_read_its_own_resident_set() {
        assert!(resident_bytes().is_some_and(|rss| rss > 0));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Carrier, Config, Error, ImpairmentCase, Measurement, ObjectSource, Payload, Rails,
        SimulatorCarrier, StreamId, TransportAdapter, escape, measure, note_cycles, parse_vm_hwm,
        record_lengths, record_payload, shared_payload, transfer_ranged, transfer_within,
    };
    use std::collections::{BTreeMap, VecDeque};
    use vot_transport_api::Event;
    use vot_verifier::Suite;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    fn case(object_bytes: u64, suite: Suite) -> Config {
        Config {
            backend: "simulator".to_owned(),
            suite,
            workers: 1,
            seed: 42,
            object_bytes,
            record_bytes: 65_536,
            rails: Rails::Shared,
            impairment: ImpairmentCase {
                mtu_bytes: 1500,
                rtt_us: 1_000,
                loss_ppm: 0,
                reorder_window: 0,
                bandwidth_bps: 10_000_000_000,
                queue_bytes: 33_554_432,
            },
        }
    }

    /// An endpoint that answers the credit call however a test needs.
    struct CreditEndpoint(Result<(), vot_transport_api::Error>);

    impl TransportAdapter for CreditEndpoint {
        fn send_control(&mut self, _frame: &[u8]) -> Result<(), vot_transport_api::Error> {
            Ok(())
        }

        fn send_reliable(
            &mut self,
            _stream: StreamId,
            _record: &[u8],
        ) -> Result<(), vot_transport_api::Error> {
            Ok(())
        }

        fn poll(&mut self) -> Option<Event> {
            None
        }

        fn set_receive_credit(&mut self, _bytes: u64) -> Result<(), vot_transport_api::Error> {
            self.0
        }
    }

    /// A carrier that behaves the way one crossing a socket does: a submission
    /// can be refused, delivery can lag behind submission or stop altogether,
    /// and the credit call can be answered any of the ways a backend answers
    /// it.
    ///
    /// The simulator does none of those things. It accepts every submission and
    /// delivers before `flush` returns, so without this double the backpressure,
    /// completion, stall, and credit paths would be exercised only under a
    /// feature the mutation matrix does not build, and the gate would report
    /// them as untested code in a required package.
    struct TestCarrier {
        /// Frames submitted and not yet released, with the lane each took, so
        /// delivery echoes the lane and a test can pin worker routing.
        inflight: VecDeque<(StreamId, Payload)>,
        /// Frames released and not yet polled.
        arrived: VecDeque<(StreamId, Payload)>,
        /// Every lane submitted on, shared so a test reads it after the
        /// transfer consumes the carrier.
        lanes: std::sync::Arc<std::sync::Mutex<Vec<StreamId>>>,
        /// Submissions to refuse before accepting one.
        refuse: usize,
        /// Deliveries that release nothing before the queue starts moving.
        lag: usize,
        /// Whether the carrier has stopped for good.
        stalled: bool,
        /// Whether to change the first frame on its way through.
        corrupt: bool,
        /// Whether the receiving endpoint reports the connection gone.
        disconnect: bool,
        endpoint: CreditEndpoint,
        /// Events the sending endpoint has raised and the driver has not taken.
        ///
        /// A real backend holds these in a bounded queue and refuses
        /// submissions once it is full, which is how an undrained sender
        /// becomes the ceiling instead of the carrier.
        undrained: usize,
        /// Every bound the driver waited with, shared so a test can read it
        /// after the transfer consumes the carrier. Recorded without sleeping,
        /// because what the tests pin is which waits were taken, not time.
        waited: std::sync::Arc<std::sync::Mutex<Vec<std::time::Duration>>>,
    }

    impl TestCarrier {
        fn new() -> Self {
            Self {
                inflight: VecDeque::new(),
                arrived: VecDeque::new(),
                lanes: std::sync::Arc::default(),
                refuse: 0,
                lag: 0,
                stalled: false,
                corrupt: false,
                disconnect: false,
                endpoint: CreditEndpoint(Ok(())),
                undrained: 0,
                waited: std::sync::Arc::default(),
            }
        }
    }

    /// Sender events this double holds before it refuses to take more.
    ///
    /// Smaller than a submission batch, so a driver that never drained its
    /// sender would reach it inside the first batch rather than only on a long
    /// object.
    const SENDER_EVENT_CAPACITY: usize = 4;

    /// Records the draining test sends. More than the sender queue holds, or it
    /// would pass whether the driver drained or not.
    const DRAIN_TEST_RECORDS: usize = 8;
    const _: () = assert!(DRAIN_TEST_RECORDS > SENDER_EVENT_CAPACITY);

    impl Carrier for TestCarrier {
        fn name(&self) -> &'static str {
            "test"
        }

        fn unmodelled(&self) -> &[&'static str] {
            &[]
        }

        fn receiving(&mut self) -> &mut dyn TransportAdapter {
            &mut self.endpoint
        }

        fn submit(
            &mut self,
            stream: StreamId,
            frame: &Payload,
        ) -> Result<(), vot_transport_api::Error> {
            if self.refuse != 0 {
                self.refuse -= 1;
                return Err(vot_transport_api::Error::OutboundQueueFull);
            }
            // Every submission raises an acknowledgement the sender queues for
            // a caller that never reads it. Once the queue is full the backend
            // has nowhere to put the next one, so the submission is refused.
            if self.undrained >= SENDER_EVENT_CAPACITY {
                return Err(vot_transport_api::Error::OutboundQueueFull);
            }
            self.undrained += 1;
            if let Ok(mut lanes) = self.lanes.lock() {
                lanes.push(stream);
            }
            self.inflight.push_back((stream, Payload::clone(frame)));
            Ok(())
        }

        fn flush(&mut self) -> Result<(), vot_transport_api::Error> {
            if self.stalled {
                return Ok(());
            }
            if self.lag != 0 {
                self.lag -= 1;
                return Ok(());
            }
            while let Some((lane, frame)) = self.inflight.pop_front() {
                if self.corrupt {
                    self.corrupt = false;
                    let mut changed = frame.to_vec();
                    // The envelope stays intact and the payload does not, which
                    // is the corruption a length check alone would miss.
                    changed.pop();
                    self.arrived.push_back((lane, shared_payload(&changed)));
                } else {
                    self.arrived.push_back((lane, frame));
                }
            }
            Ok(())
        }

        fn poll_received(&mut self) -> Option<Event> {
            if self.disconnect {
                self.disconnect = false;
                return Some(Event::Disconnected(vot_transport_api::ConnectionId(1)));
            }
            self.arrived
                .pop_front()
                .map(|(lane, bytes)| Event::Reliable {
                    stream: lane,
                    sequence: 0,
                    bytes,
                })
        }

        fn drain_sent(&mut self) {
            self.undrained = 0;
        }

        fn wait(&mut self, bound: std::time::Duration) {
            if let Ok(mut waited) = self.waited.lock() {
                waited.push(bound);
            }
            // The bound is really spent, as on every carrier: the ranged
            // spine budgets rounds on the assumption that an idle round costs
            // time, and a free wait would burn the budget before a producer
            // thread ever ran.
            std::thread::sleep(bound);
        }
    }

    /// The delivery budget a test gives a carrier. Generous enough that a
    /// healthy transfer of the sizes here finishes well inside it, and small
    /// enough that a carrier which stops is reported at once.
    const TEST_BUDGET: u64 = 64;

    fn ranged_case(object_bytes: u64, workers: usize, suite: Suite) -> Config {
        let mut config = case(object_bytes, suite);
        config.workers = workers;
        config
    }

    #[test]
    fn a_ranged_case_verifies_over_the_simulator_for_both_suites() {
        // Ragged on both edges: a short final record and a short final group,
        // split across workers whose slabs do not divide evenly. Delivery is
        // what the case asserts; the object arriving at all proves the frames,
        // the proofs, and the mid-object sources all agree.
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for workers in [2_usize, 4] {
                let object_bytes = 7 * 65_536 + 17;
                let measured = measure(&ranged_case(object_bytes, workers, suite)).unwrap();
                assert_eq!(measured.verified_bytes, object_bytes);
                assert_eq!(measured.bytes_sent, object_bytes);
                assert_eq!(note_field_text(&measured.notes, "path"), "ranged");
                assert_eq!(note_field(&measured.notes, "workers"), workers as u64);
                // The envelope, the CBOR map, and the proof are all on the
                // wire and none of them is the object.
                assert!(note_field(&measured.notes, "wire_bytes") > object_bytes);
                // One shared carrier is not the provisioned arrangement.
                assert!(!measured.notes.contains(";rails="));
                // Counted or refused, the field is always named.
                assert!(measured.notes.contains(";cycles="));
            }
        }
    }

    #[test]
    fn the_notes_always_name_the_cycle_field() {
        let mut counted = String::from("x");
        note_cycles(&mut counted, Some(5));
        assert_eq!(counted, "x;cycles=5");
        let mut refused = String::from("x");
        note_cycles(&mut refused, None);
        assert_eq!(refused, "x;cycles=unmeasured");
    }

    #[test]
    fn a_ranged_transfer_spends_its_whole_budget_before_stalling() {
        // Worker threads make rounds-to-completion timing-dependent, so the
        // edge is pinned from the stalling side, which is exact: a carrier
        // that refuses every submission makes every round idle, five budgeted
        // rounds wait five times, and the sixth check is the stall. A bound
        // that fired one round early would wait one time fewer.
        let config = ranged_case(2 * 65_536, 2, Suite::Blake3Bao64);
        let mut carrier = TestCarrier::new();
        carrier.refuse = usize::MAX;
        let waited = std::sync::Arc::clone(&carrier.waited);
        assert!(matches!(
            transfer_ranged(&config, vec![carrier], 5),
            Err(Error::Stalled)
        ));
        assert_eq!(waited.lock().unwrap().len(), 5);
    }

    #[test]
    fn the_rails_variable_names_the_arrangement_and_defaults_to_shared() {
        assert_eq!(parse(&environment()).unwrap().rails, Rails::Shared);
        assert_eq!(
            parse_with("VOT_BENCH_RAILS", "shared").unwrap().rails,
            Rails::Shared
        );
        assert!(matches!(
            parse_with("VOT_BENCH_RAILS", "braided"),
            Err(Error::Value("VOT_BENCH_RAILS"))
        ));
        // Provisioned rails need workers to provision for.
        let mut variables = environment();
        variables.insert("VOT_BENCH_RAILS".to_owned(), "provisioned".to_owned());
        assert!(matches!(
            parse(&variables),
            Err(Error::Value("VOT_BENCH_RAILS"))
        ));
        variables.insert("VOT_BENCH_WORKERS".to_owned(), "2".to_owned());
        assert_eq!(parse(&variables).unwrap().rails, Rails::Provisioned);
        // Junk at a worker count that could provision, so the rejection is
        // the spelling's and not the one-worker rule's.
        variables.insert("VOT_BENCH_RAILS".to_owned(), "braided".to_owned());
        assert!(matches!(
            parse(&variables),
            Err(Error::Value("VOT_BENCH_RAILS"))
        ));
    }

    #[test]
    fn a_provisioned_case_reaches_measure_with_a_rail_per_worker() {
        // Through measure() rather than transfer_ranged directly, so the
        // carrier construction itself is what the test pins.
        let mut config = ranged_case(4 * 65_536, 2, Suite::Blake3Bao64);
        config.rails = Rails::Provisioned;
        let measured = measure(&config).unwrap();
        assert_eq!(measured.verified_bytes, 4 * 65_536);
        assert!(measured.notes.contains(";rails=provisioned-multi-rail"));
    }

    #[test]
    fn a_provisioned_multi_rail_case_carries_each_worker_on_its_own_carrier() {
        let first = TestCarrier::new();
        let second = TestCarrier::new();
        let first_lanes = std::sync::Arc::clone(&first.lanes);
        let second_lanes = std::sync::Arc::clone(&second.lanes);
        let config = ranged_case(4 * 65_536, 2, Suite::Blake3Bao64);
        let measured = transfer_ranged(&config, vec![first, second], TEST_BUDGET).unwrap();
        assert_eq!(measured.verified_bytes, 4 * 65_536);
        assert!(measured.notes.contains(";rails=provisioned-multi-rail"));
        // The test double models everything, so the note must not claim
        // otherwise.
        assert!(!measured.notes.contains("unmodelled_impairment"));
        // Each worker rides the transfer lane of a rail of its own.
        for lanes in [first_lanes, second_lanes] {
            let seen: std::collections::BTreeSet<StreamId> =
                lanes.lock().unwrap().iter().copied().collect();
            assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![StreamId(1)]);
        }
    }

    #[test]
    fn a_ranged_transfer_reports_every_bundle_it_verified() {
        // 7 groups over 2 workers is slabs of 4 and 3 groups; at one-group
        // records and 16-record bundles that is one bundle each. The exact
        // count pins the schedule, not just its total.
        let measured = measure(&ranged_case(7 * 65_536, 2, Suite::Blake3Bao64)).unwrap();
        assert_eq!(note_field(&measured.notes, "bundles"), 2);
        // 40 groups over 2 workers: 20 groups each is two bundles each.
        let measured = measure(&ranged_case(40 * 65_536, 2, Suite::Blake3Bao64)).unwrap();
        assert_eq!(note_field(&measured.notes, "bundles"), 4);
    }

    #[test]
    fn a_prover_refuses_a_cover_wider_than_the_request() {
        // A group-unaligned length keeps the offset exact while the cover
        // widens; the widened cover must be refused, not returned.
        let config = ranged_case(2 * 65_536, 2, Suite::Blake3Bao64);
        let (_, layer) = super::prover_layer_and_subject(&config).unwrap();
        assert!(super::prove_range(&layer, 0, 100).is_err());
        assert!(super::prove_range(&layer, 0, 65_536).is_ok());
    }

    #[test]
    fn a_ranged_case_survives_reordering_and_case_a_multiplexes_lanes() {
        let mut config = ranged_case(6 * 65_536, 3, Suite::Blake3Bao64);
        config.impairment.reorder_window = 4;
        let measured = measure(&config).unwrap();
        assert_eq!(measured.verified_bytes, 6 * 65_536);

        // The one-connection case puts each worker on its own lane; a
        // transfer that serialized every worker onto one lane would measure
        // the driver's queue, not the connection's spine.
        let carrier = TestCarrier::new();
        let lanes = std::sync::Arc::clone(&carrier.lanes);
        let config = ranged_case(4 * 65_536, 2, Suite::Blake3Bao64);
        transfer_ranged(&config, vec![carrier], TEST_BUDGET).unwrap();
        let seen: std::collections::BTreeSet<StreamId> =
            lanes.lock().unwrap().iter().copied().collect();
        assert_eq!(
            seen.into_iter().collect::<Vec<_>>(),
            vec![StreamId(1), StreamId(2)]
        );
    }

    #[test]
    fn ranged_backpressure_lag_and_stall_keep_the_sequential_verdicts() {
        // A refusal is backpressure and costs rounds, not the transfer.
        let mut carrier = TestCarrier::new();
        carrier.refuse = 4;
        let config = ranged_case(2 * 65_536, 2, Suite::Blake3Bao64);
        let measured = transfer_ranged(&config, vec![carrier], TEST_BUDGET).unwrap();
        assert_eq!(measured.verified_bytes, 2 * 65_536);
        assert!(note_field(&measured.notes, "backpressure_waits") != 0);

        // Late delivery is waited out.
        let mut late = TestCarrier::new();
        late.lag = 3;
        let measured = transfer_ranged(&config, vec![late], TEST_BUDGET).unwrap();
        assert_eq!(measured.verified_bytes, 2 * 65_536);

        // A carrier that stops is stalled, never a partial number.
        let mut dead = TestCarrier::new();
        dead.stalled = true;
        assert!(matches!(
            transfer_ranged(&config, vec![dead], TEST_BUDGET),
            Err(Error::Stalled)
        ));

        // A disconnect is its own verdict.
        let mut gone = TestCarrier::new();
        gone.disconnect = true;
        assert!(matches!(
            transfer_ranged(&config, vec![gone], TEST_BUDGET),
            Err(Error::Disconnected)
        ));

        // A changed frame is corruption, found at decode rather than trusted.
        let mut lying = TestCarrier::new();
        lying.corrupt = true;
        assert!(matches!(
            transfer_ranged(&config, vec![lying], TEST_BUDGET),
            Err(Error::Corrupt)
        ));
    }

    #[test]
    fn the_ranged_paths_carrier_count_must_fit_its_workers() {
        // Two carriers for three workers is neither one shared nor one each.
        let config = ranged_case(6 * 65_536, 3, Suite::Blake3Bao64);
        let carriers = vec![TestCarrier::new(), TestCarrier::new()];
        assert!(matches!(
            transfer_ranged(&config, carriers, TEST_BUDGET),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn ranged_record_bytes_takes_whole_groups_only() {
        let config = ranged_case(4 * 65_536, 2, Suite::Blake3Bao64);
        assert_eq!(super::ranged_record_bytes(&config).unwrap(), 65_536);
        for bad in [0_usize, 1_000, 65_535, 65_537, 4 * 65_536] {
            let mut wrong = config.clone();
            wrong.record_bytes = bad;
            assert!(
                super::ranged_record_bytes(&wrong).is_err(),
                "{bad} was accepted"
            );
        }
        let mut three = config;
        three.record_bytes = 3 * 65_536;
        assert_eq!(super::ranged_record_bytes(&three).unwrap(), 3 * 65_536);
    }

    #[test]
    fn ranged_staging_holds_the_object_it_retains() {
        // The range path keeps every verified range until the object is
        // whole, so the limit is the object plus the verifier reservation,
        // exactly. Pinned by value because nothing else observes an
        // over-generous limit.
        let config = ranged_case(7 * 65_536 + 17, 2, Suite::Blake3Bao64);
        assert_eq!(
            super::ranged_staging_limit(&config),
            7 * 65_536 + 17 + 65_536
        );
    }

    #[test]
    fn a_bundle_identifier_is_its_inputs_in_order() {
        let id = super::bundle_identifier(0x0102_0304_0506_0708, 9, 10);
        assert_eq!(&id[..8], &0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(&id[8..12], &9_u32.to_le_bytes());
        assert_eq!(&id[12..], &10_u32.to_le_bytes());
    }

    #[test]
    fn a_source_started_mid_object_continues_the_same_object() {
        // A range worker's bytes must be the sequential object's bytes at that
        // offset, or worker count would change the object and no two runs
        // would be comparable. Checked word for word against the sequential
        // source across seeds and offsets, including zero.
        for seed in [0, 42, u64::MAX] {
            let mut reference = ObjectSource::new(seed);
            let words: Vec<u64> = (0..40_960).map(|_| reference.draw()).collect();
            for offset_words in [0_usize, 1, 3, 8_192, 5 * 65_536 / 8] {
                let mut jumped =
                    ObjectSource::at(seed, (offset_words * super::WORD_BYTES) as u64).unwrap();
                for (index, expected) in words.iter().enumerate().skip(offset_words).take(64) {
                    assert_eq!(
                        jumped.draw(),
                        *expected,
                        "seed {seed}, offset {offset_words}, word {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_jump_composes_and_a_misaligned_one_is_refused() {
        // Composition is what pins the high bits of the exponent: two jumps
        // must land where one jump of their sum does, at counts far past what
        // a sequential check can reach.
        for (first, second) in [(1_u64 << 33, 1_u64 << 21), (12_345, 67_890_123)] {
            let one = super::advance(42, first.wrapping_add(second));
            let two = super::advance(super::advance(42, first), second);
            assert_eq!(one, two);
        }
        // Zero draws is the identity, which square-and-multiply must not
        // disturb.
        assert_eq!(super::advance(97, 0), 97);
        // A misaligned byte offset would generate a different object than the
        // sequential path, so it is an error rather than a rounding.
        assert!(ObjectSource::at(42, 3).is_err());
    }

    #[test]
    fn worker_slabs_cover_the_object_exactly_and_stay_aligned() {
        for (object_bytes, workers) in [
            (65_536_u64, 1_usize),
            (2 * 65_536, 2),
            (7 * 65_536 + 17, 3),
            (8 * 65_536, 3),
            (65_537, 1),
        ] {
            let ranges = super::worker_ranges(object_bytes, workers).unwrap();
            assert_eq!(ranges.len(), workers);
            let mut expected_offset = 0_u64;
            for range in &ranges {
                assert_eq!(range.offset, expected_offset, "slabs are contiguous");
                assert_eq!(range.offset % super::GROUP_BYTES, 0, "slabs stay aligned");
                assert!(range.bytes > 0, "no worker is left with nothing");
                expected_offset += range.bytes;
            }
            assert_eq!(expected_offset, object_bytes, "slabs cover the object");
        }
        // The leading workers take the remainder groups, one each, so the
        // exact split is pinned rather than only its total.
        let ranges = super::worker_ranges(7 * 65_536, 3).unwrap();
        let bytes: Vec<u64> = ranges.iter().map(|range| range.bytes).collect();
        assert_eq!(bytes, vec![3 * 65_536, 2 * 65_536, 2 * 65_536]);
    }

    #[test]
    fn more_workers_than_groups_is_an_error_not_a_smaller_case() {
        assert!(matches!(
            super::worker_ranges(2 * 65_536, 3),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            super::worker_ranges(65_536, 0),
            Err(Error::Unsupported(_))
        ));
        // One group, one worker is the smallest honest case.
        assert!(super::worker_ranges(1, 1).is_ok());
    }

    #[test]
    fn the_wait_backs_off_from_the_short_end_and_stops_at_the_long_one() {
        // The first wait is the shortest, so a small object is not padded by a
        // millisecond it did not need, and the last is the longest, so a long
        // transfer reaches the interval where the driver is out of the
        // carrier's way. Both ends are pinned because the measured throughput
        // of every carrier depends on them.
        assert_eq!(super::idle_wait(1), super::IDLE_WAIT_MIN);
        assert_eq!(super::idle_wait(2), super::IDLE_WAIT_MIN * 2);
        assert_eq!(
            super::idle_wait(1 + u64::from(super::IDLE_WAIT_DOUBLINGS)),
            super::IDLE_WAIT_MAX
        );
        // Past the last doubling it stays there rather than growing, including
        // at a count no transfer reaches. The wait is what bounds how long the
        // round budget can take, so it must have a ceiling at every input.
        for waits in [2 + u64::from(super::IDLE_WAIT_DOUBLINGS), 1_000, u64::MAX] {
            assert_eq!(super::idle_wait(waits), super::IDLE_WAIT_MAX);
        }
        // A count of zero never reaches the wait, but it must not be longer
        // than the first one if it ever does.
        assert_eq!(super::idle_wait(0), super::IDLE_WAIT_MIN);
    }

    #[test]
    fn idle_deliveries_wait_on_the_carrier_at_the_backed_off_bound() {
        // The wait goes through the carrier, where a backend with a wakeup
        // signal can end it early, and each bound follows the backoff. A
        // driver that slept on its own instead would reintroduce the polling
        // interval as a property of every published number.
        let mut carrier = TestCarrier::new();
        carrier.lag = 3;
        let waited = std::sync::Arc::clone(&carrier.waited);
        let config = case(2 * 65_536, Suite::Blake3Bao64);
        transfer_within(&config, carrier, TEST_BUDGET).unwrap();
        assert_eq!(
            *waited.lock().unwrap(),
            vec![super::idle_wait(1), super::idle_wait(2)]
        );
    }

    #[test]
    fn the_simulator_wait_costs_the_bound() {
        // The simulator never has anything to signal, so its wait must cost
        // real time: it is what bounds the round budget's wall clock when a
        // transfer is stalled, and a free wait would turn that budget into a
        // spin.
        let mut carrier = SimulatorCarrier::new(&case(65_536, Suite::Blake3Bao64)).unwrap();
        let bound = std::time::Duration::from_millis(30);
        let started = std::time::Instant::now();
        carrier.wait(bound);
        assert!(started.elapsed() >= bound);
    }

    #[test]
    fn the_wait_does_not_start_over_when_a_delivery_moves_something() {
        // The count is the transfer's total, so a burst of records does not put
        // the driver back into the short waits that measure a slower carrier.
        // A carrier that lags, delivers, and lags again is still waited on at
        // the interval the transfer has reached.
        let mut carrier = TestCarrier::new();
        carrier.lag = 3;
        let config = case(2 * 65_536, Suite::Blake3Bao64);
        let measured = transfer_within(&config, carrier, TEST_BUDGET).unwrap();
        assert_eq!(measured.verified_bytes, 2 * 65_536);
        // Three lagging deliveries: the batch flush that closes the submission
        // loop takes the first and is not a wait, and the completion loop takes
        // the other two before the records are released. Exact rather than a
        // floor, because the count is what chooses every wait's length.
        assert_eq!(note_field(&measured.notes, "idle_waits"), 2);
    }

    #[test]
    fn a_backpressured_transfer_that_needs_its_whole_budget_is_not_called_stalled() {
        // The submission loop keeps its own bound, so its edge has to be pinned
        // separately from the completion loop's. Four refusals need four
        // rounds: a budget of four is exactly enough and three is exactly too
        // little. A bound that fired one round early would fail a transfer
        // whose carrier was applying backpressure rather than stopping.
        let config = case(65_536, Suite::Blake3Bao64);
        let mut carrier = TestCarrier::new();
        carrier.refuse = 4;
        let measured = transfer_within(&config, carrier, 4).unwrap();
        assert_eq!(measured.verified_bytes, 65_536);
        assert_eq!(note_field(&measured.notes, "backpressure_waits"), 4);

        let mut same = TestCarrier::new();
        same.refuse = 4;
        assert!(matches!(
            transfer_within(&config, same, 3),
            Err(Error::Stalled)
        ));
    }

    #[test]
    fn the_budget_is_per_record_above_its_floor_and_the_floor_below_it() {
        // What a real run is given, which no test that names its own budget
        // exercises. Too small a budget calls a healthy carrier stopped, and
        // too large a one makes a stopped carrier take as long to report as a
        // gigabyte takes to carry.
        let config = case(64 * 65_536, Suite::Blake3Bao64);
        assert_eq!(super::round_budget(&config), 64 * super::ROUNDS_PER_RECORD);

        // A short final record still needs deliveries of its own.
        let ragged = case(64 * 65_536 + 1, Suite::Blake3Bao64);
        assert_eq!(super::round_budget(&ragged), 65 * super::ROUNDS_PER_RECORD);

        // Under the floor, the floor. One record over a real socket takes more
        // deliveries than one, so the per-record term alone would call a
        // healthy carrier stopped.
        let small = case(1, Suite::Blake3Bao64);
        assert_eq!(super::round_budget(&small), super::MIN_ROUNDS);
    }

    /// The floor is a floor: below it the per-record term would decide, and one
    /// record over a real socket takes more deliveries than that.
    const _: () = assert!(super::MIN_ROUNDS > super::ROUNDS_PER_RECORD);

    #[test]
    fn a_transfer_that_needs_its_whole_budget_is_not_called_stalled() {
        // One record, and a carrier that releases it one delivery late. The
        // completion loop therefore needs exactly one delivery, so a budget of
        // one is exactly enough and a budget of none is exactly too little.
        // Between them they pin the edge: a bound that fired one delivery early
        // would fail a transfer that had not stopped.
        let config = case(65_536, Suite::Blake3Bao64);
        let mut carrier = TestCarrier::new();
        carrier.lag = 1;
        assert_eq!(
            transfer_within(&config, carrier, 1).unwrap().verified_bytes,
            65_536
        );

        let mut same = TestCarrier::new();
        same.lag = 1;
        assert!(matches!(
            transfer_within(&config, same, 0),
            Err(Error::Stalled)
        ));
    }

    #[test]
    fn waiting_on_the_carrier_is_counted_and_not_waiting_is_counted_as_none() {
        // The simulator delivers before flush returns, so no delivery of a
        // healthy run finds nothing and the driver never waits. A run that
        // reported waits here would be waiting on itself.
        let measured = measure(&case(4 * 65_536, Suite::Blake3Bao64)).unwrap();
        assert_eq!(note_field(&measured.notes, "idle_waits"), 0);

        // A carrier that releases late is one the driver waits on, and the
        // difference between the two is what the field is for.
        let mut lagging = TestCarrier::new();
        lagging.lag = 3;
        let waited =
            transfer_within(&case(65_536, Suite::Blake3Bao64), lagging, TEST_BUDGET).unwrap();
        assert!(
            note_field(&waited.notes, "idle_waits") >= 2,
            "{}",
            waited.notes
        );
    }

    #[test]
    fn a_refused_submission_is_backpressure_and_the_record_is_offered_again() {
        let mut carrier = TestCarrier::new();
        // Every record refused once, so the retry path runs for each of them
        // and none of them is lost by it.
        carrier.refuse = 4;
        let config = case(4 * 65_536, Suite::Blake3Bao64);
        let measured = transfer_within(&config, carrier, TEST_BUDGET).unwrap();
        assert_eq!(measured.verified_bytes, 4 * 65_536);
        assert_eq!(measured.bytes_sent, 4 * 65_536);
        assert_eq!(note_field(&measured.notes, "backpressure_waits"), 4);
    }

    #[test]
    fn a_carrier_that_delivers_late_is_waited_out() {
        let mut carrier = TestCarrier::new();
        // Nothing arrives until well after the last record is submitted, so the
        // completion loop is what finishes the object.
        carrier.lag = 8;
        let config = case(2 * 65_536, Suite::Blake3Bao64);
        let measured = transfer_within(&config, carrier, TEST_BUDGET).unwrap();
        assert_eq!(measured.verified_bytes, 2 * 65_536);
    }

    #[test]
    fn a_carrier_that_stops_is_an_error_not_a_partial_result() {
        let mut carrier = TestCarrier::new();
        carrier.stalled = true;
        let config = case(65_536, Suite::Blake3Bao64);
        assert!(matches!(
            transfer_within(&config, carrier, TEST_BUDGET),
            Err(Error::Stalled)
        ));

        // A carrier that refuses every submission and delivers nothing stalls
        // in the other loop, which has its own bound to reach.
        let mut refusing = TestCarrier::new();
        refusing.refuse = usize::MAX;
        refusing.stalled = true;
        assert!(matches!(
            transfer_within(&config, refusing, TEST_BUDGET),
            Err(Error::Stalled)
        ));
    }

    #[test]
    fn a_carrier_that_reports_the_connection_gone_says_so_at_once() {
        // Waiting out the stall bound would report a slow carrier where the
        // truth is a broken one, and the run would take thirty seconds to say
        // the wrong thing.
        let mut carrier = TestCarrier::new();
        carrier.disconnect = true;
        let config = case(65_536, Suite::Blake3Bao64);
        assert!(matches!(
            transfer_within(&config, carrier, TEST_BUDGET),
            Err(Error::Disconnected)
        ));
    }

    #[test]
    fn a_record_that_came_back_changed_is_refused() {
        let mut carrier = TestCarrier::new();
        carrier.corrupt = true;
        let config = case(65_536, Suite::Blake3Bao64);
        // Truncated inside the envelope, so the frame no longer accounts for
        // what was delivered. Accepting it would verify against bytes the
        // sender never sent.
        assert!(matches!(
            transfer_within(&config, carrier, TEST_BUDGET),
            Err(Error::Corrupt)
        ));
    }

    #[test]
    fn only_a_frame_that_is_exactly_one_data_record_is_unwrapped() {
        let mut framed = Vec::new();
        vot_codec::encode_frame(vot_codec::frame_type::DATA_RECORD, b"payload", &mut framed)
            .unwrap();
        assert_eq!(record_payload(&framed).unwrap(), b"payload");

        // Nothing at all, a truncated frame, and a frame with a second one
        // behind it are all deliveries this transfer never made.
        assert!(matches!(record_payload(&[]), Err(Error::Corrupt)));
        assert!(matches!(
            record_payload(&framed[..framed.len() - 1]),
            Err(Error::Corrupt)
        ));
        let mut two = framed.clone();
        two.extend_from_slice(&framed);
        assert!(matches!(record_payload(&two), Err(Error::Corrupt)));

        // A control frame is a frame this lane does not carry.
        let mut control = Vec::new();
        vot_codec::encode_frame(vot_codec::frame_type::SETTINGS, b"x", &mut control).unwrap();
        assert!(matches!(record_payload(&control), Err(Error::Corrupt)));
    }

    #[test]
    fn the_credit_the_report_names_is_the_one_that_was_enforced() {
        let config = case(65_536, Suite::Blake3Bao64);

        // A carrier that applies the credit says so.
        let measured = transfer_within(&config, TestCarrier::new(), TEST_BUDGET).unwrap();
        assert_eq!(note_field_text(&measured.notes, "credit_mode"), "set");

        // One that bounds its inbound at construction reports Unsupported
        // rather than accepting a credit it would not apply, and the report
        // records which of the two happened rather than implying the first.
        let mut constructed = TestCarrier::new();
        constructed.endpoint = CreditEndpoint(Err(vot_transport_api::Error::Unsupported));
        let measured = transfer_within(&config, constructed, TEST_BUDGET).unwrap();
        assert_eq!(
            note_field_text(&measured.notes, "credit_mode"),
            "constructed"
        );
        // Either way the number is the receiver's own advertised credit, which
        // the receiver enforces by refusing staging past it.
        assert_eq!(note_field(&measured.notes, "credit_bytes"), 1_250_000);

        // Any other refusal is a backend failure rather than a mode.
        let mut refused = TestCarrier::new();
        refused.endpoint = CreditEndpoint(Err(vot_transport_api::Error::InvalidConfiguration));
        assert!(matches!(
            transfer_within(&config, refused, TEST_BUDGET),
            Err(Error::Transport(
                vot_transport_api::Error::InvalidConfiguration
            ))
        ));
    }

    #[test]
    fn the_sender_events_are_drained_so_they_cannot_become_the_ceiling() {
        // A sender reports acknowledgements and connection state this transfer
        // never reads. Left queued they fill the backend's bound and it starts
        // refusing submissions, so the run would stop for a reason that has
        // nothing to do with the object or the carrier. The double refuses once
        // its sender queue is full and clears it only when the driver drains,
        // so a transfer that completes is a transfer that drained: more records
        // than the queue holds went through it.
        let object_bytes = DRAIN_TEST_RECORDS as u64 * 65_536;
        let config = case(object_bytes, Suite::Blake3Bao64);
        let measured = transfer_within(&config, TestCarrier::new(), TEST_BUDGET).unwrap();
        assert_eq!(measured.verified_bytes, object_bytes);
    }

    #[test]
    fn what_the_carrier_moved_is_reported_apart_from_the_object() {
        let config = case(4 * 65_536, Suite::Blake3Bao64);
        let measured = measure(&config).unwrap();
        // The envelope is on the wire and is not part of the object, so a
        // reader can see the difference rather than assuming there is none.
        let wire = note_field(&measured.notes, "wire_bytes");
        assert!(wire > 4 * 65_536, "wire was {wire}");
        assert!(wire < 4 * 65_536 + 4 * 64, "wire was {wire}");
        assert_eq!(measured.bytes_sent, 4 * 65_536);
    }

    #[test]
    fn every_note_is_a_named_value() {
        // `notes` is read by people and by scripts, and both take it as
        // semicolon-separated name=value. A carrier that has nothing extra to
        // say adds nothing, rather than an empty field or a bare word that
        // neither can interpret.
        let measured = measure(&case(65_536, Suite::Blake3Bao64)).unwrap();
        for field in measured.notes.split(';') {
            assert!(
                field
                    .split_once('=')
                    .is_some_and(|(name, _)| !name.is_empty()),
                "{field:?} is not a named value in {}",
                measured.notes
            );
        }
    }

    #[test]
    fn a_case_verifies_exactly_the_object_it_was_given() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for object_bytes in [1, 65_536, 196_608, 1_048_577] {
                let config = case(object_bytes, suite);
                let measured = measure(&config).unwrap();
                assert_eq!(measured.verified_bytes, object_bytes);
                assert_eq!(measured.bytes_sent, object_bytes);
                assert!(measured.elapsed_ns >= 1);
                assert_eq!(measured.cycles, None);
                // The carrier names itself in the result. A report that
                // attributed a run to the wrong backend would be worse than no
                // report, and this is the only place the name is written.
                assert_eq!(note_field_text(&measured.notes, "backend"), "simulator");
            }
        }
    }

    fn note_field(notes: &str, name: &str) -> u64 {
        note_field_text(notes, name)
            .parse()
            .unwrap_or_else(|_| panic!("{name} is not a number in {notes}"))
    }

    fn note_field_text<'a>(notes: &'a str, name: &str) -> &'a str {
        notes
            .split(';')
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} in {notes}"))
    }

    #[test]
    fn submissions_are_flushed_in_bounded_batches() {
        // Seventeen records at a batch of sixteen: one full batch, then the
        // closing flush for the record left over.
        let config = case(17 * 65_536, Suite::Blake3Bao64);
        assert_eq!(note_field(&measure(&config).unwrap().notes, "flushes"), 2);

        // An exact multiple of the batch needs no closing flush.
        let exact = case(16 * 65_536, Suite::Blake3Bao64);
        assert_eq!(note_field(&measure(&exact).unwrap().notes, "flushes"), 1);

        // Under one batch there is only the closing flush.
        let short = case(3 * 65_536, Suite::Blake3Bao64);
        assert_eq!(note_field(&measure(&short).unwrap().notes, "flushes"), 1);
    }

    #[test]
    fn generation_cost_is_reported_so_it_can_be_subtracted() {
        // Generating the object is inside the timed section, so a reader has to
        // be able to see how much of elapsed_ns it was.
        let measured = measure(&case(4 * 1_048_576, Suite::Blake3Bao64)).unwrap();
        let generator_ns = note_field(&measured.notes, "generator_ns");
        // Four mebibytes of xorshift is hundreds of microseconds even on fast
        // hardware, so ten is a floor no real measurement can fall through and
        // no constant can climb over.
        assert!(
            generator_ns > 10_000,
            "generation was reported as {generator_ns} ns"
        );
        // Deliberately no comparison against elapsed_ns. They are two separate
        // timed passes over the same work, so which is larger depends on how
        // loaded the machine is, and asserting an order made this flaky under
        // CI load rather than testing anything.
        assert!(measured.elapsed_ns >= 1);
    }

    #[test]
    fn peak_staging_does_not_track_object_size() {
        let small = measure(&case(1_048_576, Suite::Blake3Bao64)).unwrap();
        let large = measure(&case(16_777_216, Suite::Blake3Bao64)).unwrap();
        let peak_of = |notes: &str| {
            notes
                .split(';')
                .find_map(|field| field.strip_prefix("staging_peak_bytes="))
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap()
        };
        // Sixteen times the object, and the receiver holds the same window.
        assert_eq!(peak_of(&small.notes), peak_of(&large.notes));
    }

    #[test]
    fn the_same_seed_produces_the_same_object() {
        let mut first = ObjectSource::new(7);
        let mut second = ObjectSource::new(7);
        let mut other = ObjectSource::new(8);
        let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
        let mut differs = false;
        for take in record_lengths(300_000, 65_536).unwrap() {
            first.fill(&mut a, take);
            second.fill(&mut b, take);
            other.fill(&mut c, take);
            assert_eq!(a, b);
            differs |= a != c;
        }
        assert!(differs, "a different seed produced the same object");
    }

    #[test]
    fn the_record_schedule_ends_short_rather_than_padded() {
        let lengths = |object, record| record_lengths(object, record).unwrap().collect::<Vec<_>>();
        assert_eq!(lengths(65_537, 65_536), vec![65_536, 1]);
        assert_eq!(lengths(65_536, 65_536), vec![65_536]);
        assert_eq!(lengths(65_535, 65_536), vec![65_535]);
        assert_eq!(lengths(1, 65_536), vec![1]);
        assert_eq!(lengths(3 * 65_536, 65_536), vec![65_536; 3]);
        assert_eq!(lengths(196_609, 65_536), vec![65_536, 65_536, 65_536, 1]);
        // Nothing to send is an empty schedule, not one empty record.
        assert_eq!(lengths(0, 65_536), Vec::<usize>::new());
        assert_eq!(lengths(300_000, 65_536).iter().sum::<usize>(), 300_000);
    }

    #[test]
    fn an_unimplemented_case_is_an_error_not_a_number() {
        // `tcp` is a backend the result schema allows and this driver has no
        // carrier for, under any feature. It used to be `msquic`, which stopped
        // being an example of an unimplemented backend once one was built.
        let mut backend = case(65_536, Suite::Blake3Bao64);
        backend.backend = "tcp".to_owned();
        assert!(matches!(measure(&backend), Err(Error::Unsupported(_))));

        // A name no schema allows either, so the arm is what refuses both
        // rather than a list of known backends that happens to be complete.
        let mut unknown = case(65_536, Suite::Blake3Bao64);
        unknown.backend = "carrier-pigeon".to_owned();
        assert!(matches!(measure(&unknown), Err(Error::Unsupported(_))));

        let mut workers = case(65_536, Suite::Blake3Bao64);
        workers.workers = 4;
        assert!(matches!(measure(&workers), Err(Error::Unsupported(_))));
    }

    #[test]
    fn reordering_is_taken_from_the_impairment_and_bounded() {
        let mut reordered = case(196_608, Suite::Blake3Bao64);
        reordered.impairment.reorder_window = 2;
        // One stream is never reordered against itself, so the run is identical
        // to reorder_window 0 and has to say so.
        let measured = measure(&reordered).unwrap();
        assert_eq!(measured.verified_bytes, 196_608);
        let unmodelled = measured
            .notes
            .split(';')
            .find_map(|field| field.strip_prefix("unmodelled_impairment="))
            .unwrap();
        assert!(unmodelled.contains("reorder_window"), "{unmodelled}");
        // With no reordering asked for there is nothing to disclaim.
        let clean = measure(&case(196_608, Suite::Blake3Bao64)).unwrap().notes;
        let clean_unmodelled = clean
            .split(';')
            .find_map(|field| field.strip_prefix("unmodelled_impairment="))
            .unwrap();
        assert!(!clean_unmodelled.contains("reorder_window"));

        let mut excessive = case(65_536, Suite::Blake3Bao64);
        excessive.impairment.reorder_window = 65;
        assert!(matches!(measure(&excessive), Err(Error::Value(_))));
    }

    #[test]
    fn the_reorder_window_reaches_the_simulator_and_stops_at_its_ceiling() {
        let mut config = case(65_536, Suite::Blake3Bao64);
        for window in [0, 1, 7, vot_transport_sim::MAX_REORDER_DEPTH as u64] {
            config.impairment.reorder_window = window;
            let (impairment, _) = super::simulator_impairment(&config).unwrap();
            assert_eq!(impairment.reorder_depth as u64, window);
        }
        config.impairment.reorder_window = vot_transport_sim::MAX_REORDER_DEPTH as u64 + 1;
        assert!(matches!(
            super::simulator_impairment(&config),
            Err(Error::Value("VOT_BENCH_IMPAIRMENT_REORDER_WINDOW"))
        ));
    }

    #[test]
    fn unmodelled_impairment_fields_are_named() {
        let mut lossy = case(65_536, Suite::Blake3Bao64);
        lossy.impairment.loss_ppm = 100;
        let notes = measure(&lossy).unwrap().notes;
        let unmodelled = notes
            .split(';')
            .find_map(|field| field.strip_prefix("unmodelled_impairment="))
            .unwrap();
        assert!(unmodelled.contains("loss_ppm"));
        assert!(unmodelled.contains("bandwidth_bps"));
        assert!(unmodelled.contains("queue_bytes"));
        assert!(unmodelled.contains("mtu_bytes"));
        // The adapter delivers immediately, so no run waited out an RTT even
        // though the round-trip time did size the receive window.
        assert!(unmodelled.contains("rtt_us"));

        let mut instant = case(65_536, Suite::Blake3Bao64);
        instant.impairment.rtt_us = 0;
        let instant_notes = measure(&instant).unwrap().notes;
        let instant_unmodelled = instant_notes
            .split(';')
            .find_map(|field| field.strip_prefix("unmodelled_impairment="))
            .unwrap();
        assert!(!instant_unmodelled.contains("rtt_us"));

        let clean = measure(&case(65_536, Suite::Blake3Bao64)).unwrap().notes;
        let clean_unmodelled = clean
            .split(';')
            .find_map(|field| field.strip_prefix("unmodelled_impairment="))
            .unwrap();
        assert!(!clean_unmodelled.contains("loss_ppm"));
    }

    #[test]
    fn credit_follows_the_bandwidth_delay_product() {
        let config = case(65_536, Suite::Blake3Bao64);
        // 10 Gb/s for 1 ms is 1.25 MB.
        assert_eq!(config.bandwidth_delay_bytes(), 1_250_000);
        let notes = measure(&config).unwrap().notes;
        assert!(notes.contains("credit_bytes=1250000"), "{notes}");
    }

    #[test]
    fn the_emitted_object_matches_the_runner_contract() {
        let measurement = Measurement {
            bytes_sent: 7,
            verified_bytes: 7,
            elapsed_ns: 11,
            memory_high_water_bytes: 13,
            cycles: None,
            notes: "a\"b".to_owned(),
        };
        assert_eq!(
            measurement.to_json(),
            r#"{"bytes_sent":7,"verified_bytes":7,"elapsed_ns":11,"memory_high_water_bytes":13,"cycles":null,"notes":"a\"b"}"#
        );
        let with_cycles = Measurement {
            cycles: Some(5),
            notes: String::new(),
            ..measurement
        };
        assert!(with_cycles.to_json().contains(r#""cycles":5"#));
    }

    #[test]
    fn note_escaping_covers_quotes_backslashes_and_control_bytes() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a\"b"), "a\\\"b");
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("a\nb"), "a b");
    }

    /// The complete set of variables the runner sets, as strings.
    fn environment() -> BTreeMap<String, String> {
        [
            ("VOT_BENCH_BACKEND", "simulator"),
            ("VOT_BENCH_SUITE", "blake3-bao64"),
            ("VOT_BENCH_WORKERS", "1"),
            ("VOT_BENCH_SEED", "42"),
            ("VOT_BENCH_OBJECT_BYTES", "1048576"),
            ("VOT_BENCH_RECORD_BYTES", "65536"),
            ("VOT_BENCH_IMPAIRMENT_MTU_BYTES", "1500"),
            ("VOT_BENCH_IMPAIRMENT_RTT_US", "1000"),
            ("VOT_BENCH_IMPAIRMENT_LOSS_PPM", "0"),
            ("VOT_BENCH_IMPAIRMENT_REORDER_WINDOW", "0"),
            ("VOT_BENCH_IMPAIRMENT_BANDWIDTH_BPS", "10000000000"),
            ("VOT_BENCH_IMPAIRMENT_QUEUE_BYTES", "33554432"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
    }

    fn parse(variables: &BTreeMap<String, String>) -> Result<Config, Error> {
        Config::from_lookup(&|name| variables.get(name).cloned())
    }

    fn parse_with(name: &str, value: &str) -> Result<Config, Error> {
        let mut variables = environment();
        variables.insert(name.to_owned(), value.to_owned());
        parse(&variables)
    }

    fn parse_without(name: &str) -> Result<Config, Error> {
        let mut variables = environment();
        variables.remove(name);
        parse(&variables)
    }

    #[test]
    fn a_complete_environment_parses_into_the_case() {
        assert_eq!(
            parse(&environment()).unwrap(),
            case(1_048_576, Suite::Blake3Bao64)
        );
        assert_eq!(
            parse_with("VOT_BENCH_SUITE", "sha256-bep52").unwrap().suite,
            Suite::Sha256Bep52
        );
        assert_eq!(
            parse_with("VOT_BENCH_BACKEND", "msquic").unwrap().backend,
            "msquic"
        );
        let impairment = parse_with("VOT_BENCH_IMPAIRMENT_QUEUE_BYTES", "7")
            .unwrap()
            .impairment;
        assert_eq!(impairment.queue_bytes, 7);
    }

    #[test]
    fn every_variable_is_required_and_an_empty_value_is_absent() {
        for name in environment().keys() {
            assert!(
                matches!(parse_without(name), Err(Error::Environment(missing)) if missing == name),
                "{name} was not required"
            );
            assert!(
                matches!(parse_with(name, ""), Err(Error::Environment(empty)) if empty == name),
                "an empty {name} was accepted"
            );
        }
    }

    #[test]
    fn each_numeric_variable_rejects_a_non_number() {
        for name in environment()
            .keys()
            .filter(|name| *name != "VOT_BENCH_BACKEND" && *name != "VOT_BENCH_SUITE")
        {
            assert!(
                matches!(parse_with(name, "twelve"), Err(Error::Environment(bad)) if bad == name),
                "{name} accepted a non-number"
            );
        }
    }

    #[test]
    fn case_bounds_are_checked_at_their_exact_edges() {
        assert!(matches!(
            parse_with("VOT_BENCH_SUITE", "md5"),
            Err(Error::Value("VOT_BENCH_SUITE"))
        ));

        assert!(matches!(
            parse_with("VOT_BENCH_WORKERS", "0"),
            Err(Error::Value("VOT_BENCH_WORKERS"))
        ));
        assert_eq!(parse_with("VOT_BENCH_WORKERS", "1").unwrap().workers, 1);

        assert!(matches!(
            parse_with("VOT_BENCH_OBJECT_BYTES", "0"),
            Err(Error::Value("VOT_BENCH_OBJECT_BYTES"))
        ));
        assert_eq!(
            parse_with("VOT_BENCH_OBJECT_BYTES", "1")
                .unwrap()
                .object_bytes,
            1
        );

        assert!(matches!(
            parse_with("VOT_BENCH_RECORD_BYTES", "0"),
            Err(Error::Value("VOT_BENCH_RECORD_BYTES"))
        ));
        assert_eq!(
            parse_with("VOT_BENCH_RECORD_BYTES", "1")
                .unwrap()
                .record_bytes,
            1
        );
        let ceiling = vot_transport_api::MAX_DATA_RECORD_BYTES;
        assert_eq!(
            parse_with("VOT_BENCH_RECORD_BYTES", &ceiling.to_string())
                .unwrap()
                .record_bytes,
            ceiling
        );
        assert!(matches!(
            parse_with("VOT_BENCH_RECORD_BYTES", &(ceiling + 1).to_string()),
            Err(Error::Value("VOT_BENCH_RECORD_BYTES"))
        ));
    }

    #[test]
    fn generated_object_bytes_are_pinned_to_the_seed() {
        // The generator is arbitrary but must stay stable, or a seed stops
        // identifying an object and results from different builds stop being
        // comparable. These bytes are the change detector for that.
        let mut source = ObjectSource::new(0);
        let mut record = Vec::new();
        let mut seen = Vec::new();
        for take in record_lengths(24, 8).unwrap() {
            source.fill(&mut record, take);
            seen.push(hex(&record));
        }
        assert_eq!(
            seen,
            ["ad4df30bae771bdc", "76606e02b9eef064", "366190e591ce077b"]
        );

        let mut other = ObjectSource::new(1);
        let mut first = Vec::new();
        other.fill(&mut first, 8);
        assert_ne!(
            hex(&first),
            seen[0],
            "a different seed produced the same bytes"
        );
    }

    #[test]
    fn a_short_final_record_takes_the_generator_prefix() {
        // The tail must be a prefix of the full record, not a re-draw, or the
        // object depends on how it was chunked.
        let mut whole = ObjectSource::new(3);
        let mut short = ObjectSource::new(3);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        whole.fill(&mut a, 8);
        short.fill(&mut b, 3);
        assert_eq!(b.len(), 3);
        assert_eq!(a[..3], b[..]);
    }

    #[test]
    fn every_error_says_which_input_failed() {
        assert_eq!(
            Error::Environment("VOT_BENCH_SEED").to_string(),
            "VOT_BENCH_SEED is missing or not a number"
        );
        assert_eq!(
            Error::Value("VOT_BENCH_WORKERS").to_string(),
            "VOT_BENCH_WORKERS is outside the allowed range"
        );
        assert_eq!(
            Error::Unsupported("backend x".to_owned()).to_string(),
            "unsupported case: backend x"
        );
        assert_eq!(
            Error::Unmeasurable("memory_high_water_bytes").to_string(),
            "memory_high_water_bytes has no measured source on this platform"
        );
        // A pair that never connected and a carrier that stopped mid-transfer
        // are found in different places, so they may not read the same.
        assert_eq!(
            Error::Handshake.to_string(),
            "the endpoints did not connect"
        );
        assert_eq!(Error::Stalled.to_string(), "the carrier stopped delivering");
        assert_ne!(Error::Handshake.to_string(), Error::Stalled.to_string());
        assert_eq!(
            Error::from(vot_transport_api::Error::RecordTooLarge).to_string(),
            "transport error: RecordTooLarge"
        );
        assert_eq!(
            Error::from(vot_scheduler::Error::UnknownObject).to_string(),
            "receive error: UnknownObject"
        );
        assert_eq!(
            Error::from(vot_verifier::VerifyError::GroupOutOfOrder).to_string(),
            "verification error: GroupOutOfOrder"
        );
    }

    #[test]
    fn cpu_time_is_read_past_an_executable_name_that_contains_spaces() {
        // The second field of /proc/[pid]/stat is the executable name in
        // parentheses and may contain spaces and parentheses of its own.
        // Counting fields from the start of the line reads the wrong two for
        // any process named like that, which is a silent wrong number rather
        // than a failure.
        let awkward = "42 (vot bench (x) ) S 1 42 42 0 -1 4194304 125 0 0 0 700 300 0 0 20 0 1 0 8";
        assert_eq!(
            super::parse_cpu_times(awkward),
            Some((700 * 10_000_000, 300 * 10_000_000))
        );

        let plain = "7 (driver) R 1 7 7 0 -1 0 0 0 0 0 11 13 0 0 20 0 1 0 9";
        assert_eq!(
            super::parse_cpu_times(plain),
            Some((11 * 10_000_000, 13 * 10_000_000))
        );

        // Truncated, and not a stat line at all.
        assert_eq!(super::parse_cpu_times("7 (driver) R 1 7"), None);
        assert_eq!(super::parse_cpu_times(""), None);
        assert_eq!(
            super::parse_cpu_times("7 (driver) R 1 7 7 0 -1 0 0 0 0 0 x 13 0 0 20 0 1 0 9"),
            None
        );
    }

    #[test]
    fn the_cpu_a_run_spent_is_a_difference_of_two_readings() {
        assert_eq!(super::cpu_spent(Some((5, 7)), Some((9, 10))), Some((4, 3)));
        // A counter that did not advance is zero, not a wrap.
        assert_eq!(super::cpu_spent(Some((9, 9)), Some((9, 9))), Some((0, 0)));
        assert_eq!(super::cpu_spent(Some((9, 9)), Some((1, 1))), Some((0, 0)));
        // A difference against a reading never taken is not a measurement.
        assert_eq!(super::cpu_spent(None, Some((9, 9))), None);
        assert_eq!(super::cpu_spent(Some((9, 9)), None), None);
    }

    #[test]
    fn the_cpu_reading_advances_as_the_process_spends_it() {
        // A reading that never moves is not a reading. Asserting a positive
        // number inside one short run cannot say this, because the counter
        // advances in ten-millisecond ticks and a small run finishes inside
        // one, which is what made an earlier version of this test fail in CI
        // for being right about a fast machine. So spend CPU until the counter
        // moves, and give it long enough that a loaded machine still gets
        // there.
        let Some((before, _)) = super::cpu_times_ns() else {
            assert!(!cfg!(target_os = "linux"), "linux exposes this");
            return;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut sink = 0_u64;
        let mut after = before;
        while std::time::Instant::now() < deadline {
            for _ in 0..200_000 {
                sink = sink.wrapping_add(std::hint::black_box(1));
            }
            std::hint::black_box(sink);
            if let Some((user, _)) = super::cpu_times_ns()
                && user > before
            {
                after = user;
                break;
            }
        }
        assert!(
            after > before,
            "the user counter did not move while the process spent CPU"
        );
    }

    #[test]
    fn a_run_reports_the_cpu_it_spent_rather_than_only_its_duration() {
        // Throughput alone cannot separate a carrier that is slower because it
        // makes more syscalls from one that is slower because it hashes more.
        let measured = measure(&case(4 * 1_048_576, Suite::Blake3Bao64)).unwrap();
        let user = note_field_text(&measured.notes, "cpu_user_ns");
        let system = note_field_text(&measured.notes, "cpu_sys_ns");
        if cfg!(target_os = "linux") {
            // A number, and deliberately not a positive one. The counter
            // advances in ten-millisecond ticks, and a few mebibytes of
            // generating, framing, and verifying can finish inside one tick on
            // an idle machine, so zero is a true reading rather than a broken
            // one. That the fields carry the right values is pinned by the
            // parser's own test, against known input, where it is exact.
            assert!(user.parse::<u64>().is_ok(), "user cpu was {user}");
            assert!(system.parse::<u64>().is_ok(), "system cpu was {system}");
        } else {
            assert_eq!(user, "unmeasured");
            assert_eq!(system, "unmeasured");
        }
    }

    #[test]
    fn the_high_water_mark_is_read_from_the_process_not_defaulted() {
        // Any test binary that has hashed a megabyte is well past a megabyte of
        // resident memory, so a stubbed constant cannot pass this.
        let measured = measure(&case(1_048_576, Suite::Blake3Bao64)).unwrap();
        assert!(
            measured.memory_high_water_bytes > 1 << 20,
            "high water was {} bytes",
            measured.memory_high_water_bytes
        );
        // A high-water mark never falls, so a later read cannot be smaller.
        assert!(super::memory_high_water_bytes().unwrap() >= measured.memory_high_water_bytes);
    }

    #[test]
    fn vm_hwm_is_parsed_in_bytes_and_rejects_other_units() {
        assert_eq!(
            parse_vm_hwm("Name:\tx\nVmHWM:\t  12345 kB\nVmRSS:\t 1 kB\n"),
            Some(12_345 * 1024)
        );
        assert_eq!(parse_vm_hwm("VmHWM:\t12345 pages\n"), None);
        assert_eq!(parse_vm_hwm("VmRSS:\t12345 kB\n"), None);
        assert_eq!(parse_vm_hwm("VmHWM:\tnot-a-number kB\n"), None);
        assert_eq!(parse_vm_hwm(""), None);
    }
}
