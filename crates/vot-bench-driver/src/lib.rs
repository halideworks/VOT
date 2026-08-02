//! Measured backend driver for the Wave 5.5 benchmark contract.
//!
//! `tools/run_benchmark.py` runs one process per matrix case, hands it the case
//! through `VOT_BENCH_*`, and reads a single JSON object from stdout. The runner
//! deliberately refuses to invent a measurement, and this driver holds the same
//! line in the other direction: a case it cannot run honestly is an error, not
//! an approximation.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::Instant;

use vot_scheduler::ReliableReceiver;
use vot_transport_api::{Event, StreamId, SubjectId, TransportAdapter};
use vot_transport_sim::{Impairment, SimulatorAdapter};
use vot_verifier::{StreamVerifier, Suite};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub backend: String,
    pub suite: Suite,
    pub workers: usize,
    pub seed: u64,
    pub object_bytes: u64,
    pub record_bytes: usize,
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
        Ok(Self {
            backend: variable(lookup, "VOT_BENCH_BACKEND")?,
            suite,
            workers,
            seed: number(lookup, "VOT_BENCH_SEED")?,
            object_bytes,
            record_bytes,
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

    fn draw(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
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

/// Flushes submitted records and feeds every delivered one to the receiver.
fn deliver(
    adapter: &mut SimulatorAdapter,
    receiver: &mut ReliableReceiver,
    subject: SubjectId,
) -> Result<(), Error> {
    adapter.flush()?;
    while let Some(event) = adapter.poll() {
        if let Event::Reliable { bytes, .. } = event {
            receiver.receive(subject, &bytes)?;
        }
    }
    Ok(())
}

/// Runs one case and returns what was measured.
///
/// # Errors
/// Propagates transport, receive, and verification failures, and rejects any
/// case this driver cannot run honestly.
pub fn measure(config: &Config) -> Result<Measurement, Error> {
    if config.backend != "simulator" {
        return Err(Error::Unsupported(format!(
            "backend {} has no assembled transport yet; only simulator is implemented",
            config.backend
        )));
    }
    if config.workers != 1 {
        // Parallel verification of one object needs the proof-bearing range
        // path, which retains every accepted range. Reporting a worker count
        // this driver did not actually use would be the one thing the benchmark
        // contract exists to prevent.
        return Err(Error::Unsupported(format!(
            "worker_count {} is not implemented; the sequential path verifies with one worker",
            config.workers
        )));
    }

    let subject = subject_of(config)?;
    let generator_ns = generator_nanos(config)?;
    let (impairment, unmodelled) = simulator_impairment(config)?;
    let mut adapter = SimulatorAdapter::with_impairment(impairment)?;
    let mut receiver = receiver_for(config)?;
    receiver.begin(subject)?;
    adapter.set_receive_credit(receiver.advertised_credit())?;

    let mut source = ObjectSource::new(config.seed);
    let mut record = Vec::with_capacity(config.record_bytes);
    let mut bytes_sent = 0_u64;
    let mut batch = 0_usize;
    let mut flushes = 0_u64;

    let started = Instant::now();
    for take in record_lengths(config.object_bytes, config.record_bytes)? {
        source.fill(&mut record, take);
        adapter.send_reliable(StreamId(1), &record)?;
        bytes_sent = bytes_sent.saturating_add(record.len() as u64);
        batch = batch.saturating_add(1);
        // Flushing in batches keeps the adapter queue and the receiver's
        // staging bounded, so peak memory does not track object size.
        if batch >= SUBMIT_BATCH_RECORDS {
            flushes = flushes.saturating_add(1);
            deliver(&mut adapter, &mut receiver, subject)?;
            batch = 0;
        }
    }
    if batch != 0 {
        flushes = flushes.saturating_add(1);
        deliver(&mut adapter, &mut receiver, subject)?;
    }
    receiver.finish(subject)?;
    let elapsed = started.elapsed();

    if !receiver.is_verified(subject) {
        return Err(Error::Unsupported(
            "receiver did not reach a verified state".to_owned(),
        ));
    }

    let mut notes = format!(
        concat!(
            "backend=simulator;path=sequential-reliable;",
            "staging_peak_bytes={};credit_bytes={};flushes={};generator_ns={}"
        ),
        receiver.peak_staging(),
        receiver.advertised_credit(),
        flushes,
        generator_ns
    );
    if !unmodelled.is_empty() {
        notes.push_str(";unmodelled_impairment=");
        notes.push_str(&unmodelled.join(","));
    }
    notes.push_str(";cycles=unmeasured");

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

#[cfg(test)]
mod tests {
    use super::{
        Config, Error, ImpairmentCase, Measurement, ObjectSource, escape, measure, parse_vm_hwm,
        record_lengths,
    };
    use std::collections::BTreeMap;
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
            }
        }
    }

    fn note_field(notes: &str, name: &str) -> u64 {
        notes
            .split(';')
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .and_then(|value| value.parse().ok())
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
        assert!(
            generator_ns < measured.elapsed_ns,
            "generation {generator_ns} was not cheaper than the transfer {}",
            measured.elapsed_ns
        );
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
        let mut backend = case(65_536, Suite::Blake3Bao64);
        backend.backend = "msquic".to_owned();
        assert!(matches!(measure(&backend), Err(Error::Unsupported(_))));

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
