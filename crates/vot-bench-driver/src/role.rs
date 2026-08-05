//! One half of a two-machine run.
//!
//! Loopback settles the engine comparison because it charges both endpoints to
//! one host; what it cannot show is what either carrier does with a machine to
//! itself, or what send-side offload is worth when the sender no longer pays
//! for the receiver's syscalls. The two-machine run is that confirmation, and
//! this module is the driver's half of it: `VOT_BENCH_ROLE=receive` listens on
//! `VOT_BENCH_LISTEN` and reports the verified transfer, `VOT_BENCH_ROLE=send`
//! connects to `VOT_BENCH_CONNECT` and reports what it submitted. Both halves
//! are started by hand, never by CI, and their numbers are labeled `role=` so
//! they are never mixed with loopback's.
//!
//! The split keeps the loopback discipline where it can. Records are framed,
//! submitted, and verified by the same helpers `transfer` uses, the budgets and
//! idle backoff are the same, and the receiver's number is the one that means
//! throughput: its clock runs from the accepted connection to the verified
//! object. The sender cannot see verification, so the receiver tells it: one
//! record on a return lane after the object verifies, and the sender's clock
//! stops when that record arrives.
//!
//! This file compiles only under a backend feature, which the mutation matrix
//! does not enable, so it is named in `.cargo/mutants.toml` for the same reason
//! the backend files are. It is measured where it compiles, by the loopback
//! role tests at the bottom, which the live jobs run.

use std::net::SocketAddr;
use std::time::Instant;

use vot_scheduler::ReliableReceiver;
use vot_transport_api::{
    Event, MAX_FRAME_ENVELOPE_BYTES, Payload, StreamId, SubjectId, TransportAdapter, shared_payload,
};

use crate::{
    BundleProducer, BundleReassembly, Config, Credit, Error, Measurement, ObjectSource, Rails,
    RangedFrame, SUBMIT_BATCH_RECORDS, TRANSFER_LANE, Tally, cpu_spent, cpu_times_ns,
    enforced_credit, generator_nanos, idle_wait, memory_high_water_bytes, prover_layer_and_subject,
    ranged_record_bytes, receiver_for, receiver_for_ranged, record_lengths, record_payload,
    round_budget, subject_of, worker_ranges,
};
use vot_scheduler::ReliableReceiver as SchedulerReceiver;

/// Which half of the transfer this process is.
pub(crate) const ROLE: &str = "VOT_BENCH_ROLE";

/// Where the receiving half listens, as `address:port`.
pub(crate) const LISTEN: &str = "VOT_BENCH_LISTEN";

/// Where the sending half connects, as `address:port`.
pub(crate) const CONNECT: &str = "VOT_BENCH_CONNECT";

/// The lane the receiver's done marker returns on.
///
/// Any lane but [`TRANSFER_LANE`] would do: the object only flows one way, so
/// the sender reads any reliable delivery as the marker rather than depending
/// on how each backend numbers a peer-initiated lane.
const DONE_LANE: StreamId = StreamId(2);

/// What the marker says. The content is never verified; arriving is the signal.
const DONE_PAYLOAD: &[u8] = b"verified";

/// The bound a multi-rail spine sleeps on when a round makes no progress.
///
/// The sequential half escalates its idle wait because its one connection's
/// signal is the only wake it needs. A spine over W rails can only wait on
/// one rail's signal while any rail's arrival is progress, so a long bound
/// turns every wait on the wrong rail into a stall of the whole spine, and
/// the odds of the wrong rail are (W-1)/W. A small fixed bound caps that
/// stall; the rounds budget still bounds the loop.
const RAIL_IDLE_WAIT: std::time::Duration = std::time::Duration::from_micros(250);

/// Rounds the receiver stays reachable after sending the done marker, at
/// [`LINGER_WAIT`] a round, so the marker and its retransmissions have a live
/// socket to leave from. The sender's exit usually ends this early as a
/// disconnect; the count is what bounds it when no disconnect ever arrives.
const LINGER_ROUNDS: u32 = 1024;
const LINGER_WAIT: std::time::Duration = std::time::Duration::from_millis(1);

/// A connected endpoint a backend built for one role.
pub(crate) struct Endpoint {
    pub(crate) adapter: Box<dyn TransportAdapter + Send>,
    /// A listener the connection came from, held so it outlives the adapter.
    /// Dropped after `adapter` by declaration order.
    #[allow(dead_code)]
    pub(crate) keepalive: Option<Box<dyn std::any::Any + Send>>,
    /// How the report names this backend.
    pub(crate) backend: &'static str,
    /// What the endpoint was configured with, appended to `notes` as given.
    pub(crate) detail: Option<String>,
    /// Impairment fields the path was not shaped to match.
    pub(crate) unmodelled: Vec<&'static str>,
}

/// Runs the role named in the environment over the case in `config`.
///
/// # Errors
/// Rejects a missing or unrecognised role or address, and propagates whatever
/// the transfer itself reports.
pub fn measure(config: &Config) -> Result<Measurement, Error> {
    #[cfg(test)]
    crate::test_guard::arm();
    // A multi-worker case runs the ranged path over provisioned rails, one
    // connection per worker on consecutive ports. The shared arm stays
    // rejected: one connection is one pump, so sharing it across two machines
    // would measure the sequential path under the wrong label.
    if config.workers != 1 && config.rails != Rails::Provisioned {
        return Err(Error::Unsupported(
            "role mode carries workers above one on provisioned rails only".to_owned(),
        ));
    }
    let role = crate::variable(&|name| std::env::var(name).ok(), ROLE)?;
    // Before the endpoint exists, so inherit covers the driver thread too.
    let counter = crate::cycles::CycleCounter::start();
    let mut measured = run_role(config, &role)?;
    let settled = crate::settle_cycles(counter.and_then(crate::cycles::CycleCounter::read));
    measured.cycles = settled.map(|(count, _)| count);
    crate::note_cycles(&mut measured.notes, settled);
    Ok(measured)
}

fn run_role(config: &Config, role: &str) -> Result<Measurement, Error> {
    match role {
        "send" if config.workers > 1 => {
            let generator_ns = generator_nanos(config)?;
            send_ranged(config, generator_ns, address(CONNECT)?)
        }
        "send" => {
            // Generation is timed before the endpoint exists: the receiver's
            // clock starts at the accepted connection, so everything this
            // process does between connecting and sending is charged to the
            // transfer on the other machine.
            let generator_ns = generator_nanos(config)?;
            let endpoint = connect_endpoint(config, address(CONNECT)?)?;
            send(config, endpoint, generator_ns)
        }
        "receive" if config.workers > 1 => receive_ranged(config, address(LISTEN)?),
        "receive" => {
            // The subject and the staging receiver are built before listening,
            // for the same reason: once the sender connects, its clock is
            // running.
            let subject = subject_of(config)?;
            let mut staging = receiver_for(config)?;
            staging.begin(subject)?;
            let endpoint = listen_endpoint(config, address(LISTEN)?)?;
            receive(config, endpoint, subject, staging)
        }
        _ => Err(Error::Value(ROLE)),
    }
}

/// Raises the shared failure flag on drop unless defused, so a rail that
/// panics still tells its siblings.
struct Alarm<'flag>(&'flag std::sync::atomic::AtomicBool, bool);

impl Drop for Alarm<'_> {
    fn drop(&mut self) {
        if self.1 {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// The shared source rails pull bundle groups from.
type GroupSource =
    std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<Result<Vec<RangedFrame>, Error>>>>;

/// How long a rail's accept may wait once every port is bound.
const ROLE_RAIL_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether the backend can bind a listener without waiting on its handshake.
fn binds_before_accepting(config: &Config) -> bool {
    config.backend.as_str() == "quiche"
}

/// Binds a listening endpoint without waiting for its handshake.
#[cfg(feature = "quiche")]
fn bound_listener(config: &Config, listen: SocketAddr) -> Result<Endpoint, Error> {
    crate::backend_quiche::role_listen_bound(config, listen)
}

#[cfg(not(feature = "quiche"))]
fn bound_listener(_config: &Config, _listen: SocketAddr) -> Result<Endpoint, Error> {
    Err(Error::Unsupported(
        "no backend in this build binds before accepting".to_owned(),
    ))
}

/// Waits for a bound endpoint to report its accepted connection.
///
/// Anything polled before the connection is discarded, which is safe only
/// because the sending half submits nothing until every rail is connected;
/// this wait leans on that gate rather than enforcing one.
fn wait_connected(
    adapter: &mut dyn TransportAdapter,
    timeout: std::time::Duration,
) -> Result<(), Error> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        adapter.flush().map_err(Error::Transport)?;
        while let Some(event) = adapter.poll() {
            if matches!(event, Event::Connected(_)) {
                return Ok(());
            }
        }
        adapter.wait_for_event(std::time::Duration::from_millis(1));
    }
    Err(Error::Handshake)
}

/// Appends each rail's final path measurements to the notes, so a slow run
/// carries its own congestion story: losses name the path, their absence
/// names the source.
fn note_rail_paths(endpoints: &mut [Endpoint], notes: &mut String) {
    use std::fmt::Write as _;
    for (rail, endpoint) in endpoints.iter_mut().enumerate() {
        let Some(stats) = endpoint.adapter.path_stats() else {
            continue;
        };
        if let Some(lost) = stats.lost_packets {
            let _ = write!(notes, ";rail{rail}_lost={lost}");
        }
        if let Some(spurious) = stats.spurious_lost_packets {
            let _ = write!(notes, ";rail{rail}_spurious={spurious}");
        }
        if let Some(sent) = stats.packets_sent {
            let _ = write!(notes, ";rail{rail}_sent={sent}");
        }
        if let Some(received) = stats.packets_received {
            let _ = write!(notes, ";rail{rail}_recv={received}");
        }
        if let Some(rtt) = stats.smoothed_rtt_us {
            let _ = write!(notes, ";rail{rail}_rtt_us={rtt}");
        }
        if let Some(cwnd) = stats.congestion_window_bytes {
            let _ = write!(notes, ";rail{rail}_cwnd={cwnd}");
        }
    }
}

/// Sends the done marker on rail zero and stays reachable while it leaves.
fn tell_the_sender(adapter: &mut dyn TransportAdapter) -> Result<(), Error> {
    let mut marker = Vec::new();
    vot_codec::encode_frame(
        vot_codec::frame_type::DATA_RECORD,
        DONE_PAYLOAD,
        &mut marker,
    )
    .map_err(|_| Error::Value("VOT_BENCH_RECORD_BYTES"))?;
    adapter.send_reliable_shared(DONE_LANE, shared_payload(&marker))?;
    adapter.flush()?;
    linger(adapter);
    Ok(())
}

/// Verified ranges rails hold between proving and admission: transport
/// memory the receiver's own staging cannot see, reported alongside it so
/// the note describes everything the transfer held (ADR-0029).
#[derive(Default)]
struct WitnessLedger {
    held: std::sync::atomic::AtomicU64,
    peak: std::sync::atomic::AtomicU64,
}

impl WitnessLedger {
    fn hold(&self, bytes: u64) {
        let now = self
            .held
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(bytes);
        self.peak
            .fetch_max(now, std::sync::atomic::Ordering::Relaxed);
    }

    fn release(&self, bytes: u64) {
        self.held
            .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    fn peak(&self) -> u64 {
        self.peak.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Drives one receive rail: its own endpoint, its own reassembly, its own
/// proving, and nothing shared with its siblings but the admission lock and
/// the running total.
#[expect(
    clippy::too_many_arguments,
    reason = "every argument is one strand of the shared rail state"
)]
fn drive_receive_rail(
    endpoint: &mut Endpoint,
    subject: SubjectId,
    object_bytes: u64,
    receiver: &std::sync::Mutex<ReliableReceiver>,
    sink: &dyn vot_scheduler::RangeSink,
    witnesses: &WitnessLedger,
    delivered: &std::sync::atomic::AtomicU64,
    failed: &std::sync::atomic::AtomicBool,
    budget: u64,
) -> Result<(Tally, u64), Error> {
    let mut tally = Tally::default();
    // A bundle's frames stay together on their lane, so one incomplete
    // bundle is all a rail can hold.
    let mut reassembly = BundleReassembly::new(1);
    let adapter = endpoint.adapter.as_mut();
    loop {
        if delivered.load(std::sync::atomic::Ordering::Relaxed) >= object_bytes {
            return Ok((tally, reassembly.completed));
        }
        if failed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Disconnected);
        }
        tally.rounds = tally.rounds.saturating_add(1);
        if tally.rounds > budget {
            return Err(Error::Stalled);
        }
        tally.flushes = tally.flushes.saturating_add(1);
        adapter.flush()?;
        let mut progress = false;
        while let Some(event) = adapter.poll() {
            match event {
                Event::Reliable { bytes, .. } => {
                    tally.wire_bytes = tally.wire_bytes.saturating_add(bytes.len() as u64);
                    if let Some(whole) = reassembly.take(&bytes)? {
                        let range = SchedulerReceiver::verify_typed_bundle(
                            subject,
                            &whole.bundle,
                            &whole.records,
                        )?;
                        let admitted = range.len();
                        witnesses.hold(admitted);
                        // Placed before the lock: accepted writes commute,
                        // so rails serialize only on booking the extent.
                        let placed = range.write_to(sink);
                        drop(range);
                        witnesses.release(admitted);
                        let written = placed.map_err(vot_scheduler::Error::from)?;
                        {
                            let Ok(mut shared) = receiver.lock() else {
                                return Err(Error::Disconnected);
                            };
                            shared.admit_written_range(written)?;
                        }
                        delivered.fetch_add(admitted, std::sync::atomic::Ordering::Relaxed);
                        progress = true;
                    }
                }
                Event::Disconnected(_) => return Err(Error::Disconnected),
                _ => {}
            }
        }
        if !progress {
            tally.idle_waits = tally.idle_waits.saturating_add(1);
            adapter.wait_for_event(RAIL_IDLE_WAIT);
        }
    }
}

/// Accepts every rail's connection and starts the transfer clock.
///
/// Every rail binds before any handshake starts where the backend allows
/// it, or the sender's next Initial races the next bind and pays a full
/// no-sample probe timeout when it loses. Either way the clock starts at
/// the first accepted connection, the sequential half's accounting, and
/// the sibling rails' handshakes run inside it.
#[expect(clippy::type_complexity, reason = "the clock rides with what it times")]
fn accept_rails(
    config: &Config,
    base: SocketAddr,
    workers: usize,
) -> Result<(Vec<Endpoint>, Option<(u64, u64)>, Instant), Error> {
    let mut endpoints = Vec::with_capacity(workers);
    let cpu_before;
    let started;
    if binds_before_accepting(config) {
        for rail in 0..workers {
            endpoints.push(bound_listener(config, rail_address(base, rail)?)?);
        }
        wait_connected(endpoints[0].adapter.as_mut(), ROLE_RAIL_HANDSHAKE_TIMEOUT)?;
        cpu_before = cpu_times_ns();
        started = Instant::now();
        for endpoint in endpoints.iter_mut().skip(1) {
            wait_connected(endpoint.adapter.as_mut(), ROLE_RAIL_HANDSHAKE_TIMEOUT)?;
        }
    } else {
        // A backend whose listener accepts inside construction carries the
        // bind race serially; the race and its cost stay visible here
        // rather than being hidden outside the clock.
        endpoints.push(listen_endpoint(config, base)?);
        cpu_before = cpu_times_ns();
        started = Instant::now();
        for rail in 1..workers {
            endpoints.push(listen_endpoint(config, rail_address(base, rail)?)?);
        }
    }
    Ok((endpoints, cpu_before, started))
}

/// The address rail `rail` uses: the configured port plus the rail's index.
fn rail_address(base: SocketAddr, rail: usize) -> Result<SocketAddr, Error> {
    let offset = u16::try_from(rail).map_err(|_| Error::Value("VOT_BENCH_WORKERS"))?;
    let port = base
        .port()
        .checked_add(offset)
        .ok_or(Error::Value("VOT_BENCH_WORKERS"))?;
    Ok(SocketAddr::new(base.ip(), port))
}

/// Reads one address variable.
fn address(name: &'static str) -> Result<SocketAddr, Error> {
    crate::variable(&|variable| std::env::var(variable).ok(), name)?
        .parse()
        .map_err(|_| Error::Value(name))
}

/// Builds the listening endpoint for the case's backend.
fn listen_endpoint(config: &Config, listen: SocketAddr) -> Result<Endpoint, Error> {
    match config.backend.as_str() {
        #[cfg(feature = "quiche")]
        "quiche" => crate::backend_quiche::role_listen(config, listen),
        #[cfg(feature = "msquic")]
        "msquic" => crate::backend_msquic::role_listen(config, listen),
        other => Err(Error::Unsupported(format!(
            "backend {other} has no two-machine endpoint in this build"
        ))),
    }
}

/// Builds the connecting endpoint for the case's backend.
fn connect_endpoint(config: &Config, peer: SocketAddr) -> Result<Endpoint, Error> {
    match config.backend.as_str() {
        #[cfg(feature = "quiche")]
        "quiche" => crate::backend_quiche::role_connect(config, peer),
        #[cfg(feature = "msquic")]
        "msquic" => crate::backend_msquic::role_connect(config, peer),
        other => Err(Error::Unsupported(format!(
            "backend {other} has no two-machine endpoint in this build"
        ))),
    }
}

/// Takes every event the sender's endpoint has, and returns how many there
/// were.
///
/// Any reliable delivery is the receiver's done marker, because nothing else
/// ever flows toward the sender. A disconnect before the marker means the
/// object cannot have verified; one after it is the receiver leaving, which is
/// how this transfer is supposed to end.
fn drain_sender(adapter: &mut dyn TransportAdapter, done: &mut bool) -> Result<u64, Error> {
    let mut events = 0_u64;
    while let Some(event) = adapter.poll() {
        events = events.saturating_add(1);
        match event {
            Event::Reliable { .. } => *done = true,
            Event::Disconnected(_) if !*done => return Err(Error::Disconnected),
            _ => {}
        }
    }
    Ok(events)
}

/// Submits the whole object, then waits for the receiver's done marker.
///
/// The same loop shape as `transfer`: a refused submission is backpressure and
/// spends a round, a batch boundary flushes, and the rounds budget bounds both
/// loops however the carrier behaves. What `transfer` learns from its own
/// receiver this half learns from the marker, so `verified_bytes` is zero here:
/// this process verified nothing and does not report that the other one did.
fn send(config: &Config, mut endpoint: Endpoint, generator_ns: u64) -> Result<Measurement, Error> {
    let budget = round_budget(config);
    let adapter = endpoint.adapter.as_mut();
    let mut source = ObjectSource::new(config.seed);
    let mut record = Vec::with_capacity(config.record_bytes);
    let mut frame = Vec::with_capacity(config.record_bytes + MAX_FRAME_ENVELOPE_BYTES);
    let mut bytes_sent = 0_u64;
    let mut batch = 0_usize;
    let mut rounds = 0_u64;
    let mut tally = Tally::default();
    let mut done = false;

    let cpu_before = cpu_times_ns();
    let started = Instant::now();
    for take in record_lengths(config.object_bytes, config.record_bytes)? {
        source.fill(&mut record, take);
        frame.clear();
        vot_codec::encode_frame(vot_codec::frame_type::DATA_RECORD, &record, &mut frame)
            .map_err(|_| Error::Value("VOT_BENCH_RECORD_BYTES"))?;
        let shared = shared_payload(&frame);
        loop {
            match adapter.send_reliable_shared(TRANSFER_LANE, Payload::clone(&shared)) {
                Ok(()) => break,
                Err(vot_transport_api::Error::OutboundQueueFull) => {
                    rounds = rounds.saturating_add(1);
                    if rounds > budget {
                        return Err(Error::Stalled);
                    }
                    tally.backpressure_waits = tally.backpressure_waits.saturating_add(1);
                    tally.flushes = tally.flushes.saturating_add(1);
                    adapter.flush()?;
                    if drain_sender(adapter, &mut done)? == 0 {
                        tally.idle_waits = tally.idle_waits.saturating_add(1);
                        adapter.wait_for_event(idle_wait(tally.idle_waits));
                    }
                }
                Err(other) => return Err(Error::Transport(other)),
            }
        }
        bytes_sent = bytes_sent.saturating_add(record.len() as u64);
        tally.wire_bytes = tally.wire_bytes.saturating_add(frame.len() as u64);
        batch = batch.saturating_add(1);
        if batch >= SUBMIT_BATCH_RECORDS {
            tally.flushes = tally.flushes.saturating_add(1);
            adapter.flush()?;
            drain_sender(adapter, &mut done)?;
            batch = 0;
        }
    }

    // Every record is with the carrier. The marker is what says the far end
    // verified the object, so the clock runs until it arrives and a carrier
    // that never delivers it is stalled, not finished.
    while !done {
        rounds = rounds.saturating_add(1);
        if rounds > budget {
            return Err(Error::Stalled);
        }
        tally.flushes = tally.flushes.saturating_add(1);
        adapter.flush()?;
        if drain_sender(adapter, &mut done)? == 0 && !done {
            tally.idle_waits = tally.idle_waits.saturating_add(1);
            adapter.wait_for_event(idle_wait(tally.idle_waits));
        }
    }
    let elapsed = started.elapsed();
    tally.cpu = cpu_spent(cpu_before, cpu_times_ns());

    let notes = role_notes("send", &endpoint, None, tally, Some(generator_ns));
    Ok(Measurement {
        bytes_sent,
        verified_bytes: 0,
        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1),
        memory_high_water_bytes: memory_high_water_bytes()?,
        cycles: None,
        notes,
    })
}

/// Drives one rail: groups from the shared source, its own adapter's
/// backpressure, its own flushes and waits, and nothing shared with its
/// siblings but the source and the done flag.
///
/// The rails were once fed by one dealer thread, and its turn-taking
/// coupled them: a rail ran dry whenever the dealer was busy elsewhere or
/// asleep on another rail's signal, which measured about a gigabit against
/// the same flows run as independent processes. Backpressure here is
/// local: a full adapter parks this thread on this rail's own signal.
fn drive_rail(
    endpoint: &mut Endpoint,
    source: &GroupSource,
    done: &std::sync::atomic::AtomicBool,
    failed: &std::sync::atomic::AtomicBool,
    budget: u64,
) -> Result<(Tally, u64), Error> {
    let mut tally = Tally::default();
    let mut bytes_sent = 0_u64;
    let mut queued: std::collections::VecDeque<RangedFrame> = std::collections::VecDeque::new();
    let mut source_dry = false;
    let mut rail_done = false;
    let adapter = endpoint.adapter.as_mut();
    while !rail_done {
        tally.rounds = tally.rounds.saturating_add(1);
        if tally.rounds > budget {
            return Err(Error::Stalled);
        }
        if failed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Disconnected);
        }
        let mut progress = false;
        if queued.is_empty() && !source_dry {
            let taken = {
                let Ok(shared) = source.lock() else {
                    return Err(Error::Disconnected);
                };
                shared.try_recv()
            };
            match taken {
                Ok(Ok(frames)) => queued.extend(frames),
                Ok(Err(error)) => return Err(error),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => source_dry = true,
            }
        }
        while let Some((frame, plaintext)) = queued.front() {
            match adapter.send_reliable_shared(TRANSFER_LANE, Payload::clone(frame)) {
                Ok(()) => {
                    bytes_sent = bytes_sent.saturating_add(*plaintext);
                    tally.wire_bytes = tally.wire_bytes.saturating_add(frame.len() as u64);
                    queued.pop_front();
                    progress = true;
                }
                Err(vot_transport_api::Error::OutboundQueueFull) => {
                    tally.backpressure_waits = tally.backpressure_waits.saturating_add(1);
                    break;
                }
                Err(other) => return Err(Error::Transport(other)),
            }
        }
        tally.flushes = tally.flushes.saturating_add(1);
        adapter.flush()?;
        let mut marker = done.load(std::sync::atomic::Ordering::Relaxed);
        let _ = drain_sender(adapter, &mut marker)?;
        if marker {
            done.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        // A rail is finished only when everything it will ever carry has
        // been handed over and the receiver has said the whole object
        // verified; until then it keeps flushing, because its own
        // retransmissions may be what the verdict is waiting on.
        rail_done = marker && source_dry && queued.is_empty();
        // Progress means frames handed over; routine acknowledgements are
        // not it, or the closing wait would spin its budget dry on its own
        // trailing ACKs.
        if !progress && !rail_done {
            tally.idle_waits = tally.idle_waits.saturating_add(1);
            adapter.wait_for_event(RAIL_IDLE_WAIT);
        }
    }
    Ok((tally, bytes_sent))
}

fn send_ranged(config: &Config, generator_ns: u64, base: SocketAddr) -> Result<Measurement, Error> {
    let budget = round_budget(config);
    let workers = config.workers;
    ranged_record_bytes(config)?;
    let ranges = worker_ranges(config.object_bytes, workers)?;
    let (subject, layer) = prover_layer_and_subject(config)?;
    let layer = std::sync::Arc::new(layer);
    let mut endpoints = Vec::with_capacity(workers);
    for rail in 0..workers {
        endpoints.push(connect_endpoint(config, rail_address(base, rail)?)?);
    }
    let done = std::sync::atomic::AtomicBool::new(false);
    let failed = std::sync::atomic::AtomicBool::new(false);

    let cpu_before = cpu_times_ns();
    let started = std::time::Instant::now();
    let outcome = std::thread::scope(|scope| -> Result<(Tally, u64), Error> {
        // Producers feed one bounded source and every rail takes from it as
        // fast as its own adapter drains, so a quick rail carries more of
        // the object and a slow one delays nothing but its share. The bound
        // is what keeps producers from running ahead of the wire. The source
        // lives inside the scope so a failing transfer can drop it: a
        // producer parked on the full channel unblocks the moment the
        // receiver dies, rather than holding the join forever.
        let (group_tx, group_rx) =
            std::sync::mpsc::sync_channel::<Result<Vec<RangedFrame>, Error>>(workers * 2);
        let source: GroupSource = std::sync::Arc::new(std::sync::Mutex::new(group_rx));
        for (index, range) in ranges.iter().enumerate() {
            let group_tx = group_tx.clone();
            let layer = std::sync::Arc::clone(&layer);
            let mut producer = BundleProducer::new(
                config,
                layer,
                subject,
                *range,
                u32::try_from(index).map_err(|_| Error::Value("VOT_BENCH_WORKERS"))?,
            )?;
            scope.spawn(move || {
                while let Some(bundle) = producer.next_bundle() {
                    let last = bundle.is_err();
                    if group_tx.send(bundle).is_err() || last {
                        return;
                    }
                }
            });
        }
        drop(group_tx);
        let mut rails = Vec::with_capacity(workers);
        for endpoint in &mut endpoints {
            let source = std::sync::Arc::clone(&source);
            let done = &done;
            let failed = &failed;
            rails.push(scope.spawn(move || {
                let mut alarm = Alarm(failed, true);
                let outcome = drive_rail(endpoint, &source, done, failed, budget);
                alarm.1 = outcome.is_err();
                outcome
            }));
        }
        let mut tally = Tally::default();
        let mut bytes_sent = 0_u64;
        let mut first_error = None;
        for rail in rails {
            match rail.join() {
                Ok(Ok((rail_tally, rail_bytes))) => {
                    tally.merge(&rail_tally);
                    bytes_sent = bytes_sent.saturating_add(rail_bytes);
                }
                Ok(Err(error)) => first_error = first_error.or(Some(error)),
                Err(_) => first_error = first_error.or(Some(Error::Disconnected)),
            }
        }
        drop(source);
        match first_error {
            Some(error) => Err(error),
            None => Ok((tally, bytes_sent)),
        }
    });
    let (mut tally, bytes_sent) = outcome?;
    let elapsed = started.elapsed();
    tally.cpu = cpu_spent(cpu_before, cpu_times_ns());

    let mut notes = role_notes("send", &endpoints[0], None, tally, Some(generator_ns));
    {
        use std::fmt::Write as _;
        let _ = write!(notes, ";workers={workers};rails=provisioned-multi-rail");
    }
    note_rail_paths(&mut endpoints, &mut notes);
    Ok(Measurement {
        bytes_sent,
        verified_bytes: 0,
        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1),
        memory_high_water_bytes: memory_high_water_bytes()?,
        cycles: None,
        notes,
    })
}

fn receive_ranged(config: &Config, base: SocketAddr) -> Result<Measurement, Error> {
    let budget = round_budget(config);
    let workers = config.workers;
    let subject = subject_of(config)?;
    let mut receiver = receiver_for_ranged(config)?;
    let (sink, sink_handle) = crate::sink_for(config)?;
    receiver.begin_ranges(subject, Box::new(sink.clone()))?;
    let mut reassembly = BundleReassembly::new(workers);

    // Every rail binds before any handshake starts where the backend allows
    // it, or the sender's next Initial races the next bind and pays a full
    // no-sample probe timeout when it loses. Either way the clock starts at
    // the first accepted connection, the sequential half's accounting, and
    // the sibling rails' handshakes run inside it.
    let (mut endpoints, cpu_before, started) = accept_rails(config, base, workers)?;
    let mut credit = Credit::Constructed;
    for endpoint in &mut endpoints {
        credit = enforced_credit(endpoint.adapter.as_mut(), receiver.advertised_credit())?;
    }

    // Every rail is its own thread end to end: it polls its own endpoint,
    // reassembles its own bundles, proves them itself, and shares nothing
    // with its siblings but the admission lock and the running total. The
    // spine shapes this replaced measured a coupling tax twice: a dealer or
    // a slice rotation asleep on one rail stalls every other through the
    // pump's headroom gate.
    let receiver = std::sync::Mutex::new(receiver);
    let witnesses = WitnessLedger::default();
    let delivered = std::sync::atomic::AtomicU64::new(0);
    let failed = std::sync::atomic::AtomicBool::new(false);
    let mut tally = Tally::default();
    let mut bundles = 0_u64;
    let outcome = std::thread::scope(|scope| -> Result<(), Error> {
        let mut rails = Vec::with_capacity(workers);
        for endpoint in &mut endpoints {
            let receiver = &receiver;
            let sink = sink.clone();
            let witnesses = &witnesses;
            let delivered = &delivered;
            let failed = &failed;
            rails.push(scope.spawn(move || {
                let mut alarm = Alarm(failed, true);
                let outcome = drive_receive_rail(
                    endpoint,
                    subject,
                    config.object_bytes,
                    receiver,
                    sink.as_ref(),
                    witnesses,
                    delivered,
                    failed,
                    budget,
                );
                alarm.1 = outcome.is_err();
                outcome
            }));
        }
        let mut first_error = None;
        for rail in rails {
            match rail.join() {
                Ok(Ok((rail_tally, rail_bundles))) => {
                    tally.merge(&rail_tally);
                    bundles = bundles.saturating_add(rail_bundles);
                }
                Ok(Err(error)) => first_error = first_error.or(Some(error)),
                Err(_) => first_error = first_error.or(Some(Error::Disconnected)),
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    });
    outcome?;
    let mut receiver = receiver.into_inner().map_err(|_| Error::Disconnected)?;
    reassembly.completed = bundles;
    receiver.finish_ranges(subject)?;
    let elapsed = started.elapsed();
    tally.cpu = cpu_spent(cpu_before, cpu_times_ns());

    if !receiver.is_verified(subject) {
        return Err(Error::Unsupported(
            "receiver did not reach a verified state".to_owned(),
        ));
    }

    tell_the_sender(endpoints[0].adapter.as_mut())?;

    let mut notes = role_notes(
        "receive",
        &endpoints[0],
        Some((&receiver, credit)),
        tally,
        None,
    );
    {
        use std::fmt::Write as _;
        let _ = write!(
            notes,
            ";workers={workers};rails=provisioned-multi-rail;bundles={};witness_peak_bytes={}",
            reassembly.completed,
            witnesses.peak()
        );
    }
    crate::sink_note(sink_handle.as_deref(), &mut notes)?;
    note_rail_paths(&mut endpoints, &mut notes);
    Ok(Measurement {
        bytes_sent: 0,
        verified_bytes: config.object_bytes,
        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1),
        memory_high_water_bytes: memory_high_water_bytes()?,
        cycles: None,
        notes,
    })
}

/// Receives, verifies, and reports the transfer, then tells the sender.
///
/// This half's number is the one that means throughput on a wire: its clock
/// starts at the accepted connection and stops when the object verifies, so it
/// covers everything the sender did after connecting, including generating the
/// records it sent.
fn receive(
    config: &Config,
    mut endpoint: Endpoint,
    subject: SubjectId,
    mut staging: ReliableReceiver,
) -> Result<Measurement, Error> {
    let budget = round_budget(config);
    let adapter = endpoint.adapter.as_mut();
    let credit = enforced_credit(adapter, staging.advertised_credit())?;
    let mut delivered = 0_u64;
    let mut rounds = 0_u64;
    let mut tally = Tally::default();

    let cpu_before = cpu_times_ns();
    let started = Instant::now();
    while delivered < config.object_bytes {
        rounds = rounds.saturating_add(1);
        if rounds > budget {
            return Err(Error::Stalled);
        }
        // Acknowledgements and window updates are what keep the sender moving.
        tally.flushes = tally.flushes.saturating_add(1);
        adapter.flush()?;
        let mut progress = 0_u64;
        while let Some(event) = adapter.poll() {
            match event {
                Event::Reliable { bytes, .. } => {
                    tally.wire_bytes = tally.wire_bytes.saturating_add(bytes.len() as u64);
                    let payload = record_payload(&bytes)?;
                    staging.receive(subject, payload)?;
                    progress = progress.saturating_add(payload.len() as u64);
                }
                Event::Disconnected(_) => return Err(Error::Disconnected),
                _ => {}
            }
        }
        delivered = delivered.saturating_add(progress);
        if progress == 0 {
            tally.idle_waits = tally.idle_waits.saturating_add(1);
            adapter.wait_for_event(idle_wait(tally.idle_waits));
        }
    }
    staging.finish(subject)?;
    let elapsed = started.elapsed();
    tally.cpu = cpu_spent(cpu_before, cpu_times_ns());

    if !staging.is_verified(subject) {
        return Err(Error::Unsupported(
            "receiver did not reach a verified state".to_owned(),
        ));
    }

    // Tell the sender, then stay reachable long enough for the marker to
    // leave. Its delivery is what stops the sender's clock, so it goes out
    // after this half's own clock has stopped.
    let mut marker = Vec::new();
    vot_codec::encode_frame(
        vot_codec::frame_type::DATA_RECORD,
        DONE_PAYLOAD,
        &mut marker,
    )
    .map_err(|_| Error::Value("VOT_BENCH_RECORD_BYTES"))?;
    adapter.send_reliable_shared(DONE_LANE, shared_payload(&marker))?;
    adapter.flush()?;
    linger(adapter);

    let notes = role_notes("receive", &endpoint, Some((&staging, credit)), tally, None);
    Ok(Measurement {
        bytes_sent: 0,
        verified_bytes: config.object_bytes,
        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1),
        memory_high_water_bytes: memory_high_water_bytes()?,
        cycles: None,
        notes,
    })
}

/// Keeps the receiver's endpoint alive until the sender leaves or the bound
/// runs out, so the done marker is not stranded by this process exiting.
fn linger(adapter: &mut dyn TransportAdapter) {
    for _ in 0..LINGER_ROUNDS {
        if adapter.flush().is_err() {
            return;
        }
        while let Some(event) = adapter.poll() {
            if matches!(event, Event::Disconnected(_)) {
                return;
            }
        }
        std::thread::sleep(LINGER_WAIT);
    }
}

/// Renders what a role's run measured, in the loopback fields' order, plus the
/// role itself. Receiver-only fields appear only where something enforced them.
fn role_notes(
    role: &str,
    endpoint: &Endpoint,
    staging: Option<(&ReliableReceiver, Credit)>,
    tally: Tally,
    generator_ns: Option<u64>,
) -> String {
    use std::fmt::Write as _;
    let mut notes = format!(
        "backend={};path=sequential-reliable;role={role}",
        endpoint.backend
    );
    if let Some((receiver, credit)) = staging {
        let _ = write!(
            notes,
            ";staging_peak_bytes={};credit_bytes={};credit_mode={}",
            receiver.peak_staging(),
            receiver.advertised_credit(),
            credit.as_str(),
        );
    }
    let _ = write!(
        notes,
        ";flushes={};backpressure_waits={};idle_waits={};wire_bytes={}",
        tally.flushes, tally.backpressure_waits, tally.idle_waits, tally.wire_bytes,
    );
    if let Some(nanos) = generator_ns {
        let _ = write!(notes, ";generator_ns={nanos}");
    }
    let (user, system) = tally.cpu.map_or_else(
        || ("unmeasured".to_owned(), "unmeasured".to_owned()),
        |(user, system)| (user.to_string(), system.to_string()),
    );
    let _ = write!(notes, ";cpu_user_ns={user};cpu_sys_ns={system}");
    if let Some(detail) = &endpoint.detail {
        notes.push(';');
        notes.push_str(detail);
    }
    if !endpoint.unmodelled.is_empty() {
        notes.push_str(";unmodelled_impairment=");
        notes.push_str(&endpoint.unmodelled.join(","));
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::{receive, send};
    use crate::{Config, ImpairmentCase, Measurement, Rails};
    use std::net::SocketAddr;
    use vot_verifier::Suite;

    fn case(backend: &str, object_bytes: u64) -> Config {
        Config {
            backend: backend.to_owned(),
            suite: Suite::Blake3Bao64,
            workers: 1,
            seed: 42,
            object_bytes,
            record_bytes: 65_536,
            rails: Rails::Shared,
            sink: crate::SinkChoice::Discard,
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

    /// A port the kernel just proved free. Racy in principle; in these tests
    /// the rebind happens immediately and ephemeral ports are not reissued
    /// that fast.
    fn free_address() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    }

    /// Runs both halves against each other over loopback: the receive half on
    /// its own thread, as its own machine would be, the send half here.
    fn role_pair(
        config: &Config,
        listen: fn(&Config, SocketAddr) -> Result<super::Endpoint, crate::Error>,
        connect: fn(&Config, SocketAddr) -> Result<super::Endpoint, crate::Error>,
    ) -> (Measurement, Measurement) {
        let address = free_address();
        let far_config = config.clone();
        let far_half = std::thread::spawn(move || {
            let subject = crate::subject_of(&far_config).unwrap();
            let mut staging = crate::receiver_for(&far_config).unwrap();
            staging.begin(subject).unwrap();
            let endpoint = listen(&far_config, address).unwrap();
            receive(&far_config, endpoint, subject, staging).unwrap()
        });
        let generator_ns = crate::generator_nanos(config).unwrap();
        let endpoint = connect(config, address).unwrap();
        let sent = send(config, endpoint, generator_ns).unwrap();
        let received = far_half.join().unwrap();
        (sent, received)
    }

    fn assert_roles_reported(config: &Config, sent: &Measurement, received: &Measurement) {
        // The receiver's number is the throughput claim, so it must have
        // verified the whole object; the sender verified nothing and must say
        // so rather than echoing the case.
        assert_eq!(received.verified_bytes, config.object_bytes);
        assert_eq!(received.bytes_sent, 0);
        assert_eq!(sent.bytes_sent, config.object_bytes);
        assert_eq!(sent.verified_bytes, 0);
        // Labeled, so a wire number is never read as a loopback one.
        assert!(sent.notes.contains(";role=send;"), "{}", sent.notes);
        assert!(
            received.notes.contains(";role=receive;"),
            "{}",
            received.notes
        );
        assert!(
            received.notes.contains("credit_mode="),
            "{}",
            received.notes
        );
    }

    #[cfg(feature = "quiche")]
    #[test]
    fn a_quiche_role_pair_carries_and_verifies() {
        // Past one batch and past one datagram many times over, as the
        // loopback carrier tests hold, plus a short final record.
        let config = case("quiche", 40 * 65_536 + 17);
        let (sent, received) = role_pair(
            &config,
            crate::backend_quiche::role_listen,
            crate::backend_quiche::role_connect,
        );
        assert_roles_reported(&config, &sent, &received);
        assert!(
            received.notes.contains("datagram_bytes="),
            "{}",
            received.notes
        );
    }

    #[cfg(feature = "msquic")]
    #[test]
    fn an_msquic_role_pair_carries_and_verifies() {
        let config = case("msquic", 40 * 65_536 + 17);
        let (sent, received) = role_pair(
            &config,
            crate::backend_msquic::role_listen,
            crate::backend_msquic::role_connect,
        );
        assert_roles_reported(&config, &sent, &received);
    }

    #[test]
    fn a_multi_worker_case_on_a_shared_rail_is_refused_before_any_socket_exists() {
        // The guard runs before the role lookup, so no environment and no
        // network are needed to pin it. Provisioned rails carry workers above
        // one; a shared connection would mislabel the sequential path.
        let mut config = case("quiche", 65_536);
        config.workers = 2;
        assert!(matches!(
            super::measure(&config),
            Err(crate::Error::Unsupported(_))
        ));
    }

    /// A base whose next `extra` ports are also free, so consecutive rails
    /// can bind. Racy in principle, like `free_address`.
    #[cfg(feature = "quiche")]
    fn free_rail_base(extra: u16) -> SocketAddr {
        loop {
            let base = free_address();
            let Some(last) = base.port().checked_add(extra) else {
                continue;
            };
            let all_free = (base.port()..=last)
                .skip(1)
                .all(|port| std::net::UdpSocket::bind(SocketAddr::new(base.ip(), port)).is_ok());
            if all_free {
                return base;
            }
        }
    }

    #[cfg(feature = "quiche")]
    #[test]
    fn a_ranged_role_pair_carries_and_verifies_over_two_rails() {
        // Two workers on two connections: each rail carries its own range,
        // the receiver reassembles and verifies the whole object, and the
        // marker comes back on rail zero.
        let mut config = case("quiche", 8 * 1024 * 1024);
        config.workers = 2;
        config.rails = Rails::Provisioned;
        let base = free_rail_base(1);
        // The receiving half runs ram-to-disk, so this covers the role
        // path's sink registration and the sync-after-clock flow.
        let sink_path =
            std::env::temp_dir().join(format!("vot-role-sink-{}.bin", std::process::id()));
        let mut far_config = config.clone();
        far_config.sink = crate::SinkChoice::File(sink_path.clone());
        let far_half =
            std::thread::spawn(move || super::receive_ranged(&far_config, base).unwrap());
        let generator_ns = crate::generator_nanos(&config).unwrap();
        let sent = super::send_ranged(&config, generator_ns, base).unwrap();
        let received = far_half.join().unwrap();
        assert_eq!(sent.bytes_sent, config.object_bytes);
        assert_eq!(received.verified_bytes, config.object_bytes);
        for measurement in [&sent, &received] {
            assert!(
                measurement
                    .notes
                    .contains("workers=2;rails=provisioned-multi-rail"),
                "{}",
                measurement.notes
            );
        }
        // The sender's rails publish the packet ledger the loss forensics
        // read; a note that stopped carrying it would break that instrument
        // silently.
        assert!(sent.notes.contains("rail0_sent="), "{}", sent.notes);
        assert!(sent.notes.contains("rail0_recv="), "{}", sent.notes);
        assert!(sent.notes.contains("rail0_lost="), "{}", sent.notes);
        assert!(sent.notes.contains("rail0_spurious="), "{}", sent.notes);
        assert!(received.notes.contains("bundles="), "{}", received.notes);
        assert!(
            received.notes.contains(";sink=file;sync_ns="),
            "{}",
            received.notes
        );
        // The file is the object, which is the whole point of the sink.
        let written = std::fs::read(&sink_path).unwrap();
        let _ = std::fs::remove_file(&sink_path);
        let mut expected = Vec::new();
        crate::ObjectSource::new(config.seed)
            .fill(&mut expected, usize::try_from(config.object_bytes).unwrap());
        assert!(written == expected, "the sink file is not the object");
    }
}
