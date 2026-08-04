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
    Config, Credit, Error, Measurement, ObjectSource, SUBMIT_BATCH_RECORDS, TRANSFER_LANE, Tally,
    cpu_spent, cpu_times_ns, enforced_credit, generator_nanos, idle_wait, memory_high_water_bytes,
    receiver_for, record_lengths, record_payload, round_budget, subject_of,
};

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

/// Rounds the receiver stays reachable after sending the done marker, at
/// [`LINGER_WAIT`] a round, so the marker and its retransmissions have a live
/// socket to leave from. The sender's exit usually ends this early as a
/// disconnect; the count is what bounds it when no disconnect ever arrives.
const LINGER_ROUNDS: u32 = 1024;
const LINGER_WAIT: std::time::Duration = std::time::Duration::from_millis(1);

/// A connected endpoint a backend built for one role.
pub(crate) struct Endpoint {
    pub(crate) adapter: Box<dyn TransportAdapter>,
    /// A listener the connection came from, held so it outlives the adapter.
    /// Dropped after `adapter` by declaration order.
    #[allow(dead_code)]
    pub(crate) keepalive: Option<Box<dyn std::any::Any>>,
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
    let role = crate::variable(&|name| std::env::var(name).ok(), ROLE)?;
    match role.as_str() {
        "send" => {
            // Generation is timed before the endpoint exists: the receiver's
            // clock starts at the accepted connection, so everything this
            // process does between connecting and sending is charged to the
            // transfer on the other machine.
            let generator_ns = generator_nanos(config)?;
            let endpoint = connect_endpoint(config, address(CONNECT)?)?;
            send(config, endpoint, generator_ns)
        }
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
    notes.push_str(";cycles=unmeasured");
    notes
}

#[cfg(test)]
mod tests {
    use super::{receive, send};
    use crate::{Config, ImpairmentCase, Measurement};
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
}
