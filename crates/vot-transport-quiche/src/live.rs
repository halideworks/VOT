//! The pump: a socket, a connection, and the timer that drives loss recovery.
//!
//! ADR-0024 decided this arrangement. quiche does no I/O and keeps no time of
//! its own, so a driver thread owns the socket and the connection and nothing
//! else touches either. The caller's side is [`QuicheAdapter`], which holds the
//! bounded queue; submissions cross to the driver and events cross back, so a
//! slow application is backpressure rather than a broken connection and a peer
//! cannot make either side grow without limit.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vot_transport_api::{
    ConnectionId, Error, Event, PathStats, Payload, ReceiveLimits, StreamId, TransportAdapter,
};
use vot_transport_framing::{AssemblyBudget, FrameFault, Framing, StreamKind};

use crate::{
    CONTROL_STREAM_ID, Command, MAX_ASSEMBLY_BYTES, NativeEvent, QuicheAdapter, Role,
    lane_for_stream, stream_for_lane,
};

/// Largest UDP payload either direction when a caller names none.
///
/// What a 1500-byte ethernet frame carries over IPv4. This is a ceiling, not a
/// claim about the path: discovery settles under it where a tunnel or IPv6
/// header narrows the way, at the price of a few probe round trips that a
/// ceiling at or under the path answers in one. The socket asks the network
/// to refuse fragments, so an oversized probe is dropped rather than
/// reassembled into a false success. Measured over a 1472-byte path, 1350
/// here cost 19% of throughput against a matched-size peer.
const MAX_DATAGRAM_SIZE: usize = 1_472;

/// The smallest datagram a caller may ask for.
///
/// QUIC requires an endpoint to carry a 1200-byte initial datagram, so anything
/// under this cannot complete a handshake.
const MIN_DATAGRAM_SIZE: usize = 1_200;

/// The largest, which is what a UDP payload can hold inside IPv4's 65535-byte
/// total length once its own and UDP's headers are paid for. IPv6 could carry
/// 20 more, which is not worth a family-dependent ceiling: a size the socket
/// refuses with `EMSGSIZE` on one family is not a configuration, and the test
/// suite sends a record at this exact size to keep the constant honest.
const LARGEST_DATAGRAM_SIZE: usize = 65_507;

/// Most events the driver holds for a caller that has not drained them.
const MAX_INBOUND_EVENTS: usize = 1_024;

/// How long the driver waits on the socket when the connection asks for longer.
///
/// The connection's own timeout is the deadline that matters; this caps it so a
/// submission or a close request handed over between packets is noticed rather
/// than waiting on the peer. It is the latency a caller pays for the driver
/// owning the socket, and it is why this is a bound rather than a poll interval.
const TICK: Duration = Duration::from_millis(1);

/// Datagrams taken from the kernel in one pass beyond the first, counted so
/// the drain is bounded by its own body rather than by the queue's depth.
///
/// One read per pass made the loop lockstep: the connection never held more
/// than a packet of sendable data, so every data packet cost a send syscall,
/// and the receive side acknowledged every packet because each one was the
/// only one the connection had seen when it next wrote. Draining what has
/// already arrived lets the connection see arrivals as a batch, coalesce its
/// acknowledgements, and generate sends in bursts. Measured over 512 MB on
/// loopback this alone moved quiche from 1.74 to 2.71 Gbit/s at 1350-byte
/// datagrams and from 6.87 to 13.73 at 32768, with user CPU down a third.
const DRAIN_BUDGET: usize = 64;

/// No close has been requested. `u64` because an atomic is how the caller's
/// thread reaches the driver, and every registered code is a `u16`.
const NO_CLOSE: u64 = u64::MAX;

/// The application code an endpoint closes under when it is simply done.
///
/// `spec/registries.md` allocates no zero, because there is nothing to report:
/// an orderly close is the absence of a reason rather than a reason of its own.
const NO_REASON: u64 = 0;

/// What the driver holds for the caller, bounded in both directions.
///
/// Partial frames are charged to the same account as queued events, so a peer
/// cannot make this hold more than [`MAX_ASSEMBLY_BYTES`] whichever side of the
/// handover the bytes are on.
#[derive(Debug, Default)]
struct Inbound {
    events: VecDeque<NativeEvent>,
    bytes: usize,
    assembling: usize,
    /// Raised on every push, waited on by `wait_for_event`. Shared so a
    /// waiter holds no lock the pump needs while it sleeps.
    arrived: Arc<vot_transport_api::EventSignal>,
}

impl Inbound {
    const fn charged(&self) -> usize {
        self.bytes + self.assembling
    }

    fn push(&mut self, event: NativeEvent) -> bool {
        let payload = native_payload_len(&event);
        let Some(next) = self.charged().checked_add(payload) else {
            return false;
        };
        if self.events.len() >= MAX_INBOUND_EVENTS || next > MAX_ASSEMBLY_BYTES {
            return false;
        }
        self.events.push_back(event);
        self.bytes += payload;
        self.arrived.raise();
        true
    }

    /// Queues a connection lifecycle event past both bounds.
    ///
    /// Losing one is not survivable: a caller that never hears the disconnect
    /// waits for a peer that has gone. There are at most two per connection.
    fn push_lifecycle(&mut self, event: NativeEvent) {
        debug_assert_eq!(native_payload_len(&event), 0);
        self.events.push_back(event);
        self.arrived.raise();
    }

    fn pop(&mut self) -> Option<NativeEvent> {
        let event = self.events.pop_front()?;
        self.bytes = self.bytes.saturating_sub(native_payload_len(&event));
        Some(event)
    }
}

fn native_payload_len(event: &NativeEvent) -> usize {
    match event {
        NativeEvent::Control(bytes) | NativeEvent::Reliable { bytes, .. } => bytes.len(),
        NativeEvent::Connected(_)
        | NativeEvent::Disconnected(_)
        | NativeEvent::Acknowledged { .. }
        | NativeEvent::DatagramSent { .. }
        | NativeEvent::DatagramDropped { .. } => 0,
    }
}

/// The budget partial frames are charged to, which is the event budget.
#[derive(Clone)]
struct SharedBudget(Arc<Mutex<Inbound>>);

impl AssemblyBudget for SharedBudget {
    fn reserve(&self, bytes: usize) -> bool {
        let Ok(mut inbound) = self.0.lock() else {
            return false;
        };
        let Some(next) = inbound.charged().checked_add(bytes) else {
            return false;
        };
        if next > MAX_ASSEMBLY_BYTES {
            return false;
        }
        inbound.assembling += bytes;
        true
    }

    fn release(&self, bytes: usize) {
        if let Ok(mut inbound) = self.0.lock() {
            inbound.assembling = inbound.assembling.saturating_sub(bytes);
        }
    }
}

/// What an endpoint needs before it can carry anything.
#[derive(Clone, Debug)]
pub struct Config {
    /// The limits this endpoint advertises and will be held to.
    pub limits: ReceiveLimits,
    /// Server certificate chain, in PEM. Required for a server.
    pub certificate: Option<String>,
    /// Server private key, in PEM. Required for a server.
    pub private_key: Option<String>,
    /// Whether the client verifies the server's certificate.
    pub verify_peer: bool,
    /// Idle timeout in milliseconds.
    pub idle_timeout_ms: u64,
    /// Largest UDP payload this endpoint sends or expects.
    ///
    /// [`MAX_DATAGRAM_SIZE`] unless a caller knows the path. It is a first-order
    /// cost: one datagram is one syscall here, and one packet's worth of header
    /// protection and AEAD, so a path that can carry more and is not asked to
    /// spends both on every datagram. Measured over loopback, whose MTU is
    /// 65536, raising it is worth about four times the throughput.
    ///
    /// Discovery settles under this ceiling when the path is narrower, over
    /// a few probe round trips that a ceiling at or under the path answers
    /// in one.
    pub max_datagram_bytes: usize,
}

impl Config {
    /// A client configuration that verifies its peer.
    #[must_use]
    pub const fn client(limits: ReceiveLimits) -> Self {
        Self {
            limits,
            certificate: None,
            private_key: None,
            verify_peer: true,
            idle_timeout_ms: 30_000,
            max_datagram_bytes: MAX_DATAGRAM_SIZE,
        }
    }

    /// A server configuration with the credentials it presents.
    #[must_use]
    pub const fn server(limits: ReceiveLimits, certificate: String, private_key: String) -> Self {
        Self {
            limits,
            certificate: Some(certificate),
            private_key: Some(private_key),
            verify_peer: false,
            idle_timeout_ms: 30_000,
            max_datagram_bytes: MAX_DATAGRAM_SIZE,
        }
    }

    fn build(&self, role: Role) -> Result<quiche::Config, Error> {
        let mut config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|_| Error::Backend)?;
        config
            .set_application_protos(&[vot_transport_api::ALPN])
            .map_err(|_| Error::InvalidConfiguration)?;
        if role == Role::Server {
            let certificate = self
                .certificate
                .as_deref()
                .ok_or(Error::InvalidConfiguration)?;
            let key = self
                .private_key
                .as_deref()
                .ok_or(Error::InvalidConfiguration)?;
            config
                .load_cert_chain_from_pem_file(certificate)
                .map_err(|_| Error::InvalidConfiguration)?;
            config
                .load_priv_key_from_pem_file(key)
                .map_err(|_| Error::InvalidConfiguration)?;
        }
        config.verify_peer(self.verify_peer);
        config.set_max_idle_timeout(self.idle_timeout_ms);
        if !(MIN_DATAGRAM_SIZE..=LARGEST_DATAGRAM_SIZE).contains(&self.max_datagram_bytes) {
            return Err(Error::InvalidConfiguration);
        }
        config.set_max_recv_udp_payload_size(self.max_datagram_bytes);
        config.set_max_send_udp_payload_size(self.max_datagram_bytes);
        // The configured datagram is a ceiling, not a claim about the path.
        // Without discovery, a path narrower than the ceiling completes the
        // handshake at 1200 bytes and then blackholes every data packet, and
        // only the caller's budget turns the hang into an error; with it, the
        // connection probes and settles under the ceiling the way MsQuic
        // does unaided. The bakeoff report records both behaviors.
        config.discover_pmtu(true);
        // The advertised control-frame bound has to fit in one stream's flow
        // control, or a conforming frame is refused by the carrier after the
        // session promised to accept it.
        let stream_window = u64::try_from(self.limits.control_payload())
            .map_err(|_| Error::InvalidConfiguration)?
            .saturating_add(vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES as u64);
        config.set_initial_max_data(stream_window.saturating_mul(8));
        config.set_initial_max_stream_data_bidi_local(stream_window);
        config.set_initial_max_stream_data_bidi_remote(stream_window);
        // The control stream plus what was advertised, so a peer opening the
        // lanes it was promised is never refused by the carrier.
        let lanes = u64::try_from(self.limits.lanes()).map_err(|_| Error::InvalidConfiguration)?;
        config.set_initial_max_streams_bidi(lanes.saturating_add(1));
        config.set_disable_active_migration(true);
        Ok(config)
    }
}

/// A QUIC endpoint carrying VOT, with its own driver thread.
pub struct Transport {
    adapter: QuicheAdapter,
    commands: mpsc::SyncSender<Command>,
    inbound: Arc<Mutex<Inbound>>,
    /// The most recent path sample the driver read. Copied into the adapter
    /// before events are drained, so the disconnect that clears it is seen after
    /// the sample it belongs to rather than before.
    path: Arc<Mutex<Option<PathStats>>>,
    close: Arc<AtomicU64>,
    /// Held so a refused event is offered again before any later one, which is
    /// what keeps records in the order the peer sent them.
    held: Option<NativeEvent>,
    local: SocketAddr,
    connection: ConnectionId,
    driver: Option<JoinHandle<()>>,
}

impl Transport {
    /// Binds a server and waits for one connection on its own thread.
    ///
    /// # Errors
    /// Reports a socket, credential, or configuration failure.
    pub fn serve(address: SocketAddr, config: &Config) -> Result<Self, Error> {
        Self::start(address, None, config, Role::Server)
    }

    /// Connects to `peer` from `address`.
    ///
    /// # Errors
    /// Reports a socket or configuration failure.
    pub fn connect(
        address: SocketAddr,
        peer: SocketAddr,
        server_name: Option<&str>,
        config: &Config,
    ) -> Result<Self, Error> {
        Self::start(
            address,
            Some((peer, server_name.map(str::to_owned))),
            config,
            Role::Client,
        )
    }

    fn start(
        address: SocketAddr,
        peer: Option<(SocketAddr, Option<String>)>,
        config: &Config,
        role: Role,
    ) -> Result<Self, Error> {
        let socket = UdpSocket::bind(address).map_err(|_| Error::Backend)?;
        // Discovery's probes must be dropped where the path narrows, never
        // fragmented and reassembled: a reassembled probe reads as success and
        // locks the connection above the path for good.
        vot_platform_net::refuse_fragmentation(&socket).map_err(|_| Error::Backend)?;
        let local = socket.local_addr().map_err(|_| Error::Backend)?;
        let mut quiche_config = config.build(role)?;

        let mut adapter = QuicheAdapter::for_role(role);
        adapter.set_receive_limits(config.limits);
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let close = Arc::new(AtomicU64::new(NO_CLOSE));
        let control_limit = Arc::new(AtomicUsize::new(config.limits.control_payload()));
        // As deep as the adapter's own queue, so one flush moves a batch. The
        // adapter's bound is the real one either way, and a full channel leaves
        // the submission at the head of that queue rather than dropping it, but a
        // channel of one would have bounded throughput by the driver's loop rate
        // rather than by the carrier.
        let (commands, receiver) = mpsc::sync_channel(vot_transport_queue::DEFAULT_COUNT_LIMIT);
        let path = Arc::new(Mutex::new(None));
        let driver_inbound = Arc::clone(&inbound);
        let driver_close = Arc::clone(&close);
        let driver_control = Arc::clone(&control_limit);
        let driver_path = Arc::clone(&path);
        let connection = ConnectionId(u64::from(local.port()));
        let datagram_bytes = config.max_datagram_bytes;

        let driver = std::thread::Builder::new()
            .name(format!("vot-quiche-{}", local.port()))
            .spawn(move || {
                // Whatever ends the driver, the caller still owes it the
                // disconnect below.
                let _ = drive(
                    &socket,
                    local,
                    peer.as_ref()
                        .map(|(address, name)| (*address, name.as_deref())),
                    role,
                    &mut quiche_config,
                    &receiver,
                    &driver_inbound,
                    &driver_close,
                    &driver_control,
                    &driver_path,
                    connection.0,
                    datagram_bytes,
                );
                // A driver that stops for any reason still owes the caller the
                // disconnect, or the caller waits for a peer that has gone.
                if let Ok(mut inbound) = driver_inbound.lock() {
                    inbound.push_lifecycle(NativeEvent::Disconnected(connection.0));
                }
            })
            .map_err(|_| Error::Backend)?;

        Ok(Self {
            adapter,
            commands,
            inbound,
            path,
            close,
            held: None,
            local,
            connection,
            driver: Some(driver),
        })
    }

    /// The address this endpoint is bound to.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local
    }

    /// The identifier this endpoint reports its connection under.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection
    }

    /// Moves what the driver has observed into the caller's queue.
    ///
    /// An event the queue cannot hold is kept and offered again before any later
    /// one, so backpressure never reorders a record.
    fn take_inbound(&mut self) {
        // The sample first: the disconnect that clears it is drained below, and a
        // caller reading a Careful Resume observation needs the sample to still be
        // there when it sees the disconnect beside it.
        if let Ok(sample) = self.path.lock() {
            if let Some(stats) = *sample {
                drop(sample);
                self.adapter.record_path_stats(self.connection, stats);
            }
        }
        if let Some(event) = self.held.take() {
            match self.adapter.try_record_native_event(event) {
                Ok(()) => {}
                Err((event, _)) => {
                    self.held = Some(event);
                    return;
                }
            }
        }
        loop {
            let Ok(mut inbound) = self.inbound.lock() else {
                return;
            };
            let Some(event) = inbound.pop() else {
                return;
            };
            drop(inbound);
            if let Err((event, _)) = self.adapter.try_record_native_event(event) {
                self.held = Some(event);
                return;
            }
        }
    }
}

impl Drop for Transport {
    /// Stops the driver, which can wait on the peer.
    ///
    /// The close has to reach the peer for the connection to finish draining, so
    /// dropping an endpoint whose peer has vanished waits out the idle timeout
    /// rather than returning at once. That is the cost of the driver owning the
    /// socket: it cannot be released while a packet might still be owed.
    fn drop(&mut self) {
        // The driver owns the socket, so it has to stop before this returns or
        // the port outlives the endpoint that bound it. Dropping an endpoint is
        // not an error, so it closes under no code at all.
        self.close.store(NO_REASON, Ordering::Relaxed);
        if let Some(driver) = self.driver.take() {
            let _ = driver.join();
        }
    }
}

impl TransportAdapter for Transport {
    fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.adapter.send_control(frame)
    }

    fn send_control_shared(&mut self, frame: Payload) -> Result<(), Error> {
        self.adapter.send_control_shared(frame)
    }

    fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
        self.adapter.send_reliable(stream, record)
    }

    fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        self.adapter.send_reliable_shared(stream, record)
    }

    fn preflight_reliable_batch(&self, stream: StreamId, records: &[Payload]) -> Result<(), Error> {
        self.adapter.preflight_reliable_batch(stream, records)
    }

    fn send_datagram(&mut self, context: u64, payload: &[u8]) -> Result<(), Error> {
        self.adapter.send_datagram(context, payload)
    }

    /// Hands submissions to the driver.
    ///
    /// A submission the driver cannot take yet stays at the head of the queue, so
    /// a caller that flushes again offers the same one first.
    ///
    /// # Errors
    /// Never fails: a full channel is backpressure, not a failure.
    fn flush(&mut self) -> Result<(), Error> {
        let commands = self.commands.clone();
        let _ = self
            .adapter
            .drain_commands(|command| commands.try_send(command).map_err(|_| Error::Backend));
        Ok(())
    }

    fn poll(&mut self) -> Option<Event> {
        self.take_inbound();
        self.adapter.poll()
    }

    // The pump raises the queue's signal on every push, so a caller sleeps
    // until there is something rather than guessing an interval. Checked
    // before sleeping: an event already queued, or one held back from a full
    // adapter, is work the caller should poll for now.
    fn wait_for_event(&mut self, bound: Duration) {
        if self.held.is_some() {
            return;
        }
        let signal = {
            let Ok(inbound) = self.inbound.lock() else {
                return;
            };
            if !inbound.events.is_empty() {
                return;
            }
            Arc::clone(&inbound.arrived)
        };
        signal.wait(bound);
    }

    /// Not applied per call on this carrier. See [`QuicheAdapter`].
    fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error> {
        self.adapter.set_receive_credit(bytes)
    }

    fn set_control_payload_limit(&mut self, limit: usize) -> Result<(), Error> {
        self.adapter.set_control_payload_limit(limit)?;
        // The reassembly bound follows the send bound only in that both are the
        // peer's business; what is stored here is what this endpoint accepts.
        Ok(())
    }

    fn receive_limits(&self) -> Option<ReceiveLimits> {
        self.adapter.receive_limits()
    }

    fn path_stats(&self) -> Option<PathStats> {
        self.adapter.path_stats()
    }

    /// Ends the session under a registered code.
    ///
    /// # Errors
    /// Never fails: the driver applies the code when it next wakes, which is at
    /// most one tick away.
    fn close(&mut self, code: u16) -> Result<(), Error> {
        self.close.store(u64::from(code), Ordering::Relaxed);
        Ok(())
    }
}

/// Per-stream state the driver keeps.
struct StreamState {
    framing: Framing<SharedBudget>,
    kind: StreamKind,
    /// The QUIC stream these bytes travel on, kept rather than derived so the
    /// mapping is applied once, where the lane was given.
    id: u64,
    sequence: u64,
    /// What the caller handed over that the connection has not taken yet, with
    /// how much of each has gone. A stream's flow control is the peer's, so a
    /// record may be written in pieces across several loops, and holding the
    /// caller's own allocation means those pieces cost no copy of their own.
    outbox: VecDeque<(Payload, usize)>,
    /// Frames completed after the event queue refused one, kept in arrival
    /// order until the caller drains the queue. Reading the stream stops
    /// while this holds anything, so it is bounded by what one read chunk
    /// and one partial frame can complete, not by the peer's appetite.
    overflow: VecDeque<NativeEvent>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the driver takes what the caller owns and nothing more"
)]
fn drive(
    socket: &UdpSocket,
    local: SocketAddr,
    peer: Option<(SocketAddr, Option<&str>)>,
    role: Role,
    config: &mut quiche::Config,
    commands: &mpsc::Receiver<Command>,
    inbound: &Arc<Mutex<Inbound>>,
    close: &Arc<AtomicU64>,
    control_limit: &Arc<AtomicUsize>,
    path: &Arc<Mutex<Option<PathStats>>>,
    connection: u64,
    datagram_bytes: usize,
) -> Result<(), Error> {
    let budget = SharedBudget(Arc::clone(inbound));
    // Heap rather than stack, and as large as the largest frame a lane carries.
    // A read that holds a whole record hands it to the parser as one slice, so
    // reassembly is what happens when a record is split rather than what happens
    // to every record. A driver thread's stack is not the place for it either.
    let mut buffer = vec![0_u8; vot_transport_framing::MAX_PARTIAL_FRAME.max(65_535)];
    // A burst rather than a datagram, because packets are gathered and handed
    // over together. One UDP datagram is the most the kernel will segment at a
    // time, so that bounds it: at a 1472-byte path MTU this holds 44 packets
    // and costs one syscall instead of 44, which is where the offload pays.
    // A datagram already near the cap holds one, and the send is what it was.
    let burst_bytes = LARGEST_DATAGRAM_SIZE.max(datagram_bytes);
    let mut out = vec![0_u8; burst_bytes];
    let offload = offload_available();
    let scid = scid_for(local);

    let (mut conn, mut announced) = match (role, peer) {
        (Role::Client, Some((address, name))) => (
            quiche::connect(name, &scid, local, address, config).map_err(|_| Error::Backend)?,
            false,
        ),
        (Role::Server, _) => {
            // A server has nothing to do until a client speaks, and the first
            // packet is what names the connection.
            let Some(conn) = accept_one(socket, local, config, &mut buffer)? else {
                return Ok(());
            };
            (conn, false)
        }
        (Role::Client, None) => return Err(Error::InvalidConfiguration),
    };

    // Receive-side offload from here on: the handshake above read plain
    // datagrams, and everything after this can be handed a coalesced buffer
    // with the segment size beside it. A kernel that refuses the option
    // leaves each datagram its own read.
    enable_receive_offload(socket);
    // Allocated once, because a control-message buffer per read is a malloc
    // per packet, which is the cost this path exists to remove.
    let mut space = receive_space();
    let mut streams: BTreeMap<u64, StreamState> = BTreeMap::new();
    let mut closing = false;

    loop {
        // What the caller asked for, and what the connection has to say about it.
        while let Ok(command) = commands.try_recv() {
            apply(
                &mut conn,
                &mut streams,
                &budget,
                control_limit,
                command,
                inbound,
                role,
            );
        }
        if !closing {
            let requested = close.load(Ordering::Relaxed);
            if requested != NO_CLOSE {
                closing = true;
                let _ = conn.close(true, requested, b"");
            }
        }
        for stream in streams.values_mut() {
            write_outbox(&mut conn, stream);
        }
        // A socket that will not take a packet is a carrier that has gone.
        // The ceiling goes down whole: a discovery probe is only generated
        // when the buffer offered could hold one, and the connection's own
        // packet-size accessor caps its answer at 16383, so a slot sized by
        // it can never hold the probe for a larger ceiling and discovery
        // starves at the handshake floor. send_all opens each burst at the
        // ceiling and lets the first packet written set the burst's segment,
        // which keeps the offload's equal-sized runs either way.
        let Ok(paced) = send_all(socket, &mut conn, &mut out, datagram_bytes, offload) else {
            return Ok(());
        };

        if conn.is_established() && !announced {
            announced = true;
            if let Ok(mut queue) = inbound.lock() {
                queue.push_lifecycle(NativeEvent::Connected(connection));
            }
        }

        if conn.is_closed() {
            return Ok(());
        }

        // The soonest of what the connection asked for: its own timer, the
        // pacing deadline, and the cap that keeps a submission from waiting on
        // the peer.
        let pacing = paced.map(|at| at.saturating_duration_since(Instant::now()));
        let deadline = conn
            .timeout()
            .unwrap_or(TICK)
            .min(pacing.unwrap_or(TICK))
            .min(TICK)
            .max(
                // A zero timeout would spin; the connection wants attention now
                // and gets it on the next pass either way.
                Duration::from_micros(200),
            );
        socket
            .set_read_timeout(Some(deadline))
            .map_err(|_| Error::Backend)?;
        match receive_segmented(socket, &mut buffer, &mut space) {
            Ok((len, from, segment)) => {
                feed_received(&mut conn, local, &mut buffer[..len], from, segment);
                drain_arrivals(socket, &mut conn, local, &mut buffer, &mut space)?;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(_) => return Ok(()),
        }

        read_streams(
            &mut conn,
            &mut streams,
            &budget,
            inbound,
            control_limit,
            role,
            &mut buffer,
        );
        drain_datagrams(&mut conn, &mut buffer);
        if let Some(sample) = path_sample(&conn) {
            if let Ok(mut slot) = path.lock() {
                *slot = Some(sample);
            }
        }
    }
}

/// Waits for the first packet and turns it into a connection.
fn accept_one(
    socket: &UdpSocket,
    local: SocketAddr,
    config: &mut quiche::Config,
    buffer: &mut [u8],
) -> Result<Option<quiche::Connection>, Error> {
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| Error::Backend)?;
    loop {
        let Ok((len, from)) = socket.recv_from(buffer) else {
            return Ok(None);
        };
        let Ok(header) = quiche::Header::from_slice(&mut buffer[..len], quiche::MAX_CONN_ID_LEN)
        else {
            continue;
        };
        if !quiche::version_is_supported(header.version) {
            // A version this endpoint does not speak is answered rather than
            // dropped, which is what lets a client try another.
            // Version negotiation is a short packet, and the smallest datagram
            // any endpoint carries is more than enough for it.
            let mut out = [0_u8; MIN_DATAGRAM_SIZE];
            if let Ok(written) = quiche::negotiate_version(&header.scid, &header.dcid, &mut out) {
                let _ = socket.send_to(&out[..written], from);
            }
            continue;
        }
        let scid = scid_for(local);
        let mut conn =
            quiche::accept(&scid, None, local, from, config).map_err(|_| Error::Backend)?;
        let info = quiche::RecvInfo { from, to: local };
        if conn.recv(&mut buffer[..len], info).is_err() {
            continue;
        }
        return Ok(Some(conn));
    }
}

/// A connection identifier for this endpoint.
///
/// Derived from the port rather than drawn at random, because this crate takes no
/// randomness of its own and one connection per socket is what the pump carries.
/// Padded to the full length so a peer's routing has as much to key on as any
/// other implementation would give it.
fn scid_for(local: SocketAddr) -> quiche::ConnectionId<'static> {
    let mut bytes = [0_u8; quiche::MAX_CONN_ID_LEN];
    let port = local.port().to_be_bytes();
    bytes[..2].copy_from_slice(&port);
    for (index, byte) in bytes.iter_mut().enumerate().skip(2) {
        let step = u8::try_from(index % 251).unwrap_or(0);
        *byte = step.wrapping_mul(31).wrapping_add(port[index % 2]);
    }
    quiche::ConnectionId::from_vec(bytes.to_vec())
}

/// Turns on coalesced receive, where several datagrams of one flow arrive as
/// one buffer with the segment size beside them.
///
/// A cost saving and never a requirement: a kernel without the option leaves
/// each datagram its own read, and the feed path handles both shapes.
#[cfg(target_os = "linux")]
fn enable_receive_offload(socket: &UdpSocket) {
    let _ = nix::sys::socket::setsockopt(socket, nix::sys::socket::sockopt::UdpGroSegment, &true);
}

#[cfg(not(target_os = "linux"))]
fn enable_receive_offload(_socket: &UdpSocket) {}

/// One read: the bytes, the sender, and the segment size when the kernel
/// coalesced several datagrams into this buffer.
///
/// `recvmsg` rather than `recv_from`, because the segment size rides a control
/// message; the socket's read timeout applies the same either way. The unsafe
/// stays in `nix`, which is why this crate still forbids unsafe of its own.
#[cfg(target_os = "linux")]
#[expect(clippy::ptr_arg, reason = "nix's recvmsg takes the Vec itself")]
fn receive_segmented(
    socket: &UdpSocket,
    buffer: &mut [u8],
    space: &mut Vec<u8>,
) -> std::io::Result<(usize, SocketAddr, Option<usize>)> {
    use std::os::fd::AsRawFd as _;

    let mut slices = [std::io::IoSliceMut::new(buffer)];
    let message = nix::sys::socket::recvmsg::<nix::sys::socket::SockaddrStorage>(
        socket.as_raw_fd(),
        &mut slices,
        Some(space),
        nix::sys::socket::MsgFlags::empty(),
    )
    .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))?;
    let segment = message.cmsgs().ok().and_then(|mut messages| {
        messages.find_map(|control| match control {
            nix::sys::socket::ControlMessageOwned::UdpGroSegments(size) => {
                usize::try_from(size).ok()
            }
            _ => None,
        })
    });
    let from = message
        .address
        .as_ref()
        .and_then(address_of)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    Ok((message.bytes, from, segment))
}

/// The standard read where no coalescing exists to report.
#[cfg(not(target_os = "linux"))]
fn receive_segmented(
    socket: &UdpSocket,
    buffer: &mut [u8],
    _space: &mut Vec<u8>,
) -> std::io::Result<(usize, SocketAddr, Option<usize>)> {
    let (len, from) = socket.recv_from(buffer)?;
    Ok((len, from, None))
}

/// Room for the coalesced-segment control message, made once per driver.
#[cfg(target_os = "linux")]
fn receive_space() -> Vec<u8> {
    nix::cmsg_space!(nix::libc::c_int)
}

#[cfg(not(target_os = "linux"))]
fn receive_space() -> Vec<u8> {
    Vec::new()
}

/// The peer's address out of what `recvmsg` reports.
#[cfg(target_os = "linux")]
fn address_of(storage: &nix::sys::socket::SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = storage.as_sockaddr_in() {
        return Some(SocketAddr::from((v4.ip(), v4.port())));
    }
    let v6 = storage.as_sockaddr_in6()?;
    Some(SocketAddr::from((v6.ip(), v6.port())))
}

/// Hands one read to the connection, split back into datagrams if the kernel
/// coalesced them.
///
/// The kernel cuts a coalesced buffer into `segment`-sized pieces with only
/// the last allowed short, so the split is the counted walk of those pieces.
/// A packet the connection cannot read is not this connection's problem:
/// another peer's or a stray one, and dropping it is what spec/security.md
/// section 7 asks for rather than answering it.
fn feed_received(
    conn: &mut quiche::Connection,
    local: SocketAddr,
    received: &mut [u8],
    from: SocketAddr,
    segment: Option<usize>,
) {
    let step = match segment {
        Some(step) if step > 0 => step,
        _ => received.len().max(1),
    };
    for piece in received.chunks_mut(step) {
        let info = quiche::RecvInfo { from, to: local };
        let _ = conn.recv(piece, info);
    }
}

/// Takes what has already arrived without waiting, up to the counted budget.
///
/// The wait was paid on the pass's first read; this hands the rest of the
/// queue to the connection as one batch. Only behind a successful switch to
/// non-blocking, because a drain that could block would turn a batch into a
/// stall.
fn drain_arrivals(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
    local: SocketAddr,
    buffer: &mut [u8],
    space: &mut Vec<u8>,
) -> Result<(), Error> {
    if socket.set_nonblocking(true).is_err() {
        // Still blocking, so the pass loses nothing but the batch.
        return Ok(());
    }
    for _ in 0..DRAIN_BUDGET {
        match receive_segmented(socket, buffer, space) {
            Ok((len, from, segment)) => {
                feed_received(conn, local, &mut buffer[..len], from, segment);
            }
            Err(_) => break,
        }
    }
    // A socket left non-blocking would turn the next pass's bounded wait into
    // a spin, so failing to restore it ends the driver instead.
    socket.set_nonblocking(false).map_err(|_| Error::Backend)
}

/// Sends what the connection has generated, and says when it wants to send more.
///
/// A congestion controller that asks for the next packet later is not asking this
/// thread to stop: sleeping inside this loop would stop reading the socket, so
/// acknowledgements would queue in the kernel and the window would stop opening.
/// The deadline goes back to the caller instead, which waits on the socket until
/// then and keeps reading the whole time.
fn send_all(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
    ceiling: usize,
    gso: bool,
) -> Result<Option<Instant>, Error> {
    // Packets are gathered into one buffer and handed over together, because a
    // syscall per packet is most of what a fast path costs: at a 1500-byte MTU
    // it is one call, one copy, and one round through the UDP stack for every
    // 1500 bytes carried. Segmentation offload takes the whole burst in one
    // call and lets the kernel cut it up.
    let mut filled = 0_usize;
    let mut segment = 0_usize;
    let mut destination = None;
    let mut deadline = None;
    loop {
        // A burst opens with room for the ceiling and continues at the size
        // its first packet came out as. The connection only generates a
        // discovery probe when the room offered could hold one, so the
        // opening slot has to be the ceiling; every later packet is capped
        // under it, so the rest of the burst is a run of equal slots and
        // `filled` stays on a segment boundary. Cutting every slot to the
        // ceiling instead made each settled packet "short" and flushed the
        // burst per packet; sizing every slot from the connection's accessor,
        // which caps at 16383, silenced every probe a jumbo ceiling needs.
        let slot = if filled == 0 { ceiling } else { segment };
        let Some(room) = out.get_mut(filled..filled + slot) else {
            // The buffer holds no further packet, so this burst goes now.
            flush_burst(socket, &out[..filled], segment, destination, gso)?;
            filled = 0;
            destination = None;
            continue;
        };
        match conn.send(room) {
            Ok((written, info)) => {
                // A different destination cannot share a burst.
                if destination.is_some_and(|previous| previous != info.to) {
                    flush_burst(socket, &out[..filled], segment, destination, gso)?;
                    // The packet just generated sits at `filled`, so move it to
                    // the front rather than losing or resending it.
                    out.copy_within(filled..filled + written, 0);
                    filled = 0;
                }
                destination = Some(info.to);
                if filled == 0 {
                    segment = written;
                }
                filled += written;
                // Pacing is the connection's decision, and the first packet
                // the pacer holds back ends the pass: what was released goes
                // as one call, what was not waits for its own release. That
                // bounds a burst's time by the pacer's clock.
                if info.at > Instant::now() {
                    deadline = Some(info.at);
                    flush_burst(socket, &out[..filled], segment, destination, gso)?;
                    return Ok(deadline);
                }
                // A packet shorter than a segment closes the burst, because
                // the kernel cuts every segment to the same length but the
                // last; the connection may still have more to say.
                if written < segment {
                    flush_burst(socket, &out[..filled], segment, destination, gso)?;
                    filled = 0;
                    destination = None;
                }
            }
            Err(quiche::Error::Done) => {
                flush_burst(socket, &out[..filled], segment, destination, gso)?;
                // Done in a segment-sized slot only says the next packet did
                // not fit this burst's segment: a burst opened by a lone ACK
                // pins the segment near thirty bytes, and ending the pass
                // there would hand the wait floor back one packet at a time.
                // Reopen at the ceiling; Done with the ceiling on offer is
                // the connection actually finished.
                if slot == ceiling {
                    return Ok(deadline);
                }
                filled = 0;
                destination = None;
            }
            Err(_) => {
                // The gathered packets are state the connection has already
                // committed to; they go to the peer even as the driver ends.
                let _ = flush_burst(socket, &out[..filled], segment, destination, gso);
                return Err(Error::Backend);
            }
        }
    }
}

/// Sends a burst as one datagram the kernel cuts into `segment`-sized pieces.
///
/// `UDP_SEGMENT` is what `MsQuic` reaches for on this platform, and it is the
/// difference between one syscall per packet and one per burst. The unsafe work
/// is `nix`'s, which is why this crate still forbids unsafe of its own.
///
/// # Errors
/// Reports any refusal, including a kernel that does not carry the option, so
/// the caller can fall back to sending the packets one at a time.
#[cfg(target_os = "linux")]
fn send_segmented(
    socket: &UdpSocket,
    burst: &[u8],
    segment: usize,
    destination: SocketAddr,
) -> Result<(), Error> {
    use std::os::fd::AsRawFd as _;

    let segment = u16::try_from(segment).map_err(|_| Error::InvalidConfiguration)?;
    let address = nix::sys::socket::SockaddrStorage::from(destination);
    let slices = [std::io::IoSlice::new(burst)];
    let control = [nix::sys::socket::ControlMessage::UdpGsoSegments(&segment)];
    nix::sys::socket::sendmsg(
        socket.as_raw_fd(),
        &slices,
        &control,
        nix::sys::socket::MsgFlags::empty(),
        Some(&address),
    )
    .map_err(|_| Error::Backend)?;
    Ok(())
}

/// The control message does not exist here; the caller falls back to sending
/// the packets one at a time. Never reached while `offload_available` says no,
/// and honest if it somehow were.
#[cfg(not(target_os = "linux"))]
fn send_segmented(
    _socket: &UdpSocket,
    _burst: &[u8],
    _segment: usize,
    _destination: SocketAddr,
) -> Result<(), Error> {
    Err(Error::Backend)
}

/// Whether to try segmentation offload on this platform.
///
/// The send side needs no socket option, only a control message per call, so
/// this is a question about the platform rather than about the socket. A kernel
/// that refuses the message falls back for that burst.
///
/// The receive side is deliberately left alone. `UDP_GRO` makes one read return
/// several coalesced packets, and a reader that hands the whole buffer to
/// `Connection::recv` as one packet is handing it something it cannot parse.
/// Turning it on without splitting the buffer first broke every transfer large
/// enough to coalesce while every test stayed green, because a short test never
/// gives the kernel two packets to join. It is worth having, and it is worth
/// having with the read path that goes with it.
const fn offload_available() -> bool {
    cfg!(target_os = "linux")
}

/// Hands one burst of equally sized packets to the socket.
///
/// With offload the whole burst is one call and the kernel cuts it into
/// `segment`-sized datagrams. Without it, or for a burst of one, this is the
/// plain send it replaces. A kernel that refuses the control message falls back
/// rather than failing, because the offload is a cost saving and never a
/// correctness requirement.
fn flush_burst(
    socket: &UdpSocket,
    burst: &[u8],
    segment: usize,
    destination: Option<SocketAddr>,
    gso: bool,
) -> Result<(), Error> {
    let Some(destination) = destination else {
        return Ok(());
    };
    if burst.is_empty() {
        return Ok(());
    }
    // A kernel that will not segment falls through and takes the packets one
    // at a time.
    if gso && burst.len() > segment && send_segmented(socket, burst, segment, destination).is_ok() {
        return Ok(());
    }
    for packet in burst.chunks(segment) {
        if socket.send_to(packet, destination).is_err() {
            return Err(Error::Backend);
        }
    }
    Ok(())
}

/// Applies one submission to the connection.
fn apply(
    conn: &mut quiche::Connection,
    streams: &mut BTreeMap<u64, StreamState>,
    budget: &SharedBudget,
    control_limit: &Arc<AtomicUsize>,
    command: Command,
    inbound: &Arc<Mutex<Inbound>>,
    role: Role,
) {
    match command {
        Command::Control(bytes) => {
            let state = stream_state(
                streams,
                CONTROL_STREAM_ID,
                StreamKind::Control,
                budget,
                control_limit,
            );
            state.outbox.push_back((bytes, 0));
        }
        Command::Reliable { stream, bytes } => {
            // Refused at submission, so this cannot be a lane with no stream.
            let Ok(id) = stream_for_lane(stream.0, role) else {
                return;
            };
            let state = stream_state(
                streams,
                id,
                StreamKind::Reliable { lane: stream.0 },
                budget,
                control_limit,
            );
            state.outbox.push_back((bytes, 0));
        }
        Command::Datagram { context, bytes } => {
            let observed = if conn.dgram_send(&bytes).is_ok() {
                NativeEvent::DatagramSent { context }
            } else {
                NativeEvent::DatagramDropped { context }
            };
            if let Ok(mut queue) = inbound.lock() {
                queue.push(observed);
            }
        }
        // Refused at submission, so it cannot reach the driver. A silent success
        // here would hide it if that ever changed.
        Command::ReceiveCredit(_) => {}
    }
}

fn stream_state<'a>(
    streams: &'a mut BTreeMap<u64, StreamState>,
    id: u64,
    kind: StreamKind,
    budget: &SharedBudget,
    control_limit: &Arc<AtomicUsize>,
) -> &'a mut StreamState {
    streams.entry(id).or_insert_with(|| StreamState {
        framing: Framing::new(kind, budget.clone(), Arc::clone(control_limit)),
        kind,
        sequence: 0,
        outbox: VecDeque::new(),
        overflow: VecDeque::new(),
        id,
    })
}

/// Writes what a stream has waiting, as far as flow control allows.
fn write_outbox(conn: &mut quiche::Connection, stream: &mut StreamState) {
    let id = stream.id;
    while let Some((bytes, sent)) = stream.outbox.front_mut() {
        match conn.stream_send(id, &bytes[*sent..], false) {
            Ok(written) if written == bytes.len() - *sent => {
                stream.outbox.pop_front();
            }
            // Flow control is the peer's, so a record may go in pieces. The offset
            // moves and the rest waits for the next pass, which is the same answer
            // as nothing having been taken at all.
            Ok(written) => {
                *sent += written;
                return;
            }
            Err(quiche::Error::Done) => return,
            Err(_) => {
                stream.outbox.clear();
                return;
            }
        }
    }
}

/// Reads every readable stream and turns its bytes into frames.
fn read_streams(
    conn: &mut quiche::Connection,
    streams: &mut BTreeMap<u64, StreamState>,
    budget: &SharedBudget,
    inbound: &Arc<Mutex<Inbound>>,
    control_limit: &Arc<AtomicUsize>,
    role: Role,
    // The driver's own buffer, so a read costs no allocation. One per loop is
    // sixty-four kilobytes a pass, which at ten gigabits is most of the work.
    buffer: &mut [u8],
) {
    let readable: Vec<u64> = conn.readable().collect();
    for id in readable {
        // Which lane a stream's bytes belong to depends on who opened it, so a
        // peer's stream is never reported as a reply to this endpoint's own
        // request.
        let Ok(lane) = lane_for_stream(id, role) else {
            let _ = conn.close(true, u64::from(vot_codec::error_code::RESOURCE_LIMIT), b"");
            return;
        };
        let kind = if id == CONTROL_STREAM_ID {
            StreamKind::Control
        } else {
            StreamKind::Reliable { lane }
        };
        let state = stream_state(streams, id, kind, budget, control_limit);
        // A queue the caller has not drained is backpressure, not a fault:
        // frames the queue refused wait here in order, the stream is not read
        // while any wait, and the unread bytes stall the peer through flow
        // control. The overflow is bounded by what one read chunk and one
        // partial frame can complete, because reading stops the moment it
        // holds anything.
        if let Ok(mut queue) = inbound.lock() {
            while let Some(event) = state.overflow.front() {
                if queue.push(event.clone()) {
                    state.overflow.pop_front();
                } else {
                    break;
                }
            }
        }
        if !state.overflow.is_empty() {
            continue;
        }
        loop {
            // The framing reserves assembly room as bytes arrive and treats a
            // refused reservation as the peer's fault. A queue the caller has
            // not drained is this endpoint's own lag, so a chunk is not read
            // unless the budget could hold everything it can assemble: the
            // chunk itself plus the largest partial a frame can be. Checked
            // per chunk, because one pass reads until the stream is dry and
            // the caller drains nothing meanwhile.
            let headroom = {
                let Ok(queue) = inbound.lock() else {
                    break;
                };
                MAX_ASSEMBLY_BYTES.saturating_sub(queue.charged())
            };
            if headroom < vot_transport_framing::MAX_PARTIAL_FRAME.saturating_add(buffer.len()) {
                break;
            }
            let Ok((len, fin)) = conn.stream_recv(id, buffer) else {
                break;
            };
            let kind = state.kind;
            let sequence = &mut state.sequence;
            let overflow = &mut state.overflow;
            let outcome = state.framing.accept(&buffer[..len], |frame| {
                *sequence = sequence.wrapping_add(1);
                let shared = vot_transport_api::shared_payload(frame);
                let event = match kind {
                    StreamKind::Control => NativeEvent::Control(shared),
                    StreamKind::Reliable { lane } => NativeEvent::Reliable {
                        lane,
                        sequence: *sequence,
                        bytes: shared,
                    },
                };
                let Ok(mut queue) = inbound.lock() else {
                    return Err(FrameFault::exhausted());
                };
                if !overflow.is_empty() || !queue.push(event.clone()) {
                    overflow.push_back(event);
                }
                Ok(())
            });
            if let Err(fault) = outcome {
                let _ = conn.close(true, u64::from(fault.close()), b"");
                return;
            }
            if !state.overflow.is_empty() {
                break;
            }
            if fin {
                if state.framing.is_assembling() {
                    // A decoder may report incomplete while more bytes can still
                    // arrive, and it becomes malformed the moment the carrier
                    // declares the end of the stream.
                    let _ = conn.close(true, u64::from(FrameFault::truncated().close()), b"");
                }
                break;
            }
        }
    }
}

/// Takes received datagrams off the connection.
///
/// They are dropped rather than delivered: `vot-transport-api` has no inbound
/// datagram event, so there is nothing to hand a caller. Leaving them queued
/// would instead stall the connection's datagram credit.
fn drain_datagrams(conn: &mut quiche::Connection, buffer: &mut [u8]) {
    while conn.dgram_recv(buffer).is_ok() {}
}

/// Reads the active path's measurements, when there is one.
#[must_use]
pub fn path_sample(conn: &quiche::Connection) -> Option<PathStats> {
    let stats = conn.path_stats().find(|path| path.active)?;
    Some(PathStats {
        smoothed_rtt_us: u64::try_from(stats.rtt.as_micros()).ok(),
        congestion_window_bytes: u64::try_from(stats.cwnd).ok(),
        mtu_bytes: u64::try_from(stats.pmtu).ok(),
        pacing_rate_bps: Some(stats.delivery_rate.saturating_mul(8)),
    })
}

#[cfg(test)]
mod tests {
    use std::process::Command as Process;
    use std::sync::OnceLock;
    use std::time::Instant;

    use super::*;

    /// Generates a test certificate exactly once per process.
    ///
    /// Several tests need it and the harness runs them concurrently. An
    /// exists-then-create check would let two of them run `openssl` over the same
    /// two paths at once, so one could load a half-written certificate and fail
    /// for reasons that have nothing to do with what it tests.
    fn credentials() -> (String, String) {
        static MATERIAL: OnceLock<(String, String)> = OnceLock::new();
        MATERIAL
            .get_or_init(|| {
                let directory =
                    std::env::temp_dir().join(format!("vot-quiche-{}", std::process::id()));
                std::fs::create_dir_all(&directory).expect("a directory for the credentials");
                let key = directory.join("key.pem");
                let certificate = directory.join("cert.pem");
                let status = Process::new("openssl")
                    .args([
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-keyout",
                        key.to_str().expect("a path"),
                        "-out",
                        certificate.to_str().expect("a path"),
                        "-sha256",
                        "-days",
                        "1",
                        "-nodes",
                        "-subj",
                        "/CN=localhost",
                    ])
                    .status()
                    .expect("openssl runs");
                assert!(status.success(), "openssl generated the credentials");
                (certificate.display().to_string(), key.display().to_string())
            })
            .clone()
    }

    fn limits() -> ReceiveLimits {
        ReceiveLimits::advertised(
            &vot_codec::Settings {
                reliable_lane_limit: 4,
                ..vot_codec::Settings::default()
            },
            crate::INBOUND_BYTE_CAPACITY,
        )
        .expect("limits this backend can hold")
    }

    /// A connected pair over loopback.
    fn pair() -> (Transport, Transport) {
        let (certificate, key) = credentials();
        let server = Transport::serve(
            "127.0.0.1:0".parse().expect("an address"),
            &Config::server(limits(), certificate, key),
        )
        .expect("a server");
        let mut client_config = Config::client(limits());
        // The certificate is generated for this test and trusted by construction;
        // what is under test is the carrier, not the web PKI.
        client_config.verify_peer = false;
        let client = Transport::connect(
            "127.0.0.1:0".parse().expect("an address"),
            server.local_address(),
            Some("localhost"),
            &client_config,
        )
        .expect("a client");
        (client, server)
    }

    /// Polls both endpoints until `ready` says so, or fails after `seconds`.
    fn pump_until(
        client: &mut Transport,
        server: &mut Transport,
        seconds: u64,
        mut ready: impl FnMut(&mut Vec<Event>, &mut Vec<Event>) -> bool,
    ) -> (Vec<Event>, Vec<Event>) {
        let mut from_client = Vec::new();
        let mut from_server = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            let _ = client.flush();
            let _ = server.flush();
            while let Some(event) = client.poll() {
                from_client.push(event);
            }
            while let Some(event) = server.poll() {
                from_server.push(event);
            }
            if ready(&mut from_client, &mut from_server) {
                return (from_client, from_server);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!(
            "the carrier never got there: client saw {from_client:?}, server saw {from_server:?}"
        );
    }

    fn connected(events: &[Event]) -> bool {
        events
            .iter()
            .any(|event| matches!(event, Event::Connected(_)))
    }

    /// A control frame with a payload, encoded as the codec would.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        vot_codec::encode_frame(vot_codec::frame_type::SETTINGS, payload, &mut out)
            .expect("a frame the codec accepts");
        out
    }

    /// A data record, which is the frame a lane actually carries.
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        vot_codec::encode_frame(vot_codec::frame_type::DATA_RECORD, payload, &mut out)
            .expect("a record the codec accepts");
        out
    }

    #[test]
    fn a_client_and_a_server_negotiate_and_say_so() {
        let (mut client, mut server) = pair();
        let (from_client, from_server) = pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });
        assert!(connected(&from_client), "the client saw the connection");
        assert!(connected(&from_server), "the server saw it too");

        // The path is what the connection measured, not a number invented here.
        // ADR-0013 makes Careful Resume conditional on a backend exposing this.
        let stats = client.path_stats().expect("a path sample");
        assert!(stats.smoothed_rtt_us.is_some());
        assert!(stats.congestion_window_bytes.unwrap_or(0) > 0);
        assert!(stats.mtu_bytes.unwrap_or(0) > 0);
    }

    #[test]
    fn a_wait_ends_on_arrival_rather_than_at_its_bound() {
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });

        // Handshake-tail traffic can keep arriving briefly, and every push
        // leaves the latch raised, which polling never consumes. Settle
        // first: drain, then require one short wait to pass with nothing
        // arriving, so the timed wait below parks on a quiet queue and only
        // the record's own push can end it. This loop is also what pins that
        // an idle wait costs its bound: a wait that returns at once with
        // nothing to poll can never settle, and that spin is what the
        // contract forbids.
        let quiet = Duration::from_millis(100);
        let settle_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let _ = server.flush();
            while server.poll().is_some() {}
            let quiet_started = Instant::now();
            server.wait_for_event(quiet);
            if quiet_started.elapsed() >= quiet {
                break;
            }
            assert!(
                Instant::now() < settle_deadline,
                "the queue never went quiet, or an idle wait returns early"
            );
        }

        // A record is in flight when the server starts a five second wait. The
        // pump's signal must end the wait when the record lands; a wait that
        // sleeps its bound out is the polling interval this contract removes.
        client
            .send_reliable(StreamId(1), &record(b"wake"))
            .expect("a submission");
        client.flush().expect("a flush");
        let started = Instant::now();
        server.wait_for_event(Duration::from_secs(5));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the wait slept past the arrival: {:?}",
            started.elapsed()
        );
        // What arrived is what was sent, so the early return was the event
        // rather than a spurious wakeup timed luckily.
        pump_until(&mut client, &mut server, 10, |_, b| {
            b.iter()
                .any(|event| matches!(event, Event::Reliable { .. }))
        });
    }

    #[test]
    fn a_control_frame_crosses_unchanged() {
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });

        let sent = frame(b"negotiation");
        client
            .send_control(&sent)
            .expect("a control frame the peer allows");
        let (_, from_server) = pump_until(&mut client, &mut server, 10, |_, b| {
            b.iter().any(|event| matches!(event, Event::Control(_)))
        });
        let carried = from_server
            .iter()
            .find_map(|event| match event {
                Event::Control(bytes) => Some(bytes.to_vec()),
                _ => None,
            })
            .expect("a control frame");
        assert_eq!(carried, sent, "the bytes are not rewritten on the way");
    }

    #[test]
    fn records_cross_on_their_own_lanes_and_in_order() {
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });

        // Two lanes, two records each, so the test says something about ordering
        // within a lane without claiming any between them.
        for lane in [0_u64, 1] {
            for index in 0..2_u64 {
                let bytes = record(&[u8::try_from(lane * 8 + index).expect("a byte"); 64]);
                client
                    .send_reliable(StreamId(lane), &bytes)
                    .expect("a record");
            }
        }
        let (_, from_server) = pump_until(&mut client, &mut server, 15, |_, b| {
            b.iter()
                .filter(|event| matches!(event, Event::Reliable { .. }))
                .count()
                >= 4
        });

        let mut per_lane: BTreeMap<u64, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
        for event in &from_server {
            if let Event::Reliable {
                stream,
                sequence,
                bytes,
            } = event
            {
                per_lane
                    .entry(stream.0)
                    .or_default()
                    .push((*sequence, bytes.to_vec()));
            }
        }
        assert_eq!(per_lane.len(), 2, "one lane each, not one lane for both");
        for (lane, records) in &per_lane {
            // A peer's stream is reported under a peer lane, never as a reply to
            // the server's own request.
            assert!(
                crate::is_reserved_lane(*lane),
                "lane {lane:#x} is the peer's"
            );
            assert_eq!(records.len(), 2, "lane {lane:#x}");
            assert_eq!(records[0].0, 1, "the first record on the lane");
            assert_eq!(records[1].0, 2, "and the second after it");
            assert_ne!(records[0].1, records[1].1);
        }
    }

    #[test]
    fn a_record_larger_than_one_packet_arrives_whole() {
        // The reason reassembly exists: a record is far larger than a datagram, so
        // it crosses in pieces and has to be delivered once.
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });

        let payload: Vec<u8> = (0..200_000_u32)
            .map(|index| u8::try_from(index % 256).expect("a byte"))
            .collect();
        let bytes = record(&payload);
        assert!(bytes.len() > MAX_DATAGRAM_SIZE * 10, "many packets' worth");
        client
            .send_reliable(StreamId(0), &bytes)
            .expect("a record the lane carries");

        let (_, from_server) = pump_until(&mut client, &mut server, 30, |_, b| {
            b.iter()
                .any(|event| matches!(event, Event::Reliable { .. }))
        });
        let carried = from_server
            .iter()
            .find_map(|event| match event {
                Event::Reliable { bytes, .. } => Some(bytes.to_vec()),
                _ => None,
            })
            .expect("a record");
        assert_eq!(carried.len(), bytes.len());
        assert_eq!(carried, bytes, "every byte, once");
    }

    #[test]
    fn either_side_may_send_records_to_the_other() {
        // Both endpoints open their own streams for what they send, so a server
        // answering a request is not writing to a stream the client owns.
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });

        client
            .send_reliable(StreamId(0), &record(b"from the client"))
            .expect("a record");
        server
            .send_reliable(StreamId(0), &record(b"from the server"))
            .expect("a record");
        let (from_client, from_server) = pump_until(&mut client, &mut server, 15, |a, b| {
            a.iter()
                .any(|event| matches!(event, Event::Reliable { .. }))
                && b.iter()
                    .any(|event| matches!(event, Event::Reliable { .. }))
        });
        for (events, expected) in [
            (&from_server, record(b"from the client")),
            (&from_client, record(b"from the server")),
        ] {
            let carried = events
                .iter()
                .find_map(|event| match event {
                    Event::Reliable { bytes, .. } => Some(bytes.to_vec()),
                    _ => None,
                })
                .expect("a record");
            assert_eq!(carried, expected);
        }
    }

    #[test]
    fn a_datagram_reports_only_what_was_observed() {
        // ADR-0024: this carrier offers no per-datagram acknowledgement, so Sent
        // is the last state there is. Reporting an acknowledgement that was never
        // observed would be worse than reporting less.
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });
        client
            .send_datagram(9, b"experimental")
            .expect("a datagram");
        let (from_client, _) = pump_until(&mut client, &mut server, 10, |a, _| {
            a.iter()
                .any(|event| matches!(event, Event::DatagramState { .. }))
        });
        let state = from_client
            .iter()
            .find_map(|event| match event {
                Event::DatagramState { context, state } => Some((*context, *state)),
                _ => None,
            })
            .expect("a datagram state");
        assert_eq!(state.0, 9, "the context the caller gave");
        assert!(
            matches!(
                state.1,
                vot_transport_api::DatagramSendState::Sent
                    | vot_transport_api::DatagramSendState::Canceled
            ),
            "never acknowledged: {:?}",
            state.1
        );
    }

    #[test]
    fn a_close_reaches_the_peer_as_a_disconnect() {
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });
        client
            .close(vot_codec::error_code::RESOURCE_LIMIT)
            .expect("a close under a registered code");
        let (_, from_server) = pump_until(&mut client, &mut server, 15, |_, b| {
            b.iter()
                .any(|event| matches!(event, Event::Disconnected(_)))
        });
        assert!(
            from_server
                .iter()
                .any(|event| matches!(event, Event::Disconnected(_))),
            "the peer heard the connection end"
        );
    }

    /// What one lane carries over loopback, in bytes per second.
    ///
    /// Ignored because it is a measurement rather than a rule: a shared machine
    /// makes the number vary, and a threshold here would fail for reasons that
    /// have nothing to do with the carrier. Run it when the pump changes:
    ///
    /// ```text
    /// cargo test -p vot-transport-quiche --features live --release \
    ///     one_lane_throughput -- --ignored --nocapture
    /// ```
    ///
    /// It exists because the adapter can be the ceiling rather than the engine,
    /// which is exactly what PERF-001 must not measure. A number far below the
    /// link says to look here first.
    #[test]
    #[ignore = "a measurement, not a rule"]
    fn one_lane_throughput() {
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });

        let payload = vec![0x5a; vot_transport_api::MAX_DATA_RECORD_BYTES];
        let bytes = record(&payload);
        // Shared once. The contract has a shared-payload submission for exactly
        // this reason, and a caller that copies every record is measuring its own
        // copy as much as the carrier's work.
        let shared = vot_transport_api::shared_payload(&bytes);
        // Enough that the handshake and slow start are not most of the run. A
        // short measurement here varied by a factor of two between identical
        // runs, which is no basis for judging a change.
        let target = 2_048_usize;
        let started = Instant::now();
        let mut sent = 0_usize;
        let mut received = 0_usize;
        let mut carried = 0_u64;
        let deadline = started + Duration::from_secs(120);
        while received < target && Instant::now() < deadline {
            while sent < target {
                match client.send_reliable_shared(StreamId(0), Payload::clone(&shared)) {
                    Ok(()) => sent += 1,
                    // The queue is full, which is the backpressure this exists to
                    // measure rather than an error.
                    Err(_) => break,
                }
            }
            let _ = client.flush();
            let _ = server.flush();
            while let Some(event) = server.poll() {
                if let Event::Reliable { bytes, .. } = event {
                    received += 1;
                    carried += bytes.len() as u64;
                }
            }
            while client.poll().is_some() {}
        }
        let elapsed = started.elapsed();
        assert_eq!(received, target, "every record arrived in {elapsed:?}");
        assert_eq!(carried, (target * bytes.len()) as u64, "every byte of them");
        // Integer arithmetic, so the report needs no cast a lint has to forgive.
        // Nanoseconds keep the ratio exact at any rate this carries.
        let nanos = elapsed.as_nanos().max(1);
        let per_second = u64::try_from(u128::from(carried) * 1_000_000_000 / nanos).unwrap_or(0);
        // Megabits, because a gigabit rounded to an integer says almost nothing
        // at this scale and a float needs a cast a lint has to forgive.
        let megabits_per_second = per_second / 125_000;
        println!(
            "one lane, one worker: {received} records, {carried} bytes in {elapsed:?} \
             = {per_second} bytes/s = {megabits_per_second} Mbit/s"
        );
    }

    #[test]
    fn a_pair_carries_records_at_a_datagram_size_the_path_allows() {
        // Loopback carries 65536, so the ceiling itself is a real configuration
        // here: 65507 plus the IP and UDP headers is exactly IPv4's 65535-byte
        // total length. Sending at it is what proves the constant is a size
        // the socket carries rather than one validation merely accepts.
        let (certificate, key) = credentials();
        let mut server_config = Config::server(limits(), certificate, key);
        server_config.max_datagram_bytes = super::LARGEST_DATAGRAM_SIZE;
        let server = Transport::serve("127.0.0.1:0".parse().expect("an address"), &server_config)
            .expect("a server");
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        client_config.max_datagram_bytes = super::LARGEST_DATAGRAM_SIZE;
        let mut client = Transport::connect(
            "127.0.0.1:0".parse().expect("an address"),
            server.local_address(),
            Some("localhost"),
            &client_config,
        )
        .expect("a client");
        let mut server = server;
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });

        // A record several datagrams long either way, so the size is exercised
        // rather than merely accepted.
        let payload = vec![0x27; 200_000];
        let frame = record(&payload);
        client
            .send_reliable(StreamId(0), &frame)
            .expect("a record the lane carries");
        let (_, from_server) = pump_until(&mut client, &mut server, 10, |_, b| {
            b.iter()
                .any(|event| matches!(event, Event::Reliable { .. }))
        });
        let carried = from_server
            .iter()
            .find_map(|event| match event {
                Event::Reliable { bytes, .. } => Some(bytes.clone()),
                _ => None,
            })
            .expect("the record arrived");
        assert_eq!(carried.as_ref(), frame.as_slice());

        // The record can arrive while discovery is still climbing, so carrying
        // it does not yet prove the ceiling. Discovery's first probe is the
        // ceiling itself, and on a path that carries it the discovered size
        // lands there exactly; a ceiling the socket refuses can never be a
        // discovered size, which is what makes this an assertion and not a
        // wait. A budget of passes bounds the loop, not a clock.
        let target = u64::try_from(super::LARGEST_DATAGRAM_SIZE).expect("a size fits");
        let mut discovered = None;
        for _ in 0_u32..5_000 {
            let _ = client.flush();
            let _ = server.flush();
            while client.poll().is_some() {}
            while server.poll().is_some() {}
            discovered = client.path_stats().and_then(|stats| stats.mtu_bytes);
            if discovered == Some(target) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            discovered,
            Some(target),
            "discovery never reached the ceiling"
        );
    }

    #[test]
    fn a_datagram_size_the_protocol_cannot_carry_is_refused() {
        // Under the QUIC initial-packet floor no handshake can complete, and
        // past a UDP payload nothing can be sent at all. Both are configuration
        // errors rather than connections that fail later for no stated reason.
        let (certificate, key) = credentials();
        for size in [
            0,
            1,
            super::MIN_DATAGRAM_SIZE - 1,
            super::LARGEST_DATAGRAM_SIZE + 1,
        ] {
            let mut config = Config::server(limits(), certificate.clone(), key.clone());
            config.max_datagram_bytes = size;
            assert!(
                matches!(
                    Transport::serve("127.0.0.1:0".parse().expect("an address"), &config),
                    Err(Error::InvalidConfiguration)
                ),
                "a datagram size of {size} was accepted"
            );
        }
        // The edges themselves are allowed.
        for size in [super::MIN_DATAGRAM_SIZE, super::LARGEST_DATAGRAM_SIZE] {
            let mut config = Config::server(limits(), certificate.clone(), key.clone());
            config.max_datagram_bytes = size;
            assert!(
                Transport::serve("127.0.0.1:0".parse().expect("an address"), &config).is_ok(),
                "a datagram size of {size} was refused"
            );
        }
    }

    #[test]
    fn an_endpoint_that_is_dropped_gives_its_port_back() {
        // The driver owns the socket, so it has to stop before the endpoint is
        // gone. A port still bound afterwards is a driver still running.
        let address = {
            let (client, _server) = pair();
            client.local_address()
        };
        assert!(
            UdpSocket::bind(address).is_ok(),
            "the port outlived the endpoint"
        );
    }

    #[test]
    fn the_inbound_budget_counts_charges_and_refunds() {
        // The queue's byte budget is what keeps a peer from holding this
        // endpoint's memory; each bound is asserted at its exact edge.
        let inbound = Inbound {
            bytes: 2,
            assembling: 3,
            ..Inbound::default()
        };
        assert_eq!(inbound.charged(), 5);

        let mut inbound = Inbound {
            assembling: MAX_ASSEMBLY_BYTES - 8,
            ..Inbound::default()
        };
        assert!(
            inbound.push(NativeEvent::Control(vec![7_u8; 8].into())),
            "an exact fit was refused"
        );
        assert_eq!(inbound.bytes, 8);
        assert!(
            !inbound.push(NativeEvent::Control(vec![7_u8; 1].into())),
            "a byte past the budget was accepted"
        );

        let mut inbound = Inbound::default();
        for _ in 0..MAX_INBOUND_EVENTS {
            assert!(inbound.push(NativeEvent::Control(vec![].into())));
        }
        assert!(
            !inbound.push(NativeEvent::Control(vec![].into())),
            "an event past the count was accepted"
        );

        let mut inbound = Inbound::default();
        assert!(inbound.push(NativeEvent::Control(vec![7_u8; 10].into())));
        assert_eq!(inbound.bytes, 10);
        let _ = inbound.pop();
        assert_eq!(inbound.bytes, 0, "a popped event kept its charge");
    }

    #[test]
    fn the_assembly_budget_reserves_to_the_bound_and_releases() {
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        assert!(
            budget.reserve(MAX_ASSEMBLY_BYTES),
            "an exact fit was refused"
        );
        assert!(!budget.reserve(1), "a byte past the budget was reserved");
        budget.release(MAX_ASSEMBLY_BYTES);
        assert!(budget.reserve(1), "a released budget stayed spent");
        assert_eq!(inbound.lock().expect("the queue").assembling, 1);
    }

    #[test]
    fn a_connection_id_is_full_length_and_keyed_to_the_address() {
        // The exact bytes for port 4433, written out so a changed derivation
        // is a changed vector rather than a recomputed one.
        let id = scid_for("127.0.0.1:4433".parse().expect("an address"));
        assert_eq!(
            id.as_ref(),
            [
                17, 81, 79, 174, 141, 236, 203, 42, 9, 104, 71, 166, 133, 228, 195, 34, 1, 96, 63,
                158
            ]
        );
        let other = scid_for("127.0.0.1:4434".parse().expect("an address"));
        assert_ne!(id.as_ref(), other.as_ref());
    }

    #[test]
    fn a_coalesced_read_survives_every_segment_the_kernel_reports() {
        // A zero segment must fall back to the whole buffer: walking a buffer
        // in zero-sized steps is a panic, and the kernel owns the value.
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let peer: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a configuration");
        config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("a protocol");
        let scid = scid_for(local);
        let mut conn =
            quiche::connect(Some("localhost"), &scid, local, peer, &mut config).expect("a client");
        let mut junk = [0_u8; 64];
        feed_received(&mut conn, local, &mut junk, peer, Some(0));
        feed_received(&mut conn, local, &mut junk, peer, Some(16));
        feed_received(&mut conn, local, &mut junk, peer, None);
    }

    /// Carries everything one sans-IO connection has to say to the other.
    fn shuttle(
        a: &mut quiche::Connection,
        a_address: SocketAddr,
        b: &mut quiche::Connection,
        b_address: SocketAddr,
    ) {
        let mut packet = [0_u8; 2_048];
        while let Ok((written, _)) = a.send(&mut packet) {
            let info = quiche::RecvInfo {
                from: a_address,
                to: b_address,
            };
            let _ = b.recv(&mut packet[..written], info);
        }
    }

    #[test]
    fn a_record_split_by_flow_control_still_completes() {
        // The live pair above can never split a record: its stream window is
        // a megabyte and a record's bound is a quarter of that. This pair's
        // window is smaller than one record, so the outbox has to find the
        // record's end across passes rather than in the first one.
        let (certificate, key) = credentials();
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let window = 2_048_u64;
        let mut client_config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a configuration");
        client_config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("a protocol");
        client_config.verify_peer(false);
        client_config.set_initial_max_data(1_000_000);
        client_config.set_initial_max_stream_data_bidi_local(window);
        client_config.set_initial_max_stream_data_bidi_remote(window);
        client_config.set_initial_max_streams_bidi(16);
        let mut server_config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a configuration");
        server_config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("a protocol");
        server_config
            .load_cert_chain_from_pem_file(&certificate)
            .expect("the certificate");
        server_config
            .load_priv_key_from_pem_file(&key)
            .expect("the key");
        server_config.set_initial_max_data(1_000_000);
        server_config.set_initial_max_stream_data_bidi_local(window);
        server_config.set_initial_max_stream_data_bidi_remote(window);
        server_config.set_initial_max_streams_bidi(16);
        let mut client = quiche::connect(
            Some("localhost"),
            &scid_for(local),
            local,
            remote,
            &mut client_config,
        )
        .expect("a client");
        let mut server = quiche::accept(&scid_for(remote), None, remote, local, &mut server_config)
            .expect("a server");

        for _ in 0_u32..64 {
            shuttle(&mut client, local, &mut server, remote);
            shuttle(&mut server, remote, &mut client, local);
            if client.is_established() && server.is_established() {
                break;
            }
        }
        assert!(client.is_established() && server.is_established());

        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(1_000_000));
        let mut streams = BTreeMap::new();
        let stream = stream_state(
            &mut streams,
            4,
            StreamKind::Reliable { lane: 0 },
            &budget,
            &control_limit,
        );
        stream.outbox.push_back((vec![0x27_u8; 8_192].into(), 0));

        let mut drain = [0_u8; 4_096];
        let mut delivered = 0_usize;
        for _ in 0_u32..256 {
            write_outbox(&mut client, stream);
            shuttle(&mut client, local, &mut server, remote);
            while let Ok((read, _)) = server.stream_recv(4, &mut drain) {
                delivered += read;
            }
            shuttle(&mut server, remote, &mut client, local);
            if stream.outbox.is_empty() {
                break;
            }
        }
        assert!(
            stream.outbox.is_empty(),
            "a split record never completed; {delivered} of 8192 bytes arrived"
        );
        assert_eq!(delivered, 8_192);
    }

    #[test]
    fn a_full_queue_pauses_the_stream_instead_of_closing_it() {
        // A caller that has not drained the queue is this endpoint's own lag.
        // The connection must wait for it, not close: the fault path here
        // used to kill the carrier with RESOURCE_LIMIT the moment the spine
        // fell behind, which took every multi-rail transfer down with it.
        let (certificate, key) = credentials();
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let mut client_config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a configuration");
        client_config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("a protocol");
        client_config.verify_peer(false);
        client_config.set_initial_max_data(10_000_000);
        client_config.set_initial_max_stream_data_bidi_local(1_000_000);
        client_config.set_initial_max_stream_data_bidi_remote(1_000_000);
        client_config.set_initial_max_streams_bidi(16);
        let mut server_config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a configuration");
        server_config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("a protocol");
        server_config
            .load_cert_chain_from_pem_file(&certificate)
            .expect("the certificate");
        server_config
            .load_priv_key_from_pem_file(&key)
            .expect("the key");
        server_config.set_initial_max_data(10_000_000);
        server_config.set_initial_max_stream_data_bidi_local(1_000_000);
        server_config.set_initial_max_stream_data_bidi_remote(1_000_000);
        server_config.set_initial_max_streams_bidi(16);
        let mut client = quiche::connect(
            Some("localhost"),
            &scid_for(local),
            local,
            remote,
            &mut client_config,
        )
        .expect("a client");
        let mut server = quiche::accept(&scid_for(remote), None, remote, local, &mut server_config)
            .expect("a server");
        for _ in 0_u32..64 {
            shuttle(&mut client, local, &mut server, remote);
            shuttle(&mut server, remote, &mut client, local);
            if client.is_established() && server.is_established() {
                break;
            }
        }
        assert!(client.is_established() && server.is_established());

        // One whole control frame on the wire toward the server.
        let mut frame = Vec::new();
        vot_codec::encode_frame(vot_codec::frame_type::SETTINGS, &[0x27; 64], &mut frame)
            .expect("a frame");
        client
            .stream_send(CONTROL_STREAM_ID, &frame, false)
            .expect("a stream");
        shuttle(&mut client, local, &mut server, remote);

        // A queue with no room for anything: the budget is fully assembling.
        let inbound = Arc::new(Mutex::new(Inbound {
            assembling: MAX_ASSEMBLY_BYTES,
            ..Inbound::default()
        }));
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(1_000_000));
        let mut streams = BTreeMap::new();
        let mut buffer = vec![0_u8; vot_transport_framing::MAX_PARTIAL_FRAME.max(65_535)];
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(!server.is_closed(), "a full queue closed the connection");
        assert!(
            inbound.lock().expect("the queue").events.is_empty(),
            "a full queue still accepted an event"
        );

        // The caller drains; the paused stream delivers on the next pass.
        inbound.lock().expect("the queue").assembling = 0;
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(!server.is_closed());
        assert_eq!(
            inbound.lock().expect("the queue").events.len(),
            1,
            "the paused frame never arrived"
        );
    }

    #[test]
    fn the_shared_surface_answers_like_the_direct_one() {
        // Every passthrough answers with the adapter's judgment; a stub that
        // says yes to all of these is a carrier lying about its bounds.
        let (mut client, _server) = pair();
        let oversized: Payload =
            vec![7_u8; 2 * vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD + 64].into();
        assert!(client.send_control_shared(oversized).is_err());
        let record: Payload = vec![7_u8; 8].into();
        assert!(
            client
                .send_reliable_shared(StreamId(u64::MAX), Arc::clone(&record))
                .is_err()
        );
        assert!(
            client
                .preflight_reliable_batch(StreamId(u64::MAX), &[record])
                .is_err()
        );
        assert!(matches!(
            client.set_receive_credit(1),
            Err(Error::Unsupported)
        ));
        assert!(client.set_control_payload_limit(0).is_err());
        assert_eq!(client.receive_limits(), Some(limits()));
    }
}
