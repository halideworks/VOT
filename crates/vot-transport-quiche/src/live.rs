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

/// Largest UDP payload either direction, which bounds every read buffer here.
const MAX_DATAGRAM_SIZE: usize = 1_350;

/// Most events the driver holds for a caller that has not drained them.
const MAX_INBOUND_EVENTS: usize = 1_024;

/// How long the driver waits on the socket when the connection asks for longer.
///
/// The connection's own timeout is the deadline that matters; this caps it so a
/// submission or a close request handed over between packets is noticed rather
/// than waiting on the peer. It is the latency a caller pays for the driver
/// owning the socket, and it is why this is a bound rather than a poll interval.
const TICK: Duration = Duration::from_millis(1);

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
        true
    }

    /// Queues a connection lifecycle event past both bounds.
    ///
    /// Losing one is not survivable: a caller that never hears the disconnect
    /// waits for a peer that has gone. There are at most two per connection.
    fn push_lifecycle(&mut self, event: NativeEvent) {
        debug_assert_eq!(native_payload_len(&event), 0);
        self.events.push_back(event);
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
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
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
    /// Bytes accepted from the caller that the connection has not taken yet.
    /// A stream's flow control is the peer's, so a record may be written in
    /// pieces across several loops.
    outbox: VecDeque<Vec<u8>>,
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
) -> Result<(), Error> {
    let budget = SharedBudget(Arc::clone(inbound));
    // Heap rather than stack: a QUIC datagram is small, but a stream read is
    // whatever the connection has buffered, and a driver thread's stack is not
    // the place for it.
    let mut buffer = vec![0_u8; 65_535];
    let mut out = [0_u8; MAX_DATAGRAM_SIZE];
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
        let Ok(paced) = send_all(socket, &mut conn, &mut out) else {
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
        match socket.recv_from(&mut buffer) {
            Ok((len, from)) => {
                let info = quiche::RecvInfo { from, to: local };
                // A packet this connection cannot read is not this connection's
                // problem: another peer's or a stray one, and dropping it is what
                // spec/security.md section 7 asks for rather than answering it.
                let _ = conn.recv(&mut buffer[..len], info);
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
        drain_datagrams(&mut conn);
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
            let mut out = [0_u8; MAX_DATAGRAM_SIZE];
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
) -> Result<Option<Instant>, Error> {
    loop {
        match conn.send(out) {
            Ok((written, info)) => {
                if socket.send_to(&out[..written], info.to).is_err() {
                    return Err(Error::Backend);
                }
                // Pacing is the connection's decision, and it applies to what
                // comes after this packet rather than to this one, which is
                // already in flight as far as the connection is concerned.
                if info.at > Instant::now() {
                    return Ok(Some(info.at));
                }
            }
            Err(quiche::Error::Done) => return Ok(None),
            Err(_) => return Err(Error::Backend),
        }
    }
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
            state.outbox.push_back(bytes.to_vec());
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
            state.outbox.push_back(bytes.to_vec());
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
        id,
    })
}

/// Writes what a stream has waiting, as far as flow control allows.
fn write_outbox(conn: &mut quiche::Connection, stream: &mut StreamState) {
    let id = stream.id;
    while let Some(front) = stream.outbox.front_mut() {
        match conn.stream_send(id, front, false) {
            Ok(written) if written == front.len() => {
                stream.outbox.pop_front();
            }
            // Flow control is the peer's, so a record may go in pieces. What was
            // taken is dropped and the rest waits for the next pass, which is the
            // same answer as nothing having been taken at all.
            Ok(written) => {
                front.drain(..written);
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
        while let Ok((len, fin)) = conn.stream_recv(id, buffer) {
            let kind = state.kind;
            let sequence = &mut state.sequence;
            let outcome = state.framing.accept(&buffer[..len], |frame| {
                *sequence = sequence.wrapping_add(1);
                let event = match kind {
                    StreamKind::Control => NativeEvent::Control(frame.to_vec()),
                    StreamKind::Reliable { lane } => NativeEvent::Reliable {
                        lane,
                        sequence: *sequence,
                        bytes: frame.to_vec(),
                    },
                };
                let Ok(mut queue) = inbound.lock() else {
                    return Err(FrameFault::exhausted());
                };
                if queue.push(event) {
                    Ok(())
                } else {
                    // The driver cannot wait, so a queue the caller has not
                    // drained fails the connection loudly rather than growing
                    // without limit.
                    Err(FrameFault::exhausted())
                }
            });
            if let Err(fault) = outcome {
                let _ = conn.close(true, u64::from(fault.close()), b"");
                return;
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
fn drain_datagrams(conn: &mut quiche::Connection) {
    let mut buffer = [0_u8; MAX_DATAGRAM_SIZE];
    while conn.dgram_recv(&mut buffer).is_ok() {}
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
        let target = 256_usize;
        let started = Instant::now();
        let mut sent = 0_usize;
        let mut received = 0_usize;
        let mut carried = 0_u64;
        let deadline = started + Duration::from_secs(30);
        while received < target && Instant::now() < deadline {
            while sent < target {
                match client.send_reliable(StreamId(0), &bytes) {
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
}
