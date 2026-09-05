//! The pump: a driver thread owns the socket, connection, and loss recovery
//! timer. quiche does no I/O of its own.
//!
//! Every hop is bounded so a slow application is backpressure, not a broken
//! connection.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vot_transport_api::{
    CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ChannelBinding, ConnectionId, Error,
    Event, PathStats, Payload, ReceiveLimits, StreamId, TransportAdapter,
};
use vot_transport_framing::{AssemblyBudget, FrameFault, Framing, StreamKind};

use crate::{
    CONTROL_STREAM_ID, Command, MAX_ASSEMBLY_BYTES, NativeEvent, QuicheAdapter, Role,
    lane_for_stream, stream_for_lane,
};

#[derive(Clone, Debug)]
struct SharedBuf {
    bytes: Payload,
    start: usize,
    end: usize,
}

impl AsRef<[u8]> for SharedBuf {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[self.start..self.end]
    }
}

impl quiche::BufSplit for SharedBuf {
    fn split_at(&mut self, at: usize) -> Self {
        let middle = self.start + at;
        assert!(middle <= self.end);
        let tail = Self {
            bytes: self.bytes.clone(),
            start: middle,
            end: self.end,
        };
        self.end = middle;
        tail
    }
}

#[derive(Clone, Debug, Default)]
struct SharedBufFactory;

impl quiche::BufFactory for SharedBufFactory {
    type Buf = SharedBuf;
    type DgramBuf = Vec<u8>;

    fn buf_from_slice(buf: &[u8]) -> Self::Buf {
        SharedBuf {
            bytes: Payload::from(buf),
            start: 0,
            end: buf.len(),
        }
    }

    fn dgram_buf_from_slice(buf: &[u8]) -> Self::DgramBuf {
        buf.to_vec()
    }
}

type Connection = quiche::Connection<SharedBufFactory>;

/// Largest UDP payload either direction when a caller names none.
///
/// A ceiling, not a path claim: discovery settles under it where a tunnel or
/// IPv6 header narrows the way. The socket refuses fragments so an oversized
/// probe is dropped rather than reassembled into a false success.
const MAX_DATAGRAM_SIZE: usize = 1_472;

/// QUIC's idle timeout, which is what actually closes an idle connection.
///
/// Deliberately not the registered `IDLE_TIMEOUT_MS` default, and deliberately
/// shorter. The two are different things doing different jobs: the registered
/// one is negotiated and installed by nothing, and this one is the transport
/// parameter. `vot-cli`'s `STALLED_WAIT_MS` is documented as the backstop
/// behind this, so raising it past 30 seconds would make the backstop the
/// primary and surface a dead peer as a stall rather than a disconnect.
const IDLE_TIMEOUT_MS: u64 = 30_000;

/// The smallest datagram a caller may ask for.
///
/// QUIC requires an endpoint to carry a 1200-byte initial datagram, so anything
/// under this cannot complete a handshake.
pub const MIN_DATAGRAM_SIZE: usize = 1_200;

/// What the socket asks the kernel to hold in each direction.
///
/// Sized near the bandwidth-delay product of the paths this serves: a
/// gigabit and a fifth of a second is 26 MB in flight, and a seeded
/// congestion window puts thousands of packets on the wire in one round
/// trip where the previous 4 MB request held under 3,000 of them; a
/// counter capture on an emulated 200 ms path showed 1,860 of one seeded
/// 16 MB fetch's packets dropping at the receive buffer. The kernel
/// grants this in full under `CAP_NET_ADMIN` and clamps it to its own caps
/// otherwise. Send is half receive because the pump paces its own bursts
/// out.
const RECEIVE_BUFFER_BYTES: u32 = 16_777_216;
const SEND_BUFFER_BYTES: u32 = 8_388_608;

/// What an operator can do about a clamped buffer, which is a different knob
/// on each kernel and none at all where nothing clamps silently.
#[cfg(target_os = "linux")]
const RECEIVE_CLAMP_HINT: &str = "raise net.core.rmem_max (sysctl) or run with CAP_NET_ADMIN, or expect packet loss at high rates";
#[cfg(target_os = "linux")]
const SEND_CLAMP_HINT: &str = "raise net.core.wmem_max (sysctl) or run with CAP_NET_ADMIN, or expect packet loss at high rates";
#[cfg(target_os = "macos")]
const RECEIVE_CLAMP_HINT: &str =
    "raise kern.ipc.maxsockbuf (sysctl), or expect packet loss at high rates";
#[cfg(target_os = "macos")]
const SEND_CLAMP_HINT: &str =
    "raise kern.ipc.maxsockbuf (sysctl), or expect packet loss at high rates";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const RECEIVE_CLAMP_HINT: &str = "expect packet loss at high rates";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const SEND_CLAMP_HINT: &str = "expect packet loss at high rates";

/// Sizes a socket's buffers, best effort: they are throughput, not
/// correctness. A kernel that clamps the request sheds packets under bursts
/// with no other signal, so say so once per process.
fn size_buffers_reporting_clamps(socket: &UdpSocket) {
    static RECEIVE_WARNED: Once = Once::new();
    static SEND_WARNED: Once = Once::new();

    if let Ok(granted) =
        vot_platform_net::size_buffers(socket, RECEIVE_BUFFER_BYTES, SEND_BUFFER_BYTES)
    {
        if let Some(got) =
            vot_platform_net::buffer_shortfall(RECEIVE_BUFFER_BYTES, granted.receive_bytes)
        {
            RECEIVE_WARNED.call_once(|| {
                eprintln!(
                    "vot: UDP receive buffer is {got} bytes, asked for {RECEIVE_BUFFER_BYTES}; {RECEIVE_CLAMP_HINT}"
                );
            });
        }
        if let Some(got) = vot_platform_net::buffer_shortfall(SEND_BUFFER_BYTES, granted.send_bytes)
        {
            SEND_WARNED.call_once(|| {
                eprintln!(
                    "vot: UDP send buffer is {got} bytes, asked for {SEND_BUFFER_BYTES}; {SEND_CLAMP_HINT}"
                );
            });
        }
    }
}

/// Largest UDP payload: IPv4's 65535-byte total length minus its own and
/// UDP's headers. Not worth a family-dependent ceiling for IPv6's extra 20
/// bytes.
///
/// Public so a caller that trusts discovery entirely can set it as the
/// ceiling where probing stops.
pub const LARGEST_DATAGRAM_SIZE: usize = 65_507;

/// Most events the driver holds for a caller that has not drained them.
///
/// Datagrams are not held to this bound; they have their own, below.
const MAX_INBOUND_EVENTS: usize = 1_024;

/// Bounds the burst one pump pass hands the socket. A receiver whose kernel
/// clamped its 16 MiB buffer request to `rmem_max` drops from a 1,024 burst
/// and absorbs 256; what quiche will not take waits in the outbox, so the
/// small bound loses nothing.
const DATAGRAM_QUEUE_LEN: usize = 256;

/// Datagrams quiche queues inbound before it silently discards the oldest.
///
/// Sized so the queue can hold every datagram the driver's own inbound
/// account admits: at 1,024 the queue held 1.2 MB under the 32 MB account of
/// the day, since doubled below, and a seeded first flight overran it between
/// driver passes, so quiche discarded whole coding epochs below every counter
/// this stack owns. The account admits at most
/// [`MAX_DATAGRAM_INBOUND_EVENTS`] datagrams whatever their size, because its
/// byte bound is what governs at half a kilobyte and up, so that count is the
/// most the queue is ever asked to hold in both units.
const DATAGRAM_RECV_QUEUE_LEN: usize = MAX_DATAGRAM_INBOUND_EVENTS;
const _: () = assert!(DATAGRAM_RECV_QUEUE_LEN == 131_072);

/// The ceiling quiche autotunes a receive window up to, per stream and for
/// the connection.
///
/// The window over the round trip is the most one connection can carry, so
/// the library's own 16 MiB stream ceiling held an 80 ms path to 0.83
/// Gbit/s however much this end advertised, and 32 MiB took the same
/// transfer to 1.23. What a ceiling bounds is what a peer could make the
/// carrier hold for a stream this end asked for, not a working set: a peer
/// sends only what was requested, within its own credit: the sized arm's
/// fetch peak resident set moved 3 MiB while this moved 32.
///
/// 64 MiB is where the ceiling stops binding against the request credit
/// beside it. At four outstanding covers the credit bound every round trip
/// and this constant was worth 0.7% at 80 ms; at eight, 32 MiB refused 593
/// to 791 sends a second with stream capacity 0 while 12 to 25 MB of
/// connection credit and 11 to 12 MB of congestion window sat free, and 64
/// MiB moves the binder to the congestion window. 128 MiB measured flat
/// against 64 at eight covers, 284.1 MB/s against 289.0 at 80 ms and 159.8
/// against 159.3 at 160, because the congestion window binds first.
///
/// The connection ceiling is half again the stream one because the library
/// raises a connection window to 1.5 times the stream window on each grant
/// and clamps it here, so an equal figure would pin the connection window
/// at the stream window.
const STREAM_WINDOW_CEILING: u64 = 64 * 1_024 * 1_024;
const CONNECTION_WINDOW_CEILING: u64 = STREAM_WINDOW_CEILING / 2 * 3;
const _: () = assert!(STREAM_WINDOW_CEILING == 67_108_864);
const _: () = assert!(CONNECTION_WINDOW_CEILING == 100_663_296);
/// The initial window this endpoint advertises for a control-frame limit.
///
/// The advertised bound has to fit a conforming control frame plus a record,
/// or the carrier refuses a frame the session promised to accept, and it is
/// sixteenfold rather than eightfold because what is advertised before the
/// first grant is what a rail rides on while autotuning climbs. The shipped
/// 1 MiB limit puts that at 20,971,776 bytes.
///
/// Clamped at the ceiling because the limit is configurable: the spec's
/// largest legal control payload is 16 MiB, which would advertise
/// 272,630,016 bytes, past both ceilings, and quiche never retracts flow
/// control once it has granted it.
fn advertised_window(control_payload: u64) -> u64 {
    control_payload
        .saturating_add(vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES as u64)
        .saturating_mul(16)
        .min(STREAM_WINDOW_CEILING)
}

/// The shipped limit's advertised window sits under the ceiling on its own,
/// so the clamp above is for a configured limit and never for the default.
const _: () = assert!(
    STREAM_WINDOW_CEILING
        > (vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD as u64
            + vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES as u64)
            * 16
);

/// Datagrams the driver holds for a connection whose own queue is full.
///
/// A refused datagram waits here instead of being thrown away, so a sender
/// that offers a burst larger than the connection's queue loses none of it
/// to a moment's fullness. Held apart from the outbox budget rather than
/// charged to it: charging them starves the control stream behind them, and
/// a fetch whose bundles cannot get out stalls instead of slowing down.
///
/// Bounded in both units, because a datagram may be as large as
/// `MAX_DATAGRAM_BYTES` and a count alone would let a peer hold that many
/// times 64 KiB against no budget at all. At either bound the driver stops
/// taking submissions until the connection makes room.
///
/// Sized small on purpose. What waits here has left the sender's own queue
/// but is not on the wire, and a serve reads its queue emptying as "the
/// symbols are on the carrier" when it decides an epoch has gone quiet. Hold
/// much more than this and an epoch is repaired reliably while its symbols
/// are still going out, so the same bytes are paid for twice: a megabyte
/// clears in well under the serve's grace on any path fast enough to be
/// worth coding for.
const DATAGRAM_OUTBOX_LEN: usize = 2_048;
const DATAGRAM_OUTBOX_BYTES: usize = 1 << 20;

/// Received datagram bytes the driver holds for a caller that has not drained
/// them, in their own account beside the shared budget so a flood of them
/// cannot starve the stream reader's headroom.
///
/// Sized to what the wire's own datagram credit invites: the receiver
/// advertises its request credit (34,078,720 bytes) as `max_unretired_bytes`,
/// and a conforming sender may have that many generation bytes of symbols
/// in flight, which with the repair overhead is about 44 MB. The old
/// quarter-of-assembly cap (4 MB) sat far under that invitation, and the
/// pump silently dropped the difference whenever the session thread fell a
/// burst behind: 8-10% of a coded transfer's symbols on a clean path,
/// bimodally, measured on the netem rig. A bound the credit can outspend
/// is the PR 301 class again, one layer up, so this follows the staging
/// capacity: eight outstanding covers doubled it and this doubles with it.
const MAX_DATAGRAM_INBOUND_BYTES: usize = 64 * 1024 * 1024;
const _: () = assert!(MAX_DATAGRAM_INBOUND_BYTES == 67_108_864);

/// Received datagrams the driver holds for a caller that has not drained them.
///
/// Counted apart from [`MAX_INBOUND_EVENTS`], which is a bound on how many
/// records a caller may fall behind by and is met by a datagram burst long
/// before the byte cap above is. A datagram count bound is still needed,
/// because bytes alone do not bound a flood of tiny ones; at half a kilobyte
/// each the byte cap is what governs, which is what it was sized to do.
const MAX_DATAGRAM_INBOUND_EVENTS: usize = MAX_DATAGRAM_INBOUND_BYTES / 512;

/// The bound datagrams left has to be the smaller of the two, or separating
/// them holds them to a count tighter than the one they shared.
const _: () = assert!(MAX_DATAGRAM_INBOUND_EVENTS > MAX_INBOUND_EVENTS);

/// What the driver holds across every outbox before it stops taking submissions.
///
/// Matches the caller's own queue byte bound. A peer that stops reading fills
/// this and the refusal travels back as `OutboundQueueFull`.
///
/// Not measured against the connection's windows: an outbox holds only what
/// `stream_send` refused, so a full one means the connection is already
/// blocked on congestion or flow control.
const MAX_QUEUED_BYTES: usize = vot_transport_queue::DEFAULT_BYTE_LIMIT;

/// Record count bound, because bytes alone do not bound a flood of small ones.
/// A kilobyte a record, so anything larger meets the byte bound first.
const MAX_QUEUED_RECORDS: usize = MAX_QUEUED_BYTES / 1_024;

/// How long the driver waits on the socket when the connection asks for longer.
///
/// Caps the connection's timeout so a submission or close request handed over
/// between packets is noticed rather than waiting on the peer.
const TICK: Duration = Duration::from_millis(1);

/// Datagrams taken from the kernel in one pass beyond the first.
///
/// Draining arrivals as a batch lets the connection coalesce acknowledgements
/// and generate sends in bursts rather than lockstep one syscall per packet.
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
    /// Received datagram bytes, in their own account beside `bytes`.
    datagram_bytes: usize,
    /// Datagrams among `events`, counted on their own so a burst of them does
    /// not meet a bound that exists for the records beside them.
    datagram_events: usize,
    /// Raised on every push, waited on by `wait_for_event`. Shared so a
    /// waiter holds no lock the pump needs while it sleeps.
    arrived: Arc<vot_transport_api::EventSignal>,
}

impl Inbound {
    const fn charged(&self) -> usize {
        self.bytes + self.assembling
    }

    /// Whether an event of this class is already at its count bound.
    fn counted_out(&self, datagram: bool) -> bool {
        // A datagram removed from `events` without `pop` would leave this
        // count high, and the subtraction below would saturate to no bound at
        // all rather than fail.
        debug_assert!(self.datagram_events <= self.events.len());
        if datagram {
            self.datagram_events >= MAX_DATAGRAM_INBOUND_EVENTS
        } else {
            self.events.len().saturating_sub(self.datagram_events) >= MAX_INBOUND_EVENTS
        }
    }

    /// Queues one event, or gives it back when its class's bound is met.
    /// Datagrams live entirely in their own account: their bytes never
    /// charge the assembly budget, so a symbol flood cannot stall the
    /// stream reader, and the stream cannot shrink the room the datagram
    /// credit invited.
    fn push(&mut self, event: NativeEvent) -> Result<(), NativeEvent> {
        let payload = native_payload_len(&event);
        let datagram = matches!(event, NativeEvent::Datagram(_));
        if self.counted_out(datagram) {
            return Err(event);
        }
        if datagram {
            if self.datagram_bytes + payload > MAX_DATAGRAM_INBOUND_BYTES {
                return Err(event);
            }
            self.datagram_bytes += payload;
            self.datagram_events += 1;
        } else {
            let Some(next) = self.charged().checked_add(payload) else {
                return Err(event);
            };
            if next > MAX_ASSEMBLY_BYTES {
                return Err(event);
            }
            self.bytes += payload;
        }
        self.events.push_back(event);
        self.arrived.raise();
        Ok(())
    }

    /// Queues a zero-byte event that cannot be lost past both bounds.
    ///
    /// Lifecycle events number at most two per connection. Datagram states use
    /// this only while the driver exits, bounded by its fixed outbox.
    fn push_unlosable(&mut self, event: NativeEvent) {
        debug_assert_eq!(native_payload_len(&event), 0);
        self.events.push_back(event);
        self.arrived.raise();
    }

    fn pop(&mut self) -> Option<NativeEvent> {
        let event = self.events.pop_front()?;
        let payload = native_payload_len(&event);
        if matches!(event, NativeEvent::Datagram(_)) {
            self.datagram_bytes = self.datagram_bytes.saturating_sub(payload);
            self.datagram_events = self.datagram_events.saturating_sub(1);
        } else {
            self.bytes = self.bytes.saturating_sub(payload);
        }
        Some(event)
    }
}

fn native_payload_len(event: &NativeEvent) -> usize {
    match event {
        NativeEvent::Control(bytes)
        | NativeEvent::Reliable { bytes, .. }
        | NativeEvent::Datagram(bytes) => bytes.len(),
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

#[derive(Debug)]
struct AssemblyHold {
    inbound: Arc<Mutex<Inbound>>,
    bytes: usize,
}

impl Drop for AssemblyHold {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let mut inbound = self.inbound.lock().unwrap_or_else(PoisonError::into_inner);
        inbound.assembling = inbound
            .assembling
            .checked_sub(self.bytes)
            .unwrap_or(MAX_ASSEMBLY_BYTES);
        self.bytes = 0;
    }
}

impl AssemblyBudget for SharedBudget {
    type Hold = AssemblyHold;

    fn reserve(&self, bytes: usize) -> Option<Self::Hold> {
        let mut inbound = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let next = inbound.charged().checked_add(bytes)?;
        if next > MAX_ASSEMBLY_BYTES {
            return None;
        }
        inbound.assembling += bytes;
        Some(AssemblyHold {
            inbound: Arc::clone(&self.0),
            bytes,
        })
    }

    fn grow(&self, hold: &mut Self::Hold, bytes: usize) -> bool {
        let Some(total) = hold.bytes.checked_add(bytes) else {
            return false;
        };
        let mut inbound = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(next) = inbound.charged().checked_add(bytes) else {
            return false;
        };
        if next > MAX_ASSEMBLY_BYTES {
            return false;
        }
        inbound.assembling += bytes;
        hold.bytes = total;
        true
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
    /// Idle timeout in milliseconds, installed as QUIC's own.
    ///
    /// This is what actually closes an idle connection. The negotiated
    /// `IDLE_TIMEOUT_MS` cannot be: QUIC fixes its transport parameter during
    /// the handshake, before VOT negotiates anything. ADR-0035.
    pub idle_timeout_ms: u64,
    /// How long a server waits for its first packet, in milliseconds, or
    /// zero to wait for as long as it takes.
    ///
    /// Zero suits a server that exists to wait; a bound suits tests and
    /// callers that must fail rather than hang.
    pub accept_timeout_ms: u64,
    /// Largest UDP payload this endpoint sends or expects.
    ///
    /// [`MAX_DATAGRAM_SIZE`] unless a caller knows the path. One datagram is
    /// one syscall plus header protection and AEAD, so a path that can carry
    /// more and is not asked to wastes both per datagram.
    ///
    /// Discovery settles under this ceiling when the path is narrower.
    pub max_datagram_bytes: usize,
    /// The congestion controller this endpoint runs.
    pub congestion: CongestionControl,
    /// A TLS session a client resumes, as [`Transport::session_ticket`]
    /// returned it from an earlier connection to the same serve. Servers
    /// ignore it. What resumption spares is the certificate flight, not a
    /// round trip: this build sends nothing early.
    ///
    /// The blob is trust: a resumed handshake authenticates the serve with
    /// the pre-shared key inside it rather than a certificate, and the peer
    /// certificate it reports afterwards is whatever the blob carried, so a
    /// hostile blob defeats an identity pin. It must come from this
    /// process, or storage in the same trust domain as the pin, and never
    /// off the network.
    pub session: Option<Vec<u8>>,
    /// Initial congestion window in packets, or the controller's default.
    ///
    /// The sender's window governs a transfer, so this matters on the
    /// serving end. An operator who knows the path seeds it to skip most of
    /// slow start. Under Bbr2 the seed becomes the window's floor for the
    /// connection's life, and a seed past the recovery ceiling of 20,000
    /// packets pins the window outside congestion control entirely, so a
    /// caller bounds what it accepts well below that.
    pub initial_congestion_window_packets: Option<usize>,
    /// A lead byte whose datagrams are not this transport's, handed to
    /// the listener's side channel instead of routed.
    ///
    /// A caller sharing the socket with another protocol names the byte that
    /// tells them apart; without one every arrival is routed as QUIC.
    pub side_channel_lead: Option<u8>,
    /// Datagrams this endpoint sends twice at the start of a connection,
    /// or zero to send each once. ADR-0043.
    ///
    /// The copies buy the serial prefix against loss, where a lost packet
    /// waits on a recovery round trip that no other traffic can shorten.
    /// [`PREFIX_DUPLICATION_DATAGRAMS`] is the measured default.
    pub prefix_duplication_datagrams: usize,
    /// Whether a listener validates an address with QUIC Retry before accepting it.
    pub stateless_retry: bool,
}

/// Which congestion controller carries the connection.
///
/// The sender's controller governs a transfer, so the serving end's choice
/// is the one that matters. Bbr2 suits lossy wide-area paths; Cubic is the
/// default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CongestionControl {
    /// quiche's default controller.
    #[default]
    Cubic,
    /// `BBRv2` via quiche's gcongestion implementation, with quiche's pacing
    /// disabled: gcongestion's release-time schedule starves its own bandwidth
    /// estimator when a sender complies. The congestion window still governs;
    /// only the smoothing goes.
    Bbr2,
}

/// Maps each controller to its algorithm and pacing flag.
const fn congestion_config(
    congestion: CongestionControl,
) -> (quiche::CongestionControlAlgorithm, bool) {
    match congestion {
        CongestionControl::Cubic => (quiche::CongestionControlAlgorithm::CUBIC, true),
        CongestionControl::Bbr2 => (quiche::CongestionControlAlgorithm::Bbr2Gcongestion, false),
    }
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
            idle_timeout_ms: IDLE_TIMEOUT_MS,
            accept_timeout_ms: ACCEPT_TIMEOUT_MS,
            max_datagram_bytes: MAX_DATAGRAM_SIZE,
            congestion: CongestionControl::Cubic,
            initial_congestion_window_packets: None,
            session: None,
            side_channel_lead: None,
            prefix_duplication_datagrams: PREFIX_DUPLICATION_DATAGRAMS,
            stateless_retry: false,
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
            idle_timeout_ms: IDLE_TIMEOUT_MS,
            accept_timeout_ms: ACCEPT_TIMEOUT_MS,
            max_datagram_bytes: MAX_DATAGRAM_SIZE,
            congestion: CongestionControl::Cubic,
            initial_congestion_window_packets: None,
            session: None,
            side_channel_lead: None,
            prefix_duplication_datagrams: PREFIX_DUPLICATION_DATAGRAMS,
            stateless_retry: false,
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
        if !(MIN_DATAGRAM_SIZE..=LARGEST_DATAGRAM_SIZE).contains(&self.max_datagram_bytes) {
            return Err(Error::InvalidConfiguration);
        }
        if let Some(packets) = self.initial_congestion_window_packets {
            config.set_initial_congestion_window_packets(scaled_initial_window(
                packets,
                self.max_datagram_bytes,
            ));
        }
        config.set_max_idle_timeout(self.idle_timeout_ms);
        config.set_max_recv_udp_payload_size(self.max_datagram_bytes);
        config.set_max_send_udp_payload_size(self.max_datagram_bytes);
        // The configured datagram is a ceiling, not a path claim. Without
        // discovery, a narrower path completes the handshake at 1200 bytes then
        // blackholes every data packet; with it, the connection probes and
        // settles under the ceiling.
        config.discover_pmtu(true);
        // The QUIC DATAGRAM extension carries the experimental unreliable
        // path. Both queues are bounded in datagrams; the inbound event budget
        // bounds what a peer can make this end hold.
        config.enable_dgram(true, DATAGRAM_RECV_QUEUE_LEN, DATAGRAM_QUEUE_LEN);
        // The loss delay never undercuts the ack latency the connection has
        // observed. Without it, stock quiche declares delivered packets lost
        // on paths whose RTT sits at or under the pump's ack-processing cadence.
        config.set_enable_ack_latency_loss_floor(true);
        let (algorithm, pacing) = congestion_config(self.congestion);
        config.set_cc_algorithm(algorithm);
        config.enable_pacing(pacing);
        // The sized arm was measured with the advertised window and the
        // ceiling raised together, so the two move together; see
        // `advertised_window` for what it is and why it is clamped.
        let connection_window = advertised_window(
            u64::try_from(self.limits.control_payload())
                .map_err(|_| Error::InvalidConfiguration)?,
        );
        config.set_max_stream_window(STREAM_WINDOW_CEILING);
        config.set_max_connection_window(CONNECTION_WINDOW_CEILING);
        config.set_initial_max_data(connection_window);
        // The aggregate window remains the memory bound. Let one bulk stream
        // use all of it instead of stalling at the frame bound the session
        // promised.
        config.set_initial_max_stream_data_bidi_local(connection_window);
        config.set_initial_max_stream_data_bidi_remote(connection_window);
        // The control stream plus what was advertised, so a peer opening the
        // lanes it was promised is never refused by the carrier.
        let lanes = u64::try_from(self.limits.lanes()).map_err(|_| Error::InvalidConfiguration)?;
        config.set_initial_max_streams_bidi(lanes.saturating_add(1));
        config.set_disable_active_migration(true);
        Ok(config)
    }
}

/// The window seed in the units the library counts.
///
/// The library multiplies its count by the endpoint's largest UDP payload,
/// which this transport opens to the 65507-byte maximum so discovery can
/// settle the path, and ratio-rescales the window and its floor as the
/// path's real datagram size settles. An unscaled count therefore seeded
/// fifty times its bytes exactly while the payload was still the ceiling,
/// and under Bbr2 that transient is also the window's floor: congestion
/// control off during the very flights that decide the model, which a
/// lossy path turned into second-long queues and a 61 s fetch. The
/// configured count means packets of the QUIC minimum; scaled, the seed's
/// bytes are what the caller asked during the pre-settle transient where a
/// seed acts, and the floor the rescaling carries forward decays to
/// harmless rather than standing at fifty times the intent.
const fn scaled_initial_window(packets: usize, max_datagram_bytes: usize) -> usize {
    let scaled = (packets * MIN_DATAGRAM_SIZE).div_ceil(max_datagram_bytes);
    if scaled == 0 { 1 } else { scaled }
}

/// A QUIC endpoint carrying VOT, with its own driver thread.
pub struct Transport {
    adapter: QuicheAdapter,
    commands: mpsc::SyncSender<Command>,
    inbound: Arc<Mutex<Inbound>>,
    channel_binding: Arc<Mutex<Option<ChannelBinding>>>,
    /// The peer's leaf certificate in DER, kept from the handshake so a
    /// caller can pin who it is talking to before it says anything.
    peer_certificate: Arc<Mutex<Option<Vec<u8>>>>,
    /// The TLS session ticket the peer issued, once it has, for a later
    /// connection to resume with [`Config::session`].
    session_ticket: Arc<Mutex<Option<Vec<u8>>>>,
    /// Whether the handshake resumed an earlier session.
    resumed: Arc<AtomicBool>,
    /// The most recent path sample the driver read. Copied into the adapter
    /// before events are drained, so the disconnect that clears it is seen after
    /// the sample it belongs to rather than before.
    path: Arc<Mutex<Option<PathStats>>>,
    close: Arc<AtomicU64>,
    /// Held so a refused event is offered again before any later one, which is
    /// what keeps records in the order the peer sent them.
    held: Option<NativeEvent>,
    local: SocketAddr,
    peer: Option<SocketAddr>,
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

    /// Connects to `peer` on an already-bound socket.
    ///
    /// A caller that made itself reachable on a socket, by punching a NAT or
    /// announcing that socket's mapping, hands it here so the handshake comes
    /// from the mapping the peer was told to expect.
    ///
    /// # Errors
    /// Reports a socket or configuration failure. A socket bound to a
    /// wildcard address is refused: it names no one mapping, so it cannot be
    /// the mapping a peer was told to expect. [`Transport::connect`] takes a
    /// wildcard, since a caller that binds nothing itself announces nothing.
    pub fn connect_on(
        socket: UdpSocket,
        peer: SocketAddr,
        server_name: Option<&str>,
        config: &Config,
    ) -> Result<Self, Error> {
        if socket
            .local_addr()
            .map_err(|_| Error::Backend)?
            .ip()
            .is_unspecified()
        {
            return Err(Error::InvalidConfiguration);
        }
        Self::start_on(
            socket,
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
        Self::start_on(socket, peer, config, role)
    }

    fn start_on(
        socket: UdpSocket,
        peer: Option<(SocketAddr, Option<String>)>,
        config: &Config,
        role: Role,
    ) -> Result<Self, Error> {
        // Discovery's probes must be dropped where the path narrows, never
        // fragmented and reassembled: a reassembled probe reads as success and
        // locks the connection above the path for good.
        vot_platform_net::refuse_fragmentation(&socket).map_err(|_| Error::Backend)?;
        size_buffers_reporting_clamps(&socket);
        let local = socket.local_addr().map_err(|_| Error::Backend)?;
        let mut quiche_config = config.build(role)?;

        let mut adapter = QuicheAdapter::for_role(role);
        adapter.set_receive_limits(config.limits);
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let close = Arc::new(AtomicU64::new(NO_CLOSE));
        let control_limit = Arc::new(AtomicUsize::new(config.limits.control_payload()));
        // As deep as the adapter's own queue, so one flush moves a batch. The
        // adapter's bound is the real limit; a full channel leaves the
        // submission queued rather than dropped.
        let (commands, receiver) = mpsc::sync_channel(vot_transport_queue::DEFAULT_COUNT_LIMIT);
        let path = Arc::new(Mutex::new(None));
        let channel_binding = Arc::new(Mutex::new(None));
        let peer_certificate = Arc::new(Mutex::new(None));
        let session_ticket = Arc::new(Mutex::new(None));
        let resumed = Arc::new(AtomicBool::new(false));
        let driver_inbound = Arc::clone(&inbound);
        let driver_close = Arc::clone(&close);
        let driver_control = Arc::clone(&control_limit);
        let driver_path = Arc::clone(&path);
        let driver_binding = Arc::clone(&channel_binding);
        let driver_certificate = Arc::clone(&peer_certificate);
        let driver_ticket = Arc::clone(&session_ticket);
        let driver_resumed = Arc::clone(&resumed);
        let connection = ConnectionId(u64::from(local.port()));
        let datagram_bytes = config.max_datagram_bytes;
        let accept_timeout_ms = config.accept_timeout_ms;
        let prefix_duplication = config.prefix_duplication_datagrams;
        let keepalive = keepalive_interval(role, config.idle_timeout_ms);

        let session = config.session.clone();
        let peer_address = peer.as_ref().map(|(address, _)| *address);
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
                    session.as_deref(),
                    &receiver,
                    &driver_inbound,
                    &driver_close,
                    &driver_control,
                    &driver_path,
                    &driver_binding,
                    &driver_certificate,
                    &driver_ticket,
                    &driver_resumed,
                    connection.0,
                    datagram_bytes,
                    accept_timeout_ms,
                    prefix_duplication,
                    keepalive,
                );
                if let Ok(mut binding) = driver_binding.lock() {
                    *binding = None;
                }
                // A driver that stops for any reason still owes the caller the
                // disconnect, or the caller waits for a peer that has gone.
                if let Ok(mut inbound) = driver_inbound.lock() {
                    inbound.push_unlosable(NativeEvent::Disconnected(connection.0));
                }
            })
            .map_err(|_| Error::Backend)?;

        Ok(Self {
            adapter,
            commands,
            inbound,
            channel_binding,
            peer_certificate,
            session_ticket,
            resumed,
            path,
            close,
            held: None,
            local,
            peer: peer_address,
            connection,
            driver: Some(driver),
        })
    }

    /// The peer's leaf certificate in DER, or nothing before the handshake
    /// has delivered it. A client that pins a serve identity compares this
    /// against the pin before it sends anything.
    #[must_use]
    pub fn peer_certificate(&self) -> Option<Vec<u8>> {
        self.peer_certificate.lock().ok()?.clone()
    }

    /// The TLS session ticket the serve issued, or nothing until it
    /// arrives, shortly after the handshake. Feed it to [`Config::session`]
    /// to resume, which spares the resumed handshake a round trip.
    #[must_use]
    pub fn session_ticket(&self) -> Option<Vec<u8>> {
        self.session_ticket.lock().ok()?.clone()
    }

    /// Whether the handshake resumed an earlier session.
    #[must_use]
    pub fn is_resumed(&self) -> bool {
        self.resumed.load(Ordering::Relaxed)
    }

    /// The address this endpoint is bound to.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local
    }

    /// The peer address when the caller or listener established it.
    #[must_use]
    pub const fn peer_address(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// The identifier this endpoint reports its connection under.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection
    }

    /// Parks until this endpoint has something to say, without consuming it.
    ///
    /// A server's driver waits for the first packet before any connection
    /// exists. The first thing a driver queues is a lifecycle event,
    /// `Connected` or `Disconnected`, so this returns exactly when a session
    /// has something to react to.
    pub fn wait_arrival(&self) {
        loop {
            let signal = {
                let Ok(inbound) = self.inbound.lock() else {
                    return;
                };
                if !inbound.events.is_empty() {
                    return;
                }
                Arc::clone(&inbound.arrived)
            };
            if self.driver.as_ref().is_none_or(JoinHandle::is_finished) {
                // The driver pushes its disconnect before it finishes, so
                // the caller finds it on its next poll even if this races
                // the push itself.
                return;
            }
            // The signal wakes this on the driver's next push; the bound
            // only covers a driver that exited without ever pushing, which
            // the check above then sees.
            signal.wait(ARRIVAL_TICK);
        }
    }

    /// Whether the connection formed within `bound`.
    ///
    /// Peeks, so the lifecycle event it reads is still there for the session
    /// to drain. A path whose peer never opened its side fails by silence and
    /// has no other tell.
    pub fn connected_within(&self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        loop {
            let signal = {
                let Ok(inbound) = self.inbound.lock() else {
                    return false;
                };
                match inbound.events.iter().find_map(lifecycle_verdict) {
                    Some(verdict) => return verdict,
                    None => Arc::clone(&inbound.arrived),
                }
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            signal.wait(ARRIVAL_TICK.min(left));
        }
    }

    /// Moves what the driver has observed into the caller's queue.
    ///
    /// An event the queue cannot hold is kept and offered again before any later
    /// one, so backpressure never reorders a record.
    fn take_inbound(&mut self) {
        // The sample first: the disconnect that clears it is drained below, and a
        // caller reading a Careful Resume observation needs the sample to still be
        // there when it sees the disconnect beside it.
        if let Ok(sample) = self.path.lock()
            && let Some(stats) = *sample
        {
            drop(sample);
            self.adapter.record_path_stats(self.connection, stats);
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
    /// Stops the driver.
    ///
    /// The driver flushes the close onto the wire and exits without waiting
    /// out the draining period, so this returns within a pass or two even
    /// when the peer has vanished.
    fn drop(&mut self) {
        // The driver owns the socket, so it must stop before this returns or
        // the port outlives the endpoint. The command channel is disconnected
        // as well, so the driver has two ways to hear its owner is gone.
        self.close.store(NO_REASON, Ordering::Relaxed);
        let (dead, _) = mpsc::sync_channel(1);
        drop(std::mem::replace(&mut self.commands, dead));
        if let Some(driver) = self.driver.take() {
            let _ = driver.join();
        }
    }
}

/// Methods that only relay to the in-process adapter, written once. What has
/// carrier behavior of its own (flush, poll's inbound drain, waiting,
/// closing, the credit and control-limit notes) stays handwritten below.
macro_rules! forward_to_adapter {
    (&mut self: $(fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(fn $name(&mut self, $($arg: $ty),*) -> $ret {
            self.adapter.$name($($arg),*)
        })*
    };
    (&self: $(fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(fn $name(&self, $($arg: $ty),*) -> $ret {
            self.adapter.$name($($arg),*)
        })*
    };
}

impl TransportAdapter for Transport {
    forward_to_adapter!(&mut self:
        fn send_control(frame: &[u8]) -> Result<(), Error>;
        fn send_control_shared(frame: Payload) -> Result<(), Error>;
        fn send_reliable(stream: StreamId, record: &[u8]) -> Result<(), Error>;
        fn send_reliable_shared(stream: StreamId, record: Payload) -> Result<(), Error>;
        fn send_datagram(context: u64, payload: &[u8]) -> Result<(), Error>;
    );
    forward_to_adapter!(&self:
        fn preflight_reliable_batch(stream: StreamId, records: &[Payload]) -> Result<(), Error>;
        fn receive_limits() -> Option<ReceiveLimits>;
        fn path_stats() -> Option<PathStats>;
    );

    fn channel_binding(&self) -> Result<ChannelBinding, Error> {
        let binding = self.channel_binding.lock().map_err(|_| Error::Backend)?;
        (*binding).ok_or(Error::Backend)
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

/// What every outbox is holding, counted so the driver knows when to stop
/// taking submissions without walking its streams to find out.
///
/// Bytes are what is still owed, so one record is charged once and released as
/// it goes rather than when it finishes.
#[derive(Debug, Default)]
struct Queued {
    bytes: usize,
    records: usize,
}

impl Queued {
    /// Whether the driver has taken as much as it will hold.
    ///
    /// Checked before a submission so a record larger than the bound is still
    /// taken: refusing what cannot fit is a stall, not backpressure.
    const fn is_full(&self) -> bool {
        self.bytes >= MAX_QUEUED_BYTES || self.records >= MAX_QUEUED_RECORDS
    }

    /// Charges one record handed to an outbox.
    fn charge(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.records = self.records.saturating_add(1);
    }

    /// Releases bytes the connection has taken.
    fn wrote(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_sub(bytes);
    }

    /// Releases the record itself, once none of it is owed.
    fn finished(&mut self) {
        self.records = self.records.saturating_sub(1);
    }

    /// Releases everything an outbox held, for a stream that will not write
    /// again.
    fn discard(&mut self, outbox: &VecDeque<(Payload, usize)>) {
        for (bytes, sent) in outbox {
            self.wrote(bytes.len().saturating_sub(*sent));
            self.finished();
        }
    }

    /// Fails a debug build where the count drifts from what is waiting.
    /// Too high refuses submissions for an empty connection; too low
    /// invalidates the bound.
    fn debug_assert_matches(&self, streams: &BTreeMap<u64, StreamState>) {
        debug_assert_eq!(
            self.bytes,
            streams
                .values()
                .flat_map(|stream| &stream.outbox)
                .map(|(bytes, sent)| bytes.len() - sent)
                .sum::<usize>(),
            "the charged bytes drifted from what the outboxes hold"
        );
        debug_assert_eq!(
            self.records,
            streams.values().map(|stream| stream.outbox.len()).sum(),
            "the charged records drifted from what the outboxes hold"
        );
    }
}

/// Per-stream state the driver keeps.
struct StreamState {
    framing: Framing<SharedBudget>,
    kind: StreamKind,
    /// The QUIC stream these bytes travel on, cached so the lane mapping is
    /// applied once.
    id: u64,
    sequence: u64,
    /// What the caller handed over that the connection has not taken yet.
    /// A record may be written in pieces across loops because flow control is
    /// the peer's; holding the caller's allocation means no copy per piece.
    /// Bounded across every stream by [`Queued`].
    outbox: VecDeque<(Payload, usize)>,
    /// Frames completed after the event queue refused one, in arrival order.
    /// Reading stops while this holds anything, so it is bounded by what one
    /// read chunk plus one partial frame can complete.
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
    session: Option<&[u8]>,
    commands: &mpsc::Receiver<Command>,
    inbound: &Arc<Mutex<Inbound>>,
    close: &Arc<AtomicU64>,
    control_limit: &Arc<AtomicUsize>,
    path: &Arc<Mutex<Option<PathStats>>>,
    channel_binding: &Arc<Mutex<Option<ChannelBinding>>>,
    peer_certificate: &Arc<Mutex<Option<Vec<u8>>>>,
    session_ticket: &Arc<Mutex<Option<Vec<u8>>>>,
    resumed: &Arc<AtomicBool>,
    connection: u64,
    datagram_bytes: usize,
    accept_timeout_ms: u64,
    prefix_duplication: usize,
    keepalive: Option<Duration>,
) -> Result<(), Error> {
    // Heap-allocated and large enough for the largest frame a lane carries, so
    // a whole record is handed to the parser as one slice.
    let mut buffer = vec![0_u8; vot_transport_framing::MAX_PARTIAL_FRAME.max(65_535)];
    // Sized for a burst, not one datagram: packets are gathered and handed over
    // together so the offload can segment them in one call.
    let burst_bytes = LARGEST_DATAGRAM_SIZE.max(datagram_bytes);
    let out = vec![0_u8; burst_bytes];
    let offload = offload_available();
    let scid = scid_for(local);

    let conn = match (role, peer) {
        (Role::Client, Some((address, name))) => {
            let mut conn = quiche::connect_with_buffer_factory::<SharedBufFactory>(
                name, &scid, local, address, config,
            )
            .map_err(|_| Error::Backend)?;
            // Before the first send: a resumed handshake is decided at the
            // ClientHello. A ticket the library rejects is dropped and the
            // handshake runs full, which is what an expired one deserves.
            if let Some(session) = session {
                let _ = conn.set_session(session);
            }
            conn
        }
        (Role::Server, _) => {
            // A server has nothing to do until a client speaks, and the first
            // packet is what names the connection.
            let Some(conn) = accept_one(socket, local, config, &mut buffer, accept_timeout_ms)?
            else {
                return Ok(());
            };
            conn
        }
        (Role::Client, None) => return Err(Error::InvalidConfiguration),
    };

    // Receive-side offload from here on: the handshake above read plain
    // datagrams. A kernel that refuses the option leaves each datagram its own
    // read.
    enable_receive_offload(socket);
    run(
        socket,
        Intake::Socket,
        conn,
        local,
        role,
        commands,
        inbound,
        close,
        control_limit,
        path,
        channel_binding,
        peer_certificate,
        session_ticket,
        resumed,
        connection,
        datagram_bytes,
        prefix_duplication,
        buffer,
        out,
        offload,
        keepalive,
    )
}

/// Where a pump's datagrams come from: its own socket, or a listener routing
/// one socket's arrivals to many pumps.
#[derive(Clone, Copy)]
enum Intake<'a> {
    /// The pump owns the socket and reads it directly.
    Socket,
    /// A listener owns the socket; what arrives is routed by connection.
    Routed(&'a mpsc::Receiver<Arrived>),
}

/// One read a listener routed to a pump: the datagrams as one buffer, who
/// sent them, and the segment size when the kernel coalesced them.
struct Arrived {
    bytes: Vec<u8>,
    from: SocketAddr,
    segment: Option<usize>,
}

/// The pump's loop over one connection, whichever way its packets arrive.
///
/// Sends go to `socket` directly either way: the kernel serializes
/// concurrent sends, so pumps sharing a listener's socket need no lock.
#[expect(
    clippy::too_many_arguments,
    reason = "the pump takes what the caller owns and nothing more"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one pass of the pump is one piece, and splitting it would scatter its order"
)]
fn run(
    socket: &UdpSocket,
    intake: Intake<'_>,
    mut conn: Connection,
    local: SocketAddr,
    role: Role,
    commands: &mpsc::Receiver<Command>,
    inbound: &Arc<Mutex<Inbound>>,
    close: &Arc<AtomicU64>,
    control_limit: &Arc<AtomicUsize>,
    path: &Arc<Mutex<Option<PathStats>>>,
    channel_binding: &Arc<Mutex<Option<ChannelBinding>>>,
    peer_certificate: &Arc<Mutex<Option<Vec<u8>>>>,
    session_ticket: &Arc<Mutex<Option<Vec<u8>>>>,
    resumed: &Arc<AtomicBool>,
    connection: u64,
    datagram_bytes: usize,
    prefix_duplication: usize,
    mut buffer: Vec<u8>,
    mut out: Vec<u8>,
    offload: bool,
    keepalive: Option<Duration>,
) -> Result<(), Error> {
    let budget = SharedBudget(Arc::clone(inbound));
    // Allocated once to avoid a control-message allocation per packet.
    let mut space = receive_space();
    let mut streams: BTreeMap<u64, StreamState> = BTreeMap::new();
    let mut datagrams: VecDeque<(Payload, u64)> = VecDeque::new();
    let mut pending_datagram = None;
    let mut pending_datagram_state = None;
    let mut queued = Queued::default();
    let mut closing = false;
    let mut closing_passes: u32 = 0;
    let mut announced = false;
    let mut sending = Sending::new(datagram_bytes, offload, role, prefix_duplication);
    let mut read_timeout = match intake {
        Intake::Socket => {
            socket
                .set_read_timeout(Some(TICK))
                .map_err(|_| Error::Backend)?;
            Some(TICK)
        }
        Intake::Routed(_) => None,
    };

    let mut ramp_pings: u32 = 0;
    let mut last_ping = Instant::now();
    let outcome = 'drive: loop {
        // The ramp's serial prefix is a handful of sparse flights, and a
        // lost packet in a sparse flight has no later packets to reveal
        // the gap: recovery falls to probe timers, 300-900 ms against the
        // round trip a gap detection costs. A short ping cadence through
        // the ramp keeps the ack clock ticking on both ends; measured at
        // 5% loss and 200 ms it took the first byte's median from 2.56 s
        // to 1.49 s and the worst wall from 11.1 s to 5.6 s. The budget
        // bounds it: about a second of cadence, after which the keepalive's
        // much slower one takes over and holds the connection open for as
        // long as its owner keeps the pump running.
        // Armed only once the handshake completes: before establishment
        // send_ack_eliciting is a documented no-op, and a counted budget
        // that ticks through a slow lossy handshake would be spent on
        // nothing exactly where the ramp needs it (review's catch).
        if ping_due(announced, last_ping.elapsed(), ramp_pings, keepalive) {
            let _ = conn.send_ack_eliciting();
            ramp_pings = ramp_pings.saturating_add(1);
            last_ping = Instant::now();
        }
        queued.debug_assert_matches(&streams);
        let orphaned = take_submissions(
            &mut conn,
            &mut streams,
            &mut datagrams,
            &budget,
            control_limit,
            commands,
            inbound,
            role,
            &mut queued,
            &mut pending_datagram,
            &mut pending_datagram_state,
        );
        note_close_request(&mut conn, close, &mut closing);
        if orphaned {
            note_orphaned(&mut conn, &mut closing);
        }
        // A counted bound on the whole close path, in the loop's own body. A
        // requested close normally reaches the drain gate below within a
        // pass or two, but a connection wedged mid-recovery keeps producing
        // ack-eliciting packets, each of which resets QUIC's idle timer, so
        // nothing else ever ends it: a fetch suite run was caught spinning
        // in quiche's frame packing for half an hour while its owner sat in
        // [`Transport::drop`]'s join. The close was flushed best-effort
        // passes ago by then; the peer has its own idle timeout, and this
        // end's owner gets its thread back.
        if closing {
            closing_passes = closing_passes.saturating_add(1);
            if close_overstayed(closing_passes) {
                break 'drive Ok(());
            }
        }
        for stream in streams.values_mut() {
            write_outbox(&mut conn, stream, &mut queued);
        }
        write_datagrams(
            &mut conn,
            &mut datagrams,
            &mut pending_datagram_state,
            inbound,
        );
        let Ok(paced) = send_and_revalidate(socket, &mut conn, &mut out, &mut sending) else {
            break 'drive Ok(());
        };

        if conn.is_established() && !announced {
            let mut bytes = [0; CHANNEL_BINDING_LEN];
            if conn
                .export_keying_material(&mut bytes, CHANNEL_BINDING_EXPORTER_LABEL, None)
                .is_err()
            {
                break 'drive Err(Error::Backend);
            }
            let Ok(mut binding) = channel_binding.lock() else {
                break 'drive Err(Error::Backend);
            };
            *binding = Some(ChannelBinding::from_bytes(bytes));
            drop(binding);
            // Before the Connected event, so a caller woken by it never sees
            // an established connection with no certificate to check.
            if let (Some(der), Ok(mut held)) = (conn.peer_cert(), peer_certificate.lock()) {
                *held = Some(der.to_vec());
            }
            resumed.store(conn.is_resumed(), Ordering::Relaxed);
            announced = true;
            // The ramp cadence's clock starts here, with the whole budget.
            last_ping = Instant::now();
            if let Ok(mut queue) = inbound.lock() {
                queue.push_unlosable(NativeEvent::Connected(connection));
            }
        }

        if announced
            && let Ok(mut held) = session_ticket.try_lock()
            && held.is_none()
            && let Some(session) = conn.session()
        {
            *held = Some(session.to_vec());
        }
        if conn.is_closed() {
            break 'drive Ok(());
        }
        // A close this end sent is on the wire once the send above flushed
        // it: quiche arms the draining timer as it packs the frame, and
        // every path out of the send flushes its burst first. The draining
        // period that remains would answer nothing, since this quiche drops
        // straight to draining rather than answering retransmissions, so
        // waiting it out costs whole round-trip times per connection and
        // settles nothing. `local_error` rather than the request flag,
        // because it is set exactly when this end's close was packed: a
        // peer-initiated close leaves it empty and takes the full path
        // above, and a fault-path close this end sent without a caller's
        // request leaves just as promptly.
        if conn.local_error().is_some() && conn.is_draining() {
            break 'drive Ok(());
        }

        // How long is left of the release time the last pass reported, which
        // is what a held packet is waiting on.
        let pacing = paced.map(|at| at.saturating_duration_since(Instant::now()));
        let deadline = pass_deadline(conn.timeout(), pacing);
        match &intake {
            Intake::Socket => {
                if let Err(error) = install_read_timeout(socket, &mut read_timeout, deadline) {
                    break 'drive Err(error);
                }
                match receive_segmented(socket, &mut buffer, &mut space, false) {
                    Ok((len, from, segment)) => {
                        feed_received(&mut conn, local, &mut buffer[..len], from, segment);
                        if let Err(error) =
                            drain_arrivals(socket, &mut conn, local, &mut buffer, &mut space)
                        {
                            break 'drive Err(error);
                        }
                    }
                    Err(error) => {
                        if !read_ran_out(&error) {
                            break 'drive Ok(());
                        }
                        conn.on_timeout();
                    }
                }
            }
            Intake::Routed(packets) => match packets.recv_timeout(deadline) {
                Ok(mut routed) => {
                    feed_received(
                        &mut conn,
                        local,
                        &mut routed.bytes,
                        routed.from,
                        routed.segment,
                    );
                    // The wait was paid on the first read; what else has
                    // already been routed is a batch, up to the same budget
                    // the socket drain keeps.
                    for _ in 0..DRAIN_BUDGET {
                        let Ok(mut routed) = packets.try_recv() else {
                            break;
                        };
                        feed_received(
                            &mut conn,
                            local,
                            &mut routed.bytes,
                            routed.from,
                            routed.segment,
                        );
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => conn.on_timeout(),
                // The router is gone, so nothing further can ever arrive.
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break 'drive Ok(());
                }
            },
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
        drain_datagrams(&mut conn, inbound, &mut buffer);
        if let Some(sample) = path_sample_from(&conn)
            && let Ok(mut slot) = path.lock()
        {
            *slot = Some(sample);
        }
    };
    // A pass that ended while a packet waited on its release time still owes
    // the peer that packet: the connection spent a packet number on it.
    let _ = flush_held(socket, &out, &mut sending);
    finish_datagrams(
        outcome,
        &mut pending_datagram_state,
        &mut pending_datagram,
        &mut datagrams,
        inbound,
    )
}

/// How long a pass may wait: the soonest of the connection's own timer, the
/// release time the pacer set, and the cap that keeps a submission from
/// waiting on the peer.
///
/// A pending release time may be waited out to [`PACE_HOLD_TICK`] rather than
/// the tick, or the held packet is flushed ahead of its release. The
/// connection's timer stays in the minimum either way, so the wait never
/// extends the loss timer. Pure, so the edges are pinned by a table test.
fn pass_deadline(timeout: Option<Duration>, pacing: Option<Duration>) -> Duration {
    timeout
        .unwrap_or(TICK)
        .min(pacing.unwrap_or(TICK))
        .min(if pacing.is_some() {
            PACE_HOLD_TICK
        } else {
            TICK
        })
        .max(
            // A zero timeout would spin; the connection wants attention now
            // and gets it on the next pass either way.
            Duration::from_micros(200),
        )
}

fn install_read_timeout(
    socket: &UdpSocket,
    cached: &mut Option<Duration>,
    timeout: Duration,
) -> Result<(), Error> {
    if *cached != Some(timeout) {
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|_| Error::Backend)?;
        *cached = Some(timeout);
    }
    Ok(())
}

/// Whether a socket read failed only for want of a packet within its
/// timeout, which is the wait the deadline priced; anything else is the
/// carrier failing.
fn read_ran_out(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// How often an arrival wait rechecks a driver that may have gone.
///
/// The wait wakes on the driver's push signal; this bound exists only so
/// a driver that exited without pushing is noticed, and it prices that
/// detection, not the arrival itself.
const ARRIVAL_TICK: Duration = Duration::from_millis(250);

/// A lifecycle event read as a verdict on the connection. Anything else
/// says nothing about whether the handshake landed.
const fn lifecycle_verdict(event: &NativeEvent) -> Option<bool> {
    match event {
        NativeEvent::Connected(_) => Some(true),
        NativeEvent::Disconnected(_) => Some(false),
        _ => None,
    }
}

/// Reads a router holds for a pump that has not drained them.
///
/// The elasticity the kernel's receive buffer gives a pump that owns its
/// socket, restated as a bound: a pump this far behind sheds arrivals the
/// way a full kernel buffer would, and the connection recovers them.
const ROUTED_READS: usize = 512;

/// Connections one listener carries at most.
///
/// The router accepts what it can route and no more: an Initial past the
/// bound is dropped, the client retransmits it, and room appears when a
/// session ends, which is backpressure rather than failure.
const MAX_LISTENER_CONNECTIONS: usize = 64;

/// Accepted connections a listener holds for a caller that has not taken
/// them. Small, because a caller at its own session bound wants arrivals
/// waiting in the socket, where dropping them costs nothing.
const ACCEPT_BACKLOG: usize = 8;

/// How often the router looks up from an idle socket to notice its owner
/// is gone.
const ROUTER_TICK: Duration = Duration::from_millis(50);

const RETRY_TOKEN_SECONDS: u64 = 30;
const RETRY_TOKEN_TAG_BYTES: usize = 32;

/// Tells one routed connection from another in this process, because a
/// listener's connections share one local address and port.
static ROUTED: AtomicU64 = AtomicU64::new(0);

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn mint_retry_token(secret: &[u8; 32], peer: SocketAddr, odcid: &[u8], now: u64) -> Vec<u8> {
    let mut token = Vec::with_capacity(1 + 8 + 1 + 16 + 2 + 1 + odcid.len() + 32);
    token.push(1);
    token.extend_from_slice(&now.saturating_add(RETRY_TOKEN_SECONDS).to_be_bytes());
    match peer.ip() {
        std::net::IpAddr::V4(ip) => {
            token.push(4);
            token.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            token.push(6);
            token.extend_from_slice(&ip.octets());
        }
    }
    token.extend_from_slice(&peer.port().to_be_bytes());
    token.push(u8::try_from(odcid.len()).unwrap_or(u8::MAX));
    token.extend_from_slice(odcid);
    let tag = blake3::keyed_hash(secret, &token);
    token.extend_from_slice(tag.as_bytes());
    token
}

fn validate_retry_token(
    secret: &[u8; 32],
    peer: SocketAddr,
    token: &[u8],
    now: u64,
) -> Option<Vec<u8>> {
    let body_len = token.len().checked_sub(RETRY_TOKEN_TAG_BYTES)?;
    let (body, found_tag) = token.split_at(body_len);
    let expected_tag = blake3::keyed_hash(secret, body);
    let different = found_tag
        .iter()
        .zip(expected_tag.as_bytes())
        .fold(0, |difference, (left, right)| difference | (left ^ right));
    if different != 0 || body.first().copied()? != 1 {
        return None;
    }
    let expiry = u64::from_be_bytes(body.get(1..9)?.try_into().ok()?);
    if now > expiry {
        return None;
    }
    let family = *body.get(9)?;
    let mut at = 10;
    let ip = match family {
        4 => {
            let octets: [u8; 4] = body.get(at..at + 4)?.try_into().ok()?;
            at += 4;
            std::net::IpAddr::V4(octets.into())
        }
        6 => {
            let octets: [u8; 16] = body.get(at..at + 16)?.try_into().ok()?;
            at += 16;
            std::net::IpAddr::V6(octets.into())
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(body.get(at..at + 2)?.try_into().ok()?);
    at += 2;
    if SocketAddr::new(ip, port) != peer {
        return None;
    }
    let length = usize::from(*body.get(at)?);
    at += 1;
    let end = at.checked_add(length)?;
    (end == body.len()).then(|| body[at..end].to_vec())
}

/// One socket serving many connections, so W rails reach one fixed address.
///
/// A router thread owns the socket's receive side, routes each datagram to its
/// connection's pump by connection ID, and turns an unknown Initial into a new
/// connection. Each accepted connection is an ordinary [`Transport`]; its pump
/// sends on the shared socket directly, which the kernel serializes. Dropping
/// the listener stops the router; accepted connections outlive it.
pub struct Listener {
    local: SocketAddr,
    arrivals: mpsc::Receiver<Transport>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    accept_timeout_ms: u64,
    stateless_retry: bool,
    router: Option<JoinHandle<()>>,
    side: Option<SideChannel>,
}

/// The listener's socket as another protocol's, taken once and moved to
/// whichever thread speaks it.
///
/// Holds the send side of the socket the sessions arrive at: a NAT mapping
/// belongs to a socket, so replies must come from the same one. Datagrams
/// leading with the configured byte arrive here.
///
/// The socket is held weakly, so this does not keep the port alive once the
/// router has joined.
pub struct SideChannel {
    socket: std::sync::Weak<UdpSocket>,
    arrivals: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}

/// Side-channel datagrams held for a reader that has not taken them.
///
/// Small on purpose: the reader expects a handful of replies to what it
/// sent, and anyone who can reach the port can send the lead byte, so
/// what does not fit is shed the way a full receive buffer sheds.
const SIDE_CHANNEL_BACKLOG: usize = 64;

/// The most a side-channel datagram may be, checked before the router
/// copies one out of its buffer.
///
/// A side channel carries small fixed-shape datagrams. Without a bound,
/// anyone who can reach the port makes the router allocate a read's worth
/// of bytes per arrival before the queue can shed it.
const SIDE_CHANNEL_MAX_BYTES: usize = 128;

impl SideChannel {
    /// Sends one datagram from the listener's socket.
    ///
    /// # Errors
    /// Reports a socket that would not send it, and a listener that has
    /// already released it.
    pub fn send_to(&self, bytes: &[u8], to: SocketAddr) -> Result<(), Error> {
        let socket = self.socket.upgrade().ok_or(Error::Backend)?;
        socket.send_to(bytes, to).map_err(|_| Error::Backend)?;
        Ok(())
    }

    /// The address the listener's socket is bound to, which tells a caller
    /// which family its destinations have to be in.
    ///
    /// # Errors
    /// Reports a listener that has already released the socket.
    pub fn local_address(&self) -> Result<SocketAddr, Error> {
        let socket = self.socket.upgrade().ok_or(Error::Backend)?;
        socket.local_addr().map_err(|_| Error::Backend)
    }

    /// The next datagram, or nothing within `wait`.
    ///
    /// # Errors
    /// Reports a router that has ended, which is the same condition
    /// [`Listener::accept`] reports and not a wait that came up empty:
    /// a caller that could not tell them apart would spin, because a
    /// dead channel answers immediately and forever.
    pub fn next_within(&self, wait: Duration) -> Result<Option<(Vec<u8>, SocketAddr)>, Error> {
        match self.arrivals.recv_timeout(wait) {
            Ok(arrival) => Ok(Some(arrival)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(Error::Backend),
        }
    }
}

impl Listener {
    /// Binds one socket for every session a serve will carry.
    ///
    /// # Errors
    /// Reports a socket, credential, or configuration failure.
    pub fn bind(address: SocketAddr, config: &Config) -> Result<Self, Error> {
        let socket = UdpSocket::bind(address).map_err(|_| Error::Backend)?;
        vot_platform_net::refuse_fragmentation(&socket).map_err(|_| Error::Backend)?;
        size_buffers_reporting_clamps(&socket);
        enable_receive_offload(&socket);
        let local = socket.local_addr().map_err(|_| Error::Backend)?;
        // Build once while credential paths are guaranteed to exist, then
        // move the shared TLS context into the router.
        let server_config = config.build(Role::Server)?;
        let socket = Arc::new(socket);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (arrived, arrivals) = mpsc::sync_channel(ACCEPT_BACKLOG);
        let (aside, beside) = mpsc::sync_channel(SIDE_CHANNEL_BACKLOG);
        let side = config.side_channel_lead.map(|_| SideChannel {
            socket: Arc::downgrade(&socket),
            arrivals: beside,
        });
        let router_socket = Arc::clone(&socket);
        let router_stop = Arc::clone(&stop);
        let router_config = config.clone();
        let retry_secret = if config.stateless_retry {
            let mut secret = [0; 32];
            getrandom::fill(&mut secret).map_err(|_| Error::Backend)?;
            Some(secret)
        } else {
            None
        };
        let router = std::thread::Builder::new()
            .name(format!("vot-quiche-listen-{}", local.port()))
            .spawn(move || {
                route(
                    &router_socket,
                    local,
                    &router_config,
                    &arrived,
                    &aside,
                    &router_stop,
                    retry_secret,
                    server_config,
                );
            })
            .map_err(|_| Error::Backend)?;
        drop(socket);
        Ok(Self {
            local,
            arrivals,
            stop,
            accept_timeout_ms: config.accept_timeout_ms,
            stateless_retry: config.stateless_retry,
            router: Some(router),
            side,
        })
    }

    /// Takes the side channel, once, if the configuration named a lead
    /// byte for one.
    pub fn take_side_channel(&mut self) -> Option<SideChannel> {
        self.side.take()
    }

    /// The address this listener is bound to.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local
    }

    /// Whether this listener validates an address with stateless Retry before
    /// allocating connection state.
    #[must_use]
    pub const fn stateless_retry_enabled(&self) -> bool {
        self.stateless_retry
    }

    /// Waits for the next connection, as long as the accept allows
    /// (`accept_timeout_ms`, where zero is forever).
    ///
    /// # Errors
    /// Reports a wait that ended without a connection.
    pub fn accept(&self) -> Result<Transport, Error> {
        let accepted = match self.accept_timeout_ms {
            0 => self.arrivals.recv().ok(),
            bound => self
                .arrivals
                .recv_timeout(Duration::from_millis(bound))
                .ok(),
        };
        accepted.ok_or(Error::Backend)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(router) = self.router.take() {
            let _ = router.join();
        }
        // Connections still waiting to be accepted die here: their pumps
        // are joined one at a time as each `Transport` drops.
        while self.arrivals.try_recv().is_ok() {}
    }
}

/// Where a routed connection's datagrams go, and how the router learns
/// the pump is gone.
struct Route {
    pump: mpsc::SyncSender<Arrived>,
    /// Set by the pump as it ends, so the router can sweep the route
    /// without a packet having to bounce off it first.
    done: Arc<std::sync::atomic::AtomicBool>,
    /// The other identifier this connection is routed under.
    sibling: Vec<u8>,
}

fn routed_connection_count(routes: &std::collections::HashMap<Vec<u8>, Route>) -> usize {
    routes
        .iter()
        .filter(|(key, row)| key.as_slice() <= row.sibling.as_slice())
        .count()
}

/// The listener's receive loop: reads the socket, routes by connection
/// ID, and accepts what no route claims.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the routing loop keeps its socket, policy, channels, TLS context, and packet decisions in one place"
)]
fn route(
    socket: &Arc<UdpSocket>,
    local: SocketAddr,
    config: &Config,
    arrived: &mpsc::SyncSender<Transport>,
    aside: &mpsc::SyncSender<(Vec<u8>, SocketAddr)>,
    stop: &std::sync::atomic::AtomicBool,
    retry_secret: Option<[u8; 32]>,
    mut server_config: quiche::Config,
) {
    let mut buffer = vec![0_u8; vot_transport_framing::MAX_PARTIAL_FRAME.max(65_535)];
    let mut space = receive_space();
    let mut routes: std::collections::HashMap<Vec<u8>, Route> = std::collections::HashMap::new();
    // One TLS context for every connection this listener accepts, so the
    // session tickets it issues resume across connections.
    if socket.set_read_timeout(Some(ROUTER_TICK)).is_err() {
        return;
    }
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let (len, from, segment) = match receive_segmented(socket, &mut buffer, &mut space, false) {
            Ok(read) => read,
            Err(error) => {
                if read_ran_out(&error) {
                    continue;
                }
                return;
            }
        };
        if is_side_channel(config.side_channel_lead, &buffer[..len], segment) {
            for piece in split_read(&buffer[..len], segment) {
                if piece.len() > SIDE_CHANNEL_MAX_BYTES {
                    continue;
                }
                // A full queue sheds the datagram, as a full kernel
                // receive buffer would; the sender's cadence recovers it.
                let _ = aside.try_send((piece.to_vec(), from));
            }
            continue;
        }
        // The header wants only the first datagram of a coalesced read,
        // and the kernel only coalesces one flow, so its identifier
        // stands for the batch.
        let first = segment.map_or(len, |step| step.min(len)).min(len);
        let Ok(header) = quiche::Header::from_slice(&mut buffer[..first], quiche::MAX_CONN_ID_LEN)
        else {
            continue;
        };
        let key = header.dcid.to_vec();
        if let Some(row) = routes.get(&key) {
            if row.done.load(Ordering::Relaxed) {
                // The pump ended; the route and its sibling go with it.
                let sibling = row.sibling.clone();
                routes.remove(&key);
                routes.remove(&sibling);
                continue;
            }
            // A full queue sheds this read the way a full kernel receive
            // buffer would, and the connection recovers it.
            let _ = row.pump.try_send(Arrived {
                bytes: buffer[..len].to_vec(),
                from,
                segment,
            });
            continue;
        }
        // RFC 9000 requires a client's first Initial datagram to be at least
        // 1200 bytes. Never amplify a shorter spoof with Version Negotiation
        // or Retry.
        if first < MIN_DATAGRAM_SIZE {
            continue;
        }
        if version_unsupported(header.version) {
            // Answered rather than dropped, which is what lets a client
            // try another version.
            let mut out = [0_u8; MIN_DATAGRAM_SIZE];
            if let Ok(written) = quiche::negotiate_version(&header.scid, &header.dcid, &mut out) {
                let _ = socket.send_to(&out[..written], from);
            }
            continue;
        }
        if header.ty != quiche::Type::Initial {
            // Not an Initial: a stray or a straggler of a session already gone.
            // Dropped rather than growing a connection for it.
            continue;
        }
        let odcid = if let Some(secret) = &retry_secret {
            let token = header.token.as_deref().unwrap_or_default();
            if token.is_empty() {
                let index = ROUTED.fetch_add(1, Ordering::Relaxed);
                let scid = scid_routed(local, index);
                let now = unix_seconds();
                let token = mint_retry_token(secret, from, &header.dcid, now);
                let mut out = [0; MIN_DATAGRAM_SIZE];
                if let Ok(written) = quiche::retry(
                    &header.scid,
                    &header.dcid,
                    &scid,
                    &token,
                    header.version,
                    &mut out,
                ) {
                    let _ = socket.send_to(&out[..written], from);
                }
                continue;
            }
            let Some(odcid) = validate_retry_token(secret, from, token, unix_seconds()) else {
                continue;
            };
            Some(odcid)
        } else {
            None
        };
        routes.retain(|_, row| !row.done.load(Ordering::Relaxed));
        if routed_connection_count(&routes) >= MAX_LISTENER_CONNECTIONS {
            // Past the bound the Initial is shed; the client retransmits
            // it, and room appears when a session ends.
            continue;
        }
        let Some((transport, route)) = accept_routed(
            socket,
            local,
            config,
            &mut server_config,
            &mut buffer[..len],
            from,
            segment,
            &key,
            odcid.as_deref(),
        ) else {
            continue;
        };
        match arrived.try_send(transport) {
            Ok(()) => {
                routes.insert(
                    route.sibling.clone(),
                    Route {
                        pump: route.pump.clone(),
                        done: Arc::clone(&route.done),
                        sibling: key.clone(),
                    },
                );
                routes.insert(key, route);
            }
            Err(refused) => {
                // The backlog is full, so the connection dies where it was made.
                // The route goes first: its channel is what the pump waits on,
                // so the pump ends and the transport's drop joins it promptly.
                // Dropped the other way, the join waits out a close handshake
                // with this thread not reading the socket, stalling every
                // connection the listener carries.
                drop(route);
                drop(refused);
            }
        }
    }
}

/// Turns an unclaimed Initial into a connection on its own pump.
///
/// Answers the transport for the caller and the route for the router, or
/// nothing for a packet that was not a usable Initial after all.
#[allow(
    clippy::too_many_arguments,
    reason = "one accept is one piece; a parameter struct would name nothing"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one accept is one piece: the connection, the pump it runs on, and the route back"
)]
fn accept_routed(
    socket: &Arc<UdpSocket>,
    local: SocketAddr,
    config: &Config,
    quiche_config: &mut quiche::Config,
    received: &mut [u8],
    from: SocketAddr,
    segment: Option<usize>,
    original: &[u8],
    odcid: Option<&[u8]>,
) -> Option<(Transport, Route)> {
    let index = ROUTED.fetch_add(1, Ordering::Relaxed);
    let generated = scid_routed(local, index);
    // After Retry, the client's new DCID is the server-selected SCID from
    // the Retry packet and must become the accepted connection's SCID.
    let scid = odcid.map_or(generated, |_| quiche::ConnectionId::from_ref(original));
    let scid_key = scid.as_ref().to_vec();
    if odcid.is_none() && scid_key == original {
        // A client naming this end's own identifier before it exists is
        // not a connection this listener will route two ways.
        return None;
    }
    let odcid = odcid.map(quiche::ConnectionId::from_ref);
    let mut conn = quiche::accept_with_buf_factory::<SharedBufFactory>(
        &scid,
        odcid.as_ref(),
        local,
        from,
        quiche_config,
    )
    .ok()?;
    feed_received(&mut conn, local, received, from, segment);

    let mut adapter = QuicheAdapter::for_role(Role::Server);
    adapter.set_receive_limits(config.limits);
    let inbound = Arc::new(Mutex::new(Inbound::default()));
    let close = Arc::new(AtomicU64::new(NO_CLOSE));
    let control_limit = Arc::new(AtomicUsize::new(config.limits.control_payload()));
    let (commands, submissions) = mpsc::sync_channel(vot_transport_queue::DEFAULT_COUNT_LIMIT);
    let (router_side, packets) = mpsc::sync_channel(ROUTED_READS);
    let path = Arc::new(Mutex::new(None));
    let channel_binding = Arc::new(Mutex::new(None));
    let peer_certificate = Arc::new(Mutex::new(None));
    let session_ticket = Arc::new(Mutex::new(None));
    let resumed = Arc::new(AtomicBool::new(false));
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let connection = ConnectionId(routed_connection_id(local.port(), index));
    let datagram_bytes = config.max_datagram_bytes;
    let prefix_duplication = config.prefix_duplication_datagrams;
    let keepalive = keepalive_interval(Role::Server, config.idle_timeout_ms);

    let pump_socket = Arc::clone(socket);
    let pump_inbound = Arc::clone(&inbound);
    let pump_close = Arc::clone(&close);
    let pump_control = Arc::clone(&control_limit);
    let pump_path = Arc::clone(&path);
    let pump_binding = Arc::clone(&channel_binding);
    let pump_certificate = Arc::clone(&peer_certificate);
    let pump_ticket = Arc::clone(&session_ticket);
    let pump_resumed = Arc::clone(&resumed);
    let pump_done = Arc::clone(&done);
    let driver = std::thread::Builder::new()
        .name(format!("vot-quiche-{}-{index}", local.port()))
        .spawn(move || {
            let buffer = vec![0_u8; vot_transport_framing::MAX_PARTIAL_FRAME.max(65_535)];
            let out = vec![0_u8; LARGEST_DATAGRAM_SIZE.max(datagram_bytes)];
            let _ = run(
                &pump_socket,
                Intake::Routed(&packets),
                conn,
                local,
                Role::Server,
                &submissions,
                &pump_inbound,
                &pump_close,
                &pump_control,
                &pump_path,
                &pump_binding,
                &pump_certificate,
                &pump_ticket,
                &pump_resumed,
                connection.0,
                datagram_bytes,
                prefix_duplication,
                buffer,
                out,
                offload_available(),
                keepalive,
            );
            if let Ok(mut binding) = pump_binding.lock() {
                *binding = None;
            }
            // However the pump ends, the router stops routing to it and
            // the caller still hears the disconnect.
            pump_done.store(true, Ordering::Relaxed);
            if let Ok(mut inbound) = pump_inbound.lock() {
                inbound.push_unlosable(NativeEvent::Disconnected(connection.0));
            }
        })
        .ok()?;

    Some((
        Transport {
            adapter,
            commands,
            inbound,
            channel_binding,
            peer_certificate,
            session_ticket,
            resumed,
            path,
            close,
            held: None,
            local,
            peer: Some(from),
            connection,
            driver: Some(driver),
        },
        Route {
            pump: router_side,
            done,
            sibling: scid_key,
        },
    ))
}

/// What a listener's connection reports itself as: the port names the
/// endpoint, the index tells its connections apart, every one of them
/// sharing the port.
fn routed_connection_id(port: u16, index: u64) -> u64 {
    (u64::from(port) << 32) | index
}

/// A connection identifier for one of a listener's connections.
///
/// Port and index twice over, once in each byte order: nothing here is a
/// secret (the header only routes; the crypto rejects a forgery), it only
/// has to differ per connection and fill the length a peer expects.
fn scid_routed(local: SocketAddr, index: u64) -> quiche::ConnectionId<'static> {
    let mut bytes = [0_u8; quiche::MAX_CONN_ID_LEN];
    bytes[..2].copy_from_slice(&local.port().to_be_bytes());
    bytes[2..10].copy_from_slice(&index.to_be_bytes());
    bytes[10..12].copy_from_slice(&local.port().to_le_bytes());
    bytes[12..20].copy_from_slice(&index.to_le_bytes());
    quiche::ConnectionId::from_vec(bytes.to_vec())
}

/// How long a server waits for its first packet unless told otherwise.
///
/// Long enough that a test's client is always there by then, short enough
/// that a test whose client never comes fails rather than hangs.
const ACCEPT_TIMEOUT_MS: u64 = 10_000;

fn version_unsupported(version: u32) -> bool {
    !quiche::version_is_supported(version)
}

/// Waits for the first packet and turns it into a connection.
fn accept_one(
    socket: &UdpSocket,
    local: SocketAddr,
    config: &mut quiche::Config,
    buffer: &mut [u8],
    timeout_ms: u64,
) -> Result<Option<Connection>, Error> {
    // Zero means the caller will wait: a bound would read as a carrier that
    // died during the handshake.
    let bound = match timeout_ms {
        0 => None,
        milliseconds => Some(Duration::from_millis(milliseconds)),
    };
    socket.set_read_timeout(bound).map_err(|_| Error::Backend)?;
    loop {
        let Ok((len, from)) = socket.recv_from(buffer) else {
            return Ok(None);
        };
        let Ok(header) = quiche::Header::from_slice(&mut buffer[..len], quiche::MAX_CONN_ID_LEN)
        else {
            continue;
        };
        if version_unsupported(header.version) {
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
            quiche::accept_with_buf_factory::<SharedBufFactory>(&scid, None, local, from, config)
                .map_err(|_| Error::Backend)?;
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
    nonblocking: bool,
) -> std::io::Result<(usize, SocketAddr, Option<usize>)> {
    use std::os::fd::AsRawFd as _;

    let flags = if nonblocking {
        nix::sys::socket::MsgFlags::MSG_DONTWAIT
    } else {
        nix::sys::socket::MsgFlags::empty()
    };
    let mut slices = [std::io::IoSliceMut::new(buffer)];
    let message = nix::sys::socket::recvmsg::<nix::sys::socket::SockaddrStorage>(
        socket.as_raw_fd(),
        &mut slices,
        Some(space),
        flags,
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
    _nonblocking: bool,
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
/// the last allowed short. A packet the connection cannot read is a stray or
/// another peer's; it is dropped rather than answered.
fn feed_received(
    conn: &mut Connection,
    local: SocketAddr,
    received: &mut [u8],
    from: SocketAddr,
    segment: Option<usize>,
) {
    let step = segment_step(received.len(), segment);
    for piece in received.chunks_mut(step) {
        let info = quiche::RecvInfo { from, to: local };
        let _ = conn.recv(piece, info);
    }
}

/// The width the kernel cut a coalesced read into: the offload's segment
/// where it gave one, and the whole read where it did not.
const fn segment_step(len: usize, segment: Option<usize>) -> usize {
    match segment {
        Some(step) if step > 0 => step,
        _ if len == 0 => 1,
        _ => len,
    }
}

/// One read as the datagrams it arrived as.
fn split_read(bytes: &[u8], segment: Option<usize>) -> impl Iterator<Item = &[u8]> {
    bytes.chunks(segment_step(bytes.len(), segment))
}

/// Whether a read belongs to the side channel rather than to QUIC.
///
/// Every datagram in the read has to lead with the byte, not just the
/// first: one peer can send both protocols from one address, and the
/// kernel coalesces by address. A mixed read goes to QUIC, where a
/// side-channel datagram is dropped by the header parse, because losing
/// one of those costs nothing and losing a QUIC packet costs a
/// retransmission.
fn is_side_channel(lead: Option<u8>, bytes: &[u8], segment: Option<usize>) -> bool {
    let Some(named) = lead else {
        return false;
    };
    !bytes.is_empty() && split_read(bytes, segment).all(|piece| piece.first() == Some(&named))
}

/// Takes what has already arrived without waiting, up to the counted budget.
///
/// The wait was paid on the pass's first read; this hands the rest of the
/// queue to the connection as one batch. Linux applies `MSG_DONTWAIT` to each
/// drain read; other systems temporarily switch the socket to non-blocking.
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::unnecessary_wraps,
        reason = "other platforms can fail to restore blocking mode"
    )
)]
fn drain_arrivals(
    socket: &UdpSocket,
    conn: &mut Connection,
    local: SocketAddr,
    buffer: &mut [u8],
    space: &mut Vec<u8>,
) -> Result<(), Error> {
    #[cfg(not(target_os = "linux"))]
    if socket.set_nonblocking(true).is_err() {
        // Still blocking, so the pass loses nothing but the batch.
        return Ok(());
    }
    for _ in 0..DRAIN_BUDGET {
        match receive_segmented(socket, buffer, space, true) {
            Ok((len, from, segment)) => {
                feed_received(conn, local, &mut buffer[..len], from, segment);
            }
            Err(_) => break,
        }
    }
    // A socket left non-blocking would turn the next pass's bounded wait into
    // a spin, so failing to restore it ends the driver instead.
    #[cfg(not(target_os = "linux"))]
    socket.set_nonblocking(false).map_err(|_| Error::Backend)?;
    Ok(())
}

/// Sends what the connection has generated, and says when it wants to send more.
///
/// Returns a deadline rather than sleeping so the socket keeps being read:
/// sleeping would stall acknowledgements and stop the window opening.
///
/// A socket that refuses all packets is a dead carrier. Sustained size
/// refusals beyond what probing explains mean the interface narrowed under the
/// settled PMTU; revalidation reopens discovery and resets the ledger.
fn send_and_revalidate(
    socket: &UdpSocket,
    conn: &mut Connection,
    out: &mut [u8],
    sending: &mut Sending,
) -> Result<Option<Instant>, Error> {
    sending.open_duplication(conn.is_established());
    // Taken once: a per-packet `now` would let a long pass drift its own
    // horizon forward and never end.
    let paced = send_all(socket, conn, out, sending, Instant::now() + PACE_QUANTUM)?;
    if should_revalidate(sending.refused) {
        conn.revalidate_pmtu();
        sending.refused = 0;
    }
    Ok(paced)
}

/// Whether the refusals seen are more than probing explains.
const fn should_revalidate(refused: usize) -> bool {
    refused >= REVALIDATE_REFUSED_SENDS
}

/// The longest a pass may wait on a release time the pacer set.
///
/// Pacing quanta above the tick are honoured to this bound; at WAN rates a
/// millisecond is far more than one burst, so the tick alone would flush a
/// held packet ahead of its release.
const PACE_HOLD_TICK: Duration = Duration::from_millis(5);

/// How far past now a send pass will still release a packet: releases due
/// within one wake go now, as one burst, so a wake carries the rate times the
/// quantum rather than a single packet. The pacer forfeits time it was not
/// woken for, so a schedule finer than the wake cadence is only ever met by
/// bursting it.
const PACE_QUANTUM: Duration = TICK;

/// What a send pass needs beyond the connection: the ceiling, whether
/// segmentation offload is available, the size-refusal ledger, and what
/// the startup prefix still owes a second copy of.
struct Sending {
    ceiling: usize,
    gso: bool,
    refused: usize,
    role: Role,
    /// Datagrams the startup prefix still sends twice. ADR-0043.
    duplicates: usize,
    /// Whether this pass's bursts are duplicated, decided once against the
    /// connection rather than per burst.
    duplicating: bool,
    /// Bytes of a packet parked for its release time, at `out[..held]`.
    held: usize,
    /// Where that parked packet goes.
    held_to: Option<SocketAddr>,
}

impl Sending {
    const fn new(ceiling: usize, gso: bool, role: Role, duplicates: usize) -> Self {
        Self {
            ceiling,
            gso,
            refused: 0,
            role,
            duplicates,
            duplicating: false,
            held: 0,
            held_to: None,
        }
    }

    /// Decides whether this pass duplicates, from what the connection has
    /// reached and what the budget has left.
    fn open_duplication(&mut self, established: bool) {
        self.duplicating = duplication_open(self.role, established, self.duplicates);
    }
}

/// Datagrams each end sends twice at the start of a connection.
///
/// The serial prefix is a handful of sparse flights (handshake,
/// negotiation, the announcement, manifest pages, the leading edge of the
/// first data flight), so a loss in it waits on a recovery round trip that
/// no other traffic can shorten: at 5% loss and 200 ms first byte ran
/// 1.5-6.7 s against 1.03 s clean, and a probe that duplicated the prefix
/// removed the multi-second outliers outright. Counted in datagrams rather
/// than clocked, so the bound lives in the send path's own body. ADR-0043.
///
/// A copy is sent beside the carrier's congestion accounting rather than
/// through it, which is what keeps the budget small: at the QUIC minimum
/// datagram this is about 240 KB, once, per connection.
const PREFIX_DUPLICATION_DATAGRAMS: usize = 200;

/// Whether this end may duplicate the bursts of a pass.
///
/// A client duplicates from its first flight, where no amplification rule
/// binds it. A server waits for establishment: its copies are invisible to
/// the carrier's own accounting, and until the handshake completes that
/// accounting is the three-times-received bound an unvalidated address is
/// owed (spec/security.md section 7). Establishment is strictly later than
/// the address validation that lifts the bound, so the gate is the
/// conservative side of the rule.
const fn duplication_open(role: Role, established: bool, remaining: usize) -> bool {
    remaining > 0 && (matches!(role, Role::Client) || established)
}

/// Passes a closing connection may make before the driver leaves without
/// the drain gate.
///
/// The normal close exits the loop within a pass or two of the request, so
/// this binds only the wedged case. Sized so the healthy-but-slow case
/// still drains first: at the loop's 200 microsecond wait floor the budget
/// spans at least several hundred milliseconds, which is orders past the
/// passes a flushed close needs, and a spinning connection burns it in
/// well under a second of CPU.
const CLOSING_PASS_BUDGET: u32 = 4_096;

/// Whether a closing connection has outstayed its pass budget. Pure, so the
/// edge is pinned from both sides by a table test.
const fn close_overstayed(closing_passes: u32) -> bool {
    closing_passes > CLOSING_PASS_BUDGET
}

/// Packets one [`send_all`] call may draw from the connection before the
/// pass ends regardless.
///
/// A whole congestion window of full packets is far below this, so a
/// healthy pass never sees it; only a stream the connection feeds without
/// end does, and that pass has to end for the driver to read its close
/// request at all.
const SEND_PACKET_BUDGET: u32 = 16_384;

/// Whether one send pass has drawn its whole packet budget. Pure, so the
/// edge is pinned from both sides by a table test.
const fn send_exhausted(packets: u32) -> bool {
    packets > SEND_PACKET_BUDGET
}

/// How often the ramp cadence elicits an ack.
const RAMP_PING_INTERVAL: Duration = Duration::from_millis(25);

/// Pings the ramp cadence sends at its own interval, counted rather than
/// clocked so the bound lives in the loop's own body: at the interval above
/// this spans the serial prefix of any path this serves. Past it the
/// keepalive's interval takes over.
///
/// The cadence arms at establishment, where `send_ack_eliciting` starts
/// doing anything. If early data is ever enabled, the arming gate needs
/// `is_in_early_data` beside `is_established`, or the cadence stays dark
/// through the whole 0-RTT window.
const RAMP_PING_BUDGET: u32 = 48;

/// Whether the ramp cadence still owes pings. Pure, so the edge is
/// pinned from both sides by a table test.
const fn ramp_ping_due(ramp_pings: u32) -> bool {
    ramp_pings < RAMP_PING_BUDGET
}

/// What the keepalive interval divides the idle timeout by.
///
/// A ping every third of the timeout holds the connection across two lost
/// pings. It is not a way to outlive a peer that has gone: QUIC restarts
/// the idle timer on a send only for the first ack-eliciting packet since
/// a packet last arrived, so a peer that answers nothing still times this
/// end out on schedule.
const KEEPALIVE_DIVISOR: u64 = 3;

/// The keepalive cadence for an endpoint whose idle timeout is
/// `idle_timeout_ms`, or none for an endpoint with no business holding a
/// connection open. Pure, so a table test pins what it derives.
///
/// Only a client keeps one alive. A client knows whether it still needs
/// the session: a fetch rail that has finished its ranges is still owed
/// the rest of its plan. A server has no such knowledge, and a server that
/// pinged would answer its own pings for as long as a peer's stack kept
/// acknowledging them, which is what the peer stops doing when it goes.
/// The serving end's stall budget counts the carrier, so a serve that
/// generated its own carrier traffic would never reap a session again.
///
/// The interval comes from this endpoint's own idle timeout. The one in
/// force is the smaller of the two ends' (RFC 9000 section 10.1), so a peer
/// that installs less than three times this interval is not held open by
/// it. Both ends of this protocol install the same value.
///
/// What a serve's sessions are bounded by is their count, never their age:
/// a client that keeps any packet flowing holds its slot, and this cadence
/// is indistinguishable on the wire from a peer that sends one byte a
/// second. Reaping a connected peer that asks for nothing would be a slot
/// policy, which this is not.
const fn keepalive_interval(role: Role, idle_timeout_ms: u64) -> Option<Duration> {
    if !matches!(role, Role::Client) || idle_timeout_ms == 0 {
        return None;
    }
    // Rounded up, because a timeout under the divisor would otherwise floor
    // to a zero interval and ping every pass rather than never.
    Some(Duration::from_millis(
        idle_timeout_ms.div_ceil(KEEPALIVE_DIVISOR),
    ))
}

/// How long the pump waits before eliciting the next ack: the ramp's
/// interval while its budget lasts, the keepalive's after.
///
/// What the keepalive is for is a rail that has finished its ranges while
/// the fetch it belongs to runs on: nothing is due on it, and without this
/// the idle timeout closes it under an owner that is still using the
/// session. Only a ping resets the cadence's clock, so a connection with
/// traffic on it pays one ack-eliciting packet an interval as well, which
/// is one packet in ten seconds against a transfer's thousands a second.
/// Pure, so the handover is pinned from both sides by a table test.
fn ping_interval(ramp_pings: u32, keepalive: Option<Duration>) -> Duration {
    if ramp_ping_due(ramp_pings) {
        return RAMP_PING_INTERVAL;
    }
    keepalive.unwrap_or(Duration::MAX)
}

/// Whether the pump owes the peer an ack-eliciting packet: not before
/// establishment, where a ping would spend the ramp's budget on packets
/// the handshake's own flights already elicit acks for, and then once per
/// [`ping_interval`] since the last one. Pure, so the whole decision is
/// pinned by a table test rather than assembled in the loop where nothing
/// can reach it.
fn ping_due(
    announced: bool,
    since_last_ping: Duration,
    ramp_pings: u32,
    keepalive: Option<Duration>,
) -> bool {
    announced && since_last_ping >= ping_interval(ramp_pings, keepalive)
}

/// Takes the caller's close request to the connection, once.
fn note_close_request(conn: &mut Connection, close: &Arc<AtomicU64>, closing: &mut bool) {
    if *closing {
        return;
    }
    let requested = close.load(Ordering::Relaxed);
    if requested != NO_CLOSE {
        *closing = true;
        let _ = conn.close(true, requested, b"");
    }
}

/// Sends a packet parked for its release time, without waiting it out.
///
/// The pump's last word on a connection: a driver that leaves while a packet
/// is held has no further pass to open with it.
///
/// # Errors
/// Reports whatever the socket refused.
fn flush_held(socket: &UdpSocket, out: &[u8], sending: &mut Sending) -> Result<(), Error> {
    let held = std::mem::take(&mut sending.held);
    let destination = sending.held_to.take();
    flush_burst(socket, &out[..held], held, destination, sending)
}

fn send_all(
    socket: &UdpSocket,
    conn: &mut Connection,
    out: &mut [u8],
    sending: &mut Sending,
    pass_horizon: Instant,
) -> Result<Option<Instant>, Error> {
    // Packets are gathered into one buffer and handed over together so
    // segmentation offload takes the whole burst in one call.
    let ceiling = sending.ceiling;
    let mut filled = 0_usize;
    let mut segment = 0_usize;
    let mut destination = None;
    // A packet parked for its release time already sits at the front of
    // `out`, so this pass opens with it filled: it leaves first, and the
    // equal slots the kernel's segmentation needs are measured from it.
    if let Some(to) = sending.held_to.take() {
        filled = std::mem::take(&mut sending.held);
        segment = filled;
        destination = Some(to);
    }
    let mut packets: u32 = 0;
    loop {
        // The opening slot is the ceiling so a discovery probe fits; later
        // packets are capped under it, so the burst is a run of equal slots and
        // `filled` stays on a segment boundary.
        let slot = if filled == 0 { ceiling } else { segment };
        let Some(room) = out.get_mut(filled..filled + slot) else {
            // The buffer holds no further packet, so this burst goes now.
            flush_burst(socket, &out[..filled], segment, destination, sending)?;
            filled = 0;
            destination = None;
            continue;
        };
        // A pass's own bound on the stream, counted in this loop's body. A
        // healthy connection ends the pass itself at Done or its pacer, but
        // a wedged one was caught feeding this loop for half an hour inside
        // one call, and the driver's own close budget can only fire between
        // passes. What was not sent by here waits for the next pass, which
        // first reads commands and the close request.
        packets = packets.saturating_add(1);
        if send_exhausted(packets) {
            flush_burst(socket, &out[..filled], segment, destination, sending)?;
            return Ok(None);
        }
        match conn.send(room) {
            Ok((written, info)) => {
                // A different destination cannot share a burst.
                if destination.is_some_and(|previous| previous != info.to) {
                    flush_burst(socket, &out[..filled], segment, destination, sending)?;
                    // The packet just generated sits at `filled`, so move it to
                    // the front rather than losing or resending it.
                    out.copy_within(filled..filled + written, 0);
                    filled = 0;
                }
                destination = Some(info.to);
                // Pacing is the connection's decision, and a packet released
                // beyond this pass's horizon ends the pass: what is due within
                // one wake goes as one call, and the held packet is parked at
                // the front of `out` to open the next pass at its own release
                // time. Decided before the append, or the burst it was meant to
                // follow would carry it early. That bounds a burst's time by
                // the pacer's clock, to within one quantum. A release is only
                // in the future against the clock now: a pass outrunning its
                // own horizon must not park a packet already due.
                if info.at > pass_horizon && info.at > Instant::now() {
                    flush_burst(socket, &out[..filled], segment, destination, sending)?;
                    out.copy_within(filled..filled + written, 0);
                    sending.held = written;
                    sending.held_to = Some(info.to);
                    return Ok(Some(info.at));
                }
                if filled == 0 {
                    segment = written;
                }
                filled += written;
                // A packet shorter than a segment closes the burst, because
                // the kernel cuts every segment to the same length but the
                // last; the connection may still have more to say.
                if written < segment {
                    flush_burst(socket, &out[..filled], segment, destination, sending)?;
                    filled = 0;
                    destination = None;
                }
            }
            Err(quiche::Error::Done) => {
                flush_burst(socket, &out[..filled], segment, destination, sending)?;
                // Done in a segment-sized slot only says the next packet did
                // not fit this burst's segment: a burst opened by a lone ACK
                // pins the segment near thirty bytes, and ending the pass
                // there would hand the wait floor back one packet at a time.
                // Reopen at the ceiling; Done with the ceiling on offer is
                // the connection actually finished.
                if slot == ceiling {
                    return Ok(None);
                }
                filled = 0;
                destination = None;
            }
            Err(_) => {
                // The gathered packets are state the connection has already
                // committed to; they go to the peer even as the driver ends.
                let _ = flush_burst(socket, &out[..filled], segment, destination, sending);
                return Err(Error::Backend);
            }
        }
    }
}

/// Sends a burst as one datagram the kernel cuts into `segment`-sized pieces.
///
/// Uses `UDP_SEGMENT` via `nix`, which is why this crate forbids unsafe of its
/// own.
///
/// # Errors
/// Reports any refusal, including a kernel without the option, so the caller
/// can fall back to sending packets one at a time.
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
/// A kernel that refuses the control message falls back for that burst.
///
/// The receive side has its own switch, `enable_receive_offload`, because
/// `UDP_GRO` returns several coalesced packets in one buffer, which
/// `Connection::recv` cannot parse: `receive_segmented` reads the segment size
/// beside the bytes and `feed_received` cuts the buffer back into datagrams
/// first.
const fn offload_available() -> bool {
    cfg!(target_os = "linux")
}

/// Hands one burst of equally sized packets to the socket, twice while the
/// startup prefix still owes copies.
fn flush_burst(
    socket: &UdpSocket,
    burst: &[u8],
    segment: usize,
    destination: Option<SocketAddr>,
    sending: &mut Sending,
) -> Result<(), Error> {
    let Some(destination) = destination else {
        return Ok(());
    };
    if burst.is_empty() {
        return Ok(());
    }
    send_burst(
        socket,
        burst,
        segment,
        destination,
        sending.gso,
        &mut sending.refused,
    )?;
    if sending.duplicating {
        duplicate_burst(socket, burst, segment, destination, sending);
    }
    Ok(())
}

/// Sends as much of the burst a second time as the startup budget covers.
///
/// A peer discards a packet number it has already seen, so a copy costs a
/// decryption and buys the packet against one loss. Nothing here is
/// reported: the connection is owed the original, and a refused copy is
/// neither the carrier's death nor a probe's answer about the path.
fn duplicate_burst(
    socket: &UdpSocket,
    burst: &[u8],
    segment: usize,
    destination: SocketAddr,
    sending: &mut Sending,
) {
    let room = sending.duplicates.saturating_mul(segment).min(burst.len());
    let copy = &burst[..room];
    sending.duplicates = sending
        .duplicates
        .saturating_sub(copy.len().div_ceil(segment));
    let mut refused = 0;
    let _ = send_burst(
        socket,
        copy,
        segment,
        destination,
        sending.gso,
        &mut refused,
    );
}

/// Hands one burst of equally sized packets to the socket.
///
/// With offload the whole burst is one call; without it each packet is sent
/// separately. A refused control message falls back rather than failing: offload
/// is a cost saving, not a correctness requirement.
fn send_burst(
    socket: &UdpSocket,
    burst: &[u8],
    segment: usize,
    destination: SocketAddr,
    gso: bool,
    refused: &mut usize,
) -> Result<(), Error> {
    // A kernel that will not segment falls through and takes the packets one
    // at a time.
    if gso && burst.len() > segment && send_segmented(socket, burst, segment, destination).is_ok() {
        return Ok(());
    }
    for packet in burst.chunks(segment) {
        match socket.send_to(packet, destination) {
            Ok(_) => {}
            // A datagram too large for the interface is a lost path probe, and
            // losing it is the probe's answer. Ordinary packets never hit this
            // because the connection sizes them under the validated MTU.
            Err(error) if datagram_too_large(&error) => {
                *refused = refused.saturating_add(1);
            }
            Err(_) => return Err(Error::Backend),
        }
    }
    Ok(())
}

/// Size refusals a connection rides out before revalidating its PMTU.
///
/// Discovery explains a handful: a probe above the interface is refused
/// once per size it tries. It cannot explain a run of them, because data
/// packets are sized under the validated MTU; a run means the interface
/// narrowed after validation, and every retransmission will be refused at
/// the same size until discovery is reopened.
const REVALIDATE_REFUSED_SENDS: usize = 64;

/// Whether a send was refused for the datagram's size against the local
/// interface, which is `EMSGSIZE` by its per-platform number.
fn datagram_too_large(error: &std::io::Error) -> bool {
    #[cfg(target_os = "linux")]
    const MESSAGE_TOO_LONG: i32 = 90;
    #[cfg(windows)]
    const MESSAGE_TOO_LONG: i32 = 10040;
    #[cfg(all(unix, not(target_os = "linux")))]
    const MESSAGE_TOO_LONG: i32 = 40;
    error.raw_os_error() == Some(MESSAGE_TOO_LONG)
}

/// Takes what the caller has handed over, while the driver is under its bound.
///
/// Leaving submissions in the channel until the bound is what makes a stalled
/// peer backpressure: the channel fills, the caller's queue stops draining, and
/// the application is told.
#[expect(
    clippy::too_many_arguments,
    reason = "one submission needs what the driver holds, and the driver holds no less"
)]
fn take_submissions(
    conn: &mut Connection,
    streams: &mut BTreeMap<u64, StreamState>,
    datagrams: &mut VecDeque<(Payload, u64)>,
    budget: &SharedBudget,
    control_limit: &Arc<AtomicUsize>,
    commands: &mpsc::Receiver<Command>,
    inbound: &Arc<Mutex<Inbound>>,
    role: Role,
    queued: &mut Queued,
    pending_datagram: &mut Option<Command>,
    pending_datagram_state: &mut Option<NativeEvent>,
) -> bool {
    while !queued.is_full() {
        let command = if let Some(command) = pending_datagram.take() {
            command
        } else {
            match commands.try_recv() {
                Ok(command) => command,
                // The sender is gone: the endpoint was dropped, and nothing
                // more will ever arrive here.
                Err(mpsc::TryRecvError::Disconnected) => return true,
                Err(mpsc::TryRecvError::Empty) => return false,
            }
        };
        match apply(
            conn,
            streams,
            datagrams,
            budget,
            control_limit,
            command,
            inbound,
            role,
            pending_datagram_state,
        ) {
            Ok(Some(bytes)) => queued.charge(bytes),
            Ok(None) => {}
            Err(command) => {
                *pending_datagram = Some(command);
                return false;
            }
        }
    }
    false
}

/// Closes for an owner that is gone, which the dropped channel signals.
///
/// The stored-close path runs first, so a code the caller stored is already the
/// connection's. This handles an owner that vanished without one. Two paths
/// ensure no single failure strands the drop's join on an idle timeout.
fn note_orphaned(conn: &mut Connection, closing: &mut bool) {
    if *closing {
        return;
    }
    *closing = true;
    let _ = conn.close(true, NO_REASON, b"");
}

/// Applies one submission to the connection.
///
/// Reports the bytes it left in an outbox, so the charge is taken where the
/// record is queued and nowhere else.
#[expect(
    clippy::too_many_arguments,
    reason = "one submission needs what the driver holds, and the driver holds no less"
)]
fn apply(
    conn: &mut Connection,
    streams: &mut BTreeMap<u64, StreamState>,
    datagrams: &mut VecDeque<(Payload, u64)>,
    budget: &SharedBudget,
    control_limit: &Arc<AtomicUsize>,
    command: Command,
    inbound: &Arc<Mutex<Inbound>>,
    role: Role,
    pending_datagram_state: &mut Option<NativeEvent>,
) -> Result<Option<usize>, Command> {
    match command {
        Command::Control(bytes) => {
            let state = stream_state(
                streams,
                CONTROL_STREAM_ID,
                StreamKind::Control,
                budget,
                control_limit,
            );
            let charge = bytes.len();
            state.outbox.push_back((bytes, 0));
            Ok(Some(charge))
        }
        Command::Reliable { stream, bytes } => {
            // Refused at submission, so this cannot be a lane with no stream.
            let Ok(id) = stream_for_lane(stream.0, role) else {
                return Ok(None);
            };
            let state = stream_state(
                streams,
                id,
                StreamKind::Reliable { lane: stream.0 },
                budget,
                control_limit,
            );
            let charge = bytes.len();
            state.outbox.push_back((bytes, 0));
            Ok(Some(charge))
        }
        // Offered to the connection, and held for a later pass when it has
        // no room rather than thrown away. The bounded datagram queues supply
        // their own budget, so do not charge these bytes twice.
        Command::Datagram { context, bytes } => {
            // Offered first, so room the connection freed since the last pass
            // is room this datagram can have. At the bound, keep this exact
            // command and stop taking later submissions until room appears.
            write_datagrams(conn, datagrams, pending_datagram_state, inbound);
            let held_bytes: usize = datagrams.iter().map(|(held, _)| held.len()).sum();
            if !outbox_has_room(datagrams.len(), held_bytes, bytes.len()) {
                return Err(Command::Datagram { context, bytes });
            }
            datagrams.push_back((bytes, context));
            write_datagrams(conn, datagrams, pending_datagram_state, inbound);
            Ok(None)
        }
        // Refused at submission, so it cannot reach the driver. A silent success
        // here would hide it if that ever changed.
        Command::ReceiveCredit(_) => Ok(None),
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

/// What offering a datagram to the connection came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Offered {
    Taken,
    /// No room right now, so the same datagram is offered again later.
    Waiting,
    /// This datagram will never be taken, whatever room appears.
    Refused,
}

/// Reads what the connection answered when offered a datagram.
///
/// `Done` is its datagram queue being full, which passes. Every other
/// refusal is about this datagram rather than the moment, so holding it
/// would block the ones behind it forever.
///
/// Pure, because this is the branch that decides between a symbol that waits
/// and one that is thrown away, and a real connection cannot be made to
/// refuse on demand.
const fn offered(result: &Result<(), quiche::Error>) -> Offered {
    match result {
        Ok(()) => Offered::Taken,
        Err(quiche::Error::Done) => Offered::Waiting,
        Err(_) => Offered::Refused,
    }
}

/// Whether the driver has room to hold another refused datagram of `bytes`.
///
/// Pure for the same reason: filling a real connection's queue two thousand
/// deep to see the bound is not something a test can arrange.
const fn outbox_has_room(held: usize, held_bytes: usize, bytes: usize) -> bool {
    held < DATAGRAM_OUTBOX_LEN && held_bytes + bytes <= DATAGRAM_OUTBOX_BYTES
}

/// Ends every datagram still waiting, for a driver that will not offer them
/// again.
///
/// One `DatagramState` per submitted datagram is the contract the other
/// carriers keep, and a caller counting what it is owed would otherwise wait
/// on datagrams this end has forgotten.
fn abandon_datagrams(datagrams: &mut VecDeque<(Payload, u64)>, inbound: &Arc<Mutex<Inbound>>) {
    let mut queue = inbound.lock().unwrap_or_else(PoisonError::into_inner);
    for (_, context) in datagrams.drain(..) {
        queue.push_unlosable(NativeEvent::DatagramDropped { context });
    }
}

/// Ends every datagram held between the command channel and the connection.
fn abandon_all_datagrams(
    pending_state: &mut Option<NativeEvent>,
    pending: &mut Option<Command>,
    datagrams: &mut VecDeque<(Payload, u64)>,
    inbound: &Arc<Mutex<Inbound>>,
) {
    if let Some(state) = pending_state.take() {
        inbound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_unlosable(state);
    }
    // The pending command was submitted after everything in the outbox.
    abandon_datagrams(datagrams, inbound);
    match pending.take() {
        Some(Command::Datagram { context, .. }) => {
            inbound
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_unlosable(NativeEvent::DatagramDropped { context });
        }
        Some(_) => unreachable!("only a datagram can wait here"),
        None => {}
    }
}

fn finish_datagrams(
    outcome: Result<(), Error>,
    pending_state: &mut Option<NativeEvent>,
    pending: &mut Option<Command>,
    datagrams: &mut VecDeque<(Payload, u64)>,
    inbound: &Arc<Mutex<Inbound>>,
) -> Result<(), Error> {
    abandon_all_datagrams(pending_state, pending, datagrams, inbound);
    outcome
}

/// Offers waiting datagrams to the connection while it has room.
///
/// `Done` is the connection's datagram queue being full, which is "not yet":
/// the datagram stays at the front for a later pass. Anything else means
/// this one will never go, so it is dropped and the caller told, because
/// holding it would block every datagram behind it forever.
fn write_datagrams(
    conn: &mut Connection,
    datagrams: &mut VecDeque<(Payload, u64)>,
    pending_state: &mut Option<NativeEvent>,
    inbound: &Arc<Mutex<Inbound>>,
) {
    if let Some(state) = pending_state.take() {
        let mut queue = inbound.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(state) = queue.push(state) {
            *pending_state = Some(state);
            return;
        }
    }
    while let Some((bytes, context)) = datagrams.front() {
        let observed = match offered(&conn.dgram_send(bytes)) {
            Offered::Taken => NativeEvent::DatagramSent { context: *context },
            Offered::Waiting => return,
            Offered::Refused => NativeEvent::DatagramDropped { context: *context },
        };
        datagrams.pop_front();
        let mut queue = inbound.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(observed) = queue.push(observed) {
            *pending_state = Some(observed);
            return;
        }
    }
}

/// Writes what a stream has waiting, as far as flow control allows, giving
/// back what the connection took. The release side of [`apply`]'s charge.
fn write_outbox(conn: &mut Connection, stream: &mut StreamState, queued: &mut Queued) {
    let id = stream.id;
    while let Some((bytes, sent)) = stream.outbox.front_mut() {
        let owed = bytes.len() - *sent;
        let offered = SharedBuf {
            bytes: bytes.clone(),
            start: *sent,
            end: bytes.len(),
        };
        match conn.stream_send_zc(id, offered, false) {
            Ok((written, _)) => {
                *sent += written;
                // One release for both answers, because what the connection
                // took is what is no longer owed either way.
                queued.wrote(written);
                if written < owed {
                    // Flow control is the peer's, so a record may go in pieces.
                    // The offset moved and the rest waits for the next pass,
                    // which is the same answer as nothing having been taken.
                    return;
                }
                stream.outbox.pop_front();
                queued.finished();
            }
            // Both mean "not yet" rather than "never": Done is flow
            // control, and StreamLimit is the peer's stream allowance,
            // which arrives with the handshake. A caller that hands over a
            // frame before the connection is established would otherwise
            // lose it here and wait on an answer to a request the peer
            // never saw.
            Err(quiche::Error::Done | quiche::Error::StreamLimit) => return,
            Err(_) => {
                queued.discard(&stream.outbox);
                stream.outbox.clear();
                return;
            }
        }
    }
}

/// Reads every readable stream and turns its bytes into frames.
fn read_streams(
    conn: &mut Connection,
    streams: &mut BTreeMap<u64, StreamState>,
    budget: &SharedBudget,
    inbound: &Arc<Mutex<Inbound>>,
    control_limit: &Arc<AtomicUsize>,
    role: Role,
    // The driver's own buffer, so a read costs no allocation.
    buffer: &mut [u8],
) {
    // Overflow drains for every stream that holds any, not only the readable
    // ones: a stream leaves the readable set for good once its last chunk is
    // consumed, and what its queue refusal parked here must still deliver.
    if let Ok(mut queue) = inbound.lock() {
        for state in streams.values_mut() {
            while let Some(event) = state.overflow.pop_front() {
                if let Err(refused) = queue.push(event) {
                    state.overflow.push_front(refused);
                    break;
                }
            }
        }
    }
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
        // frames the queue refused wait in `overflow` in order, and the
        // stream is not read while any wait, so the unread bytes stall the
        // peer through flow control. The overflow is bounded by what one
        // read chunk can complete, because reading stops the moment it
        // holds anything.
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
            //
            // What this stream already holds for a partial frame is no part
            // of that room: the frame it completes is queued as an event of
            // its own length, so the charge moves from `assembling` to
            // `bytes` rather than being freed.
            let headroom = {
                let Ok(queue) = inbound.lock() else {
                    break;
                };
                MAX_ASSEMBLY_BYTES.saturating_sub(queue.charged())
            };
            let partial_limit = state
                .kind
                .partial_frame_limit(control_limit.load(Ordering::Relaxed));
            let needed = partial_limit.saturating_add(buffer.len());
            if headroom < needed {
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
                let event = match kind {
                    StreamKind::Control => NativeEvent::Control(frame),
                    StreamKind::Reliable { lane } => NativeEvent::Reliable {
                        lane,
                        sequence: *sequence,
                        bytes: frame,
                    },
                };
                let Ok(mut queue) = inbound.lock() else {
                    return Err(FrameFault::exhausted());
                };
                if overflow.is_empty() {
                    if let Err(refused) = queue.push(event) {
                        overflow.push_back(refused);
                    }
                } else {
                    overflow.push_back(event);
                }
                Ok(())
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
            if !state.overflow.is_empty() {
                break;
            }
        }
    }
}

/// Takes received datagrams off the connection and hands them to the caller.
///
/// One the inbound budget cannot hold is dropped: it is an unreliable
/// datagram, and leaving it queued would stall the connection's datagram
/// credit for the ones behind it.
fn drain_datagrams(conn: &mut Connection, inbound: &Arc<Mutex<Inbound>>, buffer: &mut [u8]) {
    while let Ok(len) = conn.dgram_recv(buffer) {
        let event = NativeEvent::Datagram(vot_transport_api::shared_payload(&buffer[..len]));
        if let Ok(mut queue) = inbound.lock() {
            let _ = queue.push(event);
        }
    }
}

/// Reads the active path's measurements, when there is one.
#[must_use]
pub fn path_sample(conn: &quiche::Connection) -> Option<PathStats> {
    path_sample_from(conn)
}

fn path_sample_from<F: quiche::BufFactory>(conn: &quiche::Connection<F>) -> Option<PathStats> {
    let stats = conn.path_stats().find(|path| path.active)?;
    Some(PathStats {
        smoothed_rtt_us: u64::try_from(stats.rtt.as_micros()).ok(),
        congestion_window_bytes: u64::try_from(stats.cwnd).ok(),
        mtu_bytes: u64::try_from(stats.pmtu).ok(),
        delivery_rate_bps: Some(stats.delivery_rate.saturating_mul(8)),
        lost_packets: u64::try_from(conn.stats().lost).ok(),
        spurious_lost_packets: u64::try_from(conn.stats().spurious_lost).ok(),
        // Connection scope, like the loss counters above, so all four halves
        // of the ledger cover the same packets whatever paths existed.
        packets_sent: u64::try_from(conn.stats().sent).ok(),
        packets_received: u64::try_from(conn.stats().recv).ok(),
    })
}

#[cfg(test)]
mod tests {
    use std::process::Command as Process;
    use std::sync::OnceLock;
    use std::time::Instant;

    use super::*;

    #[test]
    fn retry_tokens_bind_the_peer_expiry_and_contents() {
        let secret = [0x41; 32];
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let odcid = [0x52; 16];
        let token = mint_retry_token(&secret, peer, &odcid, 100);
        assert_eq!(
            validate_retry_token(&secret, peer, &token, 130),
            Some(odcid.to_vec())
        );
        assert!(validate_retry_token(&secret, peer, &token, 131).is_none());
        assert!(
            validate_retry_token(
                &secret,
                "127.0.0.2:4433".parse().expect("an address"),
                &token,
                100,
            )
            .is_none()
        );
        let mut forged = token.clone();
        forged[12] ^= 1;
        assert!(validate_retry_token(&secret, peer, &forged, 100).is_none());
        let mut bad_tag = token;
        let tag = bad_tag.len() - RETRY_TOKEN_TAG_BYTES;
        bad_tag[tag] ^= 1;
        assert!(validate_retry_token(&secret, peer, &bad_tag, 100).is_none());
        bad_tag[tag + 1] ^= 1;
        assert!(validate_retry_token(&secret, peer, &bad_tag, 100).is_none());
        let peer6: SocketAddr = "[::1]:4433".parse().expect("an address");
        let token6 = mint_retry_token(&secret, peer6, &odcid, 100);
        assert_eq!(
            validate_retry_token(&secret, peer6, &token6, 100),
            Some(odcid.to_vec())
        );
        assert!(validate_retry_token(&secret, peer, &[1, 2, 3], 100).is_none());
    }

    #[test]
    fn retry_uses_the_system_clock() {
        let now = unix_seconds();
        assert!((1_767_225_600..4_102_444_800).contains(&now));
    }

    #[test]
    fn shared_buffers_split_without_copying() {
        let bytes = Payload::from(vec![1, 2, 3, 4]);
        let allocation = bytes.as_ptr();
        let mut head = SharedBuf {
            bytes,
            start: 0,
            end: 4,
        };
        let mut tail = quiche::BufSplit::split_at(&mut head, 2);
        let last = quiche::BufSplit::split_at(&mut tail, 1);
        assert_eq!(head.as_ref(), [1, 2]);
        assert_eq!(tail.as_ref(), [3]);
        assert_eq!(last.as_ref(), [4]);
        assert_eq!(head.as_ref().as_ptr(), allocation);
        assert_eq!(tail.as_ref().as_ptr(), allocation.wrapping_add(2));
        assert_eq!(last.as_ref().as_ptr(), allocation.wrapping_add(3));
    }

    #[test]
    fn public_path_sample_reads_quiches_default_connection() {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a config");
        config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("the protocol");
        let scid = quiche::ConnectionId::from_ref(&[9; 16]);
        let conn = quiche::connect(
            None,
            &scid,
            "127.0.0.1:1".parse().expect("an address"),
            "127.0.0.1:2".parse().expect("an address"),
            &mut config,
        )
        .expect("a connection");
        let sample = path_sample(&conn).expect("an active path");
        assert!(sample.congestion_window_bytes.unwrap_or(0) > 0);
        assert!(sample.mtu_bytes.unwrap_or(0) > 0);
    }

    #[test]
    fn supported_and_unknown_versions_take_opposite_paths() {
        assert!(!version_unsupported(quiche::PROTOCOL_VERSION));
        assert!(version_unsupported(u32::MAX));
    }

    #[test]
    fn the_ramp_cadence_falls_silent_at_its_whole_budget() {
        assert!(ramp_ping_due(0));
        assert!(ramp_ping_due(RAMP_PING_BUDGET - 1));
        assert!(!ramp_ping_due(RAMP_PING_BUDGET));
        assert!(!ramp_ping_due(u32::MAX));
        // About a second of cadence: enough for any serial prefix this
        // serves, small enough that an idle connection reaches the much
        // slower keepalive fast.
        const {
            assert!(RAMP_PING_BUDGET >= 32);
            assert!(RAMP_PING_BUDGET <= 128);
        }
    }

    #[test]
    fn the_cadence_hands_the_ramp_over_to_the_keepalive() {
        let keepalive = keepalive_interval(Role::Client, IDLE_TIMEOUT_MS);
        assert_eq!(keepalive, Some(Duration::from_secs(10)));
        // A server holds nothing open: its own pings would feed the stall
        // budget that is meant to reap it.
        assert_eq!(keepalive_interval(Role::Server, IDLE_TIMEOUT_MS), None);
        assert_eq!(keepalive_interval(Role::Server, 3_000), None);
        // The handover from both sides of the budget.
        assert_eq!(ping_interval(0, keepalive), RAMP_PING_INTERVAL);
        assert_eq!(
            ping_interval(RAMP_PING_BUDGET - 1, keepalive),
            RAMP_PING_INTERVAL
        );
        assert_eq!(
            ping_interval(RAMP_PING_BUDGET, keepalive),
            Duration::from_secs(10)
        );
        assert_eq!(ping_interval(u32::MAX, keepalive), Duration::from_secs(10));
        // A zero timeout is a cadence with no interval to derive, so the
        // cadence ends with the ramp rather than pinging every pass.
        assert_eq!(keepalive_interval(Role::Client, 0), None);
        assert_eq!(ping_interval(RAMP_PING_BUDGET, None), Duration::MAX);
        assert_eq!(ping_interval(0, None), RAMP_PING_INTERVAL);
        assert_eq!(
            keepalive_interval(Role::Client, 3_000),
            Some(Duration::from_secs(1))
        );
        // A timeout too short to divide still names an interval, since a
        // zero one is a ping every pass.
        assert_eq!(
            keepalive_interval(Role::Client, 1),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            keepalive_interval(Role::Client, 2),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            keepalive_interval(Role::Client, 3),
            Some(Duration::from_millis(1))
        );
        // Room in any timeout for two lost pings.
        const {
            assert!(KEEPALIVE_DIVISOR >= 3);
        }
    }

    #[test]
    fn a_ping_is_due_once_established_and_once_an_interval_is_up() {
        let keepalive = keepalive_interval(Role::Client, IDLE_TIMEOUT_MS);
        // Nothing is due before establishment, however long the wait: the
        // ramp's budget is for the flights after it.
        assert!(!ping_due(false, Duration::MAX, 0, keepalive));
        assert!(!ping_due(false, Duration::MAX, RAMP_PING_BUDGET, keepalive));
        // The ramp's interval from both sides.
        assert!(!ping_due(
            true,
            RAMP_PING_INTERVAL.saturating_sub(Duration::from_nanos(1)),
            0,
            keepalive
        ));
        assert!(ping_due(true, RAMP_PING_INTERVAL, 0, keepalive));
        // The keepalive's, once the ramp's budget is spent.
        assert!(!ping_due(
            true,
            Duration::from_secs(10).saturating_sub(Duration::from_nanos(1)),
            RAMP_PING_BUDGET,
            keepalive
        ));
        assert!(ping_due(
            true,
            Duration::from_secs(10),
            RAMP_PING_BUDGET,
            keepalive
        ));
        // With the idle timer disabled the cadence ends with the ramp: a
        // day of silence owes nothing.
        assert!(!ping_due(
            true,
            Duration::from_hours(24),
            RAMP_PING_BUDGET,
            None
        ));
        assert!(ping_due(true, RAMP_PING_INTERVAL, 0, None));
    }

    /// The idle timeout the test below installs on both ends. Longer than
    /// the wait a loaded runner can impose on a pump thread, since a
    /// keepalive that misses its whole window would close the connection
    /// and read as a defect.
    const SILENT_IDLE_MS: u64 = 4_000;

    /// Rounds of silence that test holds and what each costs. Eight
    /// seconds: without the keepalive the connection dies at 5.2 s, the
    /// ramp cadence carrying the first 1.2 s and the idle timeout the rest.
    const SILENT_ROUNDS: u32 = 40;
    const SILENT_ROUND: Duration = Duration::from_millis(200);

    /// A fetch rail that has finished its ranges sends nothing for the rest
    /// of the transfer while the rest of the fetch runs on. Without the
    /// keepalive the idle timeout closes it under its owner, and one rail's
    /// death abandons the whole plan.
    #[test]
    fn a_connection_with_nothing_to_send_outlives_its_idle_timeout() {
        let (certificate, key) = credentials();
        let mut server_config = Config::server(limits(), certificate, key);
        server_config.idle_timeout_ms = SILENT_IDLE_MS;
        let mut server =
            Transport::serve("127.0.0.1:0".parse().expect("an address"), &server_config)
                .expect("a server");
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        client_config.idle_timeout_ms = SILENT_IDLE_MS;
        let mut client = Transport::connect(
            "127.0.0.1:0".parse().expect("an address"),
            server.local_address(),
            Some("localhost"),
            &client_config,
        )
        .expect("a client");
        client.send_control(&frame(b"before")).expect("a frame");
        pump_until(&mut client, &mut server, 10, |_, from_server| {
            from_server
                .iter()
                .any(|event| matches!(event, Event::Control(_)))
        });

        // Counted rounds rather than a clock: neither end says anything for
        // longer than the idle timeout, and neither may go.
        let mut gone = Vec::new();
        for _ in 0..SILENT_ROUNDS {
            std::thread::sleep(SILENT_ROUND);
            for event in
                std::iter::from_fn(|| client.poll()).chain(std::iter::from_fn(|| server.poll()))
            {
                if matches!(event, Event::Disconnected(_)) {
                    gone.push(event);
                }
            }
        }
        assert!(
            gone.is_empty(),
            "silence past the idle timeout closed a connection its owner still holds: {gone:?}"
        );

        server.send_control(&frame(b"after")).expect("a frame");
        pump_until(&mut client, &mut server, 10, |from_client, _| {
            from_client.iter().any(
                |event| matches!(event, Event::Control(bytes) if bytes.as_ref() == frame(b"after")),
            )
        });
    }

    #[test]
    fn a_closing_connection_overstays_only_past_its_whole_budget() {
        // The edge from both sides: at the budget the driver keeps trying
        // the drain gate, one pass past it the driver leaves. Zero is the
        // counter's start, never overstayed.
        assert!(!close_overstayed(0));
        assert!(!close_overstayed(1));
        assert!(!close_overstayed(CLOSING_PASS_BUDGET));
        assert!(close_overstayed(CLOSING_PASS_BUDGET + 1));
        assert!(close_overstayed(u32::MAX));
        // The budget's worst case stays test-sized: a spinning connection
        // burns it in under a second, and a waiting one in a few of them.
        const {
            assert!(CLOSING_PASS_BUDGET <= 8_192);
        }
    }

    #[test]
    fn a_send_pass_ends_at_its_whole_packet_budget() {
        assert!(!send_exhausted(0));
        assert!(!send_exhausted(1));
        assert!(!send_exhausted(SEND_PACKET_BUDGET));
        assert!(send_exhausted(SEND_PACKET_BUDGET + 1));
        assert!(send_exhausted(u32::MAX));
        // Far above a congestion window of full packets, so a healthy pass
        // never meets it, and small enough that a runaway pass ends within
        // test-sized time.
        const {
            assert!(SEND_PACKET_BUDGET >= 8_192);
            assert!(SEND_PACKET_BUDGET <= 65_536);
        }
    }

    #[test]
    fn a_changed_read_timeout_is_installed_and_cached() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        socket.set_read_timeout(Some(TICK)).unwrap();
        let timeout = Duration::from_micros(500);
        let mut cached = Some(TICK);

        install_read_timeout(&socket, &mut cached, timeout).unwrap();

        assert_eq!(cached, Some(timeout));
    }

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
        pair_with(CongestionControl::Cubic)
    }

    fn pair_with(congestion: CongestionControl) -> (Transport, Transport) {
        let (certificate, key) = credentials();
        let mut server_config = Config::server(limits(), certificate, key);
        server_config.congestion = congestion;
        let server = Transport::serve("127.0.0.1:0".parse().expect("an address"), &server_config)
            .expect("a server");
        let mut client_config = Config::client(limits());
        client_config.congestion = congestion;
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

    #[test]
    fn the_peer_certificate_is_the_serves_der() {
        let (client, server) = pair();
        assert!(client.connected_within(Duration::from_secs(5)));
        let (certificate, _) = credentials();
        let der = Process::new("openssl")
            .args(["x509", "-in", &certificate, "-outform", "der"])
            .output()
            .expect("openssl runs");
        assert!(der.status.success(), "openssl re-encoded the certificate");
        assert_eq!(
            client.peer_certificate(),
            Some(der.stdout),
            "the stashed certificate is exactly what the serve presented"
        );
        // The server asked for no client certificate, so it holds none.
        assert_eq!(server.peer_certificate(), None);
    }

    #[test]
    fn an_arrival_wait_parks_through_the_accept() {
        // The wait must hold for the full accept, not return early.
        let (certificate, key) = credentials();
        let mut config = Config::server(limits(), certificate, key);
        config.accept_timeout_ms = 400;
        let server = Transport::serve("127.0.0.1:0".parse().expect("an address"), &config)
            .expect("a server");
        let began = Instant::now();
        server.wait_arrival();
        let waited = began.elapsed();
        assert!(
            waited >= Duration::from_millis(300),
            "the wait ended at {waited:?}, inside the 400 ms accept"
        );
        let queued = server.inbound.lock().expect("the queue").events.len();
        assert!(queued > 0, "the wait ended with nothing for a session");
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

    #[test]
    fn a_listener_carries_two_connections_through_one_socket() {
        // Isolation is the property under test: each rail's frames surface on
        // its own session, both directions, both connections live at once.
        let (certificate, key) = credentials();
        let config = Config::server(limits(), certificate, key);
        let listener =
            Listener::bind("127.0.0.1:0".parse().expect("an address"), &config).expect("a bind");
        let address = listener.local_address();
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        // Short timeout so a killed router drains quickly rather than timing out.
        client_config.idle_timeout_ms = 3_000;
        let connect = || {
            Transport::connect(
                "127.0.0.1:0".parse().expect("an address"),
                address,
                Some("localhost"),
                &client_config,
            )
            .expect("a client")
        };
        let mut client1 = connect();
        let mut server1 = listener.accept().expect("the first connection");
        assert_eq!(client1.peer_address(), Some(address));
        assert_eq!(server1.peer_address(), Some(client1.local_address()));
        let mut client2 = connect();
        let mut server2 = listener.accept().expect("the second connection");

        client1
            .send_control(&frame(b"first-rail"))
            .expect("a frame");
        client2
            .send_control(&frame(b"second-rail"))
            .expect("a frame");
        let (_, on_server1) = pump_until(&mut client1, &mut server1, 15, |_, server| {
            server
                .iter()
                .any(|event| matches!(event, Event::Control(_)))
        });
        let (_, on_server2) = pump_until(&mut client2, &mut server2, 15, |_, server| {
            server
                .iter()
                .any(|event| matches!(event, Event::Control(_)))
        });
        let carried = |events: &[Event]| -> Vec<Vec<u8>> {
            events
                .iter()
                .filter_map(|event| match event {
                    Event::Control(bytes) => Some(bytes.as_ref().to_vec()),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(carried(&on_server1), vec![frame(b"first-rail")]);
        assert_eq!(carried(&on_server2), vec![frame(b"second-rail")]);

        // And each pump answers over the shared socket to its own peer.
        server1
            .send_control(&frame(b"first-answer"))
            .expect("a frame");
        server2
            .send_control(&frame(b"second-answer"))
            .expect("a frame");
        let (on_client1, _) = pump_until(&mut client1, &mut server1, 15, |client, _| {
            client
                .iter()
                .any(|event| matches!(event, Event::Control(_)))
        });
        let (on_client2, _) = pump_until(&mut client2, &mut server2, 15, |client, _| {
            client
                .iter()
                .any(|event| matches!(event, Event::Control(_)))
        });
        assert_eq!(carried(&on_client1), vec![frame(b"first-answer")]);
        assert_eq!(carried(&on_client2), vec![frame(b"second-answer")]);
    }

    #[test]
    fn the_window_seed_is_scaled_to_the_payload_ceiling() {
        // 4096 minimum-size packets stay 4096 at the minimum payload and
        // shrink to the same byte count at the ceiling.
        assert_eq!(scaled_initial_window(4096, MIN_DATAGRAM_SIZE), 4096);
        assert_eq!(
            scaled_initial_window(4096, LARGEST_DATAGRAM_SIZE),
            (4096 * MIN_DATAGRAM_SIZE).div_ceil(LARGEST_DATAGRAM_SIZE)
        );
        assert_eq!(scaled_initial_window(4096, 65_507), 76);
        assert_eq!(scaled_initial_window(4096, 1_472), 3340);
        // Never zero, whatever the caller asked.
        assert_eq!(scaled_initial_window(1, LARGEST_DATAGRAM_SIZE), 1);
    }

    #[test]
    fn a_listeners_ticket_resumes_a_second_connection() {
        let (certificate, key) = credentials();
        let config = Config::server(limits(), certificate, key);
        let listener =
            Listener::bind("127.0.0.1:0".parse().expect("an address"), &config).expect("a bind");
        let address = listener.local_address();
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;

        let first = Transport::connect(
            "127.0.0.1:0".parse().expect("an address"),
            address,
            Some("localhost"),
            &client_config,
        )
        .expect("a client");
        let _first_serve = listener.accept().expect("the first connection");
        assert!(first.connected_within(Duration::from_secs(5)));
        assert!(!first.is_resumed(), "nothing to resume the first time");
        // The ticket follows the handshake; bounded by its own count.
        let mut ticket = None;
        for _ in 0..500 {
            ticket = first.session_ticket();
            if ticket.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let ticket = ticket.expect("the listener issued a ticket");
        let mut resumed_config = Config::client(limits());
        resumed_config.verify_peer = false;
        resumed_config.session = Some(ticket);
        let second = Transport::connect(
            "127.0.0.1:0".parse().expect("an address"),
            address,
            Some("localhost"),
            &resumed_config,
        )
        .expect("a second client");
        let _second_serve = listener.accept().expect("the second connection");
        assert!(second.connected_within(Duration::from_secs(5)));
        assert!(
            second.is_resumed(),
            "one listener context, so its tickets resume"
        );
    }

    #[test]
    fn a_connection_on_a_given_socket_speaks_from_that_socket() {
        // A punched socket is only worth punching if the handshake leaves by
        // it: the peer's NAT was opened for that mapping and no other.
        let (certificate, key) = credentials();
        let config = Config::server(limits(), certificate, key);
        let listener =
            Listener::bind("127.0.0.1:0".parse().expect("an address"), &config).expect("a bind");
        let address = listener.local_address();
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        client_config.idle_timeout_ms = 3_000;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let punched = socket.local_addr().expect("a local address");
        let mut client = Transport::connect_on(socket, address, Some("localhost"), &client_config)
            .expect("a client");
        assert_eq!(client.local_address(), punched, "the socket it was given");
        let mut server = listener.accept().expect("the connection");
        client.send_control(&frame(b"punched")).expect("a frame");
        let (_, on_server) = pump_until(&mut client, &mut server, 15, |_, server| {
            server
                .iter()
                .any(|event| matches!(event, Event::Control(_)))
        });
        assert!(
            on_server
                .iter()
                .any(|event| matches!(event, Event::Control(bytes) if bytes.as_ref() == frame(b"punched"))),
            "the handshake and the frame crossed on the given socket"
        );

        let wildcard = UdpSocket::bind("0.0.0.0:0").expect("a socket");
        assert!(
            matches!(
                Transport::connect_on(wildcard, address, Some("localhost"), &client_config),
                Err(Error::InvalidConfiguration)
            ),
            "quiche needs the local address the packets will carry"
        );
    }

    #[test]
    fn a_connection_that_never_forms_says_so_before_the_idle_timeout() {
        // What a punched path that the peer's NAT never opened looks like from
        // here: an address that answers nothing at all.
        let silent = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let nowhere = silent.local_addr().expect("a local address");
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        client_config.idle_timeout_ms = 30_000;
        let client = Transport::connect(
            "127.0.0.1:0".parse().expect("an address"),
            nowhere,
            Some("localhost"),
            &client_config,
        )
        .expect("a client");
        assert!(
            !client.connected_within(Duration::from_millis(400)),
            "silence is not a connection, and the verdict beats the idle timeout"
        );

        let (certificate, key) = credentials();
        let config = Config::server(limits(), certificate, key);
        let listener =
            Listener::bind("127.0.0.1:0".parse().expect("an address"), &config).expect("a bind");
        let answering = Transport::connect(
            "127.0.0.1:0".parse().expect("an address"),
            listener.local_address(),
            Some("localhost"),
            &client_config,
        )
        .expect("a client");
        let _server = listener.accept().expect("the connection");
        assert!(
            answering.connected_within(Duration::from_secs(5)),
            "a handshake that landed is a verdict, not a wait"
        );
        assert!(
            answering.connected_within(Duration::from_millis(0)),
            "the verdict was peeked, so it is still there to read"
        );
    }

    #[test]
    fn only_a_lifecycle_event_is_a_verdict_on_the_connection() {
        // What a caller waiting on a handshake reads each event as. The whole
        // decision is this table.
        assert_eq!(lifecycle_verdict(&NativeEvent::Connected(1)), Some(true));
        assert_eq!(
            lifecycle_verdict(&NativeEvent::Disconnected(1)),
            Some(false)
        );
        assert_eq!(
            lifecycle_verdict(&NativeEvent::Control(vec![7_u8; 8].into())),
            None
        );
        assert_eq!(
            lifecycle_verdict(&NativeEvent::Acknowledged {
                lane: 1,
                sequence: 1
            }),
            None
        );
    }

    #[test]
    fn only_a_timeout_is_a_read_that_ran_out() {
        // The pump rides out a read that merely timed out and ends on
        // anything else; this table is the whole of that decision.
        use std::io::ErrorKind;
        assert!(read_ran_out(&std::io::Error::from(ErrorKind::WouldBlock)));
        assert!(read_ran_out(&std::io::Error::from(ErrorKind::TimedOut)));
        assert!(!read_ran_out(&std::io::Error::from(ErrorKind::BrokenPipe)));
        assert!(!read_ran_out(&std::io::Error::from(ErrorKind::Other)));
    }

    #[test]
    fn a_routed_connection_is_named_by_port_and_index() {
        // The exact composition: the port in the high bits, the index in
        // the low, so a listener's connections never collide with each
        // other or with a port-named single-socket endpoint.
        assert_eq!(routed_connection_id(4433, 7), (4433 << 32) | 7);
        assert_eq!(routed_connection_id(0, 9), 9);
        // An index reaching into the port's bits still combines as bits,
        // not arithmetic.
        let overlapping = (3_u64 << 32) | 1;
        assert_eq!(
            routed_connection_id(3, overlapping),
            (3 << 32) | overlapping
        );
    }

    #[test]
    fn routed_identifiers_differ_by_index_and_fill_the_length() {
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let (one, two) = (scid_routed(local, 1), scid_routed(local, 2));
        assert_ne!(one, two, "two connections, two identifiers");
        assert_eq!(one.len(), quiche::MAX_CONN_ID_LEN);
        let other: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        assert_ne!(scid_routed(other, 1), one, "another port, another name");
    }

    #[test]
    fn a_dropped_listener_releases_its_socket() {
        // The drop stops the router and joins it, which is what lets the
        // port be bound again: a router left running holds the socket for
        // as long as the process lives.
        let (certificate, key) = credentials();
        let config = Config::server(limits(), certificate, key);
        let local = {
            let listener = Listener::bind("127.0.0.1:0".parse().expect("an address"), &config)
                .expect("a bind");
            assert!(!listener.stateless_retry_enabled());
            listener.local_address()
        };
        UdpSocket::bind(local).expect("the dropped listener released its port");
    }

    #[test]
    fn a_retrying_listener_allocates_nothing_for_an_unanswered_initial() {
        let (certificate, key) = credentials();
        let mut config = Config::server(limits(), certificate, key);
        config.stateless_retry = true;
        config.accept_timeout_ms = 300;
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        assert!(listener.stateless_retry_enabled());
        let server = listener.local_address();
        let peer = UdpSocket::bind("127.0.0.1:0").expect("a peer");
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a bound");
        let local = peer.local_addr().expect("its address");
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        let mut client_config = client_config.build(Role::Client).expect("a config");
        let scid = quiche::ConnectionId::from_ref(&[0x31; 16]);
        let mut client = quiche::connect_with_buffer_factory::<SharedBufFactory>(
            Some("localhost"),
            &scid,
            local,
            server,
            &mut client_config,
        )
        .expect("a client");
        let mut initial = vec![0; LARGEST_DATAGRAM_SIZE];
        let (written, _) = client.send(&mut initial).expect("an initial");
        peer.send_to(&initial[..written], server)
            .expect("the initial");
        let mut retry = vec![0; LARGEST_DATAGRAM_SIZE];
        let (written, from) = peer.recv_from(&mut retry).expect("a retry");
        assert_eq!(from, server);
        let header = quiche::Header::from_slice(&mut retry[..written], quiche::MAX_CONN_ID_LEN)
            .expect("a retry header");
        assert_eq!(header.ty, quiche::Type::Retry);
        drop(peer);
        assert!(
            listener.accept().is_err(),
            "an unanswered Retry created a connection"
        );
    }

    #[test]
    fn a_retrying_listener_drops_an_undersized_initial_without_answering() {
        let (certificate, key) = credentials();
        let mut config = Config::server(limits(), certificate, key);
        config.stateless_retry = true;
        config.accept_timeout_ms = 200;
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let server = listener.local_address();
        let peer = UdpSocket::bind("127.0.0.1:0").expect("a peer");
        peer.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("a bound");
        let local = peer.local_addr().expect("its address");
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        let mut client_config = client_config.build(Role::Client).expect("a config");
        let scid = quiche::ConnectionId::from_ref(&[0x32; 16]);
        let mut client = quiche::connect_with_buffer_factory::<SharedBufFactory>(
            Some("localhost"),
            &scid,
            local,
            server,
            &mut client_config,
        )
        .expect("a client");
        let mut initial = vec![0; LARGEST_DATAGRAM_SIZE];
        let (written, _) = client.send(&mut initial).expect("an initial");
        assert!(written >= MIN_DATAGRAM_SIZE);
        peer.send_to(&initial[..MIN_DATAGRAM_SIZE - 1], server)
            .expect("the truncated initial");
        let mut answer = vec![0; LARGEST_DATAGRAM_SIZE];
        assert!(
            peer.recv_from(&mut answer).is_err(),
            "a short Initial was amplified"
        );
        assert!(
            listener.accept().is_err(),
            "a short Initial made connection state"
        );
    }

    #[test]
    fn retry_routes_count_connections_not_identifier_rows() {
        let (pump, _) = mpsc::sync_channel(1);
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut routes = std::collections::HashMap::new();
        for index in 0..MAX_LISTENER_CONNECTIONS {
            let key = index.to_be_bytes().to_vec();
            routes.insert(
                key.clone(),
                Route {
                    pump: pump.clone(),
                    done: Arc::clone(&done),
                    sibling: key,
                },
            );
        }
        assert_eq!(routed_connection_count(&routes), MAX_LISTENER_CONNECTIONS);

        routes.clear();
        for (key, sibling) in [(vec![1], vec![2]), (vec![2], vec![1])] {
            routes.insert(
                key,
                Route {
                    pump: pump.clone(),
                    done: Arc::clone(&done),
                    sibling,
                },
            );
        }
        assert_eq!(routed_connection_count(&routes), 1);
    }

    #[test]
    fn a_listener_accept_ends_at_its_bound_without_a_client() {
        // Zero is a server that waits forever; a bound is what lets a
        // bounded serve stop when nobody comes, and it has to hold for
        // its whole length rather than return early with nothing.
        let (certificate, key) = credentials();
        let mut config = Config::server(limits(), certificate, key);
        config.accept_timeout_ms = 400;
        let listener =
            Listener::bind("127.0.0.1:0".parse().expect("an address"), &config).expect("a bind");
        let began = Instant::now();
        assert!(listener.accept().is_err(), "nobody came");
        let waited = began.elapsed();
        assert!(
            waited >= Duration::from_millis(300),
            "the accept gave up early, at {waited:?}"
        );
    }

    #[test]
    fn the_side_channel_takes_its_lead_byte_and_leaves_the_rest_routed() {
        // A socket two protocols share: what leads with the named byte
        // reaches the side channel with its source, what does not stays
        // the router's, and the channel sends from the listener's own
        // address, which is the mapping a peer observes.
        let (certificate, key) = credentials();
        let mut config = Config::server(limits(), certificate, key);
        config.side_channel_lead = Some(0x1F);
        let mut listener =
            Listener::bind("127.0.0.1:0".parse().expect("an address"), &config).expect("a bind");
        let at = listener.local_address();
        let side = listener.take_side_channel().expect("a lead byte was named");
        assert!(
            listener.take_side_channel().is_none(),
            "the side channel is one thread's"
        );

        let peer = UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        peer.send_to(&[0x1F, 1, 2, 3], at).expect("a side datagram");
        // A QUIC-shaped datagram in between: it goes to the router, which
        // sheds it, and never to the side channel.
        peer.send_to(&[0xC0, 0, 0, 0, 1, 0, 0], at)
            .expect("a QUIC-shaped datagram");
        peer.send_to(&[0x1F, 4, 5, 6], at).expect("another");
        let first = side
            .next_within(Duration::from_secs(10))
            .expect("the router is live")
            .expect("the first side datagram");
        assert_eq!(first.0, vec![0x1F, 1, 2, 3]);
        assert_eq!(
            first.1.port(),
            peer.local_addr().expect("the socket").port()
        );
        let second = side
            .next_within(Duration::from_secs(10))
            .expect("the router is live")
            .expect("the second side datagram");
        assert_eq!(
            second.0,
            vec![0x1F, 4, 5, 6],
            "the QUIC-shaped datagram was routed, not handed aside"
        );

        // A datagram past the side channel's own bound is shed before it
        // is copied, so the lead byte cannot make the router allocate a
        // read's worth of bytes per arrival. The one at the bound still
        // arrives, which is what makes the refusal a bound and not a
        // narrower shape.
        let mut wide = vec![0x1F; SIDE_CHANNEL_MAX_BYTES + 1];
        peer.send_to(&wide, at).expect("an oversized side datagram");
        wide.pop();
        peer.send_to(&wide, at).expect("one at the bound");
        let third = side
            .next_within(Duration::from_secs(10))
            .expect("the router is live")
            .expect("the datagram at the bound");
        assert_eq!(
            third.0.len(),
            SIDE_CHANNEL_MAX_BYTES,
            "the oversized one was shed and the one at the bound was not"
        );

        side.send_to(&[0x1F, 7], first.1).expect("a reply");
        let mut buffer = [0_u8; 64];
        let (length, from) = peer.recv_from(&mut buffer).expect("the reply");
        assert_eq!(&buffer[..length], &[0x1F, 7]);
        assert_eq!(from.port(), at.port(), "the reply came from the listener");

        // The listener owns the socket: dropping it releases the port and
        // leaves the side channel with nothing to send from or wait on,
        // rather than a holder that keeps the port bound after the router
        // has ended.
        let served = listener.local_address();
        drop(listener);
        assert!(
            side.next_within(Duration::from_secs(10)).is_err(),
            "a router that ended is an error, not an empty wait"
        );
        assert!(side.send_to(&[0x1F, 8], first.1).is_err());
        UdpSocket::bind(served).expect("the dropped listener released its port");
    }

    #[test]
    fn a_lead_byte_decides_the_side_channel_and_a_segment_the_split() {
        // The two pure halves of the tap: which reads are the side
        // channel's, and how one read comes apart into the datagrams the
        // kernel coalesced. A read with no offload is one datagram.
        assert!(is_side_channel(Some(0x1F), &[0x1F, 0], None));
        assert!(!is_side_channel(Some(0x1F), &[0xC0, 0x1F], None));
        assert!(!is_side_channel(Some(0x1F), &[], None));
        assert!(!is_side_channel(None, &[0x1F, 0], None));
        // A coalesced read is the side channel's only if every datagram
        // in it is: one peer can send both protocols from one address.
        assert!(is_side_channel(Some(0x1F), &[0x1F, 0, 0x1F, 1], Some(2)));
        assert!(
            !is_side_channel(Some(0x1F), &[0x1F, 0, 0xC0, 1], Some(2)),
            "a QUIC packet coalesced behind a side datagram stays routed"
        );
        assert!(
            !is_side_channel(Some(0x1F), &[0xC0, 0, 0x1F, 1], Some(2)),
            "and ahead of one"
        );
        assert_eq!(segment_step(9, Some(4)), 4);
        assert_eq!(segment_step(9, Some(0)), 9, "no offload is one datagram");
        assert_eq!(segment_step(9, None), 9);
        assert_eq!(segment_step(0, None), 1, "a step of zero would not walk");
        assert_eq!(
            segment_step(9, Some(16)),
            16,
            "a segment wider than the read is still one datagram"
        );
        let coalesced = [1, 2, 3, 4, 5];
        assert_eq!(
            split_read(&coalesced, Some(2)).collect::<Vec<_>>(),
            vec![&[1, 2][..], &[3, 4][..], &[5][..]]
        );
        assert_eq!(
            split_read(&coalesced, None).collect::<Vec<_>>(),
            vec![&coalesced[..]]
        );
        assert_eq!(
            split_read(&coalesced, Some(16)).collect::<Vec<_>>(),
            vec![&coalesced[..]]
        );
    }

    #[test]
    fn each_controller_maps_to_its_algorithm_and_pacing() {
        // The socket test cannot tell the controllers apart, because both carry
        // traffic; this table is the only witness of which algorithm ran and
        // whether pacing ran with it.
        assert_eq!(
            congestion_config(CongestionControl::Cubic),
            (quiche::CongestionControlAlgorithm::CUBIC, true)
        );
        assert_eq!(
            congestion_config(CongestionControl::Bbr2),
            (quiche::CongestionControlAlgorithm::Bbr2Gcongestion, false)
        );
        assert_eq!(CongestionControl::default(), CongestionControl::Cubic);
    }

    #[test]
    fn a_bbr2_connection_carries_a_record_across_the_socket() {
        // The controller choice reaches quiche and the connection still carries.
        // A wiring that broke the handshake or send path would show here before
        // any WAN measurement could.
        let (mut client, mut server) = pair_with(CongestionControl::Bbr2);
        let record = frame(b"carried-under-bbr2");
        client
            .send_control(&record)
            .expect("the adapter takes the frame");
        let (_, from_server) = pump_until(&mut client, &mut server, 10, |_, server_events| {
            server_events
                .iter()
                .any(|event| matches!(event, Event::Control(_)))
        });
        let carried: Vec<_> = from_server
            .iter()
            .filter_map(|event| match event {
                Event::Control(bytes) => Some(bytes.as_ref().to_vec()),
                _ => None,
            })
            .collect();
        assert!(carried.contains(&record), "the frame never crossed");
    }

    #[test]
    fn the_refusal_budget_has_an_exact_boundary() {
        // One under the bound is probing; the bound is a narrowed
        // interface. The boundary is where every off-by-one lives.
        assert!(!should_revalidate(REVALIDATE_REFUSED_SENDS - 1));
        assert!(should_revalidate(REVALIDATE_REFUSED_SENDS));
        assert!(!should_revalidate(0));
    }

    #[test]
    fn a_send_refused_for_any_other_reason_still_fails_the_burst() {
        // Only a size refusal is a lost probe; everything else is the
        // carrier gone, and swallowing it would strand the connection
        // silently. An unspecified destination is refused for a reason
        // that has nothing to do with size, on every platform.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let burst = vec![0x53_u8; 1_200];
        let mut sending = Sending::new(1_200, false, Role::Client, 0);
        let outcome = flush_burst(
            &sender,
            &burst,
            1_200,
            Some("0.0.0.0:0".parse().expect("an address")),
            &mut sending,
        );
        assert!(outcome.is_err(), "a non-size refusal fails the burst");
        assert_eq!(sending.refused, 0, "and is no probe's answer");
    }

    #[test]
    fn only_a_client_duplicates_before_the_handshake_completes() {
        // The whole grid. A server's copies are sent beside the carrier's
        // anti-amplification accounting rather than through it, so an
        // unvalidated address must never see one; a client is bound by no
        // such rule and duplicates from its first flight. A spent budget
        // closes both.
        for established in [false, true] {
            assert!(
                duplication_open(Role::Client, established, 1),
                "a client duplicates from its first flight, established={established}"
            );
            assert!(
                !duplication_open(Role::Client, established, 0),
                "until the budget is spent, established={established}"
            );
        }
        assert!(
            !duplication_open(Role::Server, false, PREFIX_DUPLICATION_DATAGRAMS),
            "a server sends no copy an unvalidated address could be flooded with"
        );
        assert!(
            duplication_open(Role::Server, true, 1),
            "and duplicates once the handshake has validated the peer"
        );
        assert!(!duplication_open(Role::Server, true, 0), "to its budget");
        // Enough datagrams for any serial prefix this carries, and small
        // enough that the unaccounted bytes stay a rounding error against
        // a seeded window.
        const {
            assert!(PREFIX_DUPLICATION_DATAGRAMS >= 64);
            assert!(PREFIX_DUPLICATION_DATAGRAMS <= 1_024);
        }
    }

    /// Datagrams waiting at `socket`, drained to its read timeout.
    ///
    /// Bounded by its own body: a defect that duplicates without end would
    /// otherwise hang the suite instead of failing it.
    fn landed(socket: &UdpSocket) -> usize {
        let mut packet = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        for count in 0..64 {
            if socket.recv_from(&mut packet).is_err() {
                return count;
            }
        }
        panic!("the sender never stopped: more than 64 datagrams for one burst");
    }

    #[test]
    fn the_startup_budget_sends_each_burst_twice_and_no_further() {
        // The copy is the whole point of the prefix budget, and the budget
        // is what stops it becoming a doubled connection.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("a receiver");
        let destination = receiver.local_addr().expect("its address");
        receiver
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("a bounded wait");
        let burst = vec![0x54_u8; 3_600];

        // Three packets out, three copies back, and the budget pays for
        // each datagram rather than each burst.
        let mut sending = Sending::new(1_200, false, Role::Client, 8);
        sending.open_duplication(false);
        flush_burst(&sender, &burst, 1_200, Some(destination), &mut sending)
            .expect("the burst goes");
        assert_eq!(landed(&receiver), 6, "each packet arrives twice");
        assert_eq!(sending.duplicates, 5, "and three datagrams were spent");

        // A budget under the burst duplicates what it covers and no more.
        let mut sending = Sending::new(1_200, false, Role::Client, 1);
        sending.open_duplication(false);
        flush_burst(&sender, &burst, 1_200, Some(destination), &mut sending)
            .expect("the burst goes");
        assert_eq!(landed(&receiver), 4, "three packets and the one copy left");
        assert_eq!(sending.duplicates, 0, "the budget is spent exactly");

        // Spent, the burst is sent once, which is what the carrier owes.
        flush_burst(&sender, &burst, 1_200, Some(destination), &mut sending)
            .expect("the burst goes");
        assert_eq!(landed(&receiver), 3, "no copy past the budget");
    }

    #[test]
    fn a_server_flight_is_the_same_size_before_the_handshake_either_way() {
        // ADR-0043's amplification conformance: whatever a server sends an
        // unvalidated address, arming the prefix budget must not add a byte
        // to it. Two servers fed the same client Initial send the same
        // flight, so the counts are comparable.
        let (certificate, key) = credentials();
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        let mut client_config = client_config.build(Role::Client).expect("a client config");
        let mut server_config = Config::server(limits(), certificate, key)
            .build(Role::Server)
            .expect("a server config");

        let sender = UdpSocket::bind("127.0.0.1:0").expect("the server's socket");
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("the client's socket");
        let server_address = sender.local_addr().expect("its address");
        let client_address = receiver.local_addr().expect("its address");
        receiver
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("a bounded wait");

        // One client Initial, minted without a socket, is what both servers
        // answer.
        let scid = quiche::ConnectionId::from_ref(&[11; 16]);
        let mut client = quiche::connect_with_buffer_factory::<SharedBufFactory>(
            Some("localhost"),
            &scid,
            client_address,
            server_address,
            &mut client_config,
        )
        .expect("a client");
        let mut initial = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        let (len, _) = client
            .send(&mut initial)
            .expect("the client's first flight");
        initial.truncate(len);

        let mut flight = |index: u8, duplicates: usize| {
            let identifier = [index; 16];
            let scid = quiche::ConnectionId::from_ref(&identifier);
            let mut server = quiche::accept_with_buf_factory::<SharedBufFactory>(
                &scid,
                None,
                server_address,
                client_address,
                &mut server_config,
            )
            .expect("a server");
            let mut arriving = initial.clone();
            server
                .recv(
                    &mut arriving,
                    quiche::RecvInfo {
                        from: client_address,
                        to: server_address,
                    },
                )
                .expect("the client's Initial");
            assert!(
                !server.is_established(),
                "the peer's address is not validated yet"
            );
            let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
            let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Server, duplicates);
            send_and_revalidate(&sender, &mut server, &mut out, &mut sending)
                .expect("the server's answer");
            assert_eq!(
                sending.duplicates, duplicates,
                "and no budget was spent on it"
            );
            landed(&receiver)
        };

        let armed = flight(12, PREFIX_DUPLICATION_DATAGRAMS);
        let disarmed = flight(13, 0);
        assert!(armed > 0, "the server answered at all");
        assert_eq!(
            armed, disarmed,
            "an unvalidated address sees the same flight either way"
        );
    }

    #[test]
    fn a_clients_first_flight_goes_twice_and_only_to_its_budget() {
        // The client half of the same rule, through the pass the pump runs:
        // no handshake yet, and the copy still goes.
        let mut config = Config::client(limits());
        config.verify_peer = false;
        let mut config = config.build(Role::Client).expect("a client config");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("the client's socket");
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("the server's socket");
        let destination = receiver.local_addr().expect("its address");
        receiver
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("a bounded wait");

        let mut flight = |index: u8, duplicates: usize| {
            let identifier = [index; 16];
            let scid = quiche::ConnectionId::from_ref(&identifier);
            let mut client = quiche::connect_with_buffer_factory::<SharedBufFactory>(
                Some("localhost"),
                &scid,
                sender.local_addr().expect("its address"),
                destination,
                &mut config,
            )
            .expect("a client");
            let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
            let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Client, duplicates);
            send_and_revalidate(&sender, &mut client, &mut out, &mut sending)
                .expect("the first flight");
            (landed(&receiver), sending.duplicates)
        };

        let (armed, left) = flight(14, PREFIX_DUPLICATION_DATAGRAMS);
        let (disarmed, _) = flight(15, 0);
        assert_eq!(disarmed, 1, "an Initial is one datagram");
        assert_eq!(armed, 2, "and the budget sends it twice");
        assert_eq!(
            left,
            PREFIX_DUPLICATION_DATAGRAMS - 1,
            "one datagram of the budget spent"
        );
    }

    #[test]
    fn a_close_request_reaches_the_connection_exactly_once() {
        // The caller's close travels by atomic; a driver that never takes it
        // leaves the peer holding a session that only dies of idle timeout.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a config");
        config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("the protocol");
        let scid = quiche::ConnectionId::from_ref(&[7; 16]);
        let mut conn = quiche::connect_with_buffer_factory::<SharedBufFactory>(
            None,
            &scid,
            "127.0.0.1:1".parse().expect("an address"),
            "127.0.0.1:2".parse().expect("an address"),
            &mut config,
        )
        .expect("a connection");

        // Nothing requested, nothing closed.
        let close = Arc::new(AtomicU64::new(NO_CLOSE));
        let mut closing = false;
        note_close_request(&mut conn, &close, &mut closing);
        assert!(!closing, "no request, no close");
        assert!(conn.local_error().is_none());

        // Requested: taken, once, and the connection holds the code.
        close.store(258, Ordering::Relaxed);
        note_close_request(&mut conn, &close, &mut closing);
        assert!(closing, "the request was taken");
        assert!(conn.local_error().is_some(), "the connection is closing");
        note_close_request(&mut conn, &close, &mut closing);
        assert!(closing, "taken once, held thereafter");
    }

    #[test]
    fn an_orphaned_connection_closes_under_the_stored_code() {
        // The second way a driver hears its owner is gone: the dropped
        // command channel. It has to close on its own, under whatever code
        // the drop stored, because the stored-close path it is redundant
        // with may be the very thing a defect took out.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a config");
        config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("the protocol");
        let scid = quiche::ConnectionId::from_ref(&[8; 16]);
        let connect = |config: &mut quiche::Config| {
            quiche::connect_with_buffer_factory::<SharedBufFactory>(
                None,
                &scid,
                "127.0.0.1:1".parse().expect("an address"),
                "127.0.0.1:2".parse().expect("an address"),
                config,
            )
            .expect("a connection")
        };

        // An orphan closes without being asked, and only once.
        let mut conn = connect(&mut config);
        let mut closing = false;
        note_orphaned(&mut conn, &mut closing);
        assert!(closing, "an orphan closes without being asked");
        assert!(conn.local_error().is_some(), "the connection is closing");
        note_orphaned(&mut conn, &mut closing);
        assert!(closing, "noted once, held thereafter");

        // And one already closing is left exactly as it was.
        let mut conn = connect(&mut config);
        let mut closing = true;
        note_orphaned(&mut conn, &mut closing);
        assert!(
            conn.local_error().is_none(),
            "a close already noted is not repeated"
        );
    }

    #[test]
    fn an_oversized_probe_is_lost_and_the_burst_survives_it() {
        // A DPLPMTUD probe above the interface MTU is refused with EMSGSIZE.
        // That refusal is the probe's answer, and the packets around it must
        // still go. A 65,508-byte payload plus headers overflows IPv4's 16-bit
        // total length, so the refusal is the protocol's on every platform.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("a receiver");
        let destination = receiver.local_addr().expect("its address");
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a bounded wait");

        // One oversized "probe" then one ordinary packet: chunks of the
        // segment size make the first slot the refused one, and the
        // trailing short chunk is the packet that must survive.
        let oversized = 65_508;
        let mut burst = vec![0x51_u8; oversized + 1_200];
        burst[oversized..].fill(0x52);
        // Both send paths: the plain per-packet loop, and the offload
        // fallback, whose kernel rejects an over-sized segment before
        // queuing anything and so falls through to the same loop.
        for gso in [false, true] {
            let mut sending = Sending::new(oversized, gso, Role::Client, 0);
            flush_burst(&sender, &burst, oversized, Some(destination), &mut sending)
                .expect("a refused probe does not fail the burst");
            assert_eq!(
                sending.refused, 1,
                "the refusal is counted, once, gso={gso}"
            );

            let mut landed = vec![0_u8; oversized];
            let (bytes, _) = receiver
                .recv_from(&mut landed)
                .expect("the packet behind it");
            assert_eq!(bytes, 1_200, "only the ordinary packet arrives");
            assert!(landed[..bytes].iter().all(|byte| *byte == 0x52));
        }
    }

    #[test]
    fn a_frame_sent_before_the_handshake_finishes_still_arrives() {
        // The peer's stream allowance arrives with the handshake, so a frame
        // handed over before then gets StreamLimit from quiche and must be
        // retried, not dropped.
        let (mut client, mut server) = pair();
        let hello = frame(b"before-the-handshake");
        client
            .send_control(&hello)
            .expect("the adapter takes it before the carrier is up");

        let (_, from_server) = pump_until(&mut client, &mut server, 10, |_, server_events| {
            server_events
                .iter()
                .any(|event| matches!(event, Event::Control(_)))
        });
        let carried: Vec<_> = from_server
            .iter()
            .filter_map(|event| match event {
                Event::Control(bytes) => Some(bytes.as_ref().to_vec()),
                _ => None,
            })
            .collect();
        assert!(
            carried.contains(&hello),
            "the frame sent before the handshake was lost"
        );
    }

    #[test]
    fn connected_peers_expose_the_same_channel_binding() {
        let (client, server) = pair();
        assert!(client.connected_within(Duration::from_secs(5)));
        assert!(server.connected_within(Duration::from_secs(5)));

        let client_binding = client.channel_binding().expect("client binding");
        let server_binding = server.channel_binding().expect("server binding");
        assert_eq!(client_binding, server_binding);
        assert_ne!(
            client_binding.as_bytes(),
            &[0; CHANNEL_BINDING_LEN],
            "the carrier returned an uninitialized binding"
        );
    }

    #[test]
    fn independent_connections_expose_different_channel_bindings() {
        let (first_client, first_server) = pair();
        assert!(first_client.connected_within(Duration::from_secs(5)));
        assert!(first_server.connected_within(Duration::from_secs(5)));
        let first_binding = first_client.channel_binding().expect("first binding");
        drop(first_client);
        drop(first_server);

        let (second_client, second_server) = pair();
        assert!(second_client.connected_within(Duration::from_secs(5)));
        assert!(second_server.connected_within(Duration::from_secs(5)));
        let second_binding = second_client.channel_binding().expect("second binding");

        assert_ne!(first_binding, second_binding);
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

        // Settle first: drain and require a quiet wait so the timed wait below
        // parks on an empty queue and only the record's push can end it.
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
        // This carrier offers no per-datagram acknowledgement, so Sent is the
        // last state there is. Reporting an acknowledgement never observed
        // would be worse than reporting less.
        let (mut client, mut server) = pair();
        pump_until(&mut client, &mut server, 10, |a, b| {
            connected(a) && connected(b)
        });
        client
            .send_datagram(9, b"experimental")
            .expect("a datagram");
        let (from_client, at_server) = pump_until(&mut client, &mut server, 10, |a, b| {
            a.iter()
                .any(|event| matches!(event, Event::DatagramState { .. }))
                && b.iter().any(|event| matches!(event, Event::Datagram(_)))
        });
        let state = from_client
            .iter()
            .find_map(|event| match event {
                Event::DatagramState { context, state } => Some((*context, *state)),
                _ => None,
            })
            .expect("a datagram state");
        assert_eq!(state.0, 9, "the context the caller gave");
        assert_eq!(
            state.1,
            vot_transport_api::DatagramSendState::Sent,
            "the extension is enabled, so the carrier takes it"
        );
        // And the peer receives it as bytes, once, with nothing added.
        let received: Vec<&Event> = at_server
            .iter()
            .filter(|event| matches!(event, Event::Datagram(_)))
            .collect();
        assert_eq!(
            received,
            vec![&Event::Datagram(vot_transport_api::shared_payload(
                b"experimental"
            ))]
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

    #[test]
    fn a_peer_that_stops_reading_is_backpressure_rather_than_growth() {
        // The server here is held rather than polled: its driver is alive and
        // its application never reads. So its own inbound bound fills, its
        // driver stops reading the stream, and its flow control stops opening.
        // The client's driver then cannot write what it has been handed. With
        // nothing bounding what it holds it goes on taking submissions anyway,
        // and the only limit on either side is memory.
        let (mut client, server) = pair();
        // Polled alone, because polling the server is what this test must not
        // do: the driver threads finish the handshake between them.
        let mut established = false;
        for _ in 0_u32..1_024 {
            let _ = client.flush();
            while let Some(event) = client.poll() {
                established |= matches!(event, Event::Connected(_));
            }
            if established {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(established, "the pair never connected");

        let bytes = record(&vec![0x5a; 64 * 1024]);
        let shared = vot_transport_api::shared_payload(&bytes);
        // A refusal on its own is the channel between two passes rather than
        // the bound; the driver empties that in microseconds. What says the
        // carrier has stopped taking work is a refusal that outlasts every
        // chance it is given to clear. Every hop has to fill first: the
        // server's inbound queue, its flow-control window, the client's
        // outbox, the channel, and the caller's own queue, which is some tens
        // of megabytes at this record size.
        let mut stalled = false;
        let mut taken = 0_u32;
        let mut refusals = 0_u32;
        for _ in 0_u32..8_192 {
            match client.send_reliable_shared(StreamId(0), Payload::clone(&shared)) {
                Ok(()) => {
                    taken += 1;
                    refusals = 0;
                    let _ = client.flush();
                }
                Err(Error::OutboundQueueFull) => {
                    refusals += 1;
                    if refusals >= 256 {
                        stalled = true;
                        break;
                    }
                    let _ = client.flush();
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(other) => panic!("the carrier failed rather than refusing: {other:?}"),
            }
        }
        assert!(
            stalled,
            "a peer that reads nothing took {taken} records and would have taken more"
        );
        drop(client);
        drop(server);
    }

    /// What one lane carries over loopback, in bytes per second.
    ///
    /// Ignored: a shared machine makes the number vary, and a threshold here
    /// would fail for reasons unrelated to the carrier. Run it when the pump
    /// changes:
    ///
    /// ```text
    /// cargo test -p vot-transport-quiche --features live --release \
    ///     one_lane_throughput -- --ignored --nocapture
    /// ```
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
        let deadline = started + Duration::from_mins(2);
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
        //
        // Linux loopback carries the ceiling. macOS `lo0` has a 16384-byte
        // MTU and discovery settles just under it, so off Linux the
        // assertion is that discovery climbed past a jumbo frame, which no
        // default path allows without the probes working.
        let target = if cfg!(target_os = "linux") {
            u64::try_from(super::LARGEST_DATAGRAM_SIZE).expect("a size fits")
        } else {
            9_000
        };
        let mut discovered = None;
        for _ in 0_u32..5_000 {
            let _ = client.flush();
            let _ = server.flush();
            while client.poll().is_some() {}
            while server.poll().is_some() {}
            discovered = client.path_stats().and_then(|stats| stats.mtu_bytes);
            if discovered.is_some_and(|size| size >= target) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            discovered.is_some_and(|size| size >= target),
            "discovery never reached the ceiling: {discovered:?} under {target}"
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
            inbound
                .push(NativeEvent::Control(vec![7_u8; 8].into()))
                .is_ok(),
            "an exact fit was refused"
        );
        assert_eq!(inbound.bytes, 8);
        assert!(
            inbound
                .push(NativeEvent::Control(vec![7_u8; 1].into()))
                .is_err(),
            "a byte past the budget was accepted"
        );

        let mut inbound = Inbound::default();
        for _ in 0..MAX_INBOUND_EVENTS {
            assert!(inbound.push(NativeEvent::Control(vec![].into())).is_ok());
        }
        assert!(
            inbound.push(NativeEvent::Control(vec![].into())).is_err(),
            "an event past the count was accepted"
        );

        let mut inbound = Inbound::default();
        assert!(
            inbound
                .push(NativeEvent::Control(vec![7_u8; 10].into()))
                .is_ok()
        );
        assert_eq!(inbound.bytes, 10);
        let _ = inbound.pop();
        assert_eq!(inbound.bytes, 0, "a popped event kept its charge");

        // Datagrams live entirely in their own account: a flood stops at
        // their cap, never charges the assembly budget, and popping one
        // refunds only its own account.
        let mut inbound = Inbound::default();
        let datagram = || NativeEvent::Datagram(vec![1_u8; MAX_DATAGRAM_INBOUND_BYTES / 4].into());
        for _ in 0..4 {
            assert!(inbound.push(datagram()).is_ok());
        }
        assert_eq!(inbound.datagram_bytes, MAX_DATAGRAM_INBOUND_BYTES);
        assert!(inbound.push(datagram()).is_err(), "a fifth is past the cap");
        assert_eq!(
            inbound.charged(),
            0,
            "a symbol flood charges the assembly budget nothing"
        );
        assert!(
            inbound
                .push(NativeEvent::Reliable {
                    lane: 1,
                    sequence: 1,
                    bytes: vec![2_u8; 1024].into(),
                })
                .is_ok(),
            "the reliable path is untouched by the flood"
        );
        assert_eq!(inbound.bytes, 1024);
        let _ = inbound.pop();
        assert_eq!(inbound.datagram_bytes, MAX_DATAGRAM_INBOUND_BYTES * 3 / 4);
        assert_eq!(
            inbound.bytes, 1024,
            "a popped datagram refunds only its own"
        );
        assert!(inbound.push(datagram()).is_ok(), "room again");
    }

    /// A datagram burst meets the count bound sized for datagrams, not the one
    /// that exists for the records beside them, and neither class spends the
    /// other's.
    #[test]
    fn a_datagram_is_counted_apart_from_the_events_beside_it() {
        let mut inbound = Inbound::default();
        for _ in 0..MAX_INBOUND_EVENTS {
            assert!(inbound.push(NativeEvent::Control(vec![].into())).is_ok());
        }
        assert!(
            inbound.push(NativeEvent::Control(vec![].into())).is_err(),
            "an event past the count was accepted"
        );
        assert!(
            inbound
                .push(NativeEvent::Datagram(vec![1_u8].into()))
                .is_ok(),
            "a datagram was refused for a count it is not held to"
        );

        let mut inbound = Inbound::default();
        for _ in 0..MAX_DATAGRAM_INBOUND_EVENTS {
            assert!(
                inbound
                    .push(NativeEvent::Datagram(vec![1_u8].into()))
                    .is_ok()
            );
        }
        assert!(
            inbound
                .push(NativeEvent::Datagram(vec![1_u8].into()))
                .is_err(),
            "a datagram past its own count was accepted"
        );
        assert!(
            inbound.push(NativeEvent::Control(vec![].into())).is_ok(),
            "a record was refused for a count the datagrams filled"
        );
        let _ = inbound.pop();
        assert!(
            inbound
                .push(NativeEvent::Datagram(vec![1_u8].into()))
                .is_ok(),
            "a popped datagram did not give its slot back"
        );
    }

    /// The advertised initial window is sixteen times what a conforming
    /// control frame and record need, and never more than the ceiling
    /// autotuning may climb to, because quiche cannot take flow control back.
    #[test]
    fn the_advertised_window_is_clamped_at_the_ceiling() {
        let record = vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES as u64;
        let shipped = vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD as u64;
        assert_eq!(advertised_window(shipped), (shipped + record) * 16);
        assert_eq!(advertised_window(shipped), 20_971_776);

        // The spec's largest legal control payload, which is configurable and
        // would advertise 272,630,016 bytes unclamped.
        let largest = 16 * 1024 * 1024;
        assert!(
            (largest + record) * 16 > STREAM_WINDOW_CEILING,
            "the largest legal limit no longer needs the clamp"
        );
        assert_eq!(advertised_window(largest), STREAM_WINDOW_CEILING);
        assert_eq!(advertised_window(u64::MAX), STREAM_WINDOW_CEILING);
    }

    #[test]
    fn the_assembly_budget_reserves_to_the_bound_and_releases() {
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        let full = budget
            .reserve(MAX_ASSEMBLY_BYTES)
            .expect("an exact fit was refused");
        assert!(
            budget.reserve(1).is_none(),
            "a byte past the budget was reserved"
        );
        drop(full);
        let leftover = budget.reserve(1).expect("a released budget stayed spent");
        assert_eq!(inbound.lock().expect("the queue").assembling, 1);
        drop(leftover);
    }

    #[test]
    fn a_grown_assembly_hold_is_one_charge() {
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        let mut hold = budget.reserve(1).expect("a byte");
        assert!(
            budget.grow(&mut hold, MAX_ASSEMBLY_BYTES - 1),
            "an exact fit"
        );
        assert_eq!(hold.bytes, MAX_ASSEMBLY_BYTES);
        assert_eq!(
            inbound.lock().expect("the queue").assembling,
            MAX_ASSEMBLY_BYTES
        );
        assert!(!budget.grow(&mut hold, 1), "a byte past the budget");
        assert!(!budget.grow(&mut hold, usize::MAX), "an overflowing grow");
        assert_eq!(
            hold.bytes, MAX_ASSEMBLY_BYTES,
            "a refused grow leaves the hold"
        );
        drop(hold);
        assert_eq!(
            inbound.lock().expect("the queue").assembling,
            0,
            "one drop returns the grown charge"
        );
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
        let mut conn = quiche::connect_with_buffer_factory::<SharedBufFactory>(
            Some("localhost"),
            &scid,
            local,
            peer,
            &mut config,
        )
        .expect("a client");
        let mut junk = [0_u8; 64];
        feed_received(&mut conn, local, &mut junk, peer, Some(0));
        feed_received(&mut conn, local, &mut junk, peer, Some(16));
        feed_received(&mut conn, local, &mut junk, peer, None);
    }

    /// A handshaked sans-IO pair with every stream window at `window`.
    fn sans_io_pair(window: u64) -> (Connection, Connection) {
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        sans_io_pair_at(window, local, remote, None)
    }

    /// The same pair at chosen addresses, with the client's pacer on and
    /// capped at `paced` megabits per second when asked, which is what makes
    /// `send` report a release time in the future at all. Megabits because
    /// `set_max_pacing_rate` is read as `Bandwidth::from_mbits_per_second`.
    fn sans_io_pair_at(
        window: u64,
        local: SocketAddr,
        remote: SocketAddr,
        paced: Option<u64>,
    ) -> (Connection, Connection) {
        let (certificate, key) = credentials();
        let mut client_config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a configuration");
        client_config
            .set_application_protos(&[vot_transport_api::ALPN])
            .expect("a protocol");
        client_config.verify_peer(false);
        client_config.set_initial_max_data(10_000_000);
        client_config.set_initial_max_stream_data_bidi_local(window);
        client_config.set_initial_max_stream_data_bidi_remote(window);
        client_config.set_initial_max_streams_bidi(16);
        client_config.enable_dgram(true, DATAGRAM_QUEUE_LEN, DATAGRAM_QUEUE_LEN);
        if let Some(rate) = paced {
            // Only the gcongestion controller carries a pacer, so this is the
            // one algorithm that hands `send` a release time at all.
            client_config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Bbr2Gcongestion);
            client_config.enable_pacing(true);
            client_config.set_max_pacing_rate(rate);
        }
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
        server_config.set_initial_max_stream_data_bidi_local(window);
        server_config.set_initial_max_stream_data_bidi_remote(window);
        server_config.set_initial_max_streams_bidi(16);
        server_config.enable_dgram(true, DATAGRAM_QUEUE_LEN, DATAGRAM_QUEUE_LEN);
        let mut client = quiche::connect_with_buffer_factory::<SharedBufFactory>(
            Some("localhost"),
            &scid_for(local),
            local,
            remote,
            &mut client_config,
        )
        .expect("a client");
        let mut server = quiche::accept_with_buf_factory::<SharedBufFactory>(
            &scid_for(remote),
            None,
            remote,
            local,
            &mut server_config,
        )
        .expect("a server");
        for _ in 0_u32..64 {
            shuttle(&mut client, local, &mut server, remote);
            shuttle(&mut server, remote, &mut client, local);
            if client.is_established() && server.is_established() {
                break;
            }
        }
        assert!(client.is_established() && server.is_established());
        (client, server)
    }

    /// Carries everything one sans-IO connection has to say to the other.
    fn shuttle(
        a: &mut Connection,
        a_address: SocketAddr,
        b: &mut Connection,
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

    /// Every datagram a socket has waiting, in arrival order.
    fn collected(socket: &UdpSocket) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut packet = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        for _ in 0..64 {
            let Ok((len, _)) = socket.recv_from(&mut packet) else {
                return packets;
            };
            packets.push(packet[..len].to_vec());
        }
        panic!("the sender never stopped: more than 64 datagrams for one pass");
    }

    /// A bound receiver whose reads give up rather than block.
    fn bounded_receiver() -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a receiver");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a bounded wait");
        socket
    }

    /// Parks `bytes` of marker at the front of `out`, as a pass that held a
    /// packet for its release time leaves it.
    fn park(out: &mut [u8], sending: &mut Sending, bytes: usize, to: SocketAddr) -> Vec<u8> {
        out[..bytes].fill(0xA5);
        sending.held = bytes;
        sending.held_to = Some(to);
        out[..bytes].to_vec()
    }

    /// The horizon a pass takes for itself when the pump opens it.
    fn horizon() -> Instant {
        Instant::now() + PACE_QUANTUM
    }

    const HELD_BYTES: usize = 200;

    #[test]
    fn a_held_packet_opens_the_next_pass_and_leaves_once() {
        // The pass that parked it is over; the packet is owed the peer, and
        // owed it exactly once.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let receiver = bounded_receiver();
        let destination = receiver.local_addr().expect("its address");
        let (mut client, _server) = sans_io_pair(64 * 1024);
        let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Client, 0);
        let parked = park(&mut out, &mut sending, HELD_BYTES, destination);

        send_all(&sender, &mut client, &mut out, &mut sending, horizon()).expect("the pass");
        let first = collected(&receiver);
        assert_eq!(first.first(), Some(&parked), "the held packet went first");
        assert_eq!(sending.held, 0, "and the hold was released");
        assert_eq!(sending.held_to, None);

        send_all(&sender, &mut client, &mut out, &mut sending, horizon()).expect("a further pass");
        assert!(
            !collected(&receiver).contains(&parked),
            "a held packet is sent once, not on every later pass"
        );
    }

    #[test]
    fn a_held_packet_leaves_before_a_burst_to_another_destination() {
        // A burst carries one destination, so the held packet's own goes out
        // by itself rather than following the connection's packets.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let elsewhere = bounded_receiver();
        let peer = bounded_receiver();
        let held_to = elsewhere.local_addr().expect("its address");
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote = peer.local_addr().expect("its address");
        let (mut client, _server) = sans_io_pair_at(1024 * 1024, local, remote, None);
        client
            .stream_send(0, &vec![3_u8; 64 * 1024], false)
            .expect("a stream the pass has to drain");
        let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Client, 0);
        let parked = park(&mut out, &mut sending, HELD_BYTES, held_to);

        send_all(&sender, &mut client, &mut out, &mut sending, horizon()).expect("the pass");
        assert_eq!(
            collected(&elsewhere),
            vec![parked.clone()],
            "the held packet went to its own destination, alone"
        );
        let onward = collected(&peer);
        assert!(!onward.is_empty(), "the connection's own packets went too");
        assert!(!onward.contains(&parked), "and not to the wrong peer");
    }

    #[test]
    fn a_pass_opened_by_a_held_packet_keeps_its_slots_equal() {
        // The kernel cuts a burst into equal segments, so the held packet's
        // length is the slot every later packet of that burst is drawn into.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let peer = bounded_receiver();
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote = peer.local_addr().expect("its address");
        let (mut client, _server) = sans_io_pair_at(1024 * 1024, local, remote, None);
        client
            .stream_send(0, &vec![5_u8; 64 * 1024], false)
            .expect("a stream the pass has to drain");
        let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Client, 0);
        let parked = park(&mut out, &mut sending, HELD_BYTES, remote);

        send_all(&sender, &mut client, &mut out, &mut sending, horizon()).expect("the pass");
        let sent = collected(&peer);
        assert_eq!(sent.first(), Some(&parked), "the held packet opened it");
        assert!(
            sent[1].len() <= HELD_BYTES,
            "the packet after it was drawn into the held packet's slot, not the ceiling"
        );
    }

    #[test]
    fn a_driver_that_leaves_holding_a_packet_still_sends_it() {
        // The connection spent a packet number on it, so leaving must not
        // swallow it. Nothing held is nothing sent.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let receiver = bounded_receiver();
        let destination = receiver.local_addr().expect("its address");
        let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Client, 0);

        flush_held(&sender, &out, &mut sending).expect("an empty hold");
        assert!(
            collected(&receiver).is_empty(),
            "nothing held, nothing sent"
        );

        let parked = park(&mut out, &mut sending, HELD_BYTES, destination);
        flush_held(&sender, &out, &mut sending).expect("the held packet");
        assert_eq!(collected(&receiver), vec![parked], "the peer got it anyway");
        assert_eq!(sending.held, 0);
        assert_eq!(sending.held_to, None);
    }

    #[test]
    fn a_pending_release_time_is_the_only_wait_allowed_past_the_tick() {
        // Both edges of every term: without a release time nothing waits
        // longer than a tick, with one the wait reaches the release itself up
        // to the hold bound, and the connection's own timer always wins.
        let ms = Duration::from_millis;
        assert_eq!(pass_deadline(None, None), TICK, "an idle pass waits a tick");
        assert_eq!(pass_deadline(Some(ms(10)), None), TICK, "and no longer");
        assert_eq!(
            pass_deadline(Some(ms(10)), Some(ms(3))),
            ms(3),
            "a release past the tick is waited out"
        );
        assert_eq!(
            pass_deadline(Some(ms(10)), Some(ms(9))),
            PACE_HOLD_TICK,
            "to the hold bound and no further"
        );
        assert_eq!(
            pass_deadline(Some(ms(2)), Some(ms(9))),
            ms(2),
            "the connection's timer is never extended by the wait"
        );
        assert_eq!(
            pass_deadline(Some(Duration::ZERO), Some(Duration::ZERO)),
            Duration::from_micros(200),
            "and a zero wait is a spin"
        );
    }

    #[test]
    fn a_future_release_time_parks_its_packet_rather_than_flushing_it() {
        // The pacer's whole purpose: a packet it released beyond the pass's
        // horizon must not ride out with the burst before it. The rate is low
        // enough that every packet past the burst tokens is held for a wait no
        // single wake covers, which is the deadline the pass returns.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let peer = bounded_receiver();
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote = peer.local_addr().expect("its address");
        let (mut client, _server) =
            sans_io_pair_at(1024 * 1024, local, remote, Some(BEYOND_QUANTUM_RATE));
        client
            .stream_send(0, &vec![9_u8; 256 * 1024], false)
            .expect("a stream the pacer has to meter");
        let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Client, 0);

        let before = Instant::now();
        let paced = send_all(&sender, &mut client, &mut out, &mut sending, horizon())
            .expect("the pass")
            .expect("a release time the pacer set");
        assert!(
            paced > before + PACE_QUANTUM,
            "the deadline is the held packet's release, and it is past the horizon"
        );
        assert!(sending.held > 0, "and the packet it belongs to is parked");
        assert_eq!(sending.held_to, Some(remote));
        let parked = out[..sending.held].to_vec();
        assert!(
            !collected(&peer).contains(&parked),
            "the parked packet did not ride out ahead of its release"
        );
        send_all(&sender, &mut client, &mut out, &mut sending, horizon()).expect("the next pass");
        assert_eq!(
            collected(&peer).first(),
            Some(&parked),
            "and it opened the next pass"
        );
    }

    #[test]
    fn a_pass_past_its_horizon_never_parks_a_packet_already_due() {
        // With no pacer every release is `now`, so a pass running longer than
        // the quantum outruns the horizon it took at the start. Nothing is
        // owed the future there, and parking would end the pass for nothing.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let peer = bounded_receiver();
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote = peer.local_addr().expect("its address");
        let (mut client, _server) = sans_io_pair_at(1024 * 1024, local, remote, None);
        client
            .stream_send(0, &vec![7_u8; 256 * 1024], false)
            .expect("a stream the pass has to drain");
        let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Client, 0);
        // The horizon a pass longer than a quantum is left holding, without
        // waiting a quantum out.
        let stale = Instant::now()
            .checked_sub(PACE_QUANTUM)
            .expect("a clock past the quantum");

        let paced =
            send_all(&sender, &mut client, &mut out, &mut sending, stale).expect("the pass");

        assert_eq!(paced, None, "no release time is owed the next wake");
        assert_eq!(sending.held, 0, "and nothing due now was parked");
        assert_eq!(sending.held_to, None);
    }

    /// A cap above the rate the controller itself sets on a fresh connection,
    /// so the pacer runs at the controller's own rate and commands about
    /// 180 us per packet: a fraction of the quantum.
    const WITHIN_QUANTUM_RATE: u64 = 1_000;

    /// A cap that binds, at about 5 ms per packet: comfortably past the
    /// quantum, so the packet is the pacer's to hold.
    const BEYOND_QUANTUM_RATE: u64 = 2;

    /// Passes the within-quantum arm takes the best of.
    const WITHIN_QUANTUM_PASSES: u32 = 5;

    /// Packets one send pass gets out of a freshly established connection
    /// whose pacer is capped at `rate` megabits per second.
    fn packets_in_one_paced_pass(rate: u64) -> usize {
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a sender");
        let peer = bounded_receiver();
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote = peer.local_addr().expect("its address");
        let (mut client, _server) = sans_io_pair_at(1024 * 1024, local, remote, Some(rate));
        client
            .stream_send(0, &vec![9_u8; 256 * 1024], false)
            .expect("a stream the pacer has to meter");
        let mut out = vec![0_u8; LARGEST_DATAGRAM_SIZE];
        let mut sending = Sending::new(MAX_DATAGRAM_SIZE, false, Role::Client, 0);
        // Through the pump's own entry point, so the horizon it hands the pass
        // is under test too.
        send_and_revalidate(&sender, &mut client, &mut out, &mut sending).expect("the pass");
        collected(&peer).len()
    }

    #[test]
    fn a_release_within_the_quantum_goes_now_rather_than_waiting_a_wake() {
        // The starvation the quantum exists for: honouring a gap finer than
        // the pump's wake cadence one packet per wake throttles the sender to
        // the wake rate. Both rates park eventually, since the schedule
        // accumulates past any fixed horizon; what separates them is how much
        // the pass releases first. Ending the pass at the first future release
        // makes these two counts equal, which is the whole defect.
        //
        // The best of a counted few passes, because the horizon is fixed at
        // pass start while the pacer's schedule ratchets off the clock
        // (`ideal_next_packet_send_time.set_max(sent_time)`): one preemption
        // of a quantum anywhere in a pass pushes every remaining release past
        // the horizon and leaves only the burst tokens, which is the same
        // count a broken horizon gives. A stalled runner loses a repetition;
        // a broken horizon loses all of them.
        let within = (0..WITHIN_QUANTUM_PASSES)
            .map(|_| packets_in_one_paced_pass(WITHIN_QUANTUM_RATE))
            .max()
            .expect("a counted repetition");
        let beyond = packets_in_one_paced_pass(BEYOND_QUANTUM_RATE);
        assert!(
            within > beyond,
            "a pass carries the releases due inside one wake, not one packet: \
             best of {WITHIN_QUANTUM_PASSES} is {within} at \
             {WITHIN_QUANTUM_RATE} Mbit/s against {beyond} at \
             {BEYOND_QUANTUM_RATE}"
        );
    }

    #[test]
    fn the_receive_queue_holds_every_datagram_the_credit_invites() {
        // Both ends are built through `Config::build`, which is where the
        // queue depths are chosen. The receiver drains nothing until the
        // whole burst is across: quiche silently discards the oldest inbound
        // datagram past its queue depth, so a depth under what the wire's
        // credit invites loses datagrams no counter in this stack sees.
        //
        // Twice the old send queue's depth, tied to no send bound in this
        // file: what this measures is receive depth.
        const BURST: usize = 2_048;
        let (certificate, key) = credentials();
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let mut client_config = Config::client(limits());
        client_config.verify_peer = false;
        let mut client_quiche = client_config.build(Role::Client).expect("a client config");
        let server_config = Config::server(limits(), certificate, key);
        let mut server_quiche = server_config.build(Role::Server).expect("a server config");
        let mut client = quiche::connect_with_buffer_factory::<SharedBufFactory>(
            Some("localhost"),
            &scid_for(local),
            local,
            remote,
            &mut client_quiche,
        )
        .expect("a client");
        let mut server = quiche::accept_with_buf_factory::<SharedBufFactory>(
            &scid_for(remote),
            None,
            remote,
            local,
            &mut server_quiche,
        )
        .expect("a server");
        for _ in 0_u32..64 {
            shuttle(&mut client, local, &mut server, remote);
            shuttle(&mut server, remote, &mut client, local);
            if client.is_established() && server.is_established() {
                break;
            }
        }
        assert!(client.is_established() && server.is_established());
        let payload = [7_u8; 64];
        let mut sent = 0_usize;
        // Bounded by its own count: each round queues what the send queue
        // takes and shuttles both ways so acks keep the window growing.
        for _ in 0..64 {
            while sent < BURST && server.dgram_send(&payload).is_ok() {
                sent += 1;
            }
            shuttle(&mut server, remote, &mut client, local);
            shuttle(&mut client, local, &mut server, remote);
            if sent == BURST && server.dgram_send_queue_len() == 0 {
                break;
            }
        }
        assert_eq!(sent, BURST, "the whole burst was handed to the carrier");
        assert_eq!(server.dgram_send_queue_len(), 0, "and it all went out");
        assert_eq!(
            client.dgram_recv_queue_len(),
            BURST,
            "an undrained receiver holds every datagram the sender put on a lossless wire"
        );
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
        let mut client = quiche::connect_with_buffer_factory::<SharedBufFactory>(
            Some("localhost"),
            &scid_for(local),
            local,
            remote,
            &mut client_config,
        )
        .expect("a client");
        let mut server = quiche::accept_with_buf_factory::<SharedBufFactory>(
            &scid_for(remote),
            None,
            remote,
            local,
            &mut server_config,
        )
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
        let mut queued = Queued::default();
        stream.outbox.push_back((vec![0x27_u8; 8_192].into(), 0));
        queued.charge(8_192);

        let mut drain = [0_u8; 4_096];
        let mut delivered = 0_usize;
        for _ in 0_u32..256 {
            write_outbox(&mut client, stream, &mut queued);
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
        // A record written in pieces is released in pieces, so what the driver
        // counts as waiting is back where it started.
        assert_eq!(queued.bytes, 0, "a written record still counted as owed");
        assert_eq!(queued.records, 0, "a written record was still counted");
    }

    #[test]
    fn a_full_connection_queue_holds_a_datagram_and_anything_else_drops_it() {
        // The whole point of the outbox: a connection with no room right now
        // is asked again, and a datagram it will never take is let go rather
        // than blocking the ones behind it.
        assert_eq!(offered(&Ok(())), Offered::Taken);
        assert_eq!(
            offered(&Err(quiche::Error::Done)),
            Offered::Waiting,
            "no room yet"
        );
        for refusal in [
            quiche::Error::BufferTooShort,
            quiche::Error::InvalidState,
            quiche::Error::FinalSize,
            quiche::Error::CongestionControl,
        ] {
            assert_eq!(
                offered(&Err(refusal)),
                Offered::Refused,
                "{refusal:?} is about this one"
            );
        }
    }

    // Deeper than the connection's own queue, or the outbox could not
    // absorb a burst that filled it.
    const _: () = assert!(DATAGRAM_OUTBOX_LEN > DATAGRAM_QUEUE_LEN);

    #[test]
    fn a_driver_that_stops_ends_every_datagram_it_still_holds() {
        // One state per submitted datagram is the contract the other
        // carriers keep, so a caller counting what it is owed is not left
        // waiting on datagrams this end has forgotten.
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let mut datagrams: VecDeque<(Payload, u64)> = (1..=3)
            .map(|context| (vot_transport_api::shared_payload(&[7; 16]), context))
            .collect();
        let mut pending = Some(Command::Datagram {
            context: 4,
            bytes: vot_transport_api::shared_payload(&[7; 16]),
        });
        let mut pending_state = None;
        abandon_all_datagrams(&mut pending_state, &mut pending, &mut datagrams, &inbound);
        assert!(datagrams.is_empty(), "nothing is still held");
        assert!(pending.is_none(), "the pending command is still held");
        let mut held = inbound.lock().expect("the queue");
        let contexts: Vec<u64> = std::iter::from_fn(|| held.events.pop_front())
            .map(|event| match event {
                NativeEvent::DatagramDropped { context } => context,
                other => panic!("a held datagram ends as dropped, got {other:?}"),
            })
            .collect();
        assert_eq!(contexts, vec![1, 2, 3, 4], "in submission order");
    }

    #[test]
    fn a_driver_that_stops_preserves_states_past_the_normal_event_bound() {
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        {
            let mut queue = inbound.lock().expect("the queue");
            for _ in 0..MAX_INBOUND_EVENTS {
                queue
                    .push(NativeEvent::Control(vot_transport_api::shared_payload(&[])))
                    .expect("room to the normal bound");
            }
        }
        let symbol = vot_transport_api::shared_payload(&[7; 16]);
        let mut datagrams = (1..=DATAGRAM_OUTBOX_LEN)
            .map(|context| (symbol.clone(), context as u64))
            .collect();
        let mut pending = Some(Command::Datagram {
            context: DATAGRAM_OUTBOX_LEN as u64 + 1,
            bytes: symbol,
        });
        let mut pending_state = Some(NativeEvent::DatagramSent { context: 0 });

        let outcome = finish_datagrams(
            Err(Error::Backend),
            &mut pending_state,
            &mut pending,
            &mut datagrams,
            &inbound,
        );
        assert!(matches!(outcome, Err(Error::Backend)));

        let mut queue = inbound.lock().expect("the queue");
        for _ in 0..MAX_INBOUND_EVENTS {
            assert!(matches!(queue.pop(), Some(NativeEvent::Control(_))));
        }
        let contexts: Vec<u64> = std::iter::from_fn(|| queue.pop())
            .map(|event| match event {
                NativeEvent::DatagramSent { context }
                | NativeEvent::DatagramDropped { context } => context,
                other => panic!("a terminal datagram state, got {other:?}"),
            })
            .collect();
        assert_eq!(
            contexts,
            (0..=DATAGRAM_OUTBOX_LEN as u64 + 1).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_full_event_queue_holds_a_datagram_state_before_sending_more() {
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        {
            let mut queue = inbound.lock().expect("the queue");
            for _ in 0..MAX_INBOUND_EVENTS {
                queue
                    .push(NativeEvent::Control(vot_transport_api::shared_payload(&[])))
                    .expect("room to the normal bound");
            }
        }
        let mut conn = sans_io_pair(2_048).0;
        let symbol = vot_transport_api::shared_payload(&[7; 16]);
        let mut datagrams = VecDeque::from([(symbol.clone(), 1), (symbol, 2)]);
        let mut pending_state = None;

        write_datagrams(&mut conn, &mut datagrams, &mut pending_state, &inbound);
        assert!(matches!(
            &pending_state,
            Some(NativeEvent::DatagramSent { context: 1 })
        ));
        assert_eq!(datagrams.len(), 1);
        assert_eq!(conn.dgram_send_queue_len(), 1);

        write_datagrams(&mut conn, &mut datagrams, &mut pending_state, &inbound);
        assert_eq!(datagrams.len(), 1, "a later datagram passed its state");
        assert_eq!(conn.dgram_send_queue_len(), 1);

        let _ = inbound.lock().expect("the queue").pop();
        write_datagrams(&mut conn, &mut datagrams, &mut pending_state, &inbound);
        assert!(matches!(
            &pending_state,
            Some(NativeEvent::DatagramSent { context: 2 })
        ));
        assert!(datagrams.is_empty());
        assert_eq!(conn.dgram_send_queue_len(), 2);

        let _ = inbound.lock().expect("the queue").pop();
        write_datagrams(&mut conn, &mut datagrams, &mut pending_state, &inbound);
        assert!(pending_state.is_none());
    }

    #[test]
    fn the_datagram_outbox_bound_is_met_rather_than_passed() {
        assert!(outbox_has_room(0, 0, 1));
        assert!(
            outbox_has_room(DATAGRAM_OUTBOX_LEN - 1, 0, 1),
            "under both bounds still holds"
        );
        assert!(
            !outbox_has_room(DATAGRAM_OUTBOX_LEN, 0, 1),
            "at the count the next one goes"
        );
        // The byte bound binds on its own, for datagrams larger than the
        // count alone would ever reach.
        assert!(outbox_has_room(0, DATAGRAM_OUTBOX_BYTES - 1, 1));
        assert!(
            !outbox_has_room(0, DATAGRAM_OUTBOX_BYTES, 1),
            "at the bytes the next one goes"
        );
        assert!(
            !outbox_has_room(0, DATAGRAM_OUTBOX_BYTES - 1, 2),
            "one that would pass the bytes goes"
        );
    }

    #[test]
    fn the_outbox_bound_is_met_rather_than_passed() {
        assert!(!Queued::default().is_full());
        let under = Queued {
            bytes: MAX_QUEUED_BYTES - 1,
            records: MAX_QUEUED_RECORDS - 1,
        };
        assert!(!under.is_full(), "a driver under both bounds still takes");
        let bytes = Queued {
            bytes: MAX_QUEUED_BYTES,
            records: 1,
        };
        assert!(bytes.is_full(), "the byte bound is met, not passed");
        // The record bound is the one that answers a flood of small records,
        // where the bytes alone would let millions of entries through.
        let records = Queued {
            bytes: 1,
            records: MAX_QUEUED_RECORDS,
        };
        assert!(records.is_full(), "the record bound is met, not passed");
        // The values themselves, because every assertion above is written in
        // terms of them and would hold for any pair of numbers, including a
        // record bound so large that only the bytes ever bind.
        assert_eq!(MAX_QUEUED_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_QUEUED_RECORDS, 4_096);
    }

    /// The drift guard fires, which is what makes it a guard rather than a
    /// comment. Only in a debug build, because that is the only build a
    /// `debug_assert` is compiled into.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "drifted")]
    fn a_charge_that_drifts_from_the_outboxes_says_so() {
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
        stream
            .outbox
            .push_back((vot_transport_api::shared_payload(&[0x27; 64]), 0));
        // A record queued and never charged, which is the drift that would
        // otherwise leave the bound counting something that is not there.
        Queued::default().debug_assert_matches(&streams);
    }

    #[test]
    fn a_charge_is_taken_where_the_record_is_queued() {
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(1_000_000));
        let mut streams = BTreeMap::new();
        let mut conn = sans_io_pair(2_048).0;

        let mut datagrams = VecDeque::new();
        let mut pending_state = None;
        let mut queued = Queued::default();
        // What the driver does with each: a queued record is charged, and a
        // datagram is handed to the connection with nothing left to hold.
        for command in [
            Command::Control(vot_transport_api::shared_payload(&[0x27; 16])),
            Command::Reliable {
                stream: StreamId(0),
                bytes: vot_transport_api::shared_payload(&[0x27; 64]),
            },
            Command::Datagram {
                context: 1,
                bytes: vot_transport_api::shared_payload(&[0x27; 32]),
            },
            Command::ReceiveCredit(4_096),
        ] {
            if let Some(bytes) = apply(
                &mut conn,
                &mut streams,
                &mut datagrams,
                &budget,
                &control_limit,
                command,
                &inbound,
                Role::Client,
                &mut pending_state,
            )
            .expect("room for the submission")
            {
                queued.charge(bytes);
            }
        }
        // The datagram is not among them: it waits in its own outbox, which
        // the outbox budget deliberately does not hold, because charging it
        // would stop the driver taking the control frames behind it.
        assert_eq!(queued.bytes, 16 + 64);
        assert_eq!(queued.records, 2);
    }

    #[test]
    fn a_full_datagram_outbox_backpressures_without_loss() {
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(1_000_000));
        let mut streams = BTreeMap::new();
        let mut conn = sans_io_pair(2_048).0;
        for _ in 0..DATAGRAM_QUEUE_LEN {
            conn.dgram_send(&[0x27; 16]).expect("connection queue room");
        }
        let symbol = vot_transport_api::shared_payload(&[0x27; 512]);
        let mut datagrams = std::iter::repeat_n((symbol, 1), DATAGRAM_OUTBOX_LEN).collect();
        let (sent, commands) = mpsc::sync_channel(2);
        sent.send(Command::Datagram {
            context: 9,
            bytes: vot_transport_api::shared_payload(&[0x27; 16]),
        })
        .unwrap();
        sent.send(Command::Control(vot_transport_api::shared_payload(
            &[0x27; 16],
        )))
        .unwrap();
        let mut queued = Queued::default();
        let mut pending = None;
        let mut pending_state = None;

        assert!(!take_submissions(
            &mut conn,
            &mut streams,
            &mut datagrams,
            &budget,
            &control_limit,
            &commands,
            &inbound,
            Role::Client,
            &mut queued,
            &mut pending,
            &mut pending_state,
        ));
        assert!(
            matches!(&pending, Some(Command::Datagram { context: 9, .. })),
            "the refused submission was not held"
        );
        assert!(
            inbound.lock().expect("the queue").events.is_empty(),
            "backpressure was reported as a dropped datagram"
        );
        let later = commands
            .try_recv()
            .expect("the later command stayed queued");
        assert!(matches!(&later, Command::Control(_)));
        sent.send(later).unwrap();

        datagrams.pop_front();
        assert!(!take_submissions(
            &mut conn,
            &mut streams,
            &mut datagrams,
            &budget,
            &control_limit,
            &commands,
            &inbound,
            Role::Client,
            &mut queued,
            &mut pending,
            &mut pending_state,
        ));
        assert!(pending.is_none(), "the held submission was not retried");
        assert_eq!(datagrams.len(), DATAGRAM_OUTBOX_LEN);
        assert_eq!(queued.records, 1, "the later command was not applied");
    }

    #[test]
    fn a_stream_that_cannot_write_gives_its_whole_charge_back() {
        // A stream the connection refuses outright, rather than one that is
        // merely out of flow control: the outbox is dropped, and a charge left
        // behind for records nobody will ever write would refuse every later
        // submission on a connection with nothing waiting.
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(1_000_000));
        let mut streams = BTreeMap::new();
        let mut client = sans_io_pair(2_048).0;
        // Server-initiated and unidirectional, so a client writing to it is
        // not backpressure but an error.
        let stream = stream_state(
            &mut streams,
            3,
            StreamKind::Reliable { lane: 0 },
            &budget,
            &control_limit,
        );
        let mut queued = Queued::default();
        stream
            .outbox
            .push_back((vot_transport_api::shared_payload(&[0x27; 128]), 0));
        queued.charge(128);
        stream
            .outbox
            .push_back((vot_transport_api::shared_payload(&[0x27; 256]), 0));
        queued.charge(256);

        write_outbox(&mut client, stream, &mut queued);

        assert!(stream.outbox.is_empty(), "the refused outbox was kept");
        assert_eq!(queued.bytes, 0, "a discarded record still counted as owed");
        assert_eq!(queued.records, 0, "a discarded record was still counted");
    }

    /// One SETTINGS frame on the wire toward the server, returned encoded.
    fn frame_on_the_wire(client: &mut Connection, server: &mut Connection) -> Vec<u8> {
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let mut frame = Vec::new();
        vot_codec::encode_frame(vot_codec::frame_type::SETTINGS, &[0x27; 64], &mut frame)
            .expect("a frame");
        client
            .stream_send(CONTROL_STREAM_ID, &frame, false)
            .expect("a stream");
        shuttle(client, local, server, remote);
        frame
    }

    #[test]
    fn a_spent_byte_budget_pauses_the_stream_instead_of_closing_it() {
        // A caller that has not drained the queue is this endpoint's own lag.
        // The connection must wait for it, not close.
        let (mut client, mut server) = sans_io_pair(1_000_000);
        frame_on_the_wire(&mut client, &mut server);
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
            server.local_error().is_none(),
            "a full queue faulted the connection"
        );
        assert!(
            inbound.lock().expect("the queue").events.is_empty(),
            "a full queue still accepted an event"
        );

        // At the exact threshold the read proceeds: headroom for one chunk
        // plus one partial frame is enough, not a byte more.
        let threshold = StreamKind::Control
            .partial_frame_limit(control_limit.load(Ordering::Relaxed))
            + buffer.len();
        inbound.lock().expect("the queue").assembling = MAX_ASSEMBLY_BYTES - threshold;
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert_eq!(
            inbound.lock().expect("the queue").events.len(),
            1,
            "an exact-threshold headroom refused the read"
        );
        assert!(server.local_error().is_none());
        {
            let mut queue = inbound.lock().expect("the queue");
            while queue.events.pop_front().is_some() {}
            queue.bytes = 0;
        }
        frame_on_the_wire(&mut client, &mut server);
        inbound.lock().expect("the queue").assembling = MAX_ASSEMBLY_BYTES;
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(inbound.lock().expect("the queue").events.is_empty());

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
    fn a_pass_reads_a_stream_dry_rather_than_one_chunk() {
        // The read loop runs until the stream has nothing more, not once: a
        // pass that stopped at one chunk would deliver a fraction of what
        // has already arrived and pay a full pump round for each remainder.
        let (mut client, mut server) = sans_io_pair(4_000_000);
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let mut frame = Vec::new();
        for _ in 0..80 {
            frame.clear();
            vot_codec::encode_frame(
                vot_codec::frame_type::SETTINGS,
                &vec![0x27_u8; 16_000],
                &mut frame,
            )
            .expect("a frame");
            // stream_send takes what capacity allows, so the remainder loops
            // with both shuttle directions between attempts: the reverse leg
            // is what carries acknowledgements while the server's
            // application reads nothing.
            let mut sent = 0_usize;
            let mut attempts = 0_u32;
            while sent < frame.len() {
                attempts += 1;
                assert!(attempts < 1_000, "the pair stopped moving");
                match client.stream_send(CONTROL_STREAM_ID, &frame[sent..], false) {
                    Ok(written) => sent += written,
                    Err(quiche::Error::Done) => {}
                    Err(error) => panic!("a stream: {error:?}"),
                }
                shuttle(&mut client, local, &mut server, remote);
                shuttle(&mut server, remote, &mut client, local);
            }
            shuttle(&mut client, local, &mut server, remote);
        }
        let inbound = Arc::new(Mutex::new(Inbound::default()));
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
        assert_eq!(
            inbound.lock().expect("the queue").events.len(),
            80,
            "one pass left arrived frames unread"
        );
    }

    #[test]
    fn a_split_frame_waits_for_headroom_rather_than_faulting() {
        // A frame wider than the read buffer assembles across chunks. Reading
        // it with no headroom would fail the framing's reservation, which is
        // the fault path this endpoint's own lag must never reach.
        let (mut client, mut server) = sans_io_pair(1_000_000);
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let mut frame = Vec::new();
        vot_codec::encode_frame(
            vot_codec::frame_type::SETTINGS,
            &vec![0x27_u8; 16_000],
            &mut frame,
        )
        .expect("a frame");
        let mut sent = 0_usize;
        let mut attempts = 0_u32;
        while sent < frame.len() {
            attempts += 1;
            assert!(attempts < 1_000, "the pair stopped moving");
            match client.stream_send(CONTROL_STREAM_ID, &frame[sent..], false) {
                Ok(written) => sent += written,
                Err(quiche::Error::Done) => {}
                Err(error) => panic!("a stream: {error:?}"),
            }
            shuttle(&mut client, local, &mut server, remote);
            shuttle(&mut server, remote, &mut client, local);
        }
        let inbound = Arc::new(Mutex::new(Inbound {
            assembling: MAX_ASSEMBLY_BYTES,
            ..Inbound::default()
        }));
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(1_000_000));
        let mut streams = BTreeMap::new();
        let mut buffer = vec![0_u8; 4_096];
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(
            server.local_error().is_none(),
            "no headroom faulted the connection"
        );
        assert!(inbound.lock().expect("the queue").events.is_empty());

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
        assert!(server.local_error().is_none());
        assert_eq!(
            inbound.lock().expect("the queue").events.len(),
            1,
            "the split frame never assembled"
        );
    }

    #[test]
    fn a_held_partial_frame_is_not_headroom_the_account_gets_back() {
        // The charge a partial frame holds is not room the account will get
        // back: the frame it completes is queued as an event of its own
        // length, so the bytes move from `assembling` to `bytes` and stay.
        // Crediting that charge admits a chunk the account cannot hold, and
        // the trailing partial's reservation then fails as a fault, which
        // closes the connection under RESOURCE_LIMIT for this endpoint's own
        // lag.
        let (mut client, mut server) = sans_io_pair(1_000_000);
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(1_000_000));
        let mut streams = BTreeMap::new();
        let id = stream_for_lane(0, Role::Client).expect("a lane");
        let lane = lane_for_stream(id, Role::Server).expect("the peer lane");
        let state = stream_state(
            &mut streams,
            id,
            StreamKind::Reliable { lane },
            &budget,
            &control_limit,
        );

        // A stream part-way through a record, which is the charge the guard
        // used to credit itself.
        let first = record(&vec![0x27; vot_transport_api::MAX_DATA_RECORD_BYTES]);
        let held = 260_000;
        state
            .framing
            .accept(&first[..held], |_| panic!("a partial frame completed"))
            .expect("the prefix fits");
        let reserved = state.framing.reserved();
        assert_eq!(reserved, 262_144, "the prefix charged its geometric target");

        // One chunk that completes that record, carries a whole small one,
        // and starts a third. Its completions are queued, its charge is not
        // freed, and the third record's reservation is what the account
        // cannot hold.
        let small = record(&vec![0x5a; 7_750]);
        assert_eq!(small.len(), 7_753, "the small record's wire length moved");
        let next = record(&vec![0x33; vot_transport_api::MAX_DATA_RECORD_BYTES]);
        let started = 200_000;
        let mut chunk = first[held..].to_vec();
        chunk.extend_from_slice(&small);
        chunk.extend_from_slice(&next[..started]);
        let mut buffer = vec![0_u8; vot_transport_framing::MAX_PARTIAL_FRAME.max(65_535)];
        assert!(
            chunk.len() <= buffer.len(),
            "the chunk is more than one read"
        );
        let mut sent = 0_usize;
        let mut attempts = 0_u32;
        while sent < chunk.len() {
            attempts += 1;
            assert!(attempts < 1_000, "the pair stopped moving");
            match client.stream_send(id, &chunk[sent..], false) {
                Ok(written) => sent += written,
                Err(quiche::Error::Done) => {}
                Err(error) => panic!("a stream: {error:?}"),
            }
            shuttle(&mut client, local, &mut server, remote);
            shuttle(&mut server, remote, &mut client, local);
        }

        // Room for one chunk and one partial frame, less this stream's own
        // charge: the headroom the credited guard read as enough. Reading
        // here queues 269,902 bytes against 262,176 of room, which is the
        // state every fire of this close printed: 16,523,054 bytes queued,
        // 254,418 free, and a 262,144-byte reservation refused.
        let credited = vot_transport_framing::MAX_PARTIAL_FRAME + buffer.len() - reserved;
        inbound.lock().expect("the queue").bytes = MAX_ASSEMBLY_BYTES - credited - reserved;
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(
            server.local_error().is_none(),
            "a held partial's charge was credited as free room and the read closed the connection"
        );
        assert!(
            inbound.lock().expect("the queue").events.is_empty(),
            "a chunk the account cannot hold was read anyway"
        );

        // The caller drains and the paused chunk arrives whole: two records
        // queued, the third still assembling.
        inbound.lock().expect("the queue").bytes = 0;
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(server.local_error().is_none());
        assert_eq!(
            inbound.lock().expect("the queue").events.len(),
            2,
            "the paused records never arrived"
        );
        assert!(
            streams
                .get(&id)
                .expect("the stream")
                .framing
                .is_assembling(),
            "the trailing partial was dropped"
        );
    }

    #[test]
    fn a_large_control_frame_waits_for_its_own_headroom() {
        let (mut client, mut server) = sans_io_pair(2_000_000);
        let local: SocketAddr = "127.0.0.1:4433".parse().expect("an address");
        let remote: SocketAddr = "127.0.0.1:4434".parse().expect("an address");
        let mut frame = Vec::new();
        vot_codec::encode_frame(
            vot_codec::frame_type::PACKAGE_DESCRIPTOR,
            &vec![0x27; vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD],
            &mut frame,
        )
        .expect("a maximum control frame");
        let split = vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD / 2 - 32;
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(
            vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
        ));
        let mut streams = BTreeMap::new();
        let state = stream_state(
            &mut streams,
            CONTROL_STREAM_ID,
            StreamKind::Control,
            &budget,
            &control_limit,
        );
        state
            .framing
            .accept(&frame[..split], |_| panic!("a partial frame completed"))
            .expect("the prefix fits");

        let mut sent = split;
        while sent < frame.len() {
            match client.stream_send(CONTROL_STREAM_ID, &frame[sent..], false) {
                Ok(written) => sent += written,
                Err(quiche::Error::Done) => {}
                Err(error) => panic!("a stream: {error:?}"),
            }
            shuttle(&mut client, local, &mut server, remote);
            shuttle(&mut server, remote, &mut client, local);
        }
        let mut buffer = vec![0_u8; vot_transport_framing::MAX_PARTIAL_FRAME.max(65_535)];
        let reserved = streams
            .get(&CONTROL_STREAM_ID)
            .expect("the control stream")
            .framing
            .reserved();
        let low_headroom = 100_000;
        inbound.lock().expect("the queue").bytes = MAX_ASSEMBLY_BYTES - reserved - low_headroom;

        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(
            server.local_error().is_none(),
            "backpressure closed the connection"
        );
        assert!(inbound.lock().expect("the queue").events.is_empty());

        inbound.lock().expect("the queue").bytes = 0;
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(server.local_error().is_none());
        assert_eq!(
            inbound.lock().expect("the queue").events.len(),
            1,
            "the control frame did not arrive after headroom returned"
        );
    }

    #[test]
    fn a_spent_event_count_parks_the_frame_and_delivers_it_later() {
        // The byte budget cannot see a queue full of empty events, so the frame
        // completes, the queue refuses it, and it waits in overflow. The stream
        // may leave the readable set for good, which is why the drain walks
        // every stream, not only the readable ones.
        let (mut client, mut server) = sans_io_pair(1_000_000);
        let inbound = Arc::new(Mutex::new(Inbound::default()));
        {
            let mut queue = inbound.lock().expect("the queue");
            for _ in 0..MAX_INBOUND_EVENTS {
                queue
                    .push(NativeEvent::Control(vec![].into()))
                    .expect("room for an empty event");
            }
        }
        let budget = SharedBudget(Arc::clone(&inbound));
        let control_limit = Arc::new(AtomicUsize::new(1_000_000));
        let mut streams = BTreeMap::new();
        let mut buffer = vec![0_u8; vot_transport_framing::MAX_PARTIAL_FRAME.max(65_535)];
        frame_on_the_wire(&mut client, &mut server);
        frame_on_the_wire(&mut client, &mut server);
        read_streams(
            &mut server,
            &mut streams,
            &budget,
            &inbound,
            &control_limit,
            Role::Server,
            &mut buffer,
        );
        assert!(
            !server.is_closed(),
            "a full event count closed the connection"
        );
        assert!(server.local_error().is_none());
        // Both frames arrived in one read chunk, and a chunk's completions
        // are the overflow's documented bound: everything it finished parks,
        // and nothing past the chunk is read.
        let held: usize = streams.values().map(|state| state.overflow.len()).sum();
        assert_eq!(held, 2, "the chunk's completions are not all in overflow");

        {
            let mut queue = inbound.lock().expect("the queue");
            while queue.events.pop_front().is_some() {}
        }
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
            2,
            "both frames never arrived once the caller drained"
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
                .send_reliable_shared(StreamId(u64::MAX), record.clone())
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
