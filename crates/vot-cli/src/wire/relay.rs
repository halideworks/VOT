//! The relay service runtime.

use super::{
    Duration, Error, Ordering, RELAY_BYTES, RELAY_SLOTS, RELAY_TTL_MS, SERVICE_TICK, SocketAddr,
    elapsed_ms, relay_limits_from, waited_out,
};

/// How long a slot thread waits on its socket before checking its deadline.
///
/// A slot that carries nothing still has to notice its own expiry, and this
/// is how often it looks. Short enough that a closed slot releases its port
/// promptly, long enough that an idle slot is not a spinning thread.
const SLOT_TICK: Duration = Duration::from_millis(200);

/// The widest datagram a slot forwards. A relayed datagram is exactly the
/// size of a direct one, so this is the carrier's own ceiling.
const SLOT_DATAGRAM_BYTES: usize = vot_transport_quiche::live::LARGEST_DATAGRAM_SIZE;

/// Forwards one slot's datagrams until it spends its time or its bytes.
///
/// Owns its socket and its whole accounting, so no two slots share state and
/// the relay's bound is a count of threads rather than a lock.
fn run_slot(
    socket: &std::net::UdpSocket,
    mut meter: crate::relay::Meter,
    began: std::time::Instant,
    stopping: &std::sync::atomic::AtomicBool,
) {
    if socket.set_read_timeout(Some(SLOT_TICK)).is_err() {
        return;
    }
    let mut buffer = vec![0_u8; SLOT_DATAGRAM_BYTES];
    loop {
        // The relay stopping ends its slots. Without this a bounded run
        // returns and then waits out every slot's whole lifetime.
        if stopping.load(Ordering::Relaxed) {
            eprintln!("{}", closing_line(&meter));
            return;
        }
        let now_ms = elapsed_ms(began);
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                match meter.take(source, length as u64, now_ms) {
                    crate::relay::Forward::To(peer) => {
                        // A refused send is the far end gone, which the other
                        // end learns from its own session rather than here.
                        let _ = socket.send_to(&buffer[..length], peer);
                    }
                    crate::relay::Forward::Nowhere => {}
                    crate::relay::Forward::Closed => {
                        eprintln!("{}", closing_line(&meter));
                        return;
                    }
                }
            }
            // Nothing arrived. The deadline still applies, and asking about
            // it must not look like an arrival: a slot waits for its ends and
            // the first one to speak has to be the first end.
            Err(error) => match idle_after(&error, meter.expired(now_ms)) {
                Idle::Ended => return,
                Idle::Expired => {
                    eprintln!("{}", closing_line(&meter));
                    return;
                }
                Idle::Waiting => {}
            },
        }
    }
}

/// What a slot carried, which is the donation an operator is paying for and
/// the only thing the relay ever says about one.
///
/// The line rather than the printing, so a test can read what an operator
/// would. Printed at each of the three ways a slot ends rather than through
/// a helper: a function that only prints is one whose absence nothing in
/// this process can see, so no test can hold it.
pub(crate) fn closing_line(meter: &crate::relay::Meter) -> String {
    format!("slot closed after {} bytes", meter.forwarded())
}

/// What a slot does about a read that gave it nothing.
///
/// Pure, because the branch matters: a real socket error ends the slot and a
/// timeout does not, and reaching either through an actual socket failure is
/// not something a test can arrange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Idle {
    /// The socket failed. Nothing more will arrive on it.
    Ended,
    /// Nothing came, and the slot has outlived its window.
    Expired,
    /// Nothing came, and the slot is still open.
    Waiting,
}

/// Which of the three a read error and the clock mean.
pub(crate) fn idle_after(error: &std::io::Error, expired: bool) -> Idle {
    if !waited_out(error) {
        Idle::Ended
    } else if expired {
        Idle::Expired
    } else {
        Idle::Waiting
    }
}

/// Runs the relay on `address` until stopped, or until it has answered
/// `datagrams` requests for a slot when bounded.
///
/// The bound counts answers rather than loop passes, so a relay nobody asks
/// runs until it is stopped and a bounded one is not spent by its own read
/// timeouts.
///
/// The relay answers `Take` on this socket and opens one port per slot. It
/// never reads what a slot carries: ADR-0034.
///
/// # Errors
/// Surfaces a socket that will not bind, and a control socket that fails for
/// a reason other than its own read timeout.
pub fn relay_service(
    address: SocketAddr,
    datagrams: Option<u64>,
    mut listening: impl FnMut(SocketAddr),
) -> Result<(), Error> {
    let limits = relay_limits_from(
        std::env::var(RELAY_SLOTS).ok().as_deref(),
        std::env::var(RELAY_TTL_MS).ok().as_deref(),
        std::env::var(RELAY_BYTES).ok().as_deref(),
    )?;
    let socket = std::net::UdpSocket::bind(address).map_err(|_| Error::CarrierUnavailable)?;
    socket
        .set_read_timeout(Some(SERVICE_TICK))
        .map_err(|_| Error::CarrierUnavailable)?;
    let listening_at = socket.local_addr().map_err(|_| Error::CarrierUnavailable)?;
    listening(listening_at);
    // The relay's own configuration, on stderr because it is what an
    // operator agreed to donate and the one thing they need to see is that
    // the numbers running are the numbers they set.
    eprintln!(
        "relay slots {} ttl {}ms bytes {}",
        limits.concurrent, limits.ttl_ms, limits.bytes
    );
    let began = std::time::Instant::now();
    let mut slots = crate::relay::Slots::default();
    let mut buffer = [0_u8; 128];
    // Slots run on their own threads and are joined when the relay stops, so
    // a bounded run leaves nothing behind.
    let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut running = Running {
        limits,
        began,
        stopping: &stopping,
        threads: Vec::new(),
    };
    // An iterator rather than a counter compared against the bound. That
    // comparison inverts into a relay that never stops, which hangs a test
    // rather than failing it, and one pull per answer spends the bound only
    // on a request actually answered rather than on a read that timed out.
    let mut answers: Box<dyn Iterator<Item = ()>> = match datagrams {
        Some(bound) => Box::new(std::iter::repeat_n((), usize::try_from(bound).unwrap_or(0))),
        None => Box::new(std::iter::repeat(())),
    };
    while answers.next().is_some() {
        let (length, source) = match socket.recv_from(&mut buffer) {
            Ok(arrival) => arrival,
            Err(error) => {
                if waited_out(&error) {
                    slots.retire(elapsed_ms(began));
                    continue;
                }
                return Err(Error::Io(error));
            }
        };
        let Some(crate::relay::Datagram::Take { key }) = crate::relay::decode(&buffer[..length])
        else {
            continue;
        };
        let now_ms = elapsed_ms(began);
        let at = if let Some(held) = slots.held(key, now_ms) {
            // The same key asking again is answered with the slot it already
            // has, so a repeated Take costs one datagram rather than a port.
            Some(held)
        } else if slots.admit(key, now_ms, limits) {
            open_slot(&socket, &mut slots, key, now_ms, &mut running)
        } else {
            None
        };
        let _ = socket.send_to(
            &crate::relay::encode(&crate::relay::Datagram::Slot { key, at }),
            source,
        );
    }
    stopping.store(true, Ordering::Relaxed);
    for slot in running.threads {
        let _ = slot.join();
    }
    Ok(())
}

/// What every slot this relay opens shares: the bounds it runs under, the
/// clock it measures against, the flag that ends it, and the handles the
/// relay joins.
///
/// One value because they travel together and separately they are five
/// arguments to a function that opens a socket.
struct Running<'a> {
    limits: crate::relay::Limits,
    began: std::time::Instant,
    stopping: &'a std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

/// Opens one slot beside `control`, in the same family, and starts its
/// thread. Nothing is recorded if the socket will not bind.
fn open_slot(
    control: &std::net::UdpSocket,
    slots: &mut crate::relay::Slots,
    key: [u8; 32],
    now_ms: u64,
    running: &mut Running<'_>,
) -> Option<SocketAddr> {
    let local = control.local_addr().ok()?;
    let mut any = local;
    any.set_port(0);
    let socket = std::net::UdpSocket::bind(any).ok()?;
    let at = socket.local_addr().ok()?;
    let expires_at_ms = now_ms.saturating_add(running.limits.ttl_ms);
    let meter = crate::relay::Meter::new(expires_at_ms, running.limits.bytes);
    let began = running.began;
    let stopping = std::sync::Arc::clone(running.stopping);
    running.threads.push(std::thread::spawn(move || {
        run_slot(&socket, meter, began, &stopping);
    }));
    slots.opened(key, at, expires_at_ms);
    Some(crate::side_channel::address::canonical(at))
}
