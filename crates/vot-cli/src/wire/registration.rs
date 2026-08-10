//! The serve-side rendezvous runtime and the rendezvous service.

use super::{Arc, Duration, Error, Ordering, SideChannel, SocketAddr, for_socket, waited_out};

/// Returns a registration only when both a service and side channel exist.
///
/// # Errors
/// Reports a registration thread that will not start.
pub(crate) fn start_registration(
    services: &[SocketAddr],
    side: Option<SideChannel>,
    root: [u8; 32],
) -> Result<Option<Registration>, Error> {
    match (services.is_empty(), side) {
        (false, Some(side)) => Registration::begin(side, root, services).map(Some),
        _ => Ok(None),
    }
}

/// Registration thread for a serving process. Drop stops and joins it,
/// which releases the listener's socket.
pub(crate) struct Registration {
    stop: Arc<std::sync::atomic::AtomicBool>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Polls during drop to wait for the registration thread to stop. A
/// stuck thread is leaked rather than blocking the serve's return.
const STOP_TURNS: usize = 20;

impl Registration {
    /// Sends the first registration on the calling thread so a service this
    /// socket cannot reach at all fails immediately.
    ///
    /// One address of several may refuse: a host with no IPv6 route cannot
    /// send to the service's IPv6 address, and that is a route missing
    /// rather than a service missing. Only a service where none of its
    /// addresses took the registration is refused here.
    ///
    /// # Errors
    /// Reports a service none of whose addresses this socket can send to,
    /// and a thread that will not start.
    pub(crate) fn begin(
        side: SideChannel,
        root: [u8; 32],
        services: &[SocketAddr],
    ) -> Result<Self, Error> {
        let mut registrar = crate::rendezvous::Registrar::new(&root, services);
        if !posted_any(&side, registrar.due(0)) {
            return Err(Error::CarrierUnavailable);
        }
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let ended = Arc::clone(&stopped);
        let thread = std::thread::Builder::new()
            .name("vot-rendezvous".to_owned())
            .spawn(move || {
                keep_registered(&side, &mut registrar, &flag);
                ended.store(true, Ordering::Relaxed);
            })
            .map_err(|_| Error::CarrierUnavailable)?;
        Ok(Self {
            stop,
            stopped,
            thread: Some(thread),
        })
    }

    /// Whether the registration thread has ended.
    #[cfg(test)]
    pub(crate) fn watch(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.stopped)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(thread) = self.thread.take() else {
            return;
        };
        for _ in 0..STOP_TURNS {
            if self.stopped.load(Ordering::Relaxed) {
                let _ = thread.join();
                return;
            }
            std::thread::sleep(REGISTRAR_TICK);
        }
    }
}

/// Read timeout for the service loop. Also bounds idle wait time.
pub(crate) const SERVICE_TICK: Duration = Duration::from_millis(100);

/// Runs the rendezvous service on `address` until stopped, or `datagrams`
/// turns when bounded.
///
/// Malformed arrivals are shed; non-timeout socket errors end the service.
///
/// # Errors
/// Surfaces a socket that will not bind, and the endpoint's own failure.
pub fn rendezvous_service(
    address: SocketAddr,
    datagrams: Option<u64>,
    mut listening: impl FnMut(SocketAddr),
) -> Result<(), Error> {
    let socket = std::net::UdpSocket::bind(address).map_err(|_| Error::CarrierUnavailable)?;
    socket
        .set_read_timeout(Some(SERVICE_TICK))
        .map_err(|_| Error::CarrierUnavailable)?;
    let listening_at = socket.local_addr().map_err(|_| Error::CarrierUnavailable)?;
    listening(listening_at);
    let began = std::time::Instant::now();
    let mut pairings = crate::rendezvous::Pairings::default();
    let mut buffer = [0_u8; 128];
    let mut turns: Box<dyn Iterator<Item = ()>> = match datagrams {
        Some(bound) => Box::new(std::iter::repeat_n((), usize::try_from(bound).unwrap_or(0))),
        None => Box::new(std::iter::repeat(())),
    };
    while turns.next().is_some() {
        let (length, source) = match socket.recv_from(&mut buffer) {
            Ok(arrival) => arrival,
            Err(error) => {
                if waited_out(&error) {
                    continue;
                }
                return Err(Error::Io(error));
            }
        };
        let Some(datagram) = crate::rendezvous::decode(&buffer[..length]) else {
            continue;
        };
        // A dual-stack socket sees an IPv4 peer as ::ffff:a.b.c.d. What it
        // records and hands out is the address that peer can be reached at
        // from its own family; what it sends to goes back through this
        // socket's family.
        let source = crate::side_channel::address::canonical(source);
        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        let answer = pairings.take(datagram, source, now_ms);
        if let Some(reply) = answer.reply {
            let _ = socket.send_to(
                &crate::rendezvous::encode(&reply),
                for_socket(source, listening_at),
            );
        }
        if let Some((mapping, notice)) = answer.notify {
            let _ = socket.send_to(
                &crate::rendezvous::encode(&notice),
                for_socket(mapping, listening_at),
            );
        }
    }
    Ok(())
}

/// Side-channel read timeout for the registration thread.
const REGISTRAR_TICK: Duration = Duration::from_millis(200);

/// Sends registrar output on the listener's socket, reporting whether any
/// of it went.
///
/// False means this socket reached none of what it was given, which for a
/// first registration is a service that is not there. One address of
/// several refusing is a route this host does not have, and a serve with
/// no IPv6 route is still findable over IPv4.
fn posted_any(side: &SideChannel, sends: Vec<(SocketAddr, crate::rendezvous::Datagram)>) -> bool {
    let Ok(local) = side.local_address() else {
        return false;
    };
    let mut went = false;
    for (to, datagram) in sends {
        went |= side
            .send_to(&crate::rendezvous::encode(&datagram), for_socket(to, local))
            .is_ok();
    }
    went
}

/// Sends what is due and keeps the cadence whatever one datagram does.
///
/// A warming to a fetch that has gone draws an ICMP unreachable, and with
/// path-MTU discovery on the socket the kernel reports that on the next
/// send, which is usually the registration. Ending the cadence there
/// stops the serve being findable at all, over one datagram nobody was
/// waiting for.
pub(crate) fn post_regardless(
    side: &SideChannel,
    sends: Vec<(SocketAddr, crate::rendezvous::Datagram)>,
) {
    let Ok(local) = side.local_address() else {
        return;
    };
    for (to, datagram) in sends {
        let _ = side.send_to(&crate::rendezvous::encode(&datagram), for_socket(to, local));
    }
}

/// Runs the registration cadence until `stop`, or until the router that
/// owns the socket has gone.
fn keep_registered(
    side: &SideChannel,
    registrar: &mut crate::rendezvous::Registrar,
    stop: &std::sync::atomic::AtomicBool,
) {
    let began = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Send pending registrations before blocking on the channel.
        post_regardless(side, registrar.due(now_ms));
        match side.next_within(REGISTRAR_TICK) {
            Ok(Some((bytes, from))) => {
                if let Some(datagram) = crate::rendezvous::decode(&bytes) {
                    registrar.take(datagram, from);
                }
            }
            Ok(None) => {}
            // Router closed; exit to avoid spinning.
            Err(_) => return,
        }
    }
}
