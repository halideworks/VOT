//! The fetch-side resolution and punch.

use super::{Duration, Error, SocketAddr, local_for, read_failure};

/// How long a resolve attempt waits for the service to answer.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a rail waits for the serve's warming before connecting anyway.
/// Long enough to cover a wide-area round trip to the service and the
/// serve's next registrar pass.
const WARMING_WAIT: Duration = Duration::from_millis(1_500);

/// Datagrams either rendezvous wait reads before giving up, so whatever
/// else arrives on the socket cannot extend a wait without bound.
pub(crate) const STRAY_READS: usize = 8;

/// Retries a resolve when no serve is registered yet.
pub(crate) const RESOLVE_RETRIES: u32 = 6;

/// How long a rail waits between resolves when the key is not registered.
const RESOLVE_RETRY_WAIT: Duration = Duration::from_millis(500);

/// How long a punched rail waits for its handshake before the path is
/// called unpunchable.
///
/// A punch lands in the first tenth of a second when both NATs keep the
/// mapping the service observed. When the serving end's NAT gives its
/// warming a different external port, the hole and the Initial do not
/// line up until the handshake has retried a few times, measured at
/// around ten seconds on two conntrack NATs. The bound is past that, so
/// what it names is a path that cannot open rather than one that is slow.
pub(crate) const PUNCH_WAIT: Duration = Duration::from_secs(15);

/// A rail's socket after the service has seen it: bound, announced under
/// the key, and given the serve time to open its side. `serve` is the
/// mapping the service holds for the key.
pub(crate) struct Punched {
    pub(crate) socket: std::net::UdpSocket,
    pub(crate) serve: SocketAddr,
}

/// Announces one rail's socket at the service and waits for the warming.
///
/// The `Resolve` leaves by the socket the session will use, so the mapping
/// the service forwards to the serve is the one the Initial arrives from.
/// Any other socket earns a hole in the serve's NAT that this rail's
/// packets do not fit through.
///
/// # Errors
/// Returns [`Error::RendezvousUnresolved`] when no serve is registered
/// under the key before the retry budget is spent, and
/// [`Error::CarrierUnavailable`] for a socket that will not bind or send.
pub(crate) fn punch(key: [u8; 32], service: SocketAddr) -> Result<Punched, Error> {
    punch_within(key, service, RESOLVE_RETRY_WAIT, WARMING_WAIT)
}

/// [`punch`] with its two waits as arguments, so a test spends neither.
pub(crate) fn punch_within(
    key: [u8; 32],
    service: SocketAddr,
    retry: Duration,
    warming: Duration,
) -> Result<Punched, Error> {
    // Bound toward the service, so the socket is in the service's family, and
    // so is every mapping the service ever observed to answer with.
    let socket =
        std::net::UdpSocket::bind(local_for(service)?).map_err(|_| Error::CarrierUnavailable)?;
    let mut buffer = [0_u8; 128];
    for _ in 0..RESOLVE_RETRIES {
        socket
            .send_to(
                &crate::rendezvous::encode(&crate::rendezvous::Datagram::Resolve { key }),
                service,
            )
            .map_err(|_| Error::CarrierUnavailable)?;
        if let Some(serve) = resolved(&socket, &mut buffer, key, service)? {
            open_toward(&socket, serve);
            wait_warm(&socket, &mut buffer, serve, warming)?;
            return Ok(Punched { socket, serve });
        }
        // A serve that has not registered yet is the case worth waiting on:
        // the answer came back at once, so the next attempt would too.
        std::thread::sleep(retry);
    }
    Err(Error::RendezvousUnresolved)
}

/// Takes a relay slot for `key` and stands at it: the invitation sent
/// through every service address, this end's warmings claiming the slot's
/// first end, and the serve's warmings, forwarded by the slot, waited for.
pub(crate) fn take_slot(
    key: [u8; 32],
    relay: SocketAddr,
    services: &[SocketAddr],
) -> Result<Punched, Error> {
    take_slot_within(key, relay, services, RESOLVE_RETRY_WAIT, WARMING_WAIT)
}

/// [`take_slot`] with its two waits as arguments, so a test spends neither.
pub(crate) fn take_slot_within(
    key: [u8; 32],
    relay: SocketAddr,
    services: &[SocketAddr],
    retry: Duration,
    warming: Duration,
) -> Result<Punched, Error> {
    // Bound toward the relay: the slot observes this socket's mapping, and
    // every datagram of the session has to leave under the same one.
    let socket =
        std::net::UdpSocket::bind(local_for(relay)?).map_err(|_| Error::CarrierUnavailable)?;
    let mut buffer = [0_u8; 128];
    for _ in 0..RESOLVE_RETRIES {
        socket
            .send_to(
                &crate::relay::encode(&crate::relay::Datagram::Take { key }),
                relay,
            )
            .map_err(|_| Error::CarrierUnavailable)?;
        if let Some(at) = slot_answered(&socket, &mut buffer, key, relay)? {
            // The serve is told where to meet before this end warms the
            // slot, so the floor below waits on both legs at once. A lost
            // invite costs one loop turn and nothing else: a repeated Take
            // is answered with the slot the key already holds.
            let invite =
                crate::rendezvous::encode(&crate::rendezvous::Datagram::Invite { key, at });
            for service in services {
                let _ = socket.send_to(&invite, *service);
            }
            open_toward(&socket, at);
            wait_warm(&socket, &mut buffer, at, warming)?;
            return Ok(Punched { socket, serve: at });
        }
        std::thread::sleep(retry);
    }
    Err(Error::RelayUnavailable)
}

/// Reads until `relay` answers a slot for `key`, the way [`resolved`]
/// reads a serve: only the relay that was asked is heard, for the same
/// reason only the service that was asked is.
///
/// A relay with no slot to give answers `Slot { at: None }`; that is a
/// retry, because a TTL may free one, and the retry loop is what bounds it.
pub(crate) fn slot_answered(
    socket: &std::net::UdpSocket,
    buffer: &mut [u8; 128],
    key: [u8; 32],
    relay: SocketAddr,
) -> Result<Option<SocketAddr>, Error> {
    read_until(
        socket,
        buffer,
        RESOLVE_TIMEOUT,
        crate::relay::decode,
        |datagram, source| {
            if !crate::side_channel::address::from_service(source, relay) {
                return None;
            }
            match datagram {
                crate::relay::Datagram::Slot { key: answered, at } if answered == key => at,
                _ => None,
            }
        },
    )
}

/// Sends this end's own warming toward the serve, before waiting for the
/// serve's.
///
/// Both ends have to send. A warming that arrives before this end has sent
/// anything to the serve is unsolicited, and a NAT that tracks it takes the
/// mapping this socket would have used: the session's packets then leave
/// under a different one than the service observed, and the serve's hole
/// does not fit them. Sending first is what keeps the mapping.
fn open_toward(socket: &std::net::UdpSocket, serve: SocketAddr) {
    let warming = crate::rendezvous::encode(&crate::rendezvous::Datagram::Warming);
    // A lost one costs the mapping, so it goes more than once. The serve
    // sheds them: they are not from its service, so they earn nothing.
    for _ in 0..crate::rendezvous::WARMING_DATAGRAMS {
        let _ = socket.send_to(&warming, serve);
    }
}

/// Reads datagrams until `accept` names a value, [`STRAY_READS`] have
/// arrived, or `budget` is spent.
///
/// The budget is the whole wait and not the wait per read. A stranger
/// sending to this port would otherwise buy back the full timeout with
/// every datagram, so the read count alone does not bound the wall clock.
pub(crate) fn read_until<D, T>(
    socket: &std::net::UdpSocket,
    buffer: &mut [u8; 128],
    budget: Duration,
    decode: impl Fn(&[u8]) -> Option<D>,
    mut accept: impl FnMut(D, SocketAddr) -> Option<T>,
) -> Result<Option<T>, Error> {
    let began = std::time::Instant::now();
    for _ in 0..STRAY_READS {
        let left = budget.saturating_sub(began.elapsed());
        // A zero read timeout is no timeout at all, so the spent budget
        // has to end the wait rather than arm a blocking read.
        if left.is_zero() {
            return Ok(None);
        }
        socket
            .set_read_timeout(Some(left))
            .map_err(|_| Error::CarrierUnavailable)?;
        let (length, source) = match socket.recv_from(buffer) {
            Ok(arrival) => arrival,
            Err(error) => return read_failure(&error).map_or(Ok(None), Err),
        };
        if let Some(datagram) = decode(&buffer[..length])
            && let Some(found) = accept(datagram, source)
        {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Reads until `service` names a serve for `key` or the read runs out.
/// Nothing named is a retry, not a failure.
///
/// The answer decides where this rail sends its Initial, so it is taken
/// only from the service that was asked. The key alone is not enough: a
/// package root is not a secret, and anyone who can reach this port could
/// otherwise point the rail at an address of their choosing. This is the
/// check [`crate::rendezvous::Registrar::take`] makes on the serving end,
/// through the same [`crate::side_channel::address::from_service`].
///
/// A service on a multi-homed host has to answer from the address it was
/// asked at. One that answers from another of its own addresses is heard
/// only if that address is among the ones the fetch was given.
pub(crate) fn resolved(
    socket: &std::net::UdpSocket,
    buffer: &mut [u8; 128],
    key: [u8; 32],
    service: SocketAddr,
) -> Result<Option<SocketAddr>, Error> {
    let found = read_until(
        socket,
        buffer,
        RESOLVE_TIMEOUT,
        crate::rendezvous::decode,
        |datagram, source| {
            if !crate::side_channel::address::from_service(source, service) {
                return None;
            }
            match datagram {
                crate::rendezvous::Datagram::Resolved {
                    key: answered,
                    serve,
                } if answered == key => Some(serve),
                _ => None,
            }
        },
    )?;
    Ok(found.flatten())
}

/// Waits for the serve's warming, the one sign this end gets that the
/// serve has sent something toward this mapping.
///
/// A NAT that filters by port sheds the warming, so its absence proves
/// nothing and the wait is a floor on how long the serve has had to open
/// its side.
///
/// The port is not checked, unlike in [`resolved`]: a warming from a port
/// other than the one the service reported is the unpunchable case, and
/// ending the floor there costs nothing, because the warming decides no
/// address. The address is checked, because a warming from anywhere else
/// is not evidence about this serve at all and a stranger must not be
/// able to end the floor early.
///
/// `wait` is the whole floor. It is not restarted by what else arrives.
pub(crate) fn wait_warm(
    socket: &std::net::UdpSocket,
    buffer: &mut [u8; 128],
    serve: SocketAddr,
    wait: Duration,
) -> Result<(), Error> {
    read_until(
        socket,
        buffer,
        wait,
        crate::rendezvous::decode,
        |datagram, source| {
            (datagram == crate::rendezvous::Datagram::Warming
                && crate::side_channel::address::canonical(source).ip()
                    == crate::side_channel::address::canonical(serve).ip())
            .then_some(())
        },
    )?;
    Ok(())
}
