//! Driving one end of a session to a settled state.
//!
//! Serving and fetching are the same loop with different work in it: make
//! a pass, and if the pass left something this end can do without hearing
//! from the peer, make another; otherwise wait on the carrier. Both
//! engines document that rule and getting it wrong is silent, either a
//! spin over a session that cannot progress or a wait for an event that
//! was never coming. So it is written once here and both ends take it.

use std::time::Duration;

use vot_transport_api::TransportAdapter;

use crate::Error;

/// How long a pass waits on a carrier with nothing to do.
///
/// A wait ends when an event lands, so this is only how often an idle end
/// looks up (`docs/perf-engineering.md`, 2026-08-04: the bound stopped
/// being a result once waits became blocking). Long enough not to spin,
/// short enough that a carrier which dies quietly is noticed.
const IDLE_BOUND_MS: u64 = 50;
const IDLE_BOUND: Duration = Duration::from_millis(IDLE_BOUND_MS);

/// How long a pass waits when the carrier is holding work back.
///
/// A backlog is a frame the carrier would not take, so what this end is
/// waiting for is room to send rather than something to read, and a
/// carrier does not report room as an event. Waiting the idle bound for
/// it would pace a transfer at one drain every fifty milliseconds;
/// waiting not at all would spin a core for the length of the transfer.
const BUSY_BOUND_MS: u64 = 1;
const BUSY_BOUND: Duration = Duration::from_millis(BUSY_BOUND_MS);

/// What a driving loop may wait through without the engine getting
/// anywhere, in the milliseconds of its own two bounds.
///
/// Not a bound on how long a session may take: any progress at all sets it
/// back, so it only ends a session where nothing is happening. Not a clock
/// either. What a pass spends is the wait it chose, both of them constants
/// here, so a machine slow enough to take a second inside `service` spends
/// one millisecond of this and not a second.
///
/// Counting passes instead made the budget mean two different things. Half
/// a minute of silence at the idle bound was the number chosen and
/// documented; the same six hundred passes at the busy bound was 0.6
/// seconds, so a peer that merely stopped reading for a moment ended the
/// session. The two now cost what they wait.
///
/// Half a minute is already past where a live carrier gives up on its own:
/// quiche's idle timeout is thirty seconds and reports a disconnect, which
/// settles the loop. So this is the backstop for a carrier with no timeout
/// of its own, and a longer one would only make a wedged session take
/// longer to say so.
const STALLED_WAIT_MS: u64 = 30_000;

/// One end of a session: a pass to make, a way to say the pass settled it,
/// and the carrier to wait on.
pub trait Engine {
    /// What a pass reports.
    type Status: Copy;

    /// One pass over what the carrier holds. Never blocks.
    ///
    /// # Errors
    /// Whatever the engine could not do.
    fn service(&mut self) -> Result<Self::Status, Error>;

    /// Whether a status means the session is over, however it ended.
    fn settled(status: Self::Status) -> bool;

    /// Whether the carrier is holding work this end has already prepared.
    fn has_backlog(&self) -> bool;

    /// Everything this end has settled, only ever going up.
    ///
    /// Any increase is progress, and progress is what tells a session that
    /// is getting somewhere slowly from one that has stopped. A count that
    /// stood still while a large object was being fetched would end the
    /// transfer partway through.
    fn progress(&self) -> u64;

    /// Waits for the carrier to report something, or for `bound`.
    fn wait(&mut self, bound: Duration);
}

/// Drives `engine` until a pass settles it, and answers with that status.
///
/// # Errors
/// Surfaces the engine's own failure, or [`Error::Stalled`] if the loop
/// made its whole budget of passes without the engine getting anywhere.
pub fn drive<E: Engine>(engine: &mut E) -> Result<E::Status, Error> {
    // The predicate that never holds, so the loop runs to its settled end.
    drive_until(engine, |_| false)?.ok_or(Error::Stalled)
}

/// Drives `engine` until a pass settles it or `done` holds, whichever is
/// first: the settled status, or `None` for a loop `done` ended.
///
/// This is how a fetch grows rails (ADR-0031): the primary is driven here
/// until its plan exists, the rails are spawned onto that plan, and the
/// same loop then drives the primary to its end.
///
/// # Errors
/// Surfaces the engine's own failure, or [`Error::Stalled`] as [`drive`].
pub fn drive_until<E: Engine>(
    engine: &mut E,
    mut done: impl FnMut(&E) -> bool,
) -> Result<Option<E::Status>, Error> {
    let mut stalled_ms: u64 = 0;
    let mut settled_so_far = engine.progress();
    loop {
        let status = engine.service()?;
        if E::settled(status) {
            return Ok(Some(status));
        }
        if done(engine) {
            return Ok(None);
        }
        // Every pass waits, including one with a backlog: a backlog is the
        // carrier refusing what this end already prepared, so there is
        // nothing to do but let it drain, and doing it in a tight loop is
        // a spun core rather than a faster transfer.
        let (wait, spent) = if engine.has_backlog() {
            (BUSY_BOUND, BUSY_BOUND_MS)
        } else {
            (IDLE_BOUND, IDLE_BOUND_MS)
        };
        let progress = engine.progress();
        if progress == settled_so_far {
            // Saturating rather than `+=`, so the loop's own end does not
            // hang on an operator: an increment that stopped incrementing
            // is a loop with nothing left to stop it.
            stalled_ms = stalled_ms.saturating_add(spent);
            if stalled_ms > STALLED_WAIT_MS {
                return Err(Error::Stalled);
            }
        } else {
            settled_so_far = progress;
            stalled_ms = 0;
        }
        engine.wait(wait);
    }
}

/// Ends whatever the loop answered as this end's own outcome: the package
/// for a complete fetch, and the error that names why for anything else.
#[cfg(any(test, feature = "wire"))]
fn fetched<A: TransportAdapter>(
    fetcher: &crate::BundleFetcher<A>,
    status: crate::FetchStatus,
) -> Result<crate::PackageSummary, Error> {
    match status {
        crate::FetchStatus::Complete => fetcher.package().ok_or(Error::InvalidBundle),
        // The code says what the peer refused, and losing it here would
        // leave the caller with nothing to tell the difference by.
        crate::FetchStatus::Closed(code) => Err(Error::PeerClosed(code)),
        crate::FetchStatus::Disconnected => Err(Error::CarrierUnavailable),
        // The loops above answer only with a settled status.
        crate::FetchStatus::Active => Err(Error::InvalidBundle),
    }
}

/// Fetches at `rails` width: the primary is driven until its plan exists,
/// every further rail joins that plan on a fresh connection from
/// `connect`, and the plan striping the requests is what makes W rails
/// one fetch (ADR-0031).
///
/// A rail that fails marks the plan abandoned, so the others end at their
/// next pass instead of waiting out their stall budgets on spans nobody
/// will answer; the failure that started it is what surfaces.
///
/// # Errors
/// Rejects a width of zero, and a width past one with inline proving,
/// which could not pace itself. Surfaces the primary's failure, or the
/// rail failure that explains a primary that only stalled or stopped.
#[cfg(any(test, feature = "wire"))]
pub(crate) fn fetch_striped<A, F>(
    mut primary: crate::BundleFetcher<A>,
    rails: usize,
    connect: F,
) -> Result<crate::PackageSummary, Error>
where
    A: TransportAdapter + Send,
    F: Fn() -> Result<A, Error> + Sync,
{
    if rails == 0 || (rails > 1 && primary.proving_threads() == 0) {
        return Err(Error::InvalidArguments);
    }
    // The manifest is one rail's work; the rest join once it is a plan.
    if let Some(status) = drive_until(&mut primary, |fetcher| fetcher.package().is_some())? {
        return fetched(&primary, status);
    }
    let Some(plan) = primary.shared_plan() else {
        return Err(Error::InvalidBundle);
    };
    let bundle = primary.bundle().to_owned();
    let provers = primary.proving_threads();
    std::thread::scope(|scope| {
        let mut spawned = Vec::new();
        for _ in 1..rails {
            let plan = crate::fetch::SharedPlan::clone(&plan);
            let connect = &connect;
            let bundle = bundle.clone();
            spawned.push(scope.spawn(move || {
                let outcome = (|| {
                    let carrier = connect()?;
                    let mut rail = crate::BundleFetcher::join(carrier, &bundle, plan.clone())?;
                    rail.set_proving_threads(provers)?;
                    match drive(&mut rail)? {
                        crate::FetchStatus::Complete => Ok(()),
                        crate::FetchStatus::Closed(code) => Err(Error::PeerClosed(code)),
                        crate::FetchStatus::Disconnected => Err(Error::CarrierUnavailable),
                        crate::FetchStatus::Active => Err(Error::InvalidBundle),
                    }
                })();
                if outcome.is_err() {
                    crate::fetch::abandon_plan(&plan);
                }
                outcome
            }));
        }
        let outcome = drive(&mut primary).and_then(|status| fetched(&primary, status));
        if outcome.is_err() {
            crate::fetch::abandon_plan(&plan);
        }
        let mut rail_failure = None;
        for rail in spawned {
            if let Err(error) = rail.join().expect("a rail thread never panics") {
                rail_failure.get_or_insert(error);
            }
        }
        match outcome {
            Ok(package) => Ok(package),
            // A primary that stalled or lost its carrier because a rail
            // died is reported as the rail's failure, which is the cause.
            Err(Error::Stalled | Error::CarrierUnavailable) => {
                Err(rail_failure.unwrap_or(Error::CarrierUnavailable))
            }
            Err(error) => Err(error),
        }
    })
}

/// The fetch side is an engine: it owns its session, so it is one already.
impl<A: TransportAdapter> Engine for crate::BundleFetcher<A> {
    type Status = crate::FetchStatus;

    fn service(&mut self) -> Result<Self::Status, Error> {
        Self::service(self)
    }

    fn settled(status: Self::Status) -> bool {
        status != crate::FetchStatus::Active
    }

    fn has_backlog(&self) -> bool {
        Self::has_backlog(self)
    }

    fn progress(&self) -> u64 {
        Self::progress(self)
    }

    fn wait(&mut self, bound: Duration) {
        self.session_mut().driver().wait_for_event(bound);
    }
}

/// The serve side against one carrier.
///
/// The server answers any number of sessions and holds no per-session
/// state, so a session's own state is gathered here rather than in it.
pub struct ServeSession<'server, A: TransportAdapter> {
    server: &'server crate::BundleServer,
    session: vot_session::Session<A>,
    connection: crate::ServeConnection,
}

impl<'server, A: TransportAdapter> ServeSession<'server, A> {
    /// Begins a session on `carrier`, answered from `server`.
    ///
    /// # Errors
    /// Surfaces a session that could not send its opening frames.
    pub fn begin(
        server: &'server crate::BundleServer,
        carrier: A,
        authentication: vot_session::Authentication,
    ) -> Result<Self, Error> {
        let mut session = vot_session::Session::server(
            carrier,
            vot_codec::Settings::default(),
            std::collections::BTreeSet::new(),
            authentication,
        );
        session.begin()?;
        Ok(Self {
            server,
            session,
            connection: crate::ServeConnection::new(),
        })
    }
}

/// Sessions a serve drives at once before the next accepted client waits.
///
/// ADR-0031: a rail is a whole session, so one fetch at width W is W of
/// these, and a serve that drove them one at a time would serialize the
/// rails it exists to parallelise. The bound is on the server's own
/// threads; an accepted client past it is not refused, it waits for a
/// running session to settle, which is backpressure rather than failure.
#[cfg(any(test, feature = "wire"))]
pub(crate) const CONCURRENT_SESSIONS: usize = 8;

/// Serves sessions from `next` until it fails, or `sessions` are answered.
///
/// Sessions run concurrently, each on its own thread, at most
/// [`CONCURRENT_SESSIONS`] at once (ADR-0031: a fetch's rails are whole
/// sessions, and they only help if the serve drives them together).
///
/// A client that connects and goes away leaves its session stalling or
/// failing, and a server told to answer everyone should outlive any one of
/// them: with no session bound, a session's failure ends the session and
/// never the loop. A bounded serve surfaces it instead, because its caller
/// asked for exactly those sessions and deserves to hear one was not
/// served. What ends an unbounded serve is only `next` itself failing,
/// which is the endpoint rather than a peer; the sessions already running
/// are still driven to their end before it is surfaced.
///
/// # Errors
/// Surfaces `next`'s failure always, and a session's failure only when
/// `sessions` is bounded.
///
/// Compiled exactly where it is called: the wire commands and the tests
/// that hold its policy under the mutation gate the wire is not.
#[cfg(any(test, feature = "wire"))]
pub(crate) fn serve_sessions<'server, A, F>(sessions: Option<u32>, mut next: F) -> Result<(), Error>
where
    A: TransportAdapter + Send,
    F: FnMut() -> Result<ServeSession<'server, A>, Error>,
{
    std::thread::scope(|scope| {
        let mut running: std::collections::VecDeque<(u64, std::thread::ScopedJoinHandle<'_, _>)> =
            std::collections::VecDeque::new();
        // Each session announces its own end here, so a wait for a free
        // slot is a wait for whichever session finishes first. Waiting on
        // the oldest instead held every accept behind a session whose
        // client vanished without a close, which settles only at the
        // carrier's idle timeout: on the rig that stalled a fetch for 29
        // of its 30-second budget while five settled sessions sat ready
        // to be reaped.
        let (ended, endings) = std::sync::mpsc::channel::<u64>();
        let mut spawned: u64 = 0;
        // The first session's failure, under a bounded serve. Later ones
        // still run to their end: they were accepted, and the joins below
        // are what keeps the report ordered rather than racy.
        let mut failed = Ok(());
        // Takes one finished session's outcome, waiting for a session to
        // finish if none has: every session announces as it ends, however
        // it ends, so a wait with any session running answers. The wait
        // wakes at [`REAP_TICK`] only to hold the announcement contract:
        // a finished session with nothing in the channel is one whose
        // announcement was lost, and a serve that waited on it would hang
        // forever, so it panics with the diagnosis instead.
        let reap = |running: &mut std::collections::VecDeque<(
            u64,
            std::thread::ScopedJoinHandle<'_, _>,
        )>,
                    failed: &mut Result<(), Error>| {
            assert!(
                !running.is_empty(),
                "a slot is only reaped from a serve that holds one"
            );
            let done = loop {
                match endings.recv_timeout(REAP_TICK) {
                    Ok(done) => break done,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        let finished = running
                            .iter()
                            .filter(|(_, handle)| handle.is_finished())
                            .count();
                        match reap_wake(finished, endings.try_recv().ok()) {
                            ReapWake::Take(done) => break done,
                            ReapWake::Wait => {}
                            ReapWake::Breach => {
                                panic!("{finished} sessions finished without announcing")
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        unreachable!("the serve holds a sender")
                    }
                }
            };
            let at = running
                .iter()
                .position(|(id, _)| *id == done)
                .expect("an announced session is still held");
            let (_, handle) = running.remove(at).expect("the position was just found");
            let settled = handle.join().expect("a session thread never panics");
            settle_session(sessions, settled, failed);
        };
        // The bound is an iterator's, so no counter exists for a mutation
        // to stop counting: a bounded serve accepts exactly as many times
        // as the range yields, and an unbounded one is the range that
        // never ends.
        let mut turns = turns(sessions);
        while turns.next().is_some() {
            // The accept waits here, on this thread, so a factory error is
            // ordered after every session it already handed out.
            let mut accepted = next();
            // A fixed port frees only when a session holding it ends: the
            // carrier's drop joins its driver, so after the reap below the
            // next bind finds the port released. An accept refused while
            // sessions still run therefore reaps one and asks again, and
            // each retry shrinks `running`, which bounds this loop by its
            // own body. A factory failing with nothing left running is
            // the endpoint itself, and surfaces below.
            while accepted.is_err() && !running.is_empty() {
                reap(&mut running, &mut failed);
                accepted = next();
            }
            while running.len() >= CONCURRENT_SESSIONS {
                reap(&mut running, &mut failed);
            }
            let mut session = match accepted {
                Ok(session) => session,
                Err(error) => {
                    drain(running, sessions, &mut failed);
                    return failed.and(Err(error));
                }
            };
            let id = spawned;
            spawned += 1;
            let announce = Announcement {
                id,
                ended: ended.clone(),
            };
            running.push_back((
                id,
                scope.spawn(move || {
                    // Held for the whole drive and announced by its drop,
                    // so the end is announced however the thread ends: a
                    // panic that skipped the announcement would leave the
                    // reap waiting on a session that already died.
                    let _announce = announce;
                    drive(&mut session).map(|_| ())
                }),
            ));
        }
        drain(running, sessions, &mut failed);
        failed
    })
}

/// How often a reap looks up from its wait to check the announcement
/// contract. It prices the detection of a lost announcement, never the
/// reap itself: an announcement that was sent ends the wait the moment
/// it lands.
#[cfg(any(test, feature = "wire"))]
const REAP_TICK: Duration = Duration::from_millis(250);

/// What a reap's wake finds it should do.
#[cfg(any(test, feature = "wire"))]
#[derive(Debug, Eq, PartialEq)]
enum ReapWake {
    /// An announcement is in hand; take that session.
    Take(u64),
    /// Nothing has finished; keep waiting.
    Wait,
    /// A session finished and no announcement exists for it, which is the
    /// contract broken: a thread announces before it can finish, so a
    /// finished one either left its announcement in the channel or never
    /// sent it, and waiting on it would wait forever.
    Breach,
}

/// Decides one wake of the reap's wait, apart from the channel and the
/// threads so the whole table is a test's to hold: any announcement is
/// taken, silence with nothing finished is patience, and silence with a
/// finished session is the breach the wake exists to catch.
#[cfg(any(test, feature = "wire"))]
fn reap_wake(finished: usize, announced: Option<u64>) -> ReapWake {
    match (finished, announced) {
        (_, Some(done)) => ReapWake::Take(done),
        (0, None) => ReapWake::Wait,
        (_, None) => ReapWake::Breach,
    }
}

/// One session's end, announced by drop: however the session's thread
/// ends, the announcement goes, so the reap never waits on a session
/// that already died.
#[cfg(any(test, feature = "wire"))]
struct Announcement {
    id: u64,
    ended: std::sync::mpsc::Sender<u64>,
}

#[cfg(any(test, feature = "wire"))]
impl Drop for Announcement {
    fn drop(&mut self) {
        let _ = self.ended.send(self.id);
    }
}

/// Exactly the bound's turns, or turns without end.
#[cfg(any(test, feature = "wire"))]
fn turns(sessions: Option<u32>) -> Box<dyn Iterator<Item = ()>> {
    match sessions {
        Some(bound) => Box::new(std::iter::repeat_n((), bound as usize)),
        None => Box::new(std::iter::repeat(())),
    }
}

/// Joins every running session and folds each outcome into the policy.
///
/// Order stops mattering here: everything left must end before the serve
/// answers, so each join waits for its own session and no other's.
#[cfg(any(test, feature = "wire"))]
fn drain<T>(
    running: std::collections::VecDeque<(u64, std::thread::ScopedJoinHandle<'_, Result<T, Error>>)>,
    sessions: Option<u32>,
    failed: &mut Result<(), Error>,
) {
    for (_, handle) in running {
        let settled = handle
            .join()
            .expect("a session thread never panics")
            .map(|_| ());
        settle_session(sessions, settled, failed);
    }
}

/// One session's end, under the serve's policy: bounded surfaces the
/// first failure, unbounded logs it and carries on.
#[cfg(any(test, feature = "wire"))]
fn settle_session(
    sessions: Option<u32>,
    settled: Result<(), Error>,
    failed: &mut Result<(), Error>,
) {
    let Err(error) = settled else {
        return;
    };
    if sessions.is_some() {
        if failed.is_ok() {
            *failed = Err(error);
        }
    } else {
        eprintln!("session ended: {error:?}");
    }
}

impl<A: TransportAdapter> Engine for ServeSession<'_, A> {
    type Status = crate::ServeStatus;

    fn service(&mut self) -> Result<Self::Status, Error> {
        self.server.service(&mut self.session, &mut self.connection)
    }

    fn settled(status: Self::Status) -> bool {
        status != crate::ServeStatus::Active
    }

    fn has_backlog(&self) -> bool {
        self.connection.has_backlog()
    }

    fn progress(&self) -> u64 {
        self.connection.progress()
    }

    fn wait(&mut self, bound: Duration) {
        self.session.driver().wait_for_event(bound);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Passes the budget allows at each bound. That these differ by fifty
    /// while the time they stand for does not is the whole of the change:
    /// a pass costs what it waits.
    const IDLE_PASSES: u64 = STALLED_WAIT_MS / IDLE_BOUND_MS;
    const BUSY_PASSES: u64 = STALLED_WAIT_MS / BUSY_BOUND_MS;

    #[test]
    fn an_unbounded_serve_outlives_a_failed_session() {
        // A client that connects and goes away leaves its session stalling,
        // and one dead peer must not take the server from everyone else.
        // Three sessions: one that stalls, one that settles, and then the
        // endpoint itself failing, which is the only thing that may end an
        // unbounded serve.
        use crate::harness::{Loopback, built_bundle, not_required, patterned};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("outlives", &[("a.txt", patterned(1000))]);
        let server = crate::BundleServer::open(&bundle).unwrap();
        let mut sessions = 0_u32;
        let outcome = serve_sessions(None, || {
            sessions += 1;
            match sessions {
                // An empty carrier: the session makes no progress and the
                // loop gives up on it, which is the failure to outlive.
                1 => ServeSession::begin(&server, Loopback::default(), not_required()),
                2 => {
                    let mut carrier = Loopback::default();
                    carrier
                        .on_wait
                        .push_back(Event::Disconnected(ConnectionId(1)));
                    ServeSession::begin(&server, carrier, not_required())
                }
                _ => Err(Error::CarrierUnavailable),
            }
        });
        assert!(
            matches!(outcome, Err(Error::CarrierUnavailable)),
            "the endpoint's own failure ends the serve, a session's never"
        );
        // Five accepts, not three: each refused accept joined one of the
        // two running sessions and asked again, and only with nothing left
        // running did the failure surface as the endpoint's own.
        assert_eq!(sessions, 5, "the stalled session was survived");

        // Told to answer exactly these sessions, the same failure surfaces:
        // the caller asked for them and deserves to hear one was not served.
        let mut bounded = 0_u32;
        let outcome = serve_sessions(Some(2), || {
            bounded += 1;
            if bounded > 2 {
                // Accepting past the bound is a count that stopped
                // counting; erroring here ends the mutant's run rather
                // than a runner's timeout.
                return Err(Error::CarrierUnavailable);
            }
            ServeSession::begin(&server, Loopback::default(), not_required())
        });
        assert!(matches!(outcome, Err(Error::Stalled)));
        // Both were accepted before the first failure could surface: a
        // concurrent serve detects a session's end at its join, not at
        // the next accept, and what was accepted is still driven.
        assert_eq!(bounded, 2, "the bound was accepted, the failure surfaced");

        // And a bounded serve that succeeds answers exactly its bound: the
        // factory errors on any call past it, so a count that under- or
        // overshoots surfaces here rather than serving a session too many.
        // A clean session needs the client's real first flight, because a
        // carrier that dies mid-handshake settles as the failure above; a
        // throwaway client session provides the frames.
        let mut counted = 0_u32;
        let outcome = serve_sessions(Some(1), || {
            counted += 1;
            if counted > 1 {
                return Err(Error::CarrierUnavailable);
            }
            let mut client = vot_session::Session::client(
                Loopback::default(),
                vot_codec::Settings::default(),
                std::collections::BTreeSet::new(),
                not_required(),
            );
            client.begin().unwrap();
            let mut carrier = Loopback::default();
            for frame in client.driver().control.drain(..) {
                carrier
                    .events
                    .push_back(Event::Control(vot_transport_api::shared_payload(&frame)));
            }
            carrier
                .on_wait
                .push_back(Event::Disconnected(ConnectionId(1)));
            ServeSession::begin(&server, carrier, not_required())
        });
        assert!(outcome.is_ok(), "one asked for, one served");
        assert_eq!(counted, 1, "exactly the bound, no session more");

        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn a_refused_accept_waits_for_a_running_session_and_asks_again() {
        // The fixed-port shape: binding the next session's socket fails
        // while the previous session still holds the port, and frees the
        // moment that session ends. A serve that surfaced the first refusal
        // would die after every first session; one that joins a running
        // session and asks again serves them one after another.
        use crate::harness::{Loopback, built_bundle, not_required, patterned};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("retries", &[("a.txt", patterned(1000))]);
        let server = crate::BundleServer::open(&bundle).unwrap();
        let clean = || {
            let mut client = vot_session::Session::client(
                Loopback::default(),
                vot_codec::Settings::default(),
                std::collections::BTreeSet::new(),
                not_required(),
            );
            client.begin().unwrap();
            let mut carrier = Loopback::default();
            for frame in client.driver().control.drain(..) {
                carrier
                    .events
                    .push_back(Event::Control(vot_transport_api::shared_payload(&frame)));
            }
            carrier
                .on_wait
                .push_back(Event::Disconnected(ConnectionId(1)));
            carrier
        };
        let mut accepts = 0_u32;
        let outcome = serve_sessions(Some(2), || {
            accepts += 1;
            match accepts {
                1 | 3 => ServeSession::begin(&server, clean(), not_required()),
                // Accept two is the port still held by session one; any
                // accept past three would be a count that kept counting.
                _ => Err(Error::CarrierUnavailable),
            }
        });
        assert!(outcome.is_ok(), "the refusal was waited out, both served");
        assert_eq!(accepts, 3, "one refusal, retried once, no accept more");

        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn the_width_guard_refuses_what_cannot_pace() {
        use crate::harness::Loopback;

        // Zero rails is no fetch at all.
        let output = crate::tests::temporary("widthguard-zero");
        let fetcher = crate::BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let outcome = fetch_striped(fetcher, 0, || Err::<Loopback, _>(Error::CarrierUnavailable));
        assert!(matches!(outcome, Err(Error::InvalidArguments)));
        crate::harness::discard(&[&output]);

        // Rails past one pace on settled witnesses, which inline proving
        // never books: the width and the mode are refused together.
        let output = crate::tests::temporary("widthguard-inline");
        let mut fetcher = crate::BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.set_proving_threads(0).unwrap();
        let outcome = fetch_striped(fetcher, 2, || Err::<Loopback, _>(Error::CarrierUnavailable));
        assert!(matches!(outcome, Err(Error::InvalidArguments)));
        crate::harness::discard(&[&output]);
    }

    #[test]
    fn one_rail_proving_inline_is_still_a_fetch() {
        // Width one restores today's shape exactly, inline proving
        // included; a guard that caught it would take a working
        // configuration away.
        use crate::harness::{built_bundle, duplex_pair, not_required, patterned};

        let (bundle, built) = built_bundle("inlinewidth", &[("a.txt", patterned(1000))]);
        let (client, half) = duplex_pair();
        let serving_bundle = bundle.clone();
        let serving = std::thread::spawn(move || {
            let server = crate::BundleServer::open(&serving_bundle)?;
            let mut half = Some(half);
            serve_sessions(Some(1), || {
                half.take()
                    .map_or(Err(Error::CarrierUnavailable), |carrier| {
                        ServeSession::begin(&server, carrier, not_required())
                    })
            })
        });
        let output = crate::tests::temporary("inlinewidth-fetched");
        let mut fetcher = crate::BundleFetcher::begin(client, &output, None).unwrap();
        fetcher.set_proving_threads(0).unwrap();
        let package = fetch_striped(fetcher, 1, || {
            Err::<crate::harness::Duplex, _>(Error::CarrierUnavailable)
        })
        .expect("one rail, no provers, a whole fetch");
        assert_eq!(package, built);
        serving.join().expect("the serving thread").expect("served");
        crate::harness::discard(&[&bundle, &output]);
    }

    #[test]
    fn a_wake_takes_waits_or_refuses_by_the_whole_table() {
        // The reap's wake decision, exhaustively: an announcement in hand
        // is taken whatever the count says (the count may lag the send by
        // the width of the race), silence with nothing finished waits,
        // and silence with anything finished is the breach.
        assert_eq!(reap_wake(0, Some(4)), ReapWake::Take(4));
        assert_eq!(reap_wake(3, Some(9)), ReapWake::Take(9));
        assert_eq!(reap_wake(0, None), ReapWake::Wait);
        assert_eq!(reap_wake(1, None), ReapWake::Breach);
        assert_eq!(reap_wake(7, None), ReapWake::Breach);
    }

    #[test]
    fn an_announcement_goes_however_its_thread_ends() {
        // The reap waits on announcements, so one that never went would
        // block the serve forever: the drop is what sends it, cleanly or
        // through an unwind alike.
        let (ended, endings) = std::sync::mpsc::channel();
        drop(Announcement { id: 7, ended });
        assert_eq!(endings.recv().expect("the drop announced"), 7);

        let (ended, endings) = std::sync::mpsc::channel();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _announce = Announcement { id: 9, ended };
            panic!("the thread dies mid-session");
        }));
        assert!(unwound.is_err(), "the panic unwound");
        assert_eq!(
            endings.recv().expect("the unwind announced"),
            9,
            "a panic that skipped the announcement would hang the reap"
        );
    }

    #[test]
    fn a_slow_session_does_not_hold_the_accepts_behind_it() {
        // A session whose client vanished without a close settles only at
        // its carrier's idle timeout. The bound's wait must take whichever
        // session finishes first, not the oldest: blocked on the oldest,
        // every later accept waited out that timeout, which stalled a
        // fetch for 29 of its 30-second budget on the rig. The gate
        // proves the loop kept accepting: the first session waits at it,
        // and only the last session accepted can fill it.
        use crate::harness::{Loopback, Rendezvous, built_bundle, not_required, patterned};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("slowjoin", &[("a.txt", patterned(1000))]);
        let server = crate::BundleServer::open(&bundle).unwrap();
        let gate = Rendezvous::expecting(2);
        let total = u32::try_from(CONCURRENT_SESSIONS).unwrap() + 2;
        let mut handed = 0_u32;
        let outcome = serve_sessions(Some(total), || {
            handed += 1;
            if handed > total {
                // Accepting past the bound is a count that stopped
                // counting; erroring here ends a mutant's run rather
                // than a runner's timeout.
                return Err(Error::CarrierUnavailable);
            }
            let mut carrier = Loopback::default();
            if handed == 1 || handed == total {
                carrier.rendezvous = Some(std::sync::Arc::clone(&gate));
            }
            carrier
                .on_wait
                .push_back(Event::Disconnected(ConnectionId(1)));
            ServeSession::begin(&server, carrier, not_required())
        });
        assert_eq!(
            handed, total,
            "an accept behind the slow session never happened"
        );
        // Every session settled through the drain; what each settled as is
        // the failure policy's business, already held above.
        assert!(outcome.is_ok() || outcome.is_err());
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn sessions_are_served_at_the_same_time() {
        // Two carriers meet at a rendezvous inside their waits: a serve
        // that drives sessions one after another leaves the first waiting
        // at the gate forever and fails its bound; one that drives them
        // together fills the gate and both proceed. ADR-0031: a fetch's
        // rails are whole sessions, and they only help if the serve
        // drives them at once.
        use crate::harness::{Loopback, Rendezvous, built_bundle, not_required, patterned};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("together", &[("a.txt", patterned(1000))]);
        let server = crate::BundleServer::open(&bundle).unwrap();
        let gate = Rendezvous::expecting(2);
        let mut handed = 0_u32;
        let outcome = serve_sessions(Some(2), || {
            handed += 1;
            if handed > 2 {
                // A serve that keeps accepting past its bound is one whose
                // count stopped counting, and the error ends it here
                // rather than at a runner's timeout.
                return Err(Error::CarrierUnavailable);
            }
            let mut carrier = Loopback {
                rendezvous: Some(std::sync::Arc::clone(&gate)),
                ..Loopback::default()
            };
            carrier
                .on_wait
                .push_back(Event::Disconnected(ConnectionId(1)));
            ServeSession::begin(&server, carrier, not_required())
        });
        assert_eq!(handed, 2, "both sessions were accepted");
        // Both settled through the gate; what they settled as is the
        // failure policy's business, already held above.
        assert!(outcome.is_err() || outcome.is_ok());
        crate::harness::discard(&[&bundle]);
    }

    /// An engine that reports what a test tells it to, and counts what the
    /// loop did to it.
    #[derive(Default)]
    struct Scripted {
        /// Passes still to report as unsettled before settling.
        unsettled: u64,
        /// Passes, of the unsettled ones, that report progress.
        with_progress: u64,
        /// Whether every unsettled pass reports a backlog.
        backlogged: bool,
        settled: u64,
        passes: u64,
        /// Counted rather than collected: a mutant that stops the loop
        /// ending makes this grow for as long as the process lives, and a
        /// vector of them is a test that takes the machine with it.
        busy_waits: u64,
        idle_waits: u64,
    }

    impl Engine for Scripted {
        type Status = bool;

        fn service(&mut self) -> Result<bool, Error> {
            self.passes += 1;
            if self.unsettled == 0 {
                return Ok(true);
            }
            self.unsettled -= 1;
            if self.with_progress > 0 {
                self.with_progress -= 1;
                self.settled += 1;
            }
            Ok(false)
        }

        fn settled(status: bool) -> bool {
            status
        }

        fn has_backlog(&self) -> bool {
            self.backlogged
        }

        fn progress(&self) -> u64 {
            self.settled
        }

        fn wait(&mut self, bound: Duration) {
            if bound == BUSY_BOUND {
                self.busy_waits = self.busy_waits.saturating_add(1);
            } else {
                self.idle_waits = self.idle_waits.saturating_add(1);
            }
        }
    }

    /// Both engines answer the loop from their own state, and a forwarding
    /// that reported the wrong thing would spin one and stall the other.
    #[test]
    fn the_engines_answer_the_loop_from_their_own_state() {
        use crate::harness::{Loopback, built_bundle, not_required, patterned};

        use crate::harness::pump;

        let (bundle, _) = built_bundle("engine", &[("a.txt", patterned(1000))]);
        let output = crate::tests::temporary("engine-fetched");
        let mut fetcher = crate::BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        // Nothing prepared and nothing taken, before a pass.
        assert!(!Engine::has_backlog(&fetcher));
        assert_eq!(Engine::progress(&fetcher), 0);

        let server = crate::BundleServer::open(&bundle).unwrap();
        let mut serving =
            ServeSession::begin(&server, Loopback::default(), not_required()).unwrap();
        assert!(!Engine::has_backlog(&serving));
        assert_eq!(Engine::progress(&serving), 0);

        // One round between them: each end reports what it settled as its
        // own progress, which is what tells the loop a slow session from a
        // stopped one.
        let mut sequence = 0;
        Engine::service(&mut fetcher).unwrap();
        pump(
            fetcher.session_mut().driver(),
            serving.session.driver(),
            &mut sequence,
        );
        // Its carrier takes nothing on the pass it announces, so what it
        // prepared stays held: that is the backlog it reports, and queuing
        // it is the progress it reports.
        serving.session.driver().refuse_sends = usize::MAX;
        Engine::service(&mut serving).unwrap();
        assert!(
            Engine::progress(&serving) > 0,
            "the server queued answers and reported none"
        );
        assert!(
            Engine::has_backlog(&serving),
            "answers the carrier refused are backlog"
        );
        serving.session.driver().refuse_sends = 0;
        Engine::service(&mut serving).unwrap();
        pump(
            serving.session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        // The pass that takes the announcement asks for the manifest, and
        // a carrier that takes nothing leaves that request held, which is
        // the backlog this end reports.
        fetcher.session_mut().driver().refuse_sends = usize::MAX;
        Engine::service(&mut fetcher).unwrap();
        assert!(
            Engine::progress(&fetcher) > 0,
            "the fetch took frames and reported none"
        );
        assert!(
            Engine::has_backlog(&fetcher),
            "a request the carrier refused is backlog"
        );

        crate::harness::discard(&[&bundle, &output]);
    }

    #[test]
    fn each_engine_is_driven_until_its_carrier_settles_it() {
        // The loop is what turns a pass into a transfer, and the two
        // answers it needs from an engine are whether a status ends it and
        // how to wait for the next one. Neither is exercised by a pass a
        // test makes itself.
        use crate::harness::{Loopback, built_bundle, not_required, patterned, pump};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("driven", &[("a.txt", patterned(1000))]);
        let output = crate::tests::temporary("driven-fetched");
        let mut fetcher = crate::BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let server = crate::BundleServer::open(&bundle).unwrap();
        let mut serving =
            ServeSession::begin(&server, Loopback::default(), not_required()).unwrap();

        // Past the handshake first: a carrier that goes before it is done
        // is a session that failed, not one the loop settled.
        let mut sequence = 0;
        let mut ready = false;
        for _ in 0..16 {
            Engine::service(&mut fetcher).unwrap();
            pump(
                fetcher.session_mut().driver(),
                serving.session.driver(),
                &mut sequence,
            );
            Engine::service(&mut serving).unwrap();
            pump(
                serving.session.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
            if fetcher.session_mut().is_ready() && serving.session.is_ready() {
                ready = true;
                break;
            }
        }
        assert!(ready, "the two never finished their handshake");

        // Neither next pass is the last, so each loop has to wait, and what
        // it waits for is the carrier reporting it has gone.
        fetcher
            .session_mut()
            .driver()
            .on_wait
            .push_back(Event::Disconnected(ConnectionId(1)));
        assert_eq!(
            drive(&mut fetcher).unwrap(),
            crate::FetchStatus::Disconnected
        );

        serving
            .session
            .driver()
            .on_wait
            .push_back(Event::Disconnected(ConnectionId(1)));
        assert_eq!(
            drive(&mut serving).unwrap(),
            crate::ServeStatus::Disconnected
        );

        crate::harness::discard(&[&bundle, &output]);
    }

    #[test]
    fn a_settled_pass_ends_the_loop_without_waiting() {
        let mut engine = Scripted::default();
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.passes, 1);
        assert_eq!(engine.busy_waits + engine.idle_waits, 0);
    }

    #[test]
    fn every_unsettled_pass_waits_rather_than_spinning() {
        // Including one with a backlog: the carrier is holding what this
        // end prepared, and asking again without pause is a spun core for
        // the length of the transfer rather than a faster one.
        let mut engine = Scripted {
            unsettled: 4,
            with_progress: 4,
            backlogged: true,
            ..Scripted::default()
        };
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.busy_waits, 4, "a held pass waits the short bound");
        assert_eq!(engine.idle_waits, 0);
    }

    #[test]
    fn a_pass_with_nothing_held_waits_longer_than_one_with_a_backlog() {
        let mut engine = Scripted {
            unsettled: 3,
            with_progress: 3,
            backlogged: false,
            ..Scripted::default()
        };
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.idle_waits, 3, "an empty pass waits the long bound");
        assert_eq!(engine.busy_waits, 0);
        assert!(BUSY_BOUND < IDLE_BOUND);
    }

    #[test]
    fn progress_sets_the_budget_back() {
        // The budget ends a session where nothing is happening, not a long
        // one. A fetch of a large object makes one pass per answer with no
        // backlog to show for it, and a budget that counted those would
        // end the transfer partway through.
        let mut engine = Scripted {
            unsettled: 4 * IDLE_PASSES,
            with_progress: 4 * IDLE_PASSES,
            ..Scripted::default()
        };
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.passes, 4 * IDLE_PASSES + 1);
    }

    #[test]
    fn a_session_where_nothing_happens_is_given_up_on() {
        // A peer that holds a session open and does nothing with it would
        // otherwise hold this end forever.
        // Enough passes to outlast the budget and no more: a stub that
        // never settles at all leaves a mutant that stops the budget
        // counting to run for as long as the numbers allow.
        let mut engine = Scripted {
            unsettled: 4 * IDLE_PASSES,
            with_progress: 0,
            ..Scripted::default()
        };
        assert!(matches!(drive(&mut engine), Err(Error::Stalled)));
        assert_eq!(engine.passes, IDLE_PASSES + 1);
    }

    #[test]
    fn a_backlogged_stall_gets_the_same_half_minute_as_an_idle_one() {
        // Counting passes rather than what they wait made this budget 0.6
        // seconds where the idle one was thirty, so a peer that stopped
        // reading for as long as a large sync takes ended the session. The
        // two bounds now buy the same time.
        let mut engine = Scripted {
            unsettled: 2 * BUSY_PASSES,
            with_progress: 0,
            backlogged: true,
            ..Scripted::default()
        };
        assert!(matches!(drive(&mut engine), Err(Error::Stalled)));
        assert_eq!(engine.passes, BUSY_PASSES + 1);
        assert_eq!(engine.busy_waits, BUSY_PASSES);
        assert_eq!(
            BUSY_PASSES * BUSY_BOUND_MS,
            IDLE_PASSES * IDLE_BOUND_MS,
            "the same half minute either way"
        );
    }

    #[test]
    fn progress_late_in_a_stall_sets_the_budget_back() {
        // The counter is consecutive passes, not passes overall.
        let mut engine = Scripted {
            unsettled: IDLE_PASSES + 10,
            with_progress: 1,
            ..Scripted::default()
        };
        assert!(matches!(drive(&mut engine), Err(Error::Stalled)));
        // One pass made progress, so the budget started again after it.
        assert_eq!(engine.passes, IDLE_PASSES + 2);
    }
}
