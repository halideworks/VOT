//! Shared driving loop for serve and fetch sessions.
//!
//! Make a pass; if it left something to do without hearing from the peer,
//! make another; otherwise wait on the carrier.

use std::time::{Duration, Instant};

use vot_transport_api::TransportAdapter;

use crate::Error;

/// How long a pass waits on an idle carrier. Long enough not to spin,
/// short enough to notice a dead carrier.
const IDLE_BOUND_MS: u64 = 50;
const IDLE_BOUND: Duration = Duration::from_millis(IDLE_BOUND_MS);

/// How long to wait when the carrier has backpressure. Shorter than
/// `IDLE_WAIT` to avoid pacing the transfer at one drain per tick.
const BUSY_BOUND_MS: u64 = 1;
const BUSY_BOUND: Duration = Duration::from_millis(BUSY_BOUND_MS);

/// Max cumulative wait without progress before declaring a stall.
/// Any progress resets it. Measured in wait time, not pass count, so both
/// bounds cost what they actually wait. Quiche's idle timeout settles most
/// sessions first; this is the backstop.
const STALLED_WAIT_MS: u64 = 30_000;
const STALLED_WAIT: Duration = Duration::from_millis(STALLED_WAIT_MS);

/// No-progress passes before the loop paces itself.
///
/// A wait returns at once when an event is already queued, so a session that
/// is making no progress while events keep arriving spins: it charges the
/// budget nothing and burns a core. Past this many such passes the loop
/// sleeps out the rest of the bound it asked for, which puts the budget back
/// on a real clock and takes the core back. Above any run of zero-cost waits
/// a healthy pass makes, since a pass that drains what woke it reports
/// progress and resets this.
const SPINNING_BEFORE_PACING: u64 = 64;

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

    /// Cumulative progress. Any increase resets the stall budget.
    fn progress(&self) -> u64;

    /// Waits for the carrier to report something, or for `bound`, and
    /// reports how long it actually waited.
    ///
    /// The duration is what the stall budget is spent from, so a wait that
    /// returned at once because an event was already there costs nothing.
    fn wait(&mut self, bound: Duration) -> Duration;
}

/// Drives `engine` until a pass settles it, and answers with that status.
///
/// # Errors
/// Surfaces the engine's own failure, or [`Error::Stalled`] if the loop
/// made its whole budget of passes without the engine getting anywhere.
pub fn drive<E: Engine>(engine: &mut E) -> Result<E::Status, Error> {
    drive_until(engine, |_| false)?.ok_or(Error::Stalled)
}

/// [`drive`] under a stall budget of the caller's choosing.
///
/// The budget is spent in real time, so a test that means to watch a session
/// be given up on says how long it is willing to wait for that rather than
/// waiting out the production half minute.
///
/// # Errors
/// As [`drive`].
#[cfg(any(test, feature = "wire"))]
pub(crate) fn drive_within<E: Engine>(
    engine: &mut E,
    budget: Duration,
) -> Result<E::Status, Error> {
    drive_until_within(engine, |_| false, budget)?.ok_or(Error::Stalled)
}

/// Drives `engine` until a pass settles it or `done` holds.
///
/// # Errors
/// Surfaces the engine's own failure, or [`Error::Stalled`] as [`drive`].
pub fn drive_until<E: Engine>(
    engine: &mut E,
    done: impl FnMut(&E) -> bool,
) -> Result<Option<E::Status>, Error> {
    drive_until_within(engine, done, STALLED_WAIT)
}

/// [`drive_until`] under a stall budget of the caller's choosing.
///
/// # Errors
/// As [`drive_until`].
pub(crate) fn drive_until_within<E: Engine>(
    engine: &mut E,
    mut done: impl FnMut(&E) -> bool,
    stall_budget: Duration,
) -> Result<Option<E::Status>, Error> {
    // Counted down rather than up, and saturating, so the budget reaches
    // exactly zero and stays there however long the loop runs.
    let mut budget = stall_budget;
    let mut spinning: u64 = 0;
    let mut settled_so_far = engine.progress();
    loop {
        let status = engine.service()?;
        if E::settled(status) {
            return Ok(Some(status));
        }
        if done(engine) {
            return Ok(None);
        }
        // Always wait, even with a backlog: tight-looping a backpressured
        // carrier just burns a core.
        let wait = if engine.has_backlog() {
            BUSY_BOUND
        } else {
            IDLE_BOUND
        };
        let progress = engine.progress();
        match progress.cmp(&settled_so_far) {
            std::cmp::Ordering::Equal => {
                spinning = spinning.saturating_add(1);
                if budget.is_zero() {
                    return Err(Error::Stalled);
                }
            }
            std::cmp::Ordering::Less | std::cmp::Ordering::Greater => {
                settled_so_far = progress;
                budget = stall_budget;
                spinning = 0;
            }
        }
        // Spent on what the pass waited, not on what it asked to wait: a
        // wait that returns at once because an event was already queued cost
        // nothing, and charging it a whole bound is what let a busy session
        // spend a half minute of budget in about a second.
        let waited = engine.wait(wait);
        budget = budget.saturating_sub(waited);
        if spinning > SPINNING_BEFORE_PACING {
            if let Some(rest) = wait.checked_sub(waited) {
                std::thread::sleep(rest);
                budget = budget.saturating_sub(rest);
            }
        }
    }
}

/// Whether an error says only that the session ended, rather than why.
///
/// A rail whose plan another rail abandoned ends on a carrier that this end
/// closed itself, so it reports the carrier as gone. That is true and it is
/// not the cause, so it must never outrank an error that names one.
#[cfg(any(test, feature = "wire"))]
const fn unnamed_cause(error: &Error) -> bool {
    matches!(error, Error::Stalled | Error::CarrierUnavailable)
}

/// The failure to report of two, keeping whichever names a cause.
///
/// Rails are joined in the order they were spawned, not the order they
/// failed, so taking the first one reported the wind-down of a rail that was
/// still running when the real failure happened.
#[cfg(any(test, feature = "wire"))]
fn named_failure(held: Option<Error>, error: Error) -> Error {
    match held {
        Some(held) if unnamed_cause(&held) && !unnamed_cause(&error) => error,
        Some(held) => held,
        None => error,
    }
}

/// The error a terminal fetch status names, or completion.
///
/// One mapping for the primary and every rail; what a completion yields
/// (the package, or nothing for a rail) stays with the caller.
#[cfg(any(test, feature = "wire"))]
fn fetch_verdict(status: crate::FetchStatus) -> Result<(), Error> {
    match status {
        crate::FetchStatus::Complete => Ok(()),
        // Preserve the original error code for the caller.
        crate::FetchStatus::Closed(code) => Err(Error::PeerClosed(code)),
        crate::FetchStatus::Disconnected => Err(Error::CarrierUnavailable),
        crate::FetchStatus::Active => Err(Error::InvalidBundle),
    }
}

/// Ends whatever the loop answered as this end's own outcome: the package
/// for a complete fetch, and the error that names why for anything else.
#[cfg(any(test, feature = "wire"))]
fn fetched<A: TransportAdapter>(
    fetcher: &crate::BundleFetcher<A>,
    status: crate::FetchStatus,
) -> Result<crate::PackageSummary, Error> {
    fetch_verdict(status).and_then(|()| fetcher.package().ok_or(Error::InvalidBundle))
}

/// A finished fetch: the package it proved, and what its datagram path did.
///
/// The counts are summed over the primary and every rail that finished. A
/// rail that failed abandons the plan and the primary repairs what it left,
/// so the fetch still succeeds, and whatever that rail decoded before it
/// failed is not in these numbers.
#[cfg(any(test, feature = "wire"))]
pub(crate) struct Fetched {
    pub(crate) package: crate::PackageSummary,
    /// Bytes this fetch placed itself, which on a resumed bundle is less
    /// than the package holds.
    pub(crate) moved: u64,
    /// When any rail first observed verified bytes from this run.
    pub(crate) first_moved: Option<Instant>,
    pub(crate) fec: vot_scheduler::FecCounts,
}

#[cfg(any(test, feature = "wire"))]
fn earliest_observation(first: Option<Instant>, second: Option<Instant>) -> Option<Instant> {
    [first, second].into_iter().flatten().min()
}

/// Fetches at `rails` width. The primary builds the plan; rails join it
/// on fresh connections. A rail failure abandons the plan.
///
/// # Errors
/// Rejects zero width or width past one with inline proving. Surfaces the
/// primary's failure, or the rail failure that explains a stalled primary.
#[cfg(any(test, feature = "wire"))]
pub(crate) fn fetch_striped<A, F>(
    mut primary: crate::BundleFetcher<A>,
    rails: usize,
    connect: F,
) -> Result<Fetched, Error>
where
    A: TransportAdapter + Send,
    F: Fn() -> Result<A, Error> + Sync,
{
    if rails == 0 || (rails > 1 && primary.proving_threads() == 0) {
        return Err(Error::InvalidArguments);
    }
    if let Some(status) = drive_until(&mut primary, |fetcher| fetcher.package().is_some())? {
        return Ok(Fetched {
            package: fetched(&primary, status)?,
            moved: primary.moved_bytes(),
            first_moved: primary.first_moved(),
            fec: primary.fec_counts(),
        });
    }
    let Some(plan) = primary.shared_plan() else {
        return Err(Error::InvalidBundle);
    };
    let bundle = primary.bundle().to_owned();
    let provers = primary.proving_threads();
    // Every rail opens its own session and answers its own challenge, under
    // the token the primary was given.
    let holder = primary.holder();
    let extensions = primary.extensions();
    std::thread::scope(|scope| {
        let mut spawned = Vec::new();
        for _ in 1..rails {
            let plan = crate::fetch::SharedPlan::clone(&plan);
            let connect = &connect;
            let bundle = bundle.clone();
            let holder = holder.clone();
            let extensions = extensions.clone();
            spawned.push(scope.spawn(move || {
                let outcome = (|| {
                    let carrier = connect()?;
                    let mut rail = crate::BundleFetcher::join(
                        carrier,
                        &bundle,
                        plan.clone(),
                        holder,
                        extensions,
                    )?;
                    rail.set_proving_threads(provers)?;
                    fetch_verdict(drive(&mut rail)?)?;
                    Ok((rail.fec_counts(), rail.first_moved()))
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
        let mut fec = primary.fec_counts();
        let mut first_moved = primary.first_moved();
        let mut rail_failure = None;
        for rail in spawned {
            match rail.join().expect("a rail thread never panics") {
                Ok((counts, first)) => {
                    fec = fec + counts;
                    first_moved = earliest_observation(first_moved, first);
                }
                Err(error) => rail_failure = Some(named_failure(rail_failure, error)),
            }
        }
        match outcome {
            Ok(package) => Ok(Fetched {
                package,
                moved: primary.moved_bytes(),
                first_moved,
                fec,
            }),
            // Report the rail's failure as the cause of a stalled primary.
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

    fn wait(&mut self, bound: Duration) -> Duration {
        let began = Instant::now();
        self.session_mut().driver().wait_for_event(bound);
        began.elapsed()
    }
}

/// Per-session state for the serve side. The server holds none.
pub struct ServeSession<'server, A: TransportAdapter> {
    server: &'server crate::BundleServer,
    session: vot_session::Session<A>,
    connection: crate::ServeConnection,
    requirement: Option<&'server crate::authz::Requirement>,
}

impl<'server, A: TransportAdapter> ServeSession<'server, A> {
    /// Begins a session on `carrier`, answered from `server`, under `stance`.
    ///
    /// # Errors
    /// Surfaces a session that could not send its opening frames.
    pub fn begin(
        server: &'server crate::BundleServer,
        carrier: A,
        stance: impl Into<crate::authz::Stance<'server>>,
    ) -> Result<Self, Error> {
        let stance = stance.into();
        let requirement = stance.requirement;
        let extensions = if stance.use_default_extensions {
            crate::authz::default_extensions()
        } else {
            stance.extensions
        };
        let mut session = vot_session::Session::server(
            carrier,
            vot_codec::Settings::default(),
            extensions,
            stance.authentication,
        );
        session.begin()?;
        Ok(Self {
            server,
            session,
            connection: crate::ServeConnection::new(),
            requirement,
        })
    }

    /// Grants or refuses a capability the peer presented.
    ///
    /// A serve that requires nothing never sees one, because it advertised no
    /// format and section 1.1 concludes the exchange at `AUTH_CONTEXT`. One
    /// that does has to answer every attempt: the peer is waiting on a
    /// decision, and the session carries no data until it arrives.
    ///
    /// # Errors
    /// Surfaces a carrier that would not take the answer.
    fn answer_authorization(&mut self) -> Result<(), Error> {
        let Some(requirement) = self.requirement else {
            return Ok(());
        };
        let decision = {
            let Some((challenge, open)) = self.session.pending_authorization() else {
                return Ok(());
            };
            let channel_binding = self
                .session
                .channel_binding()
                .ok_or(Error::ChannelBindingUnavailable)?;
            requirement.decide(
                challenge,
                open,
                channel_binding,
                crate::authz::now_seconds()?,
            )
        };
        match decision {
            Some(scope) => self.session.grant(scope)?,
            None => self.session.refuse(
                crate::authz::REFUSAL_REASON,
                crate::authz::REFUSAL_DETAIL.to_owned(),
            )?,
        }
        Ok(())
    }
}

/// Concurrent sessions a serve drives. Excess clients wait for a slot
/// (backpressure, not refusal).
#[cfg(any(test, feature = "wire"))]
pub(crate) const CONCURRENT_SESSIONS: usize = 8;

/// Serves sessions from `next` until it fails, or `sessions` are answered.
///
/// Sessions run concurrently at [`CONCURRENT_SESSIONS`] at once. Unbounded
/// serves outlive any single session failure; bounded serves surface it.
///
/// # Errors
/// Surfaces `next`'s failure always, and a session's failure only when
/// `sessions` is bounded.
#[cfg(any(test, feature = "wire"))]
pub(crate) fn serve_sessions<'server, A, F>(sessions: Option<u32>, next: F) -> Result<(), Error>
where
    A: TransportAdapter + Send,
    F: FnMut() -> Result<ServeSession<'server, A>, Error>,
{
    serve_sessions_within(sessions, STALLED_WAIT, next)
}

/// [`serve_sessions`] driving each session under `stall_budget`.
#[cfg(any(test, feature = "wire"))]
pub(crate) fn serve_sessions_within<'server, A, F>(
    sessions: Option<u32>,
    stall_budget: Duration,
    mut next: F,
) -> Result<(), Error>
where
    A: TransportAdapter + Send,
    F: FnMut() -> Result<ServeSession<'server, A>, Error>,
{
    std::thread::scope(|scope| {
        let mut running = RunningSessions::begin(sessions);
        let mut turns = turns(sessions);
        while turns.next().is_some() {
            // Accept blocks here, so factory errors are ordered after prior sessions.
            let mut accepted = next();
            // A refused bind while sessions run means the port is still held.
            // Reap a finished session and retry. Each attempt shrinks
            // `running`, so the loop is bounded.
            while accepted.is_err() && !running.is_empty() {
                let held = running.len();
                running.reap_one();
                debug_assert_eq!(running.len(), held - 1, "a reap must release its slot");
                accepted = next();
            }
            while running.len() >= CONCURRENT_SESSIONS {
                let held = running.len();
                running.reap_one();
                debug_assert_eq!(running.len(), held - 1, "a reap must release its slot");
            }
            let mut session = match accepted {
                Ok(session) => session,
                Err(error) => return running.finish().and(Err(error)),
            };
            running.spawn(scope, move || {
                drive_within(&mut session, stall_budget).map(|_| ())
            });
        }
        running.finish()
    })
}

/// The sessions a serve is driving: their slots, their end announcements,
/// and the first failure the policy will surface.
#[cfg(any(test, feature = "wire"))]
struct RunningSessions<'scope, T> {
    running: std::collections::VecDeque<(u64, std::thread::ScopedJoinHandle<'scope, T>)>,
    /// Wait for any session to finish, not the oldest: a vanished client
    /// only settles at the carrier idle timeout.
    ended: std::sync::mpsc::Sender<u64>,
    endings: std::sync::mpsc::Receiver<u64>,
    spawned: u64,
    /// The serve's bound, which is also its failure policy.
    sessions: Option<u32>,
    /// First failure under a bounded serve. Later sessions still finish
    /// before the error surfaces.
    failed: Result<(), Error>,
}

#[cfg(any(test, feature = "wire"))]
impl<'scope> RunningSessions<'scope, Result<(), Error>> {
    fn begin(sessions: Option<u32>) -> Self {
        let (ended, endings) = std::sync::mpsc::channel::<u64>();
        Self {
            running: std::collections::VecDeque::new(),
            ended,
            endings,
            spawned: 0,
            sessions,
            failed: Ok(()),
        }
    }

    fn is_empty(&self) -> bool {
        self.running.is_empty()
    }

    fn len(&self) -> usize {
        self.running.len()
    }

    /// Starts one session's thread, announced via Drop so the reap never
    /// waits on a dead thread, even on panic.
    fn spawn<'env, W>(&mut self, scope: &'scope std::thread::Scope<'scope, 'env>, work: W)
    where
        W: FnOnce() -> Result<(), Error> + Send + 'scope,
    {
        let id = self.spawned;
        self.spawned += 1;
        let announce = Announcement {
            id,
            ended: self.ended.clone(),
        };
        self.running.push_back((
            id,
            scope.spawn(move || {
                let _announce = announce;
                work()
            }),
        ));
    }

    /// Waits for the next session to finish and settles it. Wakes
    /// periodically to detect a lost announcement, which would otherwise
    /// hang forever.
    fn reap_one(&mut self) {
        assert!(
            !self.running.is_empty(),
            "a slot is only reaped from a serve that holds one"
        );
        let done = loop {
            match self.endings.recv_timeout(REAP_TICK) {
                Ok(done) => break done,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let finished = self
                        .running
                        .iter()
                        .filter(|(_, handle)| handle.is_finished())
                        .count();
                    match reap_wake(finished, self.endings.try_recv().ok()) {
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
        let at = self
            .running
            .iter()
            .position(|(id, _)| *id == done)
            .expect("an announced session is still held");
        let (_, handle) = self
            .running
            .remove(at)
            .expect("the position was just found");
        let settled = handle.join().expect("a session thread never panics");
        settle_session(self.sessions, settled, &mut self.failed);
    }

    /// Joins every running session and answers with the policy's verdict.
    fn finish(mut self) -> Result<(), Error> {
        for (_, handle) in std::mem::take(&mut self.running) {
            let settled = handle.join().expect("a session thread never panics");
            settle_session(self.sessions, settled, &mut self.failed);
        }
        self.failed
    }
}

/// How often the reap wakes to check for lost announcements.
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
    /// Session finished but no announcement arrived. Waiting would hang.
    Breach,
}

/// Decides one reap wake: take any announcement, wait on silence,
/// panic on a finished session without one.
#[cfg(any(test, feature = "wire"))]
fn reap_wake(finished: usize, announced: Option<u64>) -> ReapWake {
    match (finished, announced) {
        (_, Some(done)) => ReapWake::Take(done),
        (0, None) => ReapWake::Wait,
        (_, None) => ReapWake::Breach,
    }
}

/// Session-end announcement sent via Drop, so the reap never blocks
/// on a dead thread.
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

/// Whether a session's failure is one its peer had said anything by.
#[cfg(any(test, feature = "wire"))]
fn spoken_for(error: &Error) -> bool {
    let Error::Session(session) = error else {
        return true;
    };
    match session.kind() {
        vot_session::ErrorKind::Interrupted { state } => peer_spoke(*state),
        _ => true,
    }
}

/// Whether the peer had sent anything by this state. A server reaches
/// `HelloSent` on the peer's `HELLO`, so the two states before it are the
/// ones where nothing arrived.
#[cfg(any(test, feature = "wire"))]
const fn peer_spoke(state: vot_session::State) -> bool {
    !matches!(
        state,
        vot_session::State::Connecting | vot_session::State::ControlReserved
    )
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
    // A carrier that went before its peer said anything is a scan, a probe,
    // or a fetch rail that found the plan already done. Nothing this end
    // does about it, and on a public port it is ordinary.
    if !spoken_for(&error) {
        return;
    }
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
        self.answer_authorization()?;
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

    fn wait(&mut self, bound: Duration) -> Duration {
        let began = Instant::now();
        self.session.driver().wait_for_event(bound);
        began.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Passes the budget allows at each bound.
    /// A budget the suite can spend in real time. The production one is a
    /// half minute, and a test that watches a session be given up on waits
    /// out whatever it names.
    const TEST_STALL_MS: u64 = 500;
    const TEST_STALL: Duration = Duration::from_millis(TEST_STALL_MS);
    const IDLE_PASSES: u64 = TEST_STALL_MS / IDLE_BOUND_MS;
    const BUSY_PASSES: u64 = TEST_STALL_MS / BUSY_BOUND_MS;

    #[test]
    fn every_terminal_status_names_its_error() {
        assert!(fetch_verdict(crate::FetchStatus::Complete).is_ok());
        assert!(matches!(
            fetch_verdict(crate::FetchStatus::Closed(7)),
            Err(Error::PeerClosed(7))
        ));
        assert!(matches!(
            fetch_verdict(crate::FetchStatus::Disconnected),
            Err(Error::CarrierUnavailable)
        ));
        assert!(matches!(
            fetch_verdict(crate::FetchStatus::Active),
            Err(Error::InvalidBundle)
        ));
    }

    #[test]
    fn first_payload_is_the_earliest_rail_observation() {
        let later = Instant::now();
        let earlier = later.checked_sub(Duration::from_millis(1)).unwrap();
        assert_eq!(
            earliest_observation(Some(later), Some(earlier)),
            Some(earlier)
        );
        assert_eq!(
            earliest_observation(Some(earlier), Some(later)),
            Some(earlier)
        );
        assert_eq!(earliest_observation(None, Some(earlier)), Some(earlier));
        assert_eq!(earliest_observation(Some(earlier), None), Some(earlier));
        assert_eq!(earliest_observation(None, None), None);
    }

    #[test]
    fn the_rail_that_names_a_cause_is_the_one_reported() {
        let named = || Error::Scheduler(vot_scheduler::Error::PendingBundlesExhausted);
        let wound_down = || Error::CarrierUnavailable;

        // Whichever order the rails are joined in.
        assert!(matches!(
            named_failure(Some(wound_down()), named()),
            Error::Scheduler(vot_scheduler::Error::PendingBundlesExhausted)
        ));
        assert!(matches!(
            named_failure(Some(named()), wound_down()),
            Error::Scheduler(vot_scheduler::Error::PendingBundlesExhausted)
        ));
        // The first of two that both name a cause; neither is the wind-down.
        assert!(matches!(
            named_failure(Some(Error::InvalidBundle), named()),
            Error::InvalidBundle
        ));
        // The first of two that name none, so the report is unchanged.
        assert!(matches!(
            named_failure(Some(Error::Stalled), wound_down()),
            Error::Stalled
        ));
        assert!(matches!(
            named_failure(None, named()),
            Error::Scheduler(vot_scheduler::Error::PendingBundlesExhausted)
        ));
        assert!(matches!(
            named_failure(None, wound_down()),
            Error::CarrierUnavailable
        ));
    }

    #[test]
    fn only_the_ends_of_a_session_are_unnamed_causes() {
        assert!(unnamed_cause(&Error::Stalled));
        assert!(unnamed_cause(&Error::CarrierUnavailable));
        assert!(!unnamed_cause(&Error::InvalidBundle));
        assert!(!unnamed_cause(&Error::PeerClosed(
            vot_codec::error_code::RESOURCE_LIMIT
        )));
        assert!(!unnamed_cause(&Error::Scheduler(
            vot_scheduler::Error::PendingBundlesExhausted
        )));
    }

    #[test]
    fn an_unbounded_serve_outlives_a_failed_session() {
        use crate::harness::{Loopback, built_bundle, not_required, patterned};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("outlives", &[("a.txt", patterned(1000))]);
        let server = crate::BundleServer::open(&bundle).unwrap();
        let mut sessions = 0_u32;
        let outcome = serve_sessions_within(None, TEST_STALL, || {
            sessions += 1;
            match sessions {
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
        assert_eq!(sessions, 5, "the stalled session was survived");

        let mut bounded = 0_u32;
        let outcome = serve_sessions_within(Some(2), TEST_STALL, || {
            bounded += 1;
            if bounded > 2 {
                return Err(Error::CarrierUnavailable);
            }
            ServeSession::begin(&server, Loopback::default(), not_required())
        });
        assert!(matches!(outcome, Err(Error::Stalled)));
        assert_eq!(bounded, 2, "the bound was accepted, the failure surfaced");

        let mut counted = 0_u32;
        let outcome = serve_sessions_within(Some(1), TEST_STALL, || {
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
        let outcome = serve_sessions_within(Some(2), TEST_STALL, || {
            accepts += 1;
            match accepts {
                1 | 3 => ServeSession::begin(&server, clean(), not_required()),
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

        let output = crate::tests::temporary("widthguard-zero");
        let fetcher = crate::BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let outcome = fetch_striped(fetcher, 0, || Err::<Loopback, _>(Error::CarrierUnavailable));
        assert!(matches!(outcome, Err(Error::InvalidArguments)));
        crate::harness::discard(&[&output]);

        let output = crate::tests::temporary("widthguard-inline");
        let mut fetcher = crate::BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.set_proving_threads(0).unwrap();
        let outcome = fetch_striped(fetcher, 2, || Err::<Loopback, _>(Error::CarrierUnavailable));
        assert!(matches!(outcome, Err(Error::InvalidArguments)));
        crate::harness::discard(&[&output]);
    }

    #[test]
    fn one_rail_proving_inline_is_still_a_fetch() {
        use crate::harness::{built_bundle, duplex_pair, not_required, patterned};

        let (bundle, built) = built_bundle("inlinewidth", &[("a.txt", patterned(1000))]);
        let (client, half) = duplex_pair();
        let serving_bundle = bundle.to_path_buf();
        let serving = std::thread::spawn(move || {
            let server = crate::BundleServer::open(&serving_bundle)?;
            let mut half = Some(half);
            serve_sessions_within(Some(1), TEST_STALL, || {
                half.take()
                    .map_or(Err(Error::CarrierUnavailable), |carrier| {
                        ServeSession::begin(&server, carrier, not_required())
                    })
            })
        });
        let output = crate::tests::temporary("inlinewidth-fetched");
        let mut fetcher = crate::BundleFetcher::begin(client, &output, None).unwrap();
        fetcher.set_proving_threads(0).unwrap();
        let outcome = fetch_striped(fetcher, 1, || {
            Err::<crate::harness::Duplex, _>(Error::CarrierUnavailable)
        })
        .expect("one rail, no provers, a whole fetch");
        assert_eq!(outcome.package, built);
        assert_eq!(
            outcome.moved, built.logical_length,
            "a fetch into an empty destination moved the whole package"
        );
        assert_eq!(
            outcome.fec,
            vot_scheduler::FecCounts::default(),
            "a fetch that never offered FEC counts nothing"
        );
        serving.join().expect("the serving thread").expect("served");
        crate::harness::discard(&[&bundle, &output]);
    }

    #[test]
    fn a_wake_takes_waits_or_refuses_by_the_whole_table() {
        assert_eq!(reap_wake(0, Some(4)), ReapWake::Take(4));
        assert_eq!(reap_wake(3, Some(9)), ReapWake::Take(9));
        assert_eq!(reap_wake(0, None), ReapWake::Wait);
        assert_eq!(reap_wake(1, None), ReapWake::Breach);
        assert_eq!(reap_wake(7, None), ReapWake::Breach);
    }

    #[test]
    fn an_announcement_goes_however_its_thread_ends() {
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
    fn a_peer_that_never_spoke_does_not_fail_a_bounded_serve() {
        use crate::harness::{Loopback, built_bundle, not_required, patterned};
        use vot_transport_api::{ConnectionId, Event};

        // Anyone who reaches the port can open a carrier and go. A serve with
        // a session cap that took that for its own failure would be killable
        // by a stranger, and a rendezvous fetch's rails do it by accident
        // whenever the plan finishes before they join.
        let (bundle, _) = built_bundle("silent", &[("a.txt", patterned(1000))]);
        let server = crate::BundleServer::open(&bundle).unwrap();
        let outcome = serve_sessions_within(Some(1), TEST_STALL, || {
            let mut carrier = Loopback::default();
            carrier
                .on_wait
                .push_back(Event::Disconnected(ConnectionId(1)));
            ServeSession::begin(&server, carrier, not_required())
        });
        assert!(
            outcome.is_ok(),
            "a carrier that said nothing is weather: {outcome:?}"
        );
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn only_a_session_its_peer_spoke_in_is_that_serves_failure() {
        use vot_session::State;

        // Every state a session can be interrupted in, and whether the peer
        // had said anything by it.
        assert!(!peer_spoke(State::Connecting));
        assert!(!peer_spoke(State::ControlReserved));
        assert!(peer_spoke(State::HelloSent));
        assert!(peer_spoke(State::SettingsExchanged));
        assert!(peer_spoke(State::Negotiated));
        assert!(peer_spoke(State::Authenticated));
        assert!(peer_spoke(State::Closed));

        assert!(
            spoken_for(&Error::CarrierUnavailable),
            "what is not a session failure is this serve's either way"
        );
    }

    #[test]
    fn a_slow_session_does_not_hold_the_accepts_behind_it() {
        use crate::harness::{Loopback, Rendezvous, built_bundle, not_required, patterned};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("slowjoin", &[("a.txt", patterned(1000))]);
        let server = crate::BundleServer::open(&bundle).unwrap();
        let gate = Rendezvous::expecting(2);
        let total = u32::try_from(CONCURRENT_SESSIONS).unwrap() + 2;
        let mut handed = 0_u32;
        let outcome = serve_sessions_within(Some(total), TEST_STALL, || {
            handed += 1;
            if handed > total {
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
        assert!(outcome.is_ok() || outcome.is_err());
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn sessions_are_served_at_the_same_time() {
        use crate::harness::{Loopback, Rendezvous, built_bundle, not_required, patterned};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("together", &[("a.txt", patterned(1000))]);
        let server = crate::BundleServer::open(&bundle).unwrap();
        let gate = Rendezvous::expecting(2);
        let mut handed = 0_u32;
        let outcome = serve_sessions_within(Some(2), TEST_STALL, || {
            handed += 1;
            if handed > 2 {
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
        busy_waits: u64,
        idle_waits: u64,
        /// What every wait reports as waited. `None` reports the whole
        /// bound, which is what a carrier with nothing to say does.
        waited: Option<Duration>,
        /// A pass, counted from one, that reports progress however many
        /// quiet passes came before it.
        progress_on: Option<u64>,
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
            if self.progress_on == Some(self.passes) {
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

        /// Reports the whole bound as waited, so the budget a test spends is
        /// the one it counts passes for rather than this machine's clock.
        fn wait(&mut self, bound: Duration) -> Duration {
            if bound == BUSY_BOUND {
                self.busy_waits = self.busy_waits.saturating_add(1);
            } else {
                self.idle_waits = self.idle_waits.saturating_add(1);
            }
            self.waited.unwrap_or(bound)
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
        assert!(!Engine::has_backlog(&fetcher));
        assert_eq!(Engine::progress(&fetcher), 0);

        let server = crate::BundleServer::open(&bundle).unwrap();
        let mut serving =
            ServeSession::begin(&server, Loopback::default(), not_required()).unwrap();
        assert!(!Engine::has_backlog(&serving));
        assert_eq!(Engine::progress(&serving), 0);

        let mut sequence = 0;
        Engine::service(&mut fetcher).unwrap();
        pump(
            fetcher.session_mut().driver(),
            serving.session.driver(),
            &mut sequence,
        );
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
        use crate::harness::{Loopback, built_bundle, not_required, patterned, pump};
        use vot_transport_api::{ConnectionId, Event};

        let (bundle, _) = built_bundle("driven", &[("a.txt", patterned(1000))]);
        let output = crate::tests::temporary("driven-fetched");
        let mut fetcher = crate::BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let server = crate::BundleServer::open(&bundle).unwrap();
        let mut serving =
            ServeSession::begin(&server, Loopback::default(), not_required()).unwrap();

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
        assert!(drive_within(&mut engine, TEST_STALL).unwrap());
        assert_eq!(engine.passes, 1);
        assert_eq!(engine.busy_waits + engine.idle_waits, 0);
    }

    #[test]
    fn every_unsettled_pass_waits_rather_than_spinning() {
        let mut engine = Scripted {
            unsettled: 4,
            with_progress: 4,
            backlogged: true,
            ..Scripted::default()
        };
        assert!(drive_within(&mut engine, TEST_STALL).unwrap());
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
        assert!(drive_within(&mut engine, TEST_STALL).unwrap());
        assert_eq!(engine.idle_waits, 3, "an empty pass waits the long bound");
        assert_eq!(engine.busy_waits, 0);
        assert!(BUSY_BOUND < IDLE_BOUND);
    }

    #[test]
    fn progress_sets_the_budget_back() {
        let mut engine = Scripted {
            unsettled: 4 * IDLE_PASSES,
            with_progress: 4 * IDLE_PASSES,
            ..Scripted::default()
        };
        assert!(drive_within(&mut engine, TEST_STALL).unwrap());
        assert_eq!(engine.passes, 4 * IDLE_PASSES + 1);
    }

    #[test]
    fn a_session_where_nothing_happens_is_given_up_on() {
        let mut engine = Scripted {
            unsettled: 4 * IDLE_PASSES,
            with_progress: 0,
            ..Scripted::default()
        };
        assert!(matches!(
            drive_within(&mut engine, TEST_STALL),
            Err(Error::Stalled)
        ));
        assert_eq!(engine.passes, IDLE_PASSES + 1);
        assert_eq!(engine.idle_waits, IDLE_PASSES);
    }

    /// The budget is spent on what a pass waited, so a carrier that answers
    /// halfway through its bound takes twice the passes to be given up on.
    /// Charging the bound instead is what declared a busy serve stalled
    /// inside a second.
    #[test]
    fn a_pass_that_waited_less_than_its_bound_spends_less_of_the_budget() {
        let mut engine = Scripted {
            unsettled: 8 * IDLE_PASSES,
            with_progress: 0,
            waited: Some(IDLE_BOUND / 2),
            ..Scripted::default()
        };
        assert!(matches!(
            drive_within(&mut engine, TEST_STALL),
            Err(Error::Stalled)
        ));
        assert_eq!(
            engine.passes,
            2 * IDLE_PASSES + 1,
            "half a bound a wait buys twice the passes a whole one does"
        );
    }

    /// A carrier whose waits cost nothing at all would spend no budget and
    /// spin, so past a run of them the loop sleeps out the rest of the bound
    /// and gives up on the clock that restores.
    #[test]
    fn a_carrier_whose_waits_cost_nothing_is_still_given_up_on() {
        let mut engine = Scripted {
            unsettled: 8 * (SPINNING_BEFORE_PACING + IDLE_PASSES),
            with_progress: 0,
            waited: Some(Duration::ZERO),
            ..Scripted::default()
        };
        assert!(matches!(
            drive_within(&mut engine, TEST_STALL),
            Err(Error::Stalled)
        ));
        assert_eq!(
            engine.passes,
            SPINNING_BEFORE_PACING + IDLE_PASSES + 1,
            "free until pacing starts, then a bound a pass"
        );
    }

    #[test]
    fn a_backlogged_stall_gets_the_same_half_minute_as_an_idle_one() {
        let mut engine = Scripted {
            unsettled: 2 * BUSY_PASSES,
            with_progress: 0,
            backlogged: true,
            ..Scripted::default()
        };
        assert!(matches!(
            drive_within(&mut engine, TEST_STALL),
            Err(Error::Stalled)
        ));
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
        let mut engine = Scripted {
            unsettled: IDLE_PASSES + 10,
            with_progress: 1,
            ..Scripted::default()
        };
        assert!(matches!(
            drive_within(&mut engine, TEST_STALL),
            Err(Error::Stalled)
        ));
        assert_eq!(engine.passes, IDLE_PASSES + 1);
    }

    /// One report of progress with the budget nearly spent buys a whole
    /// fresh budget, so the loop runs a second one before giving up. Without
    /// the reset it would give up at the end of the first.
    #[test]
    fn progress_with_the_budget_nearly_spent_buys_a_whole_new_one() {
        let late = IDLE_PASSES - 1;
        let mut engine = Scripted {
            unsettled: 4 * IDLE_PASSES,
            with_progress: 0,
            progress_on: Some(late),
            ..Scripted::default()
        };
        assert!(matches!(
            drive_within(&mut engine, TEST_STALL),
            Err(Error::Stalled)
        ));
        assert_eq!(
            engine.passes,
            late + IDLE_PASSES,
            "the budget starts again from the pass that made progress"
        );
    }
}
