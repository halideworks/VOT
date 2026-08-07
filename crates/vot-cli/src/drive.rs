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
    let mut stalled_ms: u64 = 0;
    let mut settled_so_far = engine.progress();
    loop {
        let status = engine.service()?;
        if E::settled(status) {
            return Ok(status);
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

/// Serves sessions from `next` until it fails, or `sessions` are answered.
///
/// A client that connects and goes away leaves its session stalling or
/// failing, and a server told to answer everyone should outlive any one of
/// them: with no session bound, a session's failure ends the session and
/// never the loop. A bounded serve surfaces it instead, because its caller
/// asked for exactly those sessions and deserves to hear one was not
/// served. What ends an unbounded serve is only `next` itself failing,
/// which is the endpoint rather than a peer.
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
    A: TransportAdapter,
    F: FnMut() -> Result<ServeSession<'server, A>, Error>,
{
    let mut answered = 0;
    while sessions.is_none_or(|bound| answered < bound) {
        let mut session = next()?;
        match drive(&mut session) {
            Ok(_) => {}
            Err(error) => {
                if sessions.is_some() {
                    return Err(error);
                }
                eprintln!("session ended: {error:?}");
            }
        }
        answered += 1;
    }
    Ok(())
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
        assert_eq!(sessions, 3, "the stalled session was survived");

        // Told to answer exactly these sessions, the same failure surfaces:
        // the caller asked for them and deserves to hear one was not served.
        let mut bounded = 0_u32;
        let outcome = serve_sessions(Some(2), || {
            bounded += 1;
            ServeSession::begin(&server, Loopback::default(), not_required())
        });
        assert!(matches!(outcome, Err(Error::Stalled)));
        assert_eq!(bounded, 1, "a bounded serve stops at the failure");

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
