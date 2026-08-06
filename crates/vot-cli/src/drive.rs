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
const IDLE_BOUND: Duration = Duration::from_millis(50);

/// How long a pass waits when the carrier is holding work back.
///
/// A backlog is a frame the carrier would not take, so what this end is
/// waiting for is room to send rather than something to read, and a
/// carrier does not report room as an event. Waiting the idle bound for
/// it would pace a transfer at one drain every fifty milliseconds;
/// waiting not at all would spin a core for the length of the transfer.
const BUSY_BOUND: Duration = Duration::from_millis(1);

/// Passes a driving loop may make without the engine getting anywhere.
///
/// Not a bound on how long a session may take: any progress at all sets
/// it back, so it only ends a session where nothing is happening. Counted
/// in the loop's own body rather than measured against a clock, because a
/// slow machine is not a stuck one.
///
/// At the idle bound this is about half a minute of silence, which is
/// already past where a live carrier gives up on its own: quiche's idle
/// timeout is thirty seconds and reports a disconnect, which settles the
/// loop. So this is the backstop for a carrier with no timeout of its
/// own, and a longer one would only make a wedged session take longer to
/// say so.
const STALLED_PASSES: u32 = 600;

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
    let mut stalled = 0;
    let mut settled_so_far = engine.progress();
    loop {
        let status = engine.service()?;
        if E::settled(status) {
            return Ok(status);
        }
        let progress = engine.progress();
        if progress == settled_so_far {
            stalled += 1;
            if stalled > STALLED_PASSES {
                return Err(Error::Stalled);
            }
        } else {
            settled_so_far = progress;
            stalled = 0;
        }
        // Every pass waits, including one with a backlog: a backlog is the
        // carrier refusing what this end already prepared, so there is
        // nothing to do but let it drain, and doing it in a tight loop is
        // a spun core rather than a faster transfer.
        engine.wait(if engine.has_backlog() {
            BUSY_BOUND
        } else {
            IDLE_BOUND
        });
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

    /// An engine that reports what a test tells it to, and counts what the
    /// loop did to it.
    #[derive(Default)]
    struct Scripted {
        /// Passes still to report as unsettled before settling.
        unsettled: u32,
        /// Passes, of the unsettled ones, that report progress.
        with_progress: u32,
        /// Whether every unsettled pass reports a backlog.
        backlogged: bool,
        settled: u64,
        passes: u32,
        waits: Vec<Duration>,
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
            self.waits.push(bound);
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
    fn a_settled_pass_ends_the_loop_without_waiting() {
        let mut engine = Scripted::default();
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.passes, 1);
        assert!(engine.waits.is_empty());
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
        assert_eq!(engine.waits, vec![BUSY_BOUND; 4]);
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
        assert_eq!(engine.waits, vec![IDLE_BOUND; 3]);
        assert!(BUSY_BOUND < IDLE_BOUND);
    }

    #[test]
    fn progress_sets_the_budget_back() {
        // The budget ends a session where nothing is happening, not a long
        // one. A fetch of a large object makes one pass per answer with no
        // backlog to show for it, and a budget that counted those would
        // end the transfer partway through.
        let mut engine = Scripted {
            unsettled: 4 * STALLED_PASSES,
            with_progress: 4 * STALLED_PASSES,
            ..Scripted::default()
        };
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.passes, 4 * STALLED_PASSES + 1);
    }

    #[test]
    fn a_session_where_nothing_happens_is_given_up_on() {
        // A peer that holds a session open and does nothing with it would
        // otherwise hold this end forever.
        let mut engine = Scripted {
            unsettled: u32::MAX,
            with_progress: 0,
            ..Scripted::default()
        };
        assert!(matches!(drive(&mut engine), Err(Error::Stalled)));
        assert_eq!(engine.passes, STALLED_PASSES + 1);
    }

    #[test]
    fn progress_late_in_a_stall_sets_the_budget_back() {
        // The counter is consecutive passes, not passes overall.
        let mut engine = Scripted {
            unsettled: STALLED_PASSES + 10,
            with_progress: 1,
            ..Scripted::default()
        };
        assert!(matches!(drive(&mut engine), Err(Error::Stalled)));
        // One pass made progress, so the budget started again after it.
        assert_eq!(engine.passes, STALLED_PASSES + 2);
    }
}
