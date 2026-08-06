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

/// Passes a driving loop may make with neither an event nor progress.
///
/// A carrier that reports events forever while the engine settles nothing
/// would otherwise turn a dead session into an endless one. Counted in the
/// loop's own body rather than measured against a clock, because a slow
/// machine is not a stuck one.
const IDLE_PASSES: u32 = 4096;

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

    /// Whether another pass has work that does not need an event first.
    fn has_backlog(&self) -> bool;

    /// Waits for the carrier to report something, or for `bound`.
    fn wait(&mut self, bound: Duration);
}

/// Drives `engine` until a pass settles it, and answers with that status.
///
/// # Errors
/// Surfaces the engine's own failure, or [`Error::InvalidBundle`] if the
/// loop made its whole budget of passes without settling or progressing.
pub fn drive<E: Engine>(engine: &mut E) -> Result<E::Status, Error> {
    let mut idle = 0;
    loop {
        let status = engine.service()?;
        if E::settled(status) {
            return Ok(status);
        }
        if engine.has_backlog() {
            // Work this end can do without hearing from the peer, so the
            // pass that does it is progress and does not spend the budget.
            idle = 0;
            continue;
        }
        idle += 1;
        if idle > IDLE_PASSES {
            return Err(Error::InvalidBundle);
        }
        engine.wait(IDLE_BOUND);
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
        /// Of those, how many report a backlog.
        with_backlog: u32,
        passes: u32,
        waits: u32,
    }

    impl Engine for Scripted {
        type Status = bool;

        fn service(&mut self) -> Result<bool, Error> {
            self.passes += 1;
            if self.unsettled == 0 {
                return Ok(true);
            }
            self.unsettled -= 1;
            Ok(false)
        }

        fn settled(status: bool) -> bool {
            status
        }

        fn has_backlog(&self) -> bool {
            self.with_backlog > self.unsettled
        }

        fn wait(&mut self, _bound: Duration) {
            self.waits += 1;
        }
    }

    #[test]
    fn a_settled_pass_ends_the_loop_without_waiting() {
        let mut engine = Scripted::default();
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.passes, 1);
        assert_eq!(engine.waits, 0);
    }

    #[test]
    fn a_backlog_is_worked_off_rather_than_waited_on() {
        // Every unsettled pass reports a backlog, so the loop must never
        // wait: what it is waiting for is already in its own hands.
        let mut engine = Scripted {
            unsettled: 5,
            with_backlog: 5,
            ..Scripted::default()
        };
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.passes, 6, "five unsettled and the one that ends it");
        assert_eq!(engine.waits, 0, "a backlog is not a reason to wait");
    }

    #[test]
    fn an_idle_pass_waits_on_the_carrier() {
        let mut engine = Scripted {
            unsettled: 3,
            with_backlog: 0,
            ..Scripted::default()
        };
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.waits, 3, "one wait for each pass with nothing to do");
    }

    #[test]
    fn a_carrier_that_never_settles_is_given_up_on() {
        // A peer that keeps a session open and does nothing with it would
        // otherwise hold this end forever.
        let mut engine = Scripted {
            unsettled: u32::MAX,
            with_backlog: 0,
            ..Scripted::default()
        };
        assert!(matches!(drive(&mut engine), Err(Error::InvalidBundle)));
        assert_eq!(engine.waits, IDLE_PASSES, "it waited its whole budget");
        assert_eq!(engine.passes, IDLE_PASSES + 1);
    }

    #[test]
    fn progress_gives_the_budget_back() {
        // The budget is against a session going nowhere, not against a long
        // one: a pass with a backlog to work off resets it, so an engine
        // that keeps making progress is never given up on.
        let mut engine = Scripted {
            unsettled: 2 * IDLE_PASSES,
            with_backlog: 2 * IDLE_PASSES,
            ..Scripted::default()
        };
        assert!(drive(&mut engine).unwrap());
        assert_eq!(engine.passes, 2 * IDLE_PASSES + 1);
    }
}
