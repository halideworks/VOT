//! Executable VOT commit and assurance transition model.

#![allow(clippy::missing_errors_doc)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Fast,
    Balanced,
    Strict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Assurance {
    Admitted,
    TransitVerified,
    Durable,
    AtRestVerified,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    New,
    Admitted,
    TransitVerified,
    DataFlushed,
    Durable,
    AtRestVerified,
    NamespaceLinked,
    Published,
    RecoveryRequired,
    Poisoned,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Admit,
    TransitVerified,
    DataFlushSucceeded,
    DataFlushFailed,
    JournalFlushSucceeded,
    JournalFlushFailed,
    AtRestVerified,
    AtRestVerificationFailed,
    NamespaceLinked,
    NamespaceLinkAmbiguous,
    NamespaceDurable,
    NamespaceFlushFailed,
    Crash,
    Recover,
    Abort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    StaleIncarnation,
    Terminal,
    InvalidTransition,
    MissingPredecessor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub level: Assurance,
    pub sequence: u64,
}

/// A transition that has passed every guard and is waiting to be committed.
struct Transition {
    next: State,
    sequence: u64,
    recovery_state: Option<State>,
    observation: Option<Assurance>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Machine {
    profile: Profile,
    state: State,
    current_incarnation: bool,
    recovery_state: Option<State>,
    sequence: u64,
    performed: Vec<Assurance>,
}

impl Machine {
    #[must_use]
    pub const fn new(profile: Profile) -> Self {
        Self {
            profile,
            state: State::New,
            current_incarnation: true,
            recovery_state: None,
            sequence: 0,
            performed: Vec::new(),
        }
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn performed(&self, level: Assurance) -> bool {
        self.performed.contains(&level)
    }

    pub const fn mark_stale(&mut self) {
        self.current_incarnation = false;
    }

    pub fn apply(&mut self, event: Event) -> Result<Option<Observation>, Error> {
        let transition = self.plan(event)?;
        Ok(self.commit(&transition))
    }

    /// Computes the complete transition for `event`, or rejects it. Every
    /// guard runs here so that a rejection cannot leave the machine changed.
    fn plan(&self, event: Event) -> Result<Transition, Error> {
        if !self.current_incarnation {
            return Err(Error::StaleIncarnation);
        }
        if matches!(
            self.state,
            State::Published | State::Poisoned | State::Aborted
        ) {
            return Err(Error::Terminal);
        }

        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::InvalidTransition)?;

        if event == Event::Recover {
            if self.state != State::RecoveryRequired {
                return Err(Error::InvalidTransition);
            }
            let recovered = self.recovery_state.ok_or(Error::InvalidTransition)?;
            return Ok(Transition {
                next: recovered,
                sequence,
                recovery_state: None,
                observation: None,
            });
        }

        let (next, observation) = match (self.state, event) {
            (State::New, Event::Admit) => (State::Admitted, Some(Assurance::Admitted)),
            (State::Admitted, Event::TransitVerified) => {
                (State::TransitVerified, Some(Assurance::TransitVerified))
            }
            (State::TransitVerified, Event::DataFlushSucceeded) => (State::DataFlushed, None),
            (State::DataFlushed, Event::JournalFlushSucceeded) => {
                (State::Durable, Some(Assurance::Durable))
            }
            (State::Durable, Event::AtRestVerified) => {
                (State::AtRestVerified, Some(Assurance::AtRestVerified))
            }
            (state, Event::NamespaceLinked) if self.can_publish_from(state) => {
                (State::NamespaceLinked, None)
            }
            (State::NamespaceLinked, Event::NamespaceDurable) => {
                (State::Published, Some(Assurance::Published))
            }
            (
                State::New
                | State::Admitted
                | State::TransitVerified
                | State::DataFlushed
                | State::Durable
                | State::AtRestVerified,
                Event::Abort,
            ) => (State::Aborted, None),
            (
                _,
                Event::DataFlushFailed
                | Event::JournalFlushFailed
                | Event::AtRestVerificationFailed,
            ) => (State::Poisoned, None),
            (state, Event::NamespaceLinkAmbiguous | Event::NamespaceFlushFailed | Event::Crash)
                if state != State::RecoveryRequired =>
            {
                (State::RecoveryRequired, None)
            }
            _ => return Err(Error::InvalidTransition),
        };

        if observation == Some(Assurance::Published) && !self.required_predecessor_performed() {
            return Err(Error::MissingPredecessor);
        }

        // Entering recovery saves the state it came from; every other
        // transition leaves whatever an earlier crash saved.
        let recovery_state = if next == State::RecoveryRequired {
            Some(self.state)
        } else {
            self.recovery_state
        };

        Ok(Transition {
            next,
            sequence,
            recovery_state,
            observation,
        })
    }

    /// Applies a transition this machine planned. Cannot fail.
    fn commit(&mut self, transition: &Transition) -> Option<Observation> {
        self.state = transition.next;
        self.sequence = transition.sequence;
        self.recovery_state = transition.recovery_state;
        transition.observation.map(|level| {
            self.performed.push(level);
            Observation {
                level,
                sequence: self.sequence,
            }
        })
    }

    fn can_publish_from(&self, state: State) -> bool {
        matches!(
            (self.profile, state),
            (Profile::Fast, State::TransitVerified)
                | (Profile::Balanced, State::Durable)
                | (Profile::Strict, State::AtRestVerified)
        )
    }

    fn required_predecessor_performed(&self) -> bool {
        let required = match self.profile {
            Profile::Fast => Assurance::TransitVerified,
            Profile::Balanced => Assurance::Durable,
            Profile::Strict => Assurance::AtRestVerified,
        };
        self.performed(required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENTS: [Event; 15] = [
        Event::Admit,
        Event::TransitVerified,
        Event::DataFlushSucceeded,
        Event::DataFlushFailed,
        Event::JournalFlushSucceeded,
        Event::JournalFlushFailed,
        Event::AtRestVerified,
        Event::AtRestVerificationFailed,
        Event::NamespaceLinked,
        Event::NamespaceLinkAmbiguous,
        Event::NamespaceDurable,
        Event::NamespaceFlushFailed,
        Event::Crash,
        Event::Recover,
        Event::Abort,
    ];

    /// Two machines behave alike when everything but the sequence agrees, so
    /// the search dedupes on that and terminates.
    fn shape(machine: &Machine) -> (Profile, State, bool, Option<State>, Vec<Assurance>) {
        (
            machine.profile,
            machine.state,
            machine.current_incarnation,
            machine.recovery_state,
            machine.performed.clone(),
        )
    }

    /// Every machine an accepted event sequence can produce, stale variants
    /// included. No path is longer than the number of events, which bounds
    /// the search.
    fn every_reachable_machine() -> Vec<Machine> {
        let mut frontier: Vec<Machine> = [Profile::Fast, Profile::Balanced, Profile::Strict]
            .into_iter()
            .map(Machine::new)
            .collect();
        let mut found = frontier.clone();
        for _ in 0..EVENTS.len() {
            let mut next = Vec::new();
            for machine in &frontier {
                for event in EVENTS {
                    let mut candidate = machine.clone();
                    if candidate.apply(event).is_ok()
                        && !found.iter().any(|seen| shape(seen) == shape(&candidate))
                    {
                        found.push(candidate.clone());
                        next.push(candidate);
                    }
                }
            }
            frontier = next;
        }
        let stale: Vec<Machine> = found
            .iter()
            .map(|machine| {
                let mut stale = machine.clone();
                stale.mark_stale();
                stale
            })
            .collect();
        found.extend(stale);
        found
    }

    #[test]
    fn a_rejected_event_leaves_the_machine_untouched() {
        let machines = every_reachable_machine();
        assert!(
            machines.len() > 20,
            "the search found only {} machines",
            machines.len()
        );
        let mut rejections = 0_u32;
        for machine in &machines {
            for event in EVENTS {
                let mut candidate = machine.clone();
                if candidate.apply(event).is_err() {
                    rejections += 1;
                    assert_eq!(
                        &candidate, machine,
                        "{event:?} was rejected from {:?} but changed the machine",
                        machine.state
                    );
                }
            }
        }
        assert!(rejections > 100, "only {rejections} events were rejected");
    }

    #[test]
    fn the_last_sequence_rejects_every_event_without_mutating() {
        let machine = Machine {
            profile: Profile::Fast,
            state: State::Admitted,
            current_incarnation: true,
            recovery_state: None,
            sequence: u64::MAX,
            performed: vec![Assurance::Admitted],
        };
        for event in EVENTS {
            let mut candidate = machine.clone();
            assert_eq!(candidate.apply(event), Err(Error::InvalidTransition));
            assert_eq!(candidate, machine, "{event:?} at the last sequence");
        }
    }

    #[test]
    fn a_saved_recovery_state_survives_a_rejected_event() {
        let mut machine = Machine::new(Profile::Fast);
        machine.apply(Event::Admit).unwrap();
        machine.apply(Event::Crash).unwrap();
        let waiting = machine.clone();
        assert_eq!(machine.apply(Event::Admit), Err(Error::InvalidTransition));
        assert_eq!(machine, waiting);
        machine.apply(Event::Recover).unwrap();
        assert_eq!(machine.state(), State::Admitted);
    }

    fn reach_durable(machine: &mut Machine) {
        machine.apply(Event::Admit).unwrap();
        machine.apply(Event::TransitVerified).unwrap();
        machine.apply(Event::DataFlushSucceeded).unwrap();
        machine.apply(Event::JournalFlushSucceeded).unwrap();
    }

    #[test]
    fn every_profile_requires_its_predecessor() {
        let mut fast = Machine::new(Profile::Fast);
        fast.apply(Event::Admit).unwrap();
        fast.apply(Event::TransitVerified).unwrap();
        fast.apply(Event::NamespaceLinked).unwrap();
        fast.apply(Event::NamespaceDurable).unwrap();
        assert!(fast.performed(Assurance::TransitVerified));

        let mut balanced = Machine::new(Profile::Balanced);
        reach_durable(&mut balanced);
        balanced.apply(Event::NamespaceLinked).unwrap();
        balanced.apply(Event::NamespaceDurable).unwrap();
        assert!(balanced.performed(Assurance::Durable));

        let mut strict = Machine::new(Profile::Strict);
        reach_durable(&mut strict);
        strict.apply(Event::AtRestVerified).unwrap();
        strict.apply(Event::NamespaceLinked).unwrap();
        strict.apply(Event::NamespaceDurable).unwrap();
        assert!(strict.performed(Assurance::AtRestVerified));
    }

    #[test]
    fn stale_incarnation_never_advances() {
        let mut machine = Machine::new(Profile::Fast);
        machine.mark_stale();
        assert_eq!(machine.apply(Event::Admit), Err(Error::StaleIncarnation));
        assert_eq!(machine.state(), State::New);
    }

    #[test]
    fn failed_flush_is_permanently_poisoned() {
        let mut machine = Machine::new(Profile::Balanced);
        machine.apply(Event::Admit).unwrap();
        machine.apply(Event::TransitVerified).unwrap();
        machine.apply(Event::DataFlushFailed).unwrap();
        assert_eq!(machine.state(), State::Poisoned);
        assert_eq!(
            machine.apply(Event::DataFlushSucceeded),
            Err(Error::Terminal)
        );
        assert!(!machine.performed(Assurance::Published));
    }

    #[test]
    fn crash_after_each_nonterminal_transition_recovers_exact_state() {
        let mut machine = Machine::new(Profile::Strict);
        for event in [
            None,
            Some(Event::Admit),
            Some(Event::TransitVerified),
            Some(Event::DataFlushSucceeded),
            Some(Event::JournalFlushSucceeded),
            Some(Event::AtRestVerified),
            Some(Event::NamespaceLinked),
        ] {
            if let Some(event) = event {
                machine.apply(event).unwrap();
            }
            let mut crashed = machine.clone();
            let state_before_crash = crashed.state();
            let performed_before_crash = crashed.performed.clone();
            crashed.apply(Event::Crash).unwrap();
            assert_eq!(crashed.state(), State::RecoveryRequired);
            crashed.apply(Event::Recover).unwrap();
            assert_eq!(crashed.state(), state_before_crash);
            assert_eq!(crashed.performed, performed_before_crash);
        }
    }

    #[test]
    fn weaker_state_cannot_publish() {
        let mut machine = Machine::new(Profile::Strict);
        reach_durable(&mut machine);
        assert_eq!(
            machine.apply(Event::NamespaceLinked),
            Err(Error::InvalidTransition)
        );
    }

    #[test]
    fn sequence_counts_every_accepted_transition() {
        let mut machine = Machine::new(Profile::Fast);
        assert_eq!(machine.sequence(), 0);
        assert_eq!(machine.apply(Event::Admit).unwrap().unwrap().sequence, 1);
        assert_eq!(
            machine
                .apply(Event::TransitVerified)
                .unwrap()
                .unwrap()
                .sequence,
            2
        );
        assert_eq!(machine.apply(Event::Abort), Ok(None));
        assert_eq!(machine.sequence(), 3);
    }

    #[test]
    fn every_nonterminal_work_state_can_abort() {
        let mut machine = Machine::new(Profile::Strict);
        for event in [
            None,
            Some(Event::Admit),
            Some(Event::TransitVerified),
            Some(Event::DataFlushSucceeded),
            Some(Event::JournalFlushSucceeded),
            Some(Event::AtRestVerified),
        ] {
            if let Some(event) = event {
                machine.apply(event).unwrap();
            }
            let mut aborted = machine.clone();
            assert_eq!(aborted.apply(Event::Abort), Ok(None));
            assert_eq!(aborted.state(), State::Aborted);
        }
    }

    #[test]
    fn recovery_event_cannot_replace_the_saved_state() {
        let mut machine = Machine::new(Profile::Fast);
        machine.apply(Event::Admit).unwrap();
        machine.apply(Event::Crash).unwrap();
        assert_eq!(machine.apply(Event::Crash), Err(Error::InvalidTransition));
        machine.apply(Event::Recover).unwrap();
        assert_eq!(machine.state(), State::Admitted);
    }

    #[test]
    fn publication_defense_rechecks_recorded_predecessor() {
        let mut machine = Machine {
            profile: Profile::Strict,
            state: State::NamespaceLinked,
            current_incarnation: true,
            recovery_state: None,
            sequence: 0,
            performed: Vec::new(),
        };
        let linked = machine.clone();
        assert_eq!(
            machine.apply(Event::NamespaceDurable),
            Err(Error::MissingPredecessor)
        );
        assert!(!machine.performed(Assurance::Published));
        assert_eq!(machine, linked);
    }
}
