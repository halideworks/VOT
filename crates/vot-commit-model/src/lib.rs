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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Machine {
    profile: Profile,
    state: State,
    current_incarnation: bool,
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
        if !self.current_incarnation {
            return Err(Error::StaleIncarnation);
        }
        if matches!(
            self.state,
            State::Published | State::Poisoned | State::Aborted
        ) {
            return Err(Error::Terminal);
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
            (_, Event::NamespaceLinkAmbiguous | Event::NamespaceFlushFailed | Event::Crash) => {
                (State::RecoveryRequired, None)
            }
            _ => return Err(Error::InvalidTransition),
        };

        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::InvalidTransition)?;
        self.state = next;
        if let Some(level) = observation {
            if level == Assurance::Published && !self.required_predecessor_performed() {
                return Err(Error::MissingPredecessor);
            }
            self.performed.push(level);
            Ok(Some(Observation {
                level,
                sequence: self.sequence,
            }))
        } else {
            Ok(None)
        }
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
    fn weaker_state_cannot_publish() {
        let mut machine = Machine::new(Profile::Strict);
        reach_durable(&mut machine);
        assert_eq!(
            machine.apply(Event::NamespaceLinked),
            Err(Error::InvalidTransition)
        );
    }
}
