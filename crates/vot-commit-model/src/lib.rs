//! Executable VOT commit and assurance transition model.

#![allow(clippy::missing_errors_doc)]

/// One list per enum: the variants, their `ALL` walk, their test positions,
/// and their display names all come from the same rows, so none can drift.
/// Only mechanical facts are generated; the transition relation in
/// [`Machine::apply`] stays an explicit match. `models/commit/relation.json`
/// is the independent Python/TLA table; the exhaustive walk holds this match
/// to that table.
macro_rules! enum_metadata {
    (walked $(#[$attr:meta])* $vis:vis enum $name:ident { $($variant:ident),* $(,)? }) => {
        enum_metadata!(named $(#[$attr])* $vis enum $name { $($variant),* });

        impl $name {
            /// Every variant, so a walk over the relation cannot miss one by
            /// omission: the list and the enum are the same declaration.
            pub const ALL: [Self; [$(stringify!($variant)),*].len()] = [$(Self::$variant),*];

            /// Where this sits in [`Self::ALL`]: the declaration ordinal,
            /// which is what `ALL` is built from.
            #[cfg(test)]
            const fn position(self) -> usize {
                self as usize
            }
        }
    };
    (named $(#[$attr:meta])* $vis:vis enum $name:ident { $($variant:ident),* $(,)? }) => {
        $(#[$attr])*
        $vis enum $name {
            $($variant),*
        }

        impl $name {
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant)),*
                }
            }
        }
    };
}

enum_metadata!(walked
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Profile {
    Fast,
    Balanced,
    Strict,
});

enum_metadata!(named
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Assurance {
    Admitted,
    TransitVerified,
    Durable,
    AtRestVerified,
    Published,
});

enum_metadata!(named
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
});

enum_metadata!(walked
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
});

enum_metadata!(named
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    StaleIncarnation,
    Terminal,
    InvalidTransition,
    MissingPredecessor,
});

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
        // Derived rather than written again: the state a namespace may be
        // linked from is the one standing at the assurance publication
        // requires, and one table decides both.
        state == self.profile.required_predecessor().state()
    }

    fn required_predecessor_performed(&self) -> bool {
        self.performed(self.profile.required_predecessor())
    }
}

impl Profile {
    /// The assurance a publication under this profile must already have
    /// performed. One home for the rule: a receipt chain checks the same
    /// table the machine enforces.
    #[must_use]
    pub const fn required_predecessor(self) -> Assurance {
        match self {
            Self::Fast => Assurance::TransitVerified,
            Self::Balanced => Assurance::Durable,
            Self::Strict => Assurance::AtRestVerified,
        }
    }
}

impl Assurance {
    /// The state a machine stands in once it has performed this.
    #[must_use]
    pub const fn state(self) -> State {
        match self {
            Self::Admitted => State::Admitted,
            Self::TransitVerified => State::TransitVerified,
            Self::Durable => State::Durable,
            Self::AtRestVerified => State::AtRestVerified,
            Self::Published => State::Published,
        }
    }
}

/// One row of the transition relation: a machine, an event, and what the
/// machine did with it. The sequence is left out; it counts accepted
/// transitions and says nothing a second implementation could disagree about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionRow {
    pub profile: Profile,
    pub state: State,
    pub current_incarnation: bool,
    pub recovery_state: Option<State>,
    pub performed: Vec<Assurance>,
    pub event: Event,
    pub error: Option<Error>,
    pub next_state: State,
    pub next_recovery_state: Option<State>,
    pub observation: Option<Assurance>,
    /// What the machine has performed afterwards.
    ///
    /// Without this a second implementation can only check the row against
    /// itself: the observation says what was emitted, and the guard that
    /// reads `performed` is checking something the row does not report. A
    /// model that emits the right observation and records the wrong
    /// assurance would agree with every row it produced.
    pub next_performed: Vec<Assurance>,
}

impl std::fmt::Display for TransitionRow {
    /// One JSON object per row, on one line, so a diff points at a
    /// transition rather than at a reflowed document.
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let quoted = |value: Option<&'static str>| {
            value.map_or_else(|| "null".to_owned(), |name| format!("\"{name}\""))
        };
        let performed: Vec<String> = self
            .performed
            .iter()
            .map(|level| format!("\"{}\"", level.name()))
            .collect();
        write!(
            out,
            concat!(
                "{{\"profile\": \"{}\", \"state\": \"{}\", \"current\": {}, ",
                "\"recovery_state\": {}, \"performed\": [{}], \"event\": \"{}\", ",
                "\"error\": {}, \"next_state\": \"{}\", \"next_recovery_state\": {}, ",
                "\"observation\": {}, \"next_performed\": [{}]}}"
            ),
            self.profile.name(),
            self.state.name(),
            self.current_incarnation,
            quoted(self.recovery_state.map(State::name)),
            performed.join(", "),
            self.event.name(),
            quoted(self.error.map(Error::name)),
            self.next_state.name(),
            quoted(self.next_recovery_state.map(State::name)),
            quoted(self.observation.map(Assurance::name)),
            self.next_performed
                .iter()
                .map(|level| format!("\"{}\"", level.name()))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

/// Every machine an accepted event sequence can reach, stale variants
/// included, crossed with every event. This is the whole relation over the
/// bounded state space, which is what a second implementation has to agree
/// with to be a refinement rather than a vocabulary match.
#[must_use]
pub fn transition_corpus() -> Vec<TransitionRow> {
    let mut rows = Vec::new();
    for machine in corpus_machines() {
        for event in Event::ALL {
            let mut candidate = machine.clone();
            let outcome = candidate.apply(event);
            rows.push(TransitionRow {
                profile: machine.profile,
                state: machine.state,
                current_incarnation: machine.current_incarnation,
                recovery_state: machine.recovery_state,
                performed: machine.performed.clone(),
                event,
                error: outcome.as_ref().err().copied(),
                next_state: candidate.state,
                next_recovery_state: candidate.recovery_state,
                observation: outcome.ok().flatten().map(|seen| seen.level),
                next_performed: candidate.performed.clone(),
            });
        }
    }
    rows
}

/// Every machine the walk reaches, and every one of those with a recorded
/// assurance taken away.
///
/// The weakened ones are not reachable through accepted events, which is the
/// point: a machine standing at `NamespaceLinked` with no predecessor
/// recorded is what the publication defense exists for, and a walk over
/// accepted sequences alone would never present it.
fn corpus_machines() -> Vec<Machine> {
    let reachable = reachable_machines();
    let mut weakened = Vec::new();
    for machine in &reachable {
        for dropped in 0..machine.performed.len() {
            let mut thinner = machine.clone();
            thinner.performed.remove(dropped);
            weakened.push(thinner);
        }
        // A crash that lost what it saved. Not reachable through accepted
        // events either, and the guard that refuses to recover into a state
        // nobody recorded is unreachable without it.
        if machine.state == State::RecoveryRequired && machine.recovery_state.is_some() {
            let mut forgotten = machine.clone();
            forgotten.recovery_state = None;
            weakened.push(forgotten);
        }
    }
    let mut all = reachable;
    all.append(&mut weakened);
    all
}

/// A ceiling on the walk, well above the couple of hundred shapes it reaches.
/// It is here so a walk that lost its deduplication stops rather than growing
/// by a factor of the event count every round.
const MAX_MACHINES: usize = 2048;

/// Machines differing only in their sequence behave alike, so the search
/// dedupes on everything else and terminates. No path needs more steps than
/// there are events, which bounds it.
fn reachable_machines() -> Vec<Machine> {
    let shape = |machine: &Machine| {
        (
            machine.profile,
            machine.state,
            machine.current_incarnation,
            machine.recovery_state,
            machine.performed.clone(),
        )
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut frontier: Vec<Machine> = Vec::new();
    let mut found = Vec::new();
    for profile in Profile::ALL {
        let machine = Machine::new(profile);
        seen.insert(shape(&machine));
        found.push(machine.clone());
        frontier.push(machine);
    }
    'walk: for _ in 0..Event::ALL.len() {
        let mut next = Vec::new();
        for machine in &frontier {
            for event in Event::ALL {
                // Counted in the loop's own body, so a walk that stopped
                // deduplicating would stop rather than run away. Breaking
                // rather than returning, because returning here would skip
                // the stale variants below and quietly drop half the
                // relation instead of shortening the walk.
                if found.len() >= MAX_MACHINES {
                    break 'walk;
                }
                let mut candidate = machine.clone();
                if candidate.apply(event).is_err() {
                    continue;
                }
                if !seen.insert(shape(&candidate)) {
                    continue;
                }
                found.push(candidate.clone());
                next.push(candidate);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The library's own list, so a test cannot walk a stale one.
    const EVENTS: [Event; 15] = Event::ALL;

    #[test]
    fn a_rejected_event_leaves_the_machine_untouched() {
        // Exact, not a floor. A floor cannot tell a corpus that shrank from
        // one that grew, and both mean the walk changed: update this number
        // when that is deliberate, and look when it is not.
        assert_eq!(corpus_machines().len(), 648);
        let machines = corpus_machines();
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
        assert!(rejections > 8_000, "only {rejections} events were rejected");
    }

    #[test]
    fn every_variant_is_enrolled_in_the_walk() {
        // `position` is exhaustive, so a new variant does not compile until
        // it is placed. These assertions are what make the placement have to
        // be the right one: a variant added to the match but not to ALL, or
        // added to ALL in the wrong slot, fails here rather than quietly
        // shrinking the corpus.
        for (index, event) in Event::ALL.into_iter().enumerate() {
            assert_eq!(event.position(), index, "{event:?} is out of place");
        }
        for (index, profile) in Profile::ALL.into_iter().enumerate() {
            assert_eq!(profile.position(), index, "{profile:?} is out of place");
        }
    }

    #[test]
    fn every_name_is_the_variant_it_belongs_to() {
        let names = |values: &[&'static str]| values.to_vec();
        assert_eq!(
            [Profile::Fast, Profile::Balanced, Profile::Strict]
                .map(Profile::name)
                .to_vec(),
            names(&["Fast", "Balanced", "Strict"])
        );
        assert_eq!(
            [
                Assurance::Admitted,
                Assurance::TransitVerified,
                Assurance::Durable,
                Assurance::AtRestVerified,
                Assurance::Published,
            ]
            .map(Assurance::name)
            .to_vec(),
            names(&[
                "Admitted",
                "TransitVerified",
                "Durable",
                "AtRestVerified",
                "Published"
            ])
        );
        assert_eq!(
            [
                State::New,
                State::Admitted,
                State::TransitVerified,
                State::DataFlushed,
                State::Durable,
                State::AtRestVerified,
                State::NamespaceLinked,
                State::Published,
                State::RecoveryRequired,
                State::Poisoned,
                State::Aborted,
            ]
            .map(State::name)
            .to_vec(),
            names(&[
                "New",
                "Admitted",
                "TransitVerified",
                "DataFlushed",
                "Durable",
                "AtRestVerified",
                "NamespaceLinked",
                "Published",
                "RecoveryRequired",
                "Poisoned",
                "Aborted",
            ])
        );
        assert_eq!(
            Event::ALL.map(Event::name).to_vec(),
            names(&[
                "Admit",
                "TransitVerified",
                "DataFlushSucceeded",
                "DataFlushFailed",
                "JournalFlushSucceeded",
                "JournalFlushFailed",
                "AtRestVerified",
                "AtRestVerificationFailed",
                "NamespaceLinked",
                "NamespaceLinkAmbiguous",
                "NamespaceDurable",
                "NamespaceFlushFailed",
                "Crash",
                "Recover",
                "Abort",
            ])
        );
        assert_eq!(
            [
                Error::StaleIncarnation,
                Error::Terminal,
                Error::InvalidTransition,
                Error::MissingPredecessor,
            ]
            .map(Error::name)
            .to_vec(),
            names(&[
                "StaleIncarnation",
                "Terminal",
                "InvalidTransition",
                "MissingPredecessor"
            ])
        );
    }

    #[test]
    fn the_corpus_holds_the_whole_relation() {
        let rows = transition_corpus();
        // Every event against every machine, so the count divides.
        assert_eq!(rows.len(), 648 * EVENTS.len());

        for event in EVENTS {
            assert!(
                rows.iter().any(|row| row.event == event),
                "{event:?} is in no row"
            );
        }
        for state in [
            State::New,
            State::Admitted,
            State::TransitVerified,
            State::DataFlushed,
            State::Durable,
            State::AtRestVerified,
            State::NamespaceLinked,
            State::Published,
            State::RecoveryRequired,
            State::Poisoned,
            State::Aborted,
        ] {
            assert!(
                rows.iter().any(|row| row.state == state),
                "no machine stands at {state:?}"
            );
        }

        // The machines a walk over accepted events cannot reach are what the
        // corpus adds by hand, and the predecessor defense needs them.
        assert!(
            rows.iter()
                .any(|row| row.error == Some(Error::MissingPredecessor)),
            "no row reaches the publication defense"
        );
        assert!(rows.iter().any(|row| !row.current_incarnation));
        // The other machine no accepted walk produces: a crash that lost
        // what it saved. Without it the guard refusing to recover into a
        // state nobody recorded is unreachable.
        assert!(
            rows.iter()
                .any(|row| row.state == State::RecoveryRequired && row.recovery_state.is_none()),
            "no row reaches the recovery guard"
        );

        for row in &rows {
            if row.error.is_some() {
                assert_eq!(row.next_state, row.state, "{row}");
                assert_eq!(row.next_recovery_state, row.recovery_state, "{row}");
                assert!(row.observation.is_none(), "{row}");
            }
        }
    }

    #[test]
    fn a_row_renders_the_transition_it_describes() {
        let mut machine = Machine::new(Profile::Balanced);
        machine.apply(Event::Admit).unwrap();
        machine.apply(Event::Crash).unwrap();
        let row = transition_corpus()
            .into_iter()
            .find(|row| {
                row.profile == Profile::Balanced
                    && row.state == State::RecoveryRequired
                    && row.recovery_state == Some(State::Admitted)
                    && row.current_incarnation
                    && row.event == Event::Recover
            })
            .expect("a recovery row");
        assert_eq!(
            row.to_string(),
            "{\"profile\": \"Balanced\", \"state\": \"RecoveryRequired\", \"current\": true, \
             \"recovery_state\": \"Admitted\", \"performed\": [\"Admitted\"], \
             \"event\": \"Recover\", \"error\": null, \"next_state\": \"Admitted\", \
             \"next_recovery_state\": null, \"observation\": null, \
             \"next_performed\": [\"Admitted\"]}"
        );
    }

    #[test]
    fn the_last_sequence_rejects_every_event_without_mutating() {
        // Two machines, because one state cannot reach every pre-mutation
        // the overflow used to run past. `Admitted` never enters the recover
        // branch, so a machine that has something saved is needed to prove
        // the saved state survives an overflow there.
        let waiting = Machine {
            profile: Profile::Fast,
            state: State::RecoveryRequired,
            current_incarnation: true,
            recovery_state: Some(State::Admitted),
            sequence: u64::MAX,
            performed: vec![Assurance::Admitted],
        };
        let admitted = Machine {
            profile: Profile::Fast,
            state: State::Admitted,
            current_incarnation: true,
            recovery_state: None,
            sequence: u64::MAX,
            performed: vec![Assurance::Admitted],
        };
        for machine in [&waiting, &admitted] {
            for event in EVENTS {
                let mut candidate = machine.clone();
                assert_eq!(candidate.apply(event), Err(Error::InvalidTransition));
                assert_eq!(
                    &candidate, machine,
                    "{event:?} at the last sequence from {:?}",
                    machine.state
                );
            }
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
