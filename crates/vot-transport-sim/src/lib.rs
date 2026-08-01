//! Deterministic network, receiver, and storage simulation for VOT.

#![forbid(unsafe_code)]
#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::fmt::Write as _;

use vot_transport_api::{Error as TransportError, Event as TransportEvent, Payload, StreamId};

pub const MAX_SCENARIO_BYTES: usize = 1024 * 1024;
pub const MAX_ACTIONS: usize = 4096;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_TRANSFER_BYTES: u64 = 128 * 1024 * 1024;

pub type Tick = u64;

/// A transport acknowledgement has no conversion into durability evidence.
///
/// ```compile_fail
/// use vot_journal::DurableWitness;
/// use vot_transport_sim::TransportAck;
///
/// let ack = TransportAck::new(7);
/// let durable: DurableWitness = ack.into();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportAck {
    sequence: u64,
}

impl TransportAck {
    #[must_use]
    pub const fn new(sequence: u64) -> Self {
        Self { sequence }
    }

    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}
/// Deterministic loopback adapter used by integration tests and the simulator.
///
/// It deliberately keeps application submissions separate from backend events:
/// callers must flush before polling, just as they must with a live backend.
#[derive(Clone, Debug)]
enum Submission {
    Control(Payload),
    Reliable { stream: StreamId, bytes: Payload },
    Datagram { context: u64, bytes: Payload },
    ReceiveCredit(u64),
}

#[derive(Default)]
pub struct SimulatorAdapter {
    submissions: VecDeque<Submission>,
    events: VecDeque<TransportEvent>,
    next_sequence: u64,
    receive_credit: u64,
}

impl SimulatorAdapter {
    #[must_use]
    pub fn pending_submissions(&self) -> usize {
        self.submissions.len()
    }

    #[must_use]
    pub const fn receive_credit(&self) -> u64 {
        self.receive_credit
    }
}

impl vot_transport_api::TransportAdapter for SimulatorAdapter {
    fn send_control(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD {
            return Err(TransportError::RecordTooLarge);
        }
        self.submissions
            .push_back(Submission::Control(vot_transport_api::shared_payload(
                frame,
            )));
        Ok(())
    }

    fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), TransportError> {
        self.send_reliable_shared(stream, vot_transport_api::shared_payload(record))
    }

    fn send_reliable_shared(
        &mut self,
        stream: StreamId,
        record: Payload,
    ) -> Result<(), TransportError> {
        vot_transport_api::validate_data_record(&record)?;
        self.submissions.push_back(Submission::Reliable {
            stream,
            bytes: record,
        });
        Ok(())
    }

    fn send_datagram(&mut self, context: u64, payload: &[u8]) -> Result<(), TransportError> {
        if payload.len() > vot_transport_api::MAX_DATAGRAM_BYTES {
            return Err(TransportError::RecordTooLarge);
        }
        self.submissions.push_back(Submission::Datagram {
            context,
            bytes: vot_transport_api::shared_payload(payload),
        });
        Ok(())
    }

    fn flush(&mut self) -> Result<(), TransportError> {
        while let Some(submission) = self.submissions.pop_front() {
            match submission {
                Submission::Control(bytes) => self.events.push_back(TransportEvent::Control(bytes)),
                Submission::Reliable { stream, bytes } => {
                    let sequence = self
                        .next_sequence
                        .checked_add(1)
                        .ok_or(TransportError::ArithmeticOverflow)?;
                    self.next_sequence = sequence;
                    self.events.push_back(TransportEvent::Reliable {
                        stream,
                        sequence,
                        bytes,
                    });
                }
                Submission::Datagram { context, bytes } => {
                    self.events.push_back(TransportEvent::DatagramState {
                        context,
                        state: vot_transport_api::DatagramSendState::Queued,
                    });
                    self.events.push_back(TransportEvent::DatagramState {
                        context,
                        state: vot_transport_api::DatagramSendState::Sent,
                    });
                    let _ = bytes;
                }
                Submission::ReceiveCredit(bytes) => self.receive_credit = bytes,
            }
        }
        Ok(())
    }

    fn poll(&mut self) -> Option<TransportEvent> {
        self.events.pop_front()
    }

    fn set_receive_credit(&mut self, bytes: u64) -> Result<(), TransportError> {
        self.submissions.push_back(Submission::ReceiveCredit(bytes));
        Ok(())
    }
}

/// Deliberate simulator defects used to prove the acceptance gates can fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeControl {
    DropFirstReliableFrame,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Carrier {
    Reliable,
    Datagram,
    Tcp,
}

impl Carrier {
    const fn name(self) -> &'static str {
        match self {
            Self::Reliable => "reliable",
            Self::Datagram => "datagram",
            Self::Tcp => "tcp",
        }
    }

    fn parse(value: &str) -> Result<Self, ScenarioError> {
        match value {
            "reliable" => Ok(Self::Reliable),
            "datagram" => Ok(Self::Datagram),
            "tcp" => Ok(Self::Tcp),
            _ => Err(ScenarioError::InvalidValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum QueueKind {
    Memory,
    Hash,
    Decode,
    Disk,
    Journal,
    Commit,
}

impl QueueKind {
    const ALL: [Self; 6] = [
        Self::Memory,
        Self::Hash,
        Self::Decode,
        Self::Disk,
        Self::Journal,
        Self::Commit,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Hash => "hash",
            Self::Decode => "decode",
            Self::Disk => "disk",
            Self::Journal => "journal",
            Self::Commit => "commit",
        }
    }

    fn parse(value: &str) -> Result<Self, ScenarioError> {
        match value {
            "memory" => Ok(Self::Memory),
            "hash" => Ok(Self::Hash),
            "decode" => Ok(Self::Decode),
            "disk" => Ok(Self::Disk),
            "journal" => Ok(Self::Journal),
            "commit" => Ok(Self::Commit),
            _ => Err(ScenarioError::InvalidValue),
        }
    }

    const fn next(self) -> Option<Self> {
        match self {
            Self::Memory => Some(Self::Hash),
            Self::Hash => Some(Self::Decode),
            Self::Decode => Some(Self::Disk),
            Self::Disk => Some(Self::Journal),
            Self::Journal => Some(Self::Commit),
            Self::Commit => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    AddPath {
        path: u16,
        mtu: u32,
        latency: Tick,
    },
    RemovePath {
        path: u16,
    },
    ChangeMtu {
        path: u16,
        mtu: u32,
    },
    NatRebind {
        path: u16,
        binding: u64,
    },
    LossBurst {
        path: u16,
        packets: u32,
    },
    Reorder {
        path: u16,
        window: Tick,
    },
    SwitchTransport {
        carrier: Carrier,
    },
    Send {
        path: u16,
        transfer: u64,
        bytes: u64,
    },
    QueueLimit {
        queue: QueueKind,
        bytes: u64,
        latency: Tick,
    },
    QueueFault {
        queue: QueueKind,
        operations: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledAction {
    pub at: Tick,
    pub action: Action,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedOutcome {
    Complete,
    Failed,
    Quiescent,
}

impl ExpectedOutcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Quiescent => "quiescent",
        }
    }

    fn parse(value: &str) -> Result<Self, ScenarioError> {
        match value {
            "complete" => Ok(Self::Complete),
            "failed" => Ok(Self::Failed),
            "quiescent" => Ok(Self::Quiescent),
            _ => Err(ScenarioError::InvalidValue),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scenario {
    pub name: String,
    pub seed: u64,
    pub expected: ExpectedOutcome,
    pub expected_trace: Option<[u8; 32]>,
    pub actions: Vec<ScheduledAction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioError {
    TooLarge,
    TooManyActions,
    InvalidHeader,
    InvalidName,
    InvalidLine,
    InvalidValue,
    MissingField,
}

impl Scenario {
    /// Parses the bounded public scenario format.
    ///
    /// # Errors
    /// Returns a structural or bounds error without allocating from an unchecked length.
    pub fn parse(input: &str) -> Result<Self, ScenarioError> {
        if input.len() > MAX_SCENARIO_BYTES {
            return Err(ScenarioError::TooLarge);
        }
        let mut lines = input.lines();
        if lines.next() != Some("VOT_SIM_SCENARIO_V1") {
            return Err(ScenarioError::InvalidHeader);
        }
        let name_line = lines.next().ok_or(ScenarioError::MissingField)?;
        let name = name_line
            .strip_prefix("name ")
            .ok_or(ScenarioError::InvalidLine)?;
        if name.is_empty()
            || name.len() > MAX_NAME_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ScenarioError::InvalidName);
        }
        let seed = parse_prefixed(lines.next(), "seed ")?;
        let expected = lines
            .next()
            .and_then(|line| line.strip_prefix("expect "))
            .ok_or(ScenarioError::MissingField)
            .and_then(ExpectedOutcome::parse)?;
        let expected_trace = lines
            .next()
            .and_then(|line| line.strip_prefix("trace "))
            .ok_or(ScenarioError::MissingField)
            .and_then(parse_trace_digest)?;
        let mut actions = Vec::new();
        for line in lines {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if actions.len() == MAX_ACTIONS {
                return Err(ScenarioError::TooManyActions);
            }
            actions.push(parse_action(line)?);
        }
        Ok(Self {
            name: name.to_owned(),
            seed,
            expected,
            expected_trace,
            actions,
        })
    }

    #[must_use]
    pub fn encode(&self) -> String {
        let mut output = format!(
            "VOT_SIM_SCENARIO_V1\nname {}\nseed {}\nexpect {}\ntrace {}\n",
            self.name,
            self.seed,
            self.expected.name(),
            self.expected_trace
                .map_or_else(|| "-".to_owned(), |digest| hex_digest(&digest))
        );
        for scheduled in &self.actions {
            encode_action(&mut output, scheduled);
        }
        output
    }
}

fn parse_trace_digest(value: &str) -> Result<Option<[u8; 32]>, ScenarioError> {
    if value == "-" {
        return Ok(None);
    }
    if value.len() != 64 {
        return Err(ScenarioError::InvalidValue);
    }
    let mut digest = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        digest[index] = high * 16 + low;
    }
    Ok(Some(digest))
}

fn decode_nibble(value: u8) -> Result<u8, ScenarioError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ScenarioError::InvalidValue),
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn parse_prefixed<T: std::str::FromStr>(
    line: Option<&str>,
    prefix: &str,
) -> Result<T, ScenarioError> {
    line.and_then(|value| value.strip_prefix(prefix))
        .ok_or(ScenarioError::MissingField)?
        .parse()
        .map_err(|_| ScenarioError::InvalidValue)
}

fn parse_u64(value: Option<&str>) -> Result<u64, ScenarioError> {
    value
        .ok_or(ScenarioError::InvalidLine)?
        .parse()
        .map_err(|_| ScenarioError::InvalidValue)
}

fn parse_u32(value: Option<&str>) -> Result<u32, ScenarioError> {
    value
        .ok_or(ScenarioError::InvalidLine)?
        .parse()
        .map_err(|_| ScenarioError::InvalidValue)
}

fn parse_u16(value: Option<&str>) -> Result<u16, ScenarioError> {
    value
        .ok_or(ScenarioError::InvalidLine)?
        .parse()
        .map_err(|_| ScenarioError::InvalidValue)
}

fn parse_action(line: &str) -> Result<ScheduledAction, ScenarioError> {
    let mut fields = line.split_ascii_whitespace();
    if fields.next() != Some("at") {
        return Err(ScenarioError::InvalidLine);
    }
    let at = parse_u64(fields.next())?;
    let operation = fields.next().ok_or(ScenarioError::InvalidLine)?;
    let action = match operation {
        "add-path" => Action::AddPath {
            path: parse_u16(fields.next())?,
            mtu: parse_u32(fields.next())?,
            latency: parse_u64(fields.next())?,
        },
        "remove-path" => Action::RemovePath {
            path: parse_u16(fields.next())?,
        },
        "mtu" => Action::ChangeMtu {
            path: parse_u16(fields.next())?,
            mtu: parse_u32(fields.next())?,
        },
        "rebind" => Action::NatRebind {
            path: parse_u16(fields.next())?,
            binding: parse_u64(fields.next())?,
        },
        "loss" => Action::LossBurst {
            path: parse_u16(fields.next())?,
            packets: parse_u32(fields.next())?,
        },
        "reorder" => Action::Reorder {
            path: parse_u16(fields.next())?,
            window: parse_u64(fields.next())?,
        },
        "switch" => Action::SwitchTransport {
            carrier: Carrier::parse(fields.next().ok_or(ScenarioError::InvalidLine)?)?,
        },
        "send" => Action::Send {
            path: parse_u16(fields.next())?,
            transfer: parse_u64(fields.next())?,
            bytes: parse_u64(fields.next())?,
        },
        "queue-limit" => Action::QueueLimit {
            queue: QueueKind::parse(fields.next().ok_or(ScenarioError::InvalidLine)?)?,
            bytes: parse_u64(fields.next())?,
            latency: parse_u64(fields.next())?,
        },
        "queue-fault" => Action::QueueFault {
            queue: QueueKind::parse(fields.next().ok_or(ScenarioError::InvalidLine)?)?,
            operations: parse_u32(fields.next())?,
        },
        _ => return Err(ScenarioError::InvalidLine),
    };
    if fields.next().is_some() {
        return Err(ScenarioError::InvalidLine);
    }
    validate_action(&action)?;
    Ok(ScheduledAction { at, action })
}

fn validate_action(action: &Action) -> Result<(), ScenarioError> {
    match action {
        Action::AddPath { mtu, latency, .. } if *mtu < 576 || *latency == 0 => {
            Err(ScenarioError::InvalidValue)
        }
        Action::ChangeMtu { mtu, .. } if *mtu < 576 => Err(ScenarioError::InvalidValue),
        Action::LossBurst { packets, .. } if *packets as usize > MAX_ACTIONS => {
            Err(ScenarioError::InvalidValue)
        }
        Action::Reorder { window, .. } if *window > 1_000_000_000 => {
            Err(ScenarioError::InvalidValue)
        }
        Action::Send { bytes, .. } if *bytes == 0 || *bytes > MAX_TRANSFER_BYTES => {
            Err(ScenarioError::InvalidValue)
        }
        Action::QueueLimit { bytes, latency, .. }
            if *bytes == 0 || *bytes > MAX_TRANSFER_BYTES || *latency == 0 =>
        {
            Err(ScenarioError::InvalidValue)
        }
        Action::QueueFault { operations, .. } if *operations as usize > MAX_ACTIONS => {
            Err(ScenarioError::InvalidValue)
        }
        _ => Ok(()),
    }
}

fn encode_action(output: &mut String, scheduled: &ScheduledAction) {
    let at = scheduled.at;
    match scheduled.action {
        Action::AddPath { path, mtu, latency } => {
            let _ = writeln!(output, "at {at} add-path {path} {mtu} {latency}");
        }
        Action::RemovePath { path } => {
            let _ = writeln!(output, "at {at} remove-path {path}");
        }
        Action::ChangeMtu { path, mtu } => {
            let _ = writeln!(output, "at {at} mtu {path} {mtu}");
        }
        Action::NatRebind { path, binding } => {
            let _ = writeln!(output, "at {at} rebind {path} {binding}");
        }
        Action::LossBurst { path, packets } => {
            let _ = writeln!(output, "at {at} loss {path} {packets}");
        }
        Action::Reorder { path, window } => {
            let _ = writeln!(output, "at {at} reorder {path} {window}");
        }
        Action::SwitchTransport { carrier } => {
            let _ = writeln!(output, "at {at} switch {}", carrier.name());
        }
        Action::Send {
            path,
            transfer,
            bytes,
        } => {
            let _ = writeln!(output, "at {at} send {path} {transfer} {bytes}");
        }
        Action::QueueLimit {
            queue,
            bytes,
            latency,
        } => {
            let _ = writeln!(
                output,
                "at {at} queue-limit {} {bytes} {latency}",
                queue.name()
            );
        }
        Action::QueueFault { queue, operations } => {
            let _ = writeln!(output, "at {at} queue-fault {} {operations}", queue.name());
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Failure {
    InvalidScenario,
    CarrierUnavailable { path: u16 },
    DatagramTooLarge { path: u16, bytes: u64, mtu: u32 },
    QueueFull { queue: QueueKind },
    QueueFault { queue: QueueKind },
    IncompleteReliable { missing: usize },
    TimeOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    Complete { published: u64 },
    Failed(Failure),
    Quiescent,
}

impl Outcome {
    #[must_use]
    pub const fn expected(&self) -> ExpectedOutcome {
        match self {
            Self::Complete { .. } => ExpectedOutcome::Complete,
            Self::Failed(_) => ExpectedOutcome::Failed,
            Self::Quiescent => ExpectedOutcome::Quiescent,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceEntry {
    pub at: Tick,
    pub event: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trace {
    pub scenario: String,
    pub seed: u64,
    pub entries: Vec<TraceEntry>,
    pub outcome: Outcome,
}

impl Trace {
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut output = format!(
            "VOT_SIM_TRACE_V1\nscenario {}\nseed {}\n",
            self.scenario, self.seed
        );
        for entry in &self.entries {
            let _ = writeln!(output, "{} {}", entry.at, entry.event);
        }
        let _ = writeln!(output, "outcome {}", outcome_name(&self.outcome));
        output
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(self.canonical().as_bytes()).as_bytes()
    }

    #[must_use]
    pub fn digest_hex(&self) -> String {
        blake3::Hash::from_bytes(self.digest()).to_hex().to_string()
    }
}

fn outcome_name(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Complete { published } => format!("complete:{published}"),
        Outcome::Failed(failure) => format!("failed:{failure:?}"),
        Outcome::Quiescent => "quiescent".to_owned(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Action(Action),
    Deliver {
        path: u16,
        carrier: Carrier,
        transfer: u64,
        bytes: u64,
        attempt: u32,
    },
    QueueEnter {
        queue: QueueKind,
        transfer: u64,
        bytes: u64,
    },
    QueueDone {
        queue: QueueKind,
        transfer: u64,
        bytes: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Pending {
    at: Tick,
    sequence: u64,
    event: Event,
}

impl Ord for Pending {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug)]
struct PathState {
    mtu: u32,
    latency: Tick,
    binding: u64,
    loss_remaining: u32,
    reorder_window: Tick,
}

#[derive(Clone, Copy, Debug)]
struct QueueState {
    capacity: u64,
    used: u64,
    latency: Tick,
    failures_remaining: u32,
}

impl Default for QueueState {
    fn default() -> Self {
        Self {
            capacity: MAX_TRANSFER_BYTES,
            used: 0,
            latency: 1,
            failures_remaining: 0,
        }
    }
}

#[derive(Clone, Debug)]
struct Prng(u64);

impl Prng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

pub struct Simulator {
    now: Tick,
    sequence: u64,
    pending: BinaryHeap<Pending>,
    paths: BTreeMap<u16, PathState>,
    queues: BTreeMap<QueueKind, QueueState>,
    carrier: Carrier,
    prng: Prng,
    trace: Vec<TraceEntry>,
    failure: Option<Failure>,
    published: u64,
    expected_reliable: BTreeSet<u64>,
    published_transfers: BTreeSet<u64>,
    drop_first_reliable: bool,
}

impl Simulator {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let queues = QueueKind::ALL
            .into_iter()
            .map(|queue| (queue, QueueState::default()))
            .collect();
        Self {
            now: 0,
            sequence: 0,
            pending: BinaryHeap::new(),
            paths: BTreeMap::new(),
            queues,
            carrier: Carrier::Reliable,
            prng: Prng::new(seed),
            trace: Vec::new(),
            failure: None,
            published: 0,
            expected_reliable: BTreeSet::new(),
            published_transfers: BTreeSet::new(),
            drop_first_reliable: false,
        }
    }

    #[must_use]
    pub fn run(scenario: &Scenario) -> Trace {
        Self::run_inner(scenario, None)
    }

    #[must_use]
    pub fn run_negative_control(scenario: &Scenario, control: NegativeControl) -> Trace {
        Self::run_inner(scenario, Some(control))
    }

    fn run_inner(scenario: &Scenario, control: Option<NegativeControl>) -> Trace {
        if scenario.name.is_empty()
            || scenario.name.len() > MAX_NAME_BYTES
            || scenario.actions.len() > MAX_ACTIONS
            || scenario
                .actions
                .iter()
                .any(|scheduled| validate_action(&scheduled.action).is_err())
        {
            return Trace {
                scenario: "invalid".to_owned(),
                seed: scenario.seed,
                entries: vec![TraceEntry {
                    at: 0,
                    event: "failure InvalidScenario".to_owned(),
                }],
                outcome: Outcome::Failed(Failure::InvalidScenario),
            };
        }
        let mut simulator = Self::new(scenario.seed);
        simulator.drop_first_reliable = control == Some(NegativeControl::DropFirstReliableFrame);
        for scheduled in &scenario.actions {
            simulator.schedule_at(scheduled.at, Event::Action(scheduled.action));
        }
        while let Some(pending) = simulator.pending.pop() {
            simulator.now = pending.at;
            simulator.process(pending.event);
        }
        if simulator.failure.is_none() {
            let missing = simulator
                .expected_reliable
                .difference(&simulator.published_transfers)
                .count();
            if missing > 0 {
                simulator.fail(Failure::IncompleteReliable { missing });
            }
        }
        let outcome = if let Some(failure) = simulator.failure {
            Outcome::Failed(failure)
        } else if simulator.published > 0 {
            Outcome::Complete {
                published: simulator.published,
            }
        } else {
            Outcome::Quiescent
        };
        Trace {
            scenario: scenario.name.clone(),
            seed: scenario.seed,
            entries: simulator.trace,
            outcome,
        }
    }

    fn process(&mut self, event: Event) {
        match event {
            Event::Action(action) => self.process_action(action),
            Event::Deliver {
                path,
                carrier,
                transfer,
                bytes,
                attempt,
            } => self.deliver(path, carrier, transfer, bytes, attempt),
            Event::QueueEnter {
                queue,
                transfer,
                bytes,
            } => self.queue_enter(queue, transfer, bytes),
            Event::QueueDone {
                queue,
                transfer,
                bytes,
            } => self.queue_done(queue, transfer, bytes),
        }
    }

    fn process_action(&mut self, action: Action) {
        match action {
            Action::AddPath { path, mtu, latency } => {
                self.paths.insert(
                    path,
                    PathState {
                        mtu,
                        latency,
                        binding: 0,
                        loss_remaining: 0,
                        reorder_window: 0,
                    },
                );
                self.record(format!("path.add path={path} mtu={mtu} latency={latency}"));
            }
            Action::RemovePath { path } => {
                self.paths.remove(&path);
                self.record(format!("path.remove path={path}"));
            }
            Action::ChangeMtu { path, mtu } => {
                if let Some(state) = self.paths.get_mut(&path) {
                    state.mtu = mtu;
                    self.record(format!("path.mtu path={path} mtu={mtu}"));
                } else {
                    self.fail(Failure::CarrierUnavailable { path });
                }
            }
            Action::NatRebind { path, binding } => {
                if let Some(state) = self.paths.get_mut(&path) {
                    state.binding = binding;
                    self.record(format!("path.rebind path={path} binding={binding}"));
                } else {
                    self.fail(Failure::CarrierUnavailable { path });
                }
            }
            Action::LossBurst { path, packets } => {
                if let Some(state) = self.paths.get_mut(&path) {
                    state.loss_remaining = packets;
                    self.record(format!("path.loss path={path} packets={packets}"));
                } else {
                    self.fail(Failure::CarrierUnavailable { path });
                }
            }
            Action::Reorder { path, window } => {
                if let Some(state) = self.paths.get_mut(&path) {
                    state.reorder_window = window;
                    self.record(format!("path.reorder path={path} window={window}"));
                } else {
                    self.fail(Failure::CarrierUnavailable { path });
                }
            }
            Action::SwitchTransport { carrier } => {
                let previous = self.carrier;
                self.carrier = carrier;
                self.record(format!(
                    "transport.switch from={} to={}",
                    previous.name(),
                    carrier.name()
                ));
            }
            Action::Send {
                path,
                transfer,
                bytes,
            } => {
                if self.carrier != Carrier::Datagram {
                    self.expected_reliable.insert(transfer);
                }
                self.record(format!(
                    "transport.send carrier={} path={path} transfer={transfer} bytes={bytes}",
                    self.carrier.name()
                ));
                self.schedule_at(
                    self.now,
                    Event::Deliver {
                        path,
                        carrier: self.carrier,
                        transfer,
                        bytes,
                        attempt: 0,
                    },
                );
            }
            action @ (Action::QueueLimit { .. } | Action::QueueFault { .. }) => {
                self.process_queue_action(action);
            }
        }
    }

    fn process_queue_action(&mut self, action: Action) {
        match action {
            Action::QueueLimit {
                queue,
                bytes,
                latency,
            } => {
                if let Some(state) = self.queues.get_mut(&queue) {
                    state.capacity = bytes;
                    state.latency = latency;
                }
                self.record(format!(
                    "queue.configure queue={} capacity={bytes} latency={latency}",
                    queue.name()
                ));
            }
            Action::QueueFault { queue, operations } => {
                if let Some(state) = self.queues.get_mut(&queue) {
                    state.failures_remaining = operations;
                }
                self.record(format!(
                    "queue.fault queue={} operations={operations}",
                    queue.name()
                ));
            }
            _ => unreachable!("queue action helper received a network action"),
        }
    }

    fn deliver(&mut self, path: u16, carrier: Carrier, transfer: u64, bytes: u64, attempt: u32) {
        let Some(path_state) = self.paths.get_mut(&path) else {
            self.fail(Failure::CarrierUnavailable { path });
            return;
        };
        let mtu = path_state.mtu;
        if self.drop_first_reliable && carrier != Carrier::Datagram {
            self.drop_first_reliable = false;
            self.record(format!(
                "negative.drop carrier={} path={path} transfer={transfer}",
                carrier.name()
            ));
            return;
        }
        if carrier == Carrier::Datagram && bytes > u64::from(mtu) {
            self.fail(Failure::DatagramTooLarge { path, bytes, mtu });
            return;
        }
        if path_state.loss_remaining > 0 {
            path_state.loss_remaining = path_state
                .loss_remaining
                .checked_sub(1)
                .expect("positive loss count");
            let latency = path_state.latency;
            self.record(format!(
                "transport.loss carrier={} path={path} transfer={transfer} attempt={attempt}",
                carrier.name()
            ));
            if carrier != Carrier::Datagram {
                let Some(at) = self.now.checked_add(latency.saturating_mul(2)) else {
                    self.fail(Failure::TimeOverflow);
                    return;
                };
                self.schedule_at(
                    at,
                    Event::Deliver {
                        path,
                        carrier,
                        transfer,
                        bytes,
                        attempt: attempt.saturating_add(1),
                    },
                );
            }
            return;
        }
        let jitter = if path_state.reorder_window == 0 {
            0
        } else {
            self.prng.next() % (path_state.reorder_window + 1)
        };
        let Some(at) = self
            .now
            .checked_add(path_state.latency)
            .and_then(|tick| tick.checked_add(jitter))
        else {
            self.fail(Failure::TimeOverflow);
            return;
        };
        let binding = path_state.binding;
        self.record(format!(
            "transport.accept carrier={} path={path} binding={binding} transfer={transfer} attempt={attempt} deliver={at}",
            carrier.name()
        ));
        self.schedule_at(
            at,
            Event::QueueEnter {
                queue: QueueKind::Memory,
                transfer,
                bytes,
            },
        );
    }

    fn queue_enter(&mut self, queue: QueueKind, transfer: u64, bytes: u64) {
        let state = self.queues.get_mut(&queue).expect("all queues configured");
        if state.failures_remaining > 0 {
            state.failures_remaining = state
                .failures_remaining
                .checked_sub(1)
                .expect("positive failure count");
            self.fail(Failure::QueueFault { queue });
            return;
        }
        let Some(used) = state.used.checked_add(bytes) else {
            self.fail(Failure::QueueFull { queue });
            return;
        };
        if used > state.capacity {
            self.fail(Failure::QueueFull { queue });
            return;
        }
        state.used = used;
        let Some(at) = self.now.checked_add(state.latency) else {
            self.fail(Failure::TimeOverflow);
            return;
        };
        self.record(format!(
            "queue.enter queue={} transfer={transfer} bytes={bytes}",
            queue.name()
        ));
        self.schedule_at(
            at,
            Event::QueueDone {
                queue,
                transfer,
                bytes,
            },
        );
    }

    fn queue_done(&mut self, queue: QueueKind, transfer: u64, bytes: u64) {
        if let Some(state) = self.queues.get_mut(&queue) {
            state.used = state.used.saturating_sub(bytes);
        }
        self.record(format!(
            "queue.done queue={} transfer={transfer} bytes={bytes}",
            queue.name()
        ));
        if let Some(next) = queue.next() {
            self.schedule_at(
                self.now,
                Event::QueueEnter {
                    queue: next,
                    transfer,
                    bytes,
                },
            );
        } else {
            self.published = self.published.saturating_add(1);
            self.published_transfers.insert(transfer);
            self.record(format!(
                "transfer.published transfer={transfer} bytes={bytes}"
            ));
        }
    }

    fn schedule_at(&mut self, at: Tick, event: Event) {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        self.pending.push(Pending {
            at,
            sequence,
            event,
        });
    }

    fn record(&mut self, event: String) {
        self.trace.push(TraceEntry {
            at: self.now,
            event,
        });
    }

    fn fail(&mut self, failure: Failure) {
        self.record(format!("failure {failure:?}"));
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
    }
}

#[must_use]
pub fn shrink_failing(scenario: &Scenario) -> Scenario {
    let target = Simulator::run(scenario).outcome;
    let Outcome::Failed(_) = target else {
        return scenario.clone();
    };
    let mut candidate = scenario.clone();
    candidate.expected_trace = None;
    let mut granularity = 2;
    for _ in 0..MAX_ACTIONS {
        let Some(_) = candidate.actions.len().checked_sub(2) else {
            break;
        };
        let chunk = candidate.actions.len().div_ceil(granularity);
        let mut reduced = false;
        for start in (0..candidate.actions.len()).step_by(chunk) {
            let end = start.saturating_add(chunk).min(candidate.actions.len());
            let mut trial = candidate.clone();
            trial.actions.drain(start..end);
            if Simulator::run(&trial).outcome == target {
                candidate = trial;
                granularity = granularity.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
        }
        if !reduced {
            let Some(_) = candidate.actions.len().checked_sub(granularity) else {
                break;
            };
            granularity = granularity
                .saturating_add(granularity)
                .min(candidate.actions.len());
        }
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    const FALLBACK: &str = include_str!("../../../sim/scenarios/rebind-fallback.vot");
    const STORAGE_FAULT: &str = include_str!("../../../sim/scenarios/storage-fault.vot");

    #[test]
    fn same_seed_replays_byte_for_byte() {
        let scenario = Scenario::parse(FALLBACK).unwrap();
        let first = Simulator::run(&scenario);
        let second = Simulator::run(&scenario);
        assert_eq!(first, second);
        assert_eq!(first.outcome.expected(), scenario.expected);
        assert_eq!(first.canonical(), second.canonical());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(Some(first.digest()), scenario.expected_trace);
    }

    #[test]
    fn public_scenarios_round_trip() {
        for input in [FALLBACK, STORAGE_FAULT] {
            let scenario = Scenario::parse(input).unwrap();
            let encoded = scenario.encode();
            assert_eq!(Scenario::parse(&encoded).unwrap(), scenario);
            assert_eq!(
                Simulator::run(&scenario).outcome.expected(),
                scenario.expected
            );
            assert_eq!(
                Some(Simulator::run(&scenario).digest()),
                scenario.expected_trace
            );
        }
    }

    #[test]
    fn network_and_storage_faults_compose() {
        let scenario = Scenario::parse(STORAGE_FAULT).unwrap();
        let trace = Simulator::run(&scenario);
        assert!(
            trace
                .entries
                .iter()
                .any(|entry| entry.event.contains("transport.loss"))
        );
        assert_eq!(
            trace.outcome,
            Outcome::Failed(Failure::QueueFault {
                queue: QueueKind::Journal
            })
        );
    }

    #[test]
    fn shrinker_preserves_exact_failure() {
        let scenario = Scenario::parse(STORAGE_FAULT).unwrap();
        let expected = Simulator::run(&scenario).outcome;
        let shrunk = shrink_failing(&scenario);
        assert!(shrunk.actions.len() < scenario.actions.len());
        assert_eq!(Simulator::run(&shrunk).outcome, expected);
        assert_eq!(Scenario::parse(&shrunk.encode()).unwrap(), shrunk);
    }

    #[test]
    fn datagram_mtu_is_enforced() {
        let scenario = Scenario::parse(
            "VOT_SIM_SCENARIO_V1\nname mtu\nseed 1\nexpect failed\ntrace -\n\
             at 0 add-path 1 1200 1\n\
             at 1 switch datagram\n\
             at 2 send 1 1 1201\n",
        )
        .unwrap();
        assert!(matches!(
            Simulator::run(&scenario).outcome,
            Outcome::Failed(Failure::DatagramTooLarge { .. })
        ));
    }

    #[test]
    fn parser_rejects_unbounded_or_malformed_scenarios() {
        let oversized = "x".repeat(MAX_SCENARIO_BYTES + 1);
        assert_eq!(Scenario::parse(&oversized), Err(ScenarioError::TooLarge));
        assert_eq!(
            Scenario::parse("not-a-scenario"),
            Err(ScenarioError::InvalidHeader)
        );
    }

    #[test]
    fn seed_changes_reordered_trace() {
        let scenario = Scenario::parse(FALLBACK).unwrap();
        let mut different = scenario.clone();
        different.seed ^= u64::MAX;
        different.expected_trace = None;
        assert_ne!(
            Simulator::run(&scenario).entries,
            Simulator::run(&different).entries
        );
    }

    #[test]
    fn removed_paths_are_unavailable() {
        let scenario = Scenario {
            name: "removed-path".to_owned(),
            seed: 1,
            expected: ExpectedOutcome::Failed,
            expected_trace: None,
            actions: vec![
                ScheduledAction {
                    at: 0,
                    action: Action::AddPath {
                        path: 1,
                        mtu: 1500,
                        latency: 1,
                    },
                },
                ScheduledAction {
                    at: 1,
                    action: Action::RemovePath { path: 1 },
                },
                ScheduledAction {
                    at: 2,
                    action: Action::Send {
                        path: 1,
                        transfer: 1,
                        bytes: 1,
                    },
                },
            ],
        };
        assert_eq!(
            Simulator::run(&scenario).outcome,
            Outcome::Failed(Failure::CarrierUnavailable { path: 1 })
        );
    }

    #[test]
    fn direct_construction_still_enforces_action_bounds() {
        let scenario = Scenario {
            name: "too-many".to_owned(),
            seed: 1,
            expected: ExpectedOutcome::Failed,
            expected_trace: None,
            actions: vec![
                ScheduledAction {
                    at: 0,
                    action: Action::SwitchTransport {
                        carrier: Carrier::Reliable,
                    },
                };
                MAX_ACTIONS + 1
            ],
        };
        assert_eq!(
            Simulator::run(&scenario).outcome,
            Outcome::Failed(Failure::InvalidScenario)
        );
    }

    fn scenario_text(name: &str, expected: &str, body: &str) -> String {
        format!("VOT_SIM_SCENARIO_V1\nname {name}\nseed 1\nexpect {expected}\ntrace -\n{body}")
    }

    fn direct_scenario(name: String, actions: Vec<ScheduledAction>) -> Scenario {
        Scenario {
            name,
            seed: 1,
            expected: ExpectedOutcome::Quiescent,
            expected_trace: None,
            actions,
        }
    }

    #[test]
    fn public_limits_are_frozen() {
        assert_eq!(MAX_SCENARIO_BYTES, 1_048_576);
        assert_eq!(MAX_ACTIONS, 4096);
        assert_eq!(MAX_NAME_BYTES, 64);
        assert_eq!(MAX_TRANSFER_BYTES, 134_217_728);
        assert_eq!(TransportAck::new(42).sequence(), 42);
    }

    #[test]
    fn parser_accepts_exact_size_and_rejects_one_byte_more() {
        let prefix = scenario_text("boundary", "quiescent", "#");
        let exact = format!("{prefix}{}", "x".repeat(MAX_SCENARIO_BYTES - prefix.len()));
        assert_eq!(exact.len(), MAX_SCENARIO_BYTES);
        assert!(Scenario::parse(&exact).is_ok());
        let over = format!("{exact}x");
        assert_eq!(Scenario::parse(&over), Err(ScenarioError::TooLarge));
    }

    #[test]
    fn parser_validates_each_name_condition() {
        assert_eq!(
            Scenario::parse(&scenario_text("", "quiescent", "")),
            Err(ScenarioError::InvalidName)
        );
        assert!(
            Scenario::parse(&scenario_text(&"a".repeat(MAX_NAME_BYTES), "quiescent", "")).is_ok()
        );
        assert_eq!(
            Scenario::parse(&scenario_text(
                &"a".repeat(MAX_NAME_BYTES + 1),
                "quiescent",
                ""
            )),
            Err(ScenarioError::InvalidName)
        );
        assert_eq!(
            Scenario::parse(&scenario_text("bad/name", "quiescent", "")),
            Err(ScenarioError::InvalidName)
        );
    }

    #[test]
    fn parser_covers_outcomes_carriers_and_remove_path() {
        let scenario = Scenario::parse(&scenario_text(
            "grammar",
            "quiescent",
            "at 0 switch reliable\nat 1 remove-path 7\n",
        ))
        .unwrap();
        assert_eq!(scenario.expected, ExpectedOutcome::Quiescent);
        assert_eq!(
            scenario.actions,
            vec![
                ScheduledAction {
                    at: 0,
                    action: Action::SwitchTransport {
                        carrier: Carrier::Reliable
                    }
                },
                ScheduledAction {
                    at: 1,
                    action: Action::RemovePath { path: 7 }
                }
            ]
        );
    }

    #[test]
    fn parser_enforces_action_count_exactly() {
        let line = "at 0 switch reliable\n";
        let exact = scenario_text("actions", "quiescent", &line.repeat(MAX_ACTIONS));
        assert_eq!(Scenario::parse(&exact).unwrap().actions.len(), MAX_ACTIONS);
        let over = scenario_text("actions", "quiescent", &line.repeat(MAX_ACTIONS + 1));
        assert_eq!(Scenario::parse(&over), Err(ScenarioError::TooManyActions));
    }

    #[test]
    fn every_action_bound_rejects_each_bad_operand() {
        let invalid = [
            Action::AddPath {
                path: 1,
                mtu: 575,
                latency: 1,
            },
            Action::AddPath {
                path: 1,
                mtu: 576,
                latency: 0,
            },
            Action::ChangeMtu { path: 1, mtu: 575 },
            Action::LossBurst {
                path: 1,
                packets: u32::try_from(MAX_ACTIONS).unwrap() + 1,
            },
            Action::Reorder {
                path: 1,
                window: 1_000_000_001,
            },
            Action::Send {
                path: 1,
                transfer: 1,
                bytes: 0,
            },
            Action::Send {
                path: 1,
                transfer: 1,
                bytes: MAX_TRANSFER_BYTES + 1,
            },
            Action::QueueLimit {
                queue: QueueKind::Memory,
                bytes: 0,
                latency: 1,
            },
            Action::QueueLimit {
                queue: QueueKind::Memory,
                bytes: MAX_TRANSFER_BYTES + 1,
                latency: 1,
            },
            Action::QueueLimit {
                queue: QueueKind::Memory,
                bytes: 1,
                latency: 0,
            },
            Action::QueueFault {
                queue: QueueKind::Memory,
                operations: u32::try_from(MAX_ACTIONS).unwrap() + 1,
            },
        ];
        for action in invalid {
            assert_eq!(validate_action(&action), Err(ScenarioError::InvalidValue));
        }
    }

    #[test]
    fn every_action_bound_accepts_its_exact_edge() {
        let valid = [
            Action::AddPath {
                path: 1,
                mtu: 576,
                latency: 1,
            },
            Action::ChangeMtu { path: 1, mtu: 576 },
            Action::LossBurst {
                path: 1,
                packets: u32::try_from(MAX_ACTIONS).unwrap(),
            },
            Action::Reorder {
                path: 1,
                window: 1_000_000_000,
            },
            Action::Send {
                path: 1,
                transfer: 1,
                bytes: 1,
            },
            Action::Send {
                path: 1,
                transfer: 1,
                bytes: MAX_TRANSFER_BYTES,
            },
            Action::QueueLimit {
                queue: QueueKind::Memory,
                bytes: MAX_TRANSFER_BYTES,
                latency: 1,
            },
            Action::QueueFault {
                queue: QueueKind::Memory,
                operations: u32::try_from(MAX_ACTIONS).unwrap(),
            },
        ];
        for action in valid {
            assert_eq!(validate_action(&action), Ok(()));
        }
    }

    #[test]
    fn direct_scenarios_enforce_name_and_action_edges() {
        assert!(matches!(
            Simulator::run(&direct_scenario(String::new(), vec![])).outcome,
            Outcome::Failed(Failure::InvalidScenario)
        ));
        assert_eq!(
            Simulator::run(&direct_scenario("a".repeat(MAX_NAME_BYTES), vec![])).outcome,
            Outcome::Quiescent
        );
        assert!(matches!(
            Simulator::run(&direct_scenario("a".repeat(MAX_NAME_BYTES + 1), vec![])).outcome,
            Outcome::Failed(Failure::InvalidScenario)
        ));
        let switches = vec![
            ScheduledAction {
                at: 0,
                action: Action::SwitchTransport {
                    carrier: Carrier::Reliable,
                },
            };
            MAX_ACTIONS
        ];
        assert_eq!(
            Simulator::run(&direct_scenario("edge".to_owned(), switches)).outcome,
            Outcome::Quiescent
        );
        let invalid = vec![ScheduledAction {
            at: 0,
            action: Action::Send {
                path: 1,
                transfer: 1,
                bytes: 0,
            },
        }];
        assert!(matches!(
            Simulator::run(&direct_scenario("invalid".to_owned(), invalid)).outcome,
            Outcome::Failed(Failure::InvalidScenario)
        ));
    }

    #[test]
    fn exact_capacity_and_exact_mtu_complete() {
        let queue = Scenario::parse(&scenario_text(
            "capacity",
            "complete",
            "at 0 add-path 1 1500 1\nat 1 queue-limit memory 1024 1\nat 2 send 1 1 1024\n",
        ))
        .unwrap();
        assert_eq!(
            Simulator::run(&queue).outcome,
            Outcome::Complete { published: 1 }
        );
        let datagram = Scenario::parse(&scenario_text(
            "mtu-edge",
            "complete",
            "at 0 add-path 1 1200 1\nat 1 switch datagram\nat 2 send 1 1 1200\n",
        ))
        .unwrap();
        assert_eq!(
            Simulator::run(&datagram).outcome,
            Outcome::Complete { published: 1 }
        );
    }

    #[test]
    fn trace_digest_and_prng_are_exact() {
        let trace = Simulator::run(&Scenario::parse(FALLBACK).unwrap());
        assert_eq!(trace.digest_hex(), hex_digest(&trace.digest()));
        let mut prng = Prng::new(1);
        assert_eq!(prng.next(), 10_451_216_379_200_822_465);
    }

    #[test]
    fn shrinker_result_is_exact_and_nonfailures_are_unchanged() {
        let scenario = Scenario::parse(STORAGE_FAULT).unwrap();
        let shrunk = shrink_failing(&scenario);
        assert_eq!(shrunk.actions.len(), 3);
        assert_eq!(
            shrunk.encode(),
            "VOT_SIM_SCENARIO_V1\nname storage-fault\nseed 1099511627791\nexpect failed\ntrace -\n\
             at 0 add-path 3 1500 3\n\
             at 3 queue-fault journal 1\n\
             at 4 send 3 22 1024\n"
        );
        let quiescent = direct_scenario("quiet".to_owned(), vec![]);
        assert_eq!(shrink_failing(&quiescent), quiescent);
    }
}
