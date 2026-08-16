//! The receiving end of datagram FEC: credit, the epoch table, and generation
//! assembly (`spec/fec.md` sections 11 and 12). Pure state; the caller moves
//! frames and datagrams.

use std::collections::BTreeMap;

use crate::plan::{EpochPlan, SourceSpan};
use crate::{Error, decode};

/// One `DATAGRAM_CREDIT`: the caps a newer credit epoch replaces whole.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credit {
    pub credit_epoch: u64,
    pub max_unretired_bytes: u64,
    pub max_active_generations: u64,
    pub max_decode_work: u64,
    pub max_open_epochs: u64,
}

/// What `CODING_EPOCH_OPEN` did at this end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Open {
    Opened,
    /// An exact repeat; nothing changed.
    Repeated,
    /// Past `max_open_epochs`, past `MAX_TRACKED_GENERATIONS`, or before
    /// any credit: the epoch stays unknown and the caller answers `GEN_DONE`
    /// outcome refused.
    Refused,
}

/// Why a symbol was dropped. None of these is a session error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Drop {
    NoCredit,
    UnknownEpoch,
    WrongLength,
    EsiOutOfRange,
    GenerationPastEpoch,
    /// A source ESI entirely past the range, which is never sent.
    ZeroSource,
    Duplicate,
    GenerationDone,
    PastCredit,
}

/// A generation reconstructed: `bytes` are the object bytes it covers,
/// padding removed, starting at `offset`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded {
    pub generation: u32,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// What one symbol did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Symbol {
    /// Held for a generation that is not complete yet. `first` marks the
    /// symbol that opened the generation, which is the one occasion a
    /// caller reports its state unprompted: a generation nothing has
    /// arrived for is one the sender has no reason to hear about.
    Stored {
        first: bool,
    },
    Decoded(Decoded),
    /// The generation needed elimination and the decode budget is spent; it
    /// is retired and the caller answers `GEN_DONE` outcome abandoned. The
    /// state travels with it because the generation is gone from `live` by
    /// the time the caller sees this, so [`Receiver::report`] can no longer
    /// answer for it, and what a generation was missing when it was given up
    /// on is the loss sample worth keeping.
    Abandoned {
        generation: u32,
        state: Report,
    },
    Dropped(Drop),
}

/// One `GEN_STATE` this end would send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub sequence: u64,
    pub received: u8,
    pub missing_sources: Vec<u8>,
}

/// The `GEN_STATE` for a live generation, and the sequence bump that makes
/// it newer than any this end sent before.
///
/// One function for both the caller's own request and the state carried out
/// of an abandonment, so the sequence advances in exactly one place.
fn report_of(plan: &EpochPlan, generation: u32, slot: &mut Generation) -> Report {
    slot.sequence += 1;
    let sent = plan.sent_source_count(generation);
    Report {
        sequence: slot.sequence,
        received: u8::try_from(slot.received).expect("at most k + r"),
        missing_sources: (0..sent)
            .map(|j| u8::try_from(j).expect("a source ESI"))
            .filter(|j| !slot.has(*j))
            .collect(),
    }
}

/// The most generations one epoch may have for this receiver to track it:
/// one bit per generation is allocated at open, so this bounds that
/// allocation (128 KiB) and an epoch past it is refused like one past
/// `max_open_epochs`. At the shipped profile it is 64 GiB per epoch.
pub const MAX_TRACKED_GENERATIONS: u64 = 1 << 20;

/// A live generation: only the symbols that arrived, at most `k - 1` of them
/// since the `k`-th completes it.
#[derive(Debug)]
struct Generation {
    symbols: Vec<(u8, Vec<u8>)>,
    /// One bit per ESI in hand, so a duplicate is found without a scan.
    seen: u128,
    /// Distinct symbols in hand, zero sources included.
    received: usize,
    sequence: u64,
}

impl Generation {
    fn has(&self, esi: u8) -> bool {
        self.seen & (1_u128 << esi) != 0
    }
}

#[derive(Debug)]
struct Epoch {
    plan: EpochPlan,
    /// Live generations only; a done one leaves the map and sets its bit.
    live: BTreeMap<u32, Generation>,
    /// One bit per generation of the epoch, set when it retires.
    done: Vec<u64>,
}

impl Epoch {
    fn is_done(&self, generation: u32) -> bool {
        self.done[(generation / 64) as usize] & (1_u64 << (generation % 64)) != 0
    }

    fn mark_done(&mut self, generation: u32) {
        self.done[(generation / 64) as usize] |= 1_u64 << (generation % 64);
    }
}

/// The two levels credit caps, kept apart from the epoch table so the two
/// can be borrowed together.
#[derive(Debug, Default)]
struct Counters {
    active_generations: u64,
    unretired_bytes: u64,
}

impl Counters {
    fn admit(&mut self, credit: Credit, bytes: u64) -> bool {
        if self.active_generations >= credit.max_active_generations
            || self
                .unretired_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > credit.max_unretired_bytes)
        {
            return false;
        }
        self.active_generations += 1;
        self.unretired_bytes += bytes;
        true
    }

    fn retire(&mut self, bytes: u64) {
        self.active_generations -= 1;
        self.unretired_bytes -= bytes;
    }
}

/// The receiver's whole FEC state for one session.
#[derive(Debug, Default)]
pub struct Receiver {
    credit: Option<Credit>,
    decode_work_spent: u64,
    epochs: BTreeMap<u32, Epoch>,
    counters: Counters,
}

/// The section 12 drop rows a symbol's header and length decide on their own.
fn admit(plan: &EpochPlan, generation: u32, esi: u8, bytes: &[u8]) -> Result<usize, Drop> {
    let geometry = plan.geometry();
    if bytes.len() != geometry.symbol_length() {
        return Err(Drop::WrongLength);
    }
    if usize::from(esi) >= geometry.symbol_count() {
        return Err(Drop::EsiOutOfRange);
    }
    if !plan.holds(generation) {
        return Err(Drop::GenerationPastEpoch);
    }
    let sent_sources = plan.sent_source_count(generation);
    if usize::from(esi) < geometry.source_count() && usize::from(esi) >= sent_sources {
        return Err(Drop::ZeroSource);
    }
    Ok(sent_sources)
}

/// Every sent source in hand: the sources themselves, no elimination.
fn take_sources(slot: &mut Generation, sent_sources: usize) -> Option<Vec<Vec<u8>>> {
    if (0..sent_sources).any(|j| !slot.has(u8::try_from(j).expect("a source ESI"))) {
        return None;
    }
    // `k` in hand and every sent source among them: the zero sources make
    // up the rest, so what is stored is exactly the sent sources.
    let mut symbols = std::mem::take(&mut slot.symbols);
    debug_assert_eq!(symbols.len(), sent_sources);
    symbols.sort_by_key(|(esi, _)| *esi);
    Some(symbols.into_iter().map(|(_, symbol)| symbol).collect())
}

/// `k` distinct symbols in hand, not all of them sources: eliminate.
fn eliminate(plan: &EpochPlan, slot: &Generation, sent_sources: usize) -> Vec<Vec<u8>> {
    let geometry = plan.geometry();
    let zero = vec![0_u8; geometry.symbol_length()];
    let mut received: Vec<(usize, &[u8])> = Vec::with_capacity(geometry.source_count());
    for (esi, symbol) in &slot.symbols {
        received.push((usize::from(*esi), symbol.as_slice()));
    }
    for esi in sent_sources..geometry.source_count() {
        received.push((esi, zero.as_slice()));
    }
    let mut decoded = decode(geometry, &received).expect("k distinct symbols in hand");
    decoded.truncate(sent_sources);
    decoded
}

/// The object bytes of a generation from its sent sources, padding removed.
fn assemble(plan: &EpochPlan, generation: u32, sources: &[Vec<u8>]) -> Decoded {
    let (offset, length) = plan.generation_span(generation);
    let mut out = Vec::with_capacity(usize::try_from(length).expect("at most k * L"));
    for (j, symbol) in sources.iter().enumerate() {
        match plan.source_span(generation, u8::try_from(j).expect("a source ESI")) {
            SourceSpan::Bytes { bytes, .. } => out.extend_from_slice(&symbol[..bytes]),
            SourceSpan::Zero => unreachable!("only sent sources are assembled"),
        }
    }
    debug_assert_eq!(out.len() as u64, length);
    Decoded {
        generation,
        offset,
        bytes: out,
    }
}

impl Receiver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs a newer credit epoch. Returns whether it was newer; an older
    /// or equal one is ignored. Decode work starts over under new credit.
    pub fn credit(&mut self, credit: Credit) -> bool {
        if self
            .credit
            .is_some_and(|held| held.credit_epoch >= credit.credit_epoch)
        {
            return false;
        }
        self.credit = Some(credit);
        self.decode_work_spent = 0;
        true
    }

    /// `CODING_EPOCH_OPEN`.
    ///
    /// # Errors
    /// A repeat of a known epoch with a different plan is
    /// `CODING_EPOCH_CONFLICT`, reported as `InvalidGeometry` here.
    ///
    /// # Panics
    /// Never: the bitmap size is bounded by `MAX_TRACKED_GENERATIONS`.
    pub fn open(&mut self, plan: EpochPlan) -> Result<Open, Error> {
        if let Some(known) = self.epochs.get(&plan.epoch()) {
            return if known.plan == plan {
                Ok(Open::Repeated)
            } else {
                Err(Error::InvalidGeometry)
            };
        }
        let Some(credit) = self.credit else {
            return Ok(Open::Refused);
        };
        if self.epochs.len() as u64 >= credit.max_open_epochs
            || plan.generation_count() > MAX_TRACKED_GENERATIONS
        {
            return Ok(Open::Refused);
        }
        let words = usize::try_from(plan.generation_count().div_ceil(64)).expect("bounded above");
        self.epochs.insert(
            plan.epoch(),
            Epoch {
                plan,
                live: BTreeMap::new(),
                done: vec![0; words],
            },
        );
        Ok(Open::Opened)
    }

    /// One symbol datagram, already split into its header and bytes.
    ///
    /// # Panics
    /// Never: every index is checked by `admit` and every expect names an
    /// invariant the same call established.
    pub fn symbol(&mut self, epoch: u32, generation: u32, esi: u8, bytes: &[u8]) -> Symbol {
        let Some(credit) = self.credit else {
            return Symbol::Dropped(Drop::NoCredit);
        };
        let Some(state) = self.epochs.get_mut(&epoch) else {
            return Symbol::Dropped(Drop::UnknownEpoch);
        };
        let plan = state.plan;
        let sent_sources = match admit(&plan, generation, esi, bytes) {
            Ok(sent) => sent,
            Err(drop) => return Symbol::Dropped(drop),
        };
        let geometry = plan.geometry();
        if state.is_done(generation) {
            return Symbol::Dropped(Drop::GenerationDone);
        }
        let mut first = false;
        if let Some(existing) = state.live.get(&generation) {
            if existing.has(esi) {
                return Symbol::Dropped(Drop::Duplicate);
            }
        } else {
            if !self.counters.admit(credit, plan.generation_bytes()) {
                return Symbol::Dropped(Drop::PastCredit);
            }
            state.live.insert(
                generation,
                Generation {
                    symbols: Vec::new(),
                    seen: 0,
                    // Zero sources are in hand from the start.
                    received: geometry.source_count() - sent_sources,
                    sequence: 0,
                },
            );
            first = true;
        }
        let slot = state.live.get_mut(&generation).expect("inserted above");
        slot.symbols.push((esi, bytes.to_vec()));
        slot.seen |= 1_u128 << esi;
        slot.received += 1;
        if slot.received < geometry.source_count() {
            return Symbol::Stored { first };
        }
        let sources = if let Some(sources) = take_sources(slot, sent_sources) {
            sources
        } else {
            let work = plan.generation_bytes();
            if self
                .decode_work_spent
                .checked_add(work)
                .is_none_or(|spent| spent > credit.max_decode_work)
            {
                let state_report = report_of(
                    &plan,
                    generation,
                    state.live.get_mut(&generation).expect("live above"),
                );
                state.live.remove(&generation);
                state.mark_done(generation);
                self.counters.retire(plan.generation_bytes());
                return Symbol::Abandoned {
                    generation,
                    state: state_report,
                };
            }
            self.decode_work_spent += work;
            eliminate(&plan, slot, sent_sources)
        };
        state.live.remove(&generation);
        state.mark_done(generation);
        self.counters.retire(plan.generation_bytes());
        Symbol::Decoded(assemble(&plan, generation, &sources))
    }

    /// The `GEN_STATE` to send for a generation this end holds, with the
    /// next sequence. `None` for an unknown epoch, a generation past it, a
    /// generation no symbol has opened, or one already done.
    ///
    /// # Panics
    /// Never: counts are bounded by the geometry.
    pub fn report(&mut self, epoch: u32, generation: u32) -> Option<Report> {
        let state = self.epochs.get_mut(&epoch)?;
        let plan = state.plan;
        Some(report_of(
            &plan,
            generation,
            state.live.get_mut(&generation)?,
        ))
    }

    /// Gives up on a generation this end holds; it retires as abandoned and
    /// the caller sends `GEN_DONE` outcome abandoned. Returns whether there
    /// was such a live generation.
    pub fn abandon(&mut self, epoch: u32, generation: u32) -> bool {
        let Some(state) = self.epochs.get_mut(&epoch) else {
            return false;
        };
        let plan = state.plan;
        if state.live.remove(&generation).is_none() {
            return false;
        }
        state.mark_done(generation);
        self.counters.retire(plan.generation_bytes());
        true
    }

    /// `CODING_EPOCH_CLOSE`: retires every live generation and forgets the
    /// epoch. Returns whether the epoch was known.
    pub fn close(&mut self, epoch: u32) -> bool {
        let Some(state) = self.epochs.remove(&epoch) else {
            return false;
        };
        for _ in 0..state.live.len() {
            self.counters.retire(state.plan.generation_bytes());
        }
        true
    }

    #[must_use]
    pub fn open_epochs(&self) -> usize {
        self.epochs.len()
    }

    #[must_use]
    pub const fn active_generations(&self) -> u64 {
        self.counters.active_generations
    }

    #[must_use]
    pub const fn unretired_bytes(&self) -> u64 {
        self.counters.unretired_bytes
    }

    #[must_use]
    pub const fn decode_work_spent(&self) -> u64 {
        self.decode_work_spent
    }

    #[must_use]
    pub const fn credit_held(&self) -> Option<Credit> {
        self.credit
    }
}
