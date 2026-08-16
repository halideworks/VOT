//! The sending end of datagram FEC: what may be opened and sent under the
//! credit the receiver extended, and how a generation's bytes become symbols.

use std::collections::BTreeMap;

use crate::plan::{EpochPlan, SourceSpan};
use crate::receiver::Credit;
use crate::{Error, encode};

/// The symbols of one generation, in the order a sender puts them on the
/// wire: the sent sources (`0..sent`), then every repair symbol.
///
/// `bytes` are the object bytes the generation covers, exactly
/// `plan.generation_span(generation).1` of them; a short last generation is
/// padded here and its all-zero sources are never produced.
///
/// # Errors
/// `InvalidSymbol` when `bytes` is not the generation's length;
/// `InvalidGeometry` when `generation` is past the epoch.
///
/// # Panics
/// Never: every span the plan yields lies inside `bytes` once its length is
/// checked.
pub fn encode_generation(
    plan: &EpochPlan,
    generation: u32,
    bytes: &[u8],
) -> Result<Vec<(u8, Vec<u8>)>, Error> {
    if !plan.holds(generation) {
        return Err(Error::InvalidGeometry);
    }
    let (_, length) = plan.generation_span(generation);
    if bytes.len() as u64 != length {
        return Err(Error::InvalidSymbol);
    }
    let geometry = plan.geometry();
    let l = geometry.symbol_length();
    let sent = plan.sent_source_count(generation);
    let mut sources: Vec<Vec<u8>> = Vec::with_capacity(geometry.source_count());
    for j in 0..geometry.source_count() {
        let mut symbol = vec![0_u8; l];
        if let SourceSpan::Bytes { offset, bytes: n } =
            plan.source_span(generation, u8::try_from(j).expect("a source ESI"))
        {
            let start = usize::try_from(offset - plan.generation_span(generation).0)
                .expect("inside one generation");
            symbol[..n].copy_from_slice(&bytes[start..start + n]);
        }
        sources.push(symbol);
    }
    let borrowed: Vec<&[u8]> = sources.iter().map(Vec::as_slice).collect();
    let repair = encode(geometry, &borrowed)?;
    let mut out = Vec::with_capacity(sent + repair.len());
    for (j, symbol) in sources.into_iter().enumerate().take(sent) {
        out.push((u8::try_from(j).expect("a source ESI"), symbol));
    }
    for (i, symbol) in repair.into_iter().enumerate() {
        out.push((
            u8::try_from(geometry.source_count() + i).expect("below 80"),
            symbol,
        ));
    }
    Ok(out)
}

/// What the receiver said a generation became.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Done {
    Decoded,
    Abandoned,
}

#[derive(Debug)]
struct Epoch {
    plan: EpochPlan,
    /// Generations this end has begun sending, with the outcome once known.
    generations: BTreeMap<u32, Option<Done>>,
    /// The highest `GEN_STATE` sequence accepted per generation.
    sequences: BTreeMap<u32, u64>,
}

/// The sender's whole FEC state for one session.
#[derive(Debug, Default)]
pub struct Sender {
    credit: Option<Credit>,
    epochs: BTreeMap<u32, Epoch>,
    active_generations: u64,
    unretired_bytes: u64,
}

impl Sender {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs a newer credit epoch; an older or equal one is ignored.
    pub fn credit(&mut self, credit: Credit) -> bool {
        if self
            .credit
            .is_some_and(|held| held.credit_epoch >= credit.credit_epoch)
        {
            return false;
        }
        self.credit = Some(credit);
        true
    }

    /// Whether one more epoch may be opened under the credit seen.
    #[must_use]
    pub fn may_open(&self) -> bool {
        self.credit
            .is_some_and(|credit| (self.epochs.len() as u64) < credit.max_open_epochs)
    }

    /// Records an epoch this end is about to announce.
    ///
    /// # Errors
    /// `InvalidGeometry` when the identifier is in use or credit forbids it.
    pub fn open(&mut self, plan: EpochPlan) -> Result<(), Error> {
        if self.epochs.contains_key(&plan.epoch()) || !self.may_open() {
            return Err(Error::InvalidGeometry);
        }
        self.epochs.insert(
            plan.epoch(),
            Epoch {
                plan,
                generations: BTreeMap::new(),
                sequences: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Whether the first symbol of one more generation may go out now.
    #[must_use]
    pub fn may_begin(&self, epoch: u32) -> bool {
        let Some(credit) = self.credit else {
            return false;
        };
        let Some(state) = self.epochs.get(&epoch) else {
            return false;
        };
        self.active_generations < credit.max_active_generations
            && self
                .unretired_bytes
                .checked_add(state.plan.generation_bytes())
                .is_some_and(|total| total <= credit.max_unretired_bytes)
    }

    /// Charges one generation before its first symbol is sent.
    ///
    /// # Errors
    /// `InvalidGeometry` for an unknown epoch, a generation past it, one
    /// already begun, or credit that forbids it.
    ///
    /// # Panics
    /// Never: `may_begin` has just found the epoch.
    pub fn begin(&mut self, epoch: u32, generation: u32) -> Result<(), Error> {
        if !self.may_begin(epoch) {
            return Err(Error::InvalidGeometry);
        }
        let state = self.epochs.get_mut(&epoch).expect("may_begin checked");
        if !state.plan.holds(generation) || state.generations.contains_key(&generation) {
            return Err(Error::InvalidGeometry);
        }
        let bytes = state.plan.generation_bytes();
        state.generations.insert(generation, None);
        self.active_generations += 1;
        self.unretired_bytes += bytes;
        Ok(())
    }

    /// `GEN_STATE` from the receiver. Returns whether it was newer than what
    /// this end already had for that generation; ignored otherwise, and for
    /// an epoch or generation this end does not have live.
    pub fn state(&mut self, epoch: u32, generation: u32, sequence: u64) -> bool {
        let Some(state) = self.epochs.get_mut(&epoch) else {
            return false;
        };
        if state.generations.get(&generation) != Some(&None) {
            return false;
        }
        let held = state.sequences.entry(generation).or_insert(0);
        if sequence <= *held {
            return false;
        }
        *held = sequence;
        true
    }

    /// `GEN_DONE` from the receiver for one generation. Retires it. Returns
    /// whether it was live; a repeat or an unknown one is ignored.
    pub fn done(&mut self, epoch: u32, generation: u32, done: Done) -> bool {
        let Some(state) = self.epochs.get_mut(&epoch) else {
            return false;
        };
        let bytes = state.plan.generation_bytes();
        match state.generations.get_mut(&generation) {
            Some(slot @ None) => {
                *slot = Some(done);
                self.active_generations -= 1;
                self.unretired_bytes -= bytes;
                true
            }
            _ => false,
        }
    }

    /// `GEN_DONE` outcome refused: the receiver never held the epoch. Every
    /// live generation retires as abandoned and the epoch is forgotten, so
    /// the caller sends `CODING_EPOCH_CLOSE` and moves the bytes to the
    /// reliable path. Returns whether the epoch was known.
    pub fn refused(&mut self, epoch: u32) -> bool {
        self.close(epoch)
    }

    /// This end closes an epoch: every live generation retires and the
    /// identifier is spent. Returns whether the epoch was known.
    pub fn close(&mut self, epoch: u32) -> bool {
        let Some(state) = self.epochs.remove(&epoch) else {
            return false;
        };
        let live = state.generations.values().filter(|d| d.is_none()).count() as u64;
        self.active_generations -= live;
        self.unretired_bytes -= live * state.plan.generation_bytes();
        true
    }

    /// The outcome the receiver reported for a generation, `Some(None)` while
    /// live, `None` when the epoch or generation is not known.
    #[must_use]
    pub fn outcome(&self, epoch: u32, generation: u32) -> Option<Option<Done>> {
        self.epochs
            .get(&epoch)?
            .generations
            .get(&generation)
            .copied()
    }

    #[must_use]
    pub fn open_epochs(&self) -> usize {
        self.epochs.len()
    }

    #[must_use]
    pub const fn active_generations(&self) -> u64 {
        self.active_generations
    }

    #[must_use]
    pub const fn unretired_bytes(&self) -> u64 {
        self.unretired_bytes
    }
}
