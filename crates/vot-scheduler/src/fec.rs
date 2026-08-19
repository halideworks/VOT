//! Datagram FEC intake for a receiving session (`spec/fec.md` sections 9 to
//! 12, ADR-0040): the epoch table, the symbol path, and the join between a
//! decoded generation and the proof bundle that vouches for its bytes.
//!
//! A serve that answers a range over the datagram path announces the same
//! `PROOF_BUNDLE` it would have sent reliably, with `data_record_count` equal
//! to the epoch's generation count, and opens one coding epoch whose range is
//! exactly the bundle's covered range. Each generation this end decodes
//! becomes one `DataRecord` of that bundle, so verification, replay, and
//! delivery are the bundle path's, unchanged. Everything here that arrives
//! for state this end does not hold is dropped, as section 12 says.

use std::collections::{BTreeMap, VecDeque};

use vot_codec::frames::{
    CodingEpochClose, CodingEpochOpen, DataRecord, GenDone, GenOutcome, GenState,
    SYMBOL_HEADER_LEN, SymbolHeader, TypedFrame,
};
use vot_fec::{Credit, Decoded, EpochPlan, Open, Receiver, Report, Symbol};

/// Decoded generations held for a bundle that has not arrived yet, at most
/// this many and this many bytes across every epoch. Datagrams overtake the
/// control stream, so a few are normal; past either bound the oldest goes
/// and the reliable path repairs it. Their FEC credit was released when they
/// decoded, so this is the whole bound on them.
pub(crate) const MAX_ORPHAN_GENERATIONS: usize = 16;

/// Most `GEN_STATE` frames held for sending at once.
///
/// A state is advisory (`spec/fec.md` section 11), so one this end has no
/// room for is dropped rather than queued. Without that bound the datagram
/// path can mint them faster than the control stream drains: one arrives per
/// generation opened, a peer that stops reading leaves everything queued,
/// and closing an epoch frees the credit that limits how many generations
/// may be live, so opening and closing epochs mints another queue's worth
/// each time. Credit and done frames are never dropped, because the
/// sender's own state machine waits on them.
pub(crate) const MAX_OWED_STATES: usize = 256;
pub(crate) const MAX_ORPHAN_BYTES: usize = 16 * 65_536;

/// The bundle a decoded generation belongs to: the object root and the exact
/// covered range the epoch was opened over.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Cover {
    pub(crate) root: [u8; 32],
    pub(crate) offset: u64,
    pub(crate) length: u64,
}

#[derive(Clone, Copy, Debug)]
struct OpenEpoch {
    cover: Cover,
    plan: EpochPlan,
}

impl Cover {
    pub(crate) const fn of(open: &CodingEpochOpen) -> Self {
        Self {
            root: open.object.root,
            offset: open.offset,
            length: open.length,
        }
    }
}

/// One generation's bytes waiting for its bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Orphan {
    pub(crate) cover: Cover,
    pub(crate) generation: u32,
    pub(crate) offset: u64,
    pub(crate) bytes: Vec<u8>,
}

/// A frame this end owes the sender, in the order to send them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Owed {
    Credit(Credit),
    State(GenState),
    Done(GenDone),
}

/// What one accepted event yielded for the bundle path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Joined {
    pub(crate) cover: Cover,
    pub(crate) generation: u32,
    /// The record's absolute object offset, as `DataRecord` carries it.
    pub(crate) plaintext_offset: u64,
    pub(crate) bytes: Vec<u8>,
}

/// What the datagram path did with what a sender offered this session.
///
/// `offered` bounds the other generation counts: `decoded` and `abandoned`
/// are disjoint subsets of it, and every generation it holds that did not
/// decode was carried by the reliable path instead, whether this end gave it
/// up for want of decode budget or its symbols simply never reached the
/// decode threshold before the epoch closed. `refused` counts epochs rather
/// than generations, because an epoch this end would not open never said how
/// many generations it held.
///
/// `offered` is what the epoch spans, not what the sender chose to code. A
/// sender past this end's generation credit sends the remainder as reliable
/// records from the outset, and this end cannot tell those apart from the
/// ones whose symbols were lost: both are simply generations of an open
/// epoch that never decoded. So `offered - decoded` is the share the
/// reliable path carried, for either reason, and not a loss rate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FecCounts {
    /// Generations spanned by every coding epoch this end opened, whether or
    /// not the sender coded them.
    pub offered: u64,
    /// Generations at least one symbol arrived for. Of the offered ones, the
    /// rest were answered on the reliable path without a symbol ever being
    /// sent, so `decoded` against this is how well the coded path decodes
    /// what it carries, and this against `offered` is how much of what was
    /// offered it carried at all.
    pub coded: u64,
    /// Generations decoded from symbols.
    pub decoded: u64,
    /// Generations dropped for want of decode budget, after enough symbols
    /// arrived to attempt one.
    pub abandoned: u64,
    /// Coding epochs refused, whose generation count this end never learned.
    pub refused: u64,
}

impl std::ops::Add for FecCounts {
    type Output = Self;

    /// Sums what several rails of one fetch each did.
    fn add(self, other: Self) -> Self {
        Self {
            offered: self.offered.saturating_add(other.offered),
            coded: self.coded.saturating_add(other.coded),
            decoded: self.decoded.saturating_add(other.decoded),
            abandoned: self.abandoned.saturating_add(other.abandoned),
            refused: self.refused.saturating_add(other.refused),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Intake {
    receiver: Receiver,
    epochs: BTreeMap<u32, OpenEpoch>,
    orphans: VecDeque<Orphan>,
    orphan_bytes: usize,
    owed: VecDeque<Owed>,
    credit_epoch: u64,
    /// States among `owed`, so the advisory ones can be bounded without
    /// walking the queue.
    owed_states: usize,
    /// What the datagram path did over the session's life.
    counts: FecCounts,
}

impl Intake {
    /// Extends credit derived from the staging capacity the reliable path
    /// advertises, so one number bounds both paths: unretired bytes are the
    /// staging bytes, active generations are what those bytes hold at the
    /// shipped 64 KiB generation, open epochs are a small constant, and
    /// decode work is `DECODE_WORK_PER_STAGING_BYTE` times the staging
    /// bytes, since elimination is bounded by the bytes a peer can put on
    /// the wire and costs about what receiving them did. Nothing is sent
    /// while the caps stand and the decode budget is under half spent.
    pub(crate) fn extend_credit(&mut self, staging_bytes: u64, epoch_capacity: u64) {
        let credit = Credit {
            credit_epoch: self.credit_epoch + 1,
            max_unretired_bytes: staging_bytes,
            max_active_generations: (staging_bytes / GENERATION_BYTES).max(1),
            max_decode_work: staging_bytes.saturating_mul(DECODE_WORK_PER_STAGING_BYTE),
            // Never more epochs than this end has bundles to put them in. An
            // open epoch pins a pending bundle until its last generation
            // lands, so inviting more than that is inviting the sender to
            // open one this end then refuses, which ends the fetch rather
            // than slowing it.
            max_open_epochs: MAX_OPEN_EPOCHS.min(epoch_capacity),
        };
        let held = self.receiver.credit_held();
        let unchanged = held.is_some_and(|held| {
            held.max_unretired_bytes == credit.max_unretired_bytes
                && held.max_active_generations == credit.max_active_generations
                // The epoch cap comes from mutable pending state, so a caller
                // that narrows its depth has to reach the sender: leaving it
                // out held the sender at the wider cap it had already been
                // given, which is the invitation this end would then refuse.
                && held.max_open_epochs == credit.max_open_epochs
        });
        let budget_fresh =
            held.is_some_and(|held| self.receiver.decode_work_spent() <= held.max_decode_work / 2);
        if unchanged && budget_fresh {
            return;
        }
        self.credit_epoch = credit.credit_epoch;
        self.receiver.credit(credit);
        self.owed.push_back(Owed::Credit(credit));
    }

    /// `CODING_EPOCH_OPEN`. `Err(())` is the conflict the spec closes the
    /// session over.
    pub(crate) fn open(&mut self, open: &CodingEpochOpen) -> Result<(), ()> {
        let Ok(plan) = EpochPlan::new(open.epoch, open.offset, open.length, open.geometry) else {
            return Err(());
        };
        let generations = plan.generation_count();
        match self.receiver.open(plan) {
            Ok(Open::Opened) => {
                self.counts.offered += generations;
                self.epochs.insert(
                    open.epoch,
                    OpenEpoch {
                        cover: Cover::of(open),
                        plan,
                    },
                );
                Ok(())
            }
            Ok(Open::Repeated) => Ok(()),
            Ok(Open::Refused) => {
                self.counts.refused += 1;
                self.owed.push_back(Owed::Done(GenDone {
                    epoch: open.epoch,
                    generation: 0,
                    outcome: GenOutcome::Refused,
                }));
                Ok(())
            }
            Err(_) => Err(()),
        }
    }

    /// `CODING_EPOCH_CLOSE`. Orphans of the closed epoch go with it: their
    /// bundle, if it ever comes, is answered by the reliable path.
    pub(crate) fn close(&mut self, close: CodingEpochClose) {
        self.receiver.close(close.epoch);
        if let Some(epoch) = self.epochs.remove(&close.epoch) {
            let _ = self.take_orphans(epoch.cover);
        }
    }

    /// One symbol datagram. Returns the generation it completed, if any, for
    /// the bundle path to take; a completed generation whose bundle is not
    /// here yet is held as an orphan.
    pub(crate) fn symbol(&mut self, datagram: &[u8]) -> Option<Joined> {
        let header = peek_header(datagram)?;
        let epoch = *self.epochs.get(&header.epoch)?;
        let outcome = self.receiver.symbol(
            header.epoch,
            header.generation,
            header.esi,
            &datagram[SYMBOL_HEADER_LEN..],
        );
        match outcome {
            Symbol::Decoded(Decoded {
                generation,
                offset,
                bytes,
            }) => {
                if epoch.plan.sent_source_count(generation) == 1 {
                    self.counts.coded += 1;
                }
                self.counts.decoded += 1;
                self.owed.push_back(Owed::Done(GenDone {
                    epoch: header.epoch,
                    generation,
                    outcome: GenOutcome::Decoded,
                }));
                Some(Joined {
                    cover: epoch.cover,
                    generation,
                    plaintext_offset: offset,
                    bytes,
                })
            }
            Symbol::Abandoned { generation, state } => {
                if epoch.plan.sent_source_count(generation) == 1 {
                    self.counts.coded += 1;
                }
                self.counts.abandoned += 1;
                // Before the `GEN_DONE`, because the done is terminal for the
                // generation and no state is accepted after it. What this one
                // was still missing when it was given up on is the only loss
                // sample the sender gets for it.
                self.owe_state(state_of(header.epoch, generation, state));
                self.owed.push_back(Owed::Done(GenDone {
                    epoch: header.epoch,
                    generation,
                    outcome: GenOutcome::Abandoned,
                }));
                None
            }
            Symbol::Stored { first } => {
                // Only the symbol that opened the generation: one report says
                // this end is working on it, and a report per symbol would put
                // a control frame behind every datagram.
                if first {
                    self.counts.coded += 1;
                    if self.owed_states < MAX_OWED_STATES
                        && let Some(state) = self.receiver.report(header.epoch, header.generation)
                    {
                        self.owe_state(state_of(header.epoch, header.generation, state));
                    }
                }
                None
            }
            Symbol::Dropped(_) => None,
        }
    }

    /// Holds a decoded generation until its bundle arrives. Past either
    /// bound the oldest is dropped; the reliable path repairs it.
    pub(crate) fn hold_orphan(&mut self, joined: Joined) {
        if joined.bytes.len() > MAX_ORPHAN_BYTES {
            return;
        }
        while self.orphans.len() >= MAX_ORPHAN_GENERATIONS
            || self.orphan_bytes + joined.bytes.len() > MAX_ORPHAN_BYTES
        {
            let Some(oldest) = self.orphans.pop_front() else {
                break;
            };
            self.orphan_bytes -= oldest.bytes.len();
        }
        self.orphan_bytes += joined.bytes.len();
        self.orphans.push_back(Orphan {
            cover: joined.cover,
            generation: joined.generation,
            offset: joined.plaintext_offset,
            bytes: joined.bytes,
        });
    }

    /// Takes every held generation for a bundle that has just arrived.
    pub(crate) fn take_orphans(&mut self, cover: Cover) -> Vec<Joined> {
        let mut taken = Vec::new();
        self.orphans.retain(|orphan| {
            if orphan.cover == cover {
                taken.push(Joined {
                    cover,
                    generation: orphan.generation,
                    plaintext_offset: orphan.offset,
                    bytes: orphan.bytes.clone(),
                });
                false
            } else {
                true
            }
        });
        self.orphan_bytes -= taken.iter().map(|joined| joined.bytes.len()).sum::<usize>();
        taken
    }

    /// What the datagram path has done so far.
    pub(crate) const fn counts(&self) -> FecCounts {
        self.counts
    }

    /// The next frame this end owes the sender, left in place: the caller
    /// settles it once the carrier took it, so backpressure retries it.
    pub(crate) fn owed(&self) -> Option<&Owed> {
        self.owed.front()
    }

    /// How many frames are owed, which bounds one sending pass.
    pub(crate) fn owed_len(&self) -> usize {
        self.owed.len()
    }

    /// The front owed frame reached the carrier.
    /// Queues an advisory state, or drops it when this end is already
    /// holding [`MAX_OWED_STATES`] of them.
    fn owe_state(&mut self, state: GenState) {
        if self.owed_states >= MAX_OWED_STATES {
            return;
        }
        self.owed_states += 1;
        self.owed.push_back(Owed::State(state));
    }

    pub(crate) fn settle_owed(&mut self) {
        if let Some(Owed::State(_)) = self.owed.pop_front() {
            self.owed_states -= 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn take_owed(&mut self) -> Option<Owed> {
        let taken = self.owed.pop_front();
        if let Some(Owed::State(_)) = taken {
            self.owed_states -= 1;
        }
        taken
    }
}

/// The shipped profile's generation: one 64 KiB integrity group.
pub(crate) const GENERATION_BYTES: u64 = 65_536;
/// Epochs a sender may hold open at once under this receiver's credit, as
/// far as the coding side is concerned. What is advertised is this or the
/// receiver's pending-bundle capacity, whichever is smaller.
pub(crate) const MAX_OPEN_EPOCHS: u64 = crate::session::MAX_CODING_EPOCHS as u64;
/// Decode work per staging byte under one credit epoch. Elimination of one
/// generation costs about the bytes it holds; sixteen refills of staging
/// before a new epoch is due keeps the budget from binding on a lossy path.
pub(crate) const DECODE_WORK_PER_STAGING_BYTE: u64 = 16;

/// The nine-byte header, read before the epoch's geometry is known.
fn peek_header(datagram: &[u8]) -> Option<SymbolHeader> {
    let head: [u8; SYMBOL_HEADER_LEN] = datagram.get(..SYMBOL_HEADER_LEN)?.try_into().ok()?;
    Some(SymbolHeader {
        epoch: u32::from_be_bytes([head[0], head[1], head[2], head[3]]),
        generation: u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
        esi: head[8],
    })
}

/// The record a decoded generation becomes for its bundle.
pub(crate) fn record_of(bundle_id: [u8; 16], joined: Joined) -> DataRecord {
    DataRecord {
        bundle_id,
        record_index: u64::from(joined.generation),
        plaintext_offset: joined.plaintext_offset,
        plaintext_length: joined.bytes.len() as u64,
        compression: 0,
        encoded: joined.bytes,
    }
}

/// One `GEN_STATE` frame from what the receiver reported.
fn state_of(epoch: u32, generation: u32, report: Report) -> GenState {
    GenState {
        epoch,
        generation,
        sequence: report.sequence,
        received: report.received,
        missing_sources: report.missing_sources,
    }
}

/// Encodes one owed frame.
pub(crate) fn frame_of(owed: &Owed) -> Vec<u8> {
    let typed = match owed {
        Owed::Credit(credit) => TypedFrame::DatagramCredit(vot_codec::frames::DatagramCredit {
            credit_epoch: credit.credit_epoch,
            max_unretired_bytes: credit.max_unretired_bytes,
            max_active_generations: credit.max_active_generations,
            max_decode_work: credit.max_decode_work,
            max_open_epochs: credit.max_open_epochs,
        }),
        Owed::State(state) => TypedFrame::GenState(state.clone()),
        Owed::Done(done) => TypedFrame::GenDone(*done),
    };
    let mut out = Vec::new();
    vot_codec::frames::encode(&typed, &mut out).expect("bounded values encode");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_codec::frames::ObjectId;
    use vot_fec::Geometry;

    fn open_of(
        epoch: u32,
        offset: u64,
        length: u64,
        k: usize,
        r: usize,
        l: usize,
    ) -> CodingEpochOpen {
        CodingEpochOpen {
            epoch,
            object: ObjectId {
                suite: 1,
                root: [7; 32],
                length: 1 << 40,
            },
            offset,
            length,
            geometry: Geometry::new(k, r, l).unwrap(),
        }
    }

    fn datagram(epoch: u32, generation: u32, esi: u8, symbol: &[u8]) -> Vec<u8> {
        let mut out = epoch.to_be_bytes().to_vec();
        out.extend_from_slice(&generation.to_be_bytes());
        out.push(esi);
        out.extend_from_slice(symbol);
        out
    }

    #[test]
    fn credit_is_sized_from_staging_and_reissued_only_when_something_moved() {
        let mut intake = Intake::default();
        intake.extend_credit(200_000, MAX_OPEN_EPOCHS);
        let Some(Owed::Credit(first)) = intake.take_owed() else {
            panic!("credit is owed on the first extension");
        };
        assert_eq!(first.credit_epoch, 1);
        assert_eq!(first.max_unretired_bytes, 200_000);
        assert_eq!(first.max_active_generations, 3, "200000 / 65536");
        assert_eq!(first.max_decode_work, 3_200_000);
        assert_eq!(first.max_open_epochs, MAX_OPEN_EPOCHS);
        intake.extend_credit(200_000, MAX_OPEN_EPOCHS);
        assert_eq!(intake.take_owed(), None, "nothing moved");
        intake.extend_credit(199_000, MAX_OPEN_EPOCHS);
        let Some(Owed::Credit(second)) = intake.take_owed() else {
            panic!("a changed byte cap is a new epoch even at the same generation cap");
        };
        assert_eq!(second.credit_epoch, 2);
        assert_eq!(second.max_active_generations, 3);
        assert_eq!(second.max_unretired_bytes, 199_000);
        intake.extend_credit(65_536, MAX_OPEN_EPOCHS);
        let Some(Owed::Credit(third)) = intake.take_owed() else {
            panic!("a changed generation cap is a new epoch");
        };
        assert_eq!(third.credit_epoch, 3);
        assert_eq!(third.max_active_generations, 1);
        // Tiny staging: 1 byte, so one generation of k = 1, L = 1 costs the
        // whole active cap and the decode budget is 16. Nine eliminations
        // spend past half of it and a fresh epoch is owed at the next call.
        let mut small = Intake::default();
        small.extend_credit(1, MAX_OPEN_EPOCHS);
        assert!(matches!(small.take_owed(), Some(Owed::Credit(_))));
        small.open(&open_of(1, 0, 16, 1, 1, 1)).unwrap();
        for generation in 0..9_u32 {
            // The repair symbol of source [g]: with k = 1 it is that byte
            // itself, and its arrival alone completes k by elimination.
            let byte = u8::try_from(generation).unwrap();
            let joined = small.symbol(&datagram(1, generation, 1, &[byte]));
            assert!(joined.is_some(), "generation {generation}");
            assert!(matches!(small.take_owed(), Some(Owed::Done(_))));
            if generation == 0 {
                small.extend_credit(1, MAX_OPEN_EPOCHS);
                assert_eq!(small.take_owed(), None, "one of sixteen spent is fresh");
            }
        }
        small.extend_credit(1, MAX_OPEN_EPOCHS);
        let Some(Owed::Credit(refreshed)) = small.take_owed() else {
            panic!("half the decode budget is spent, so a new epoch is due");
        };
        assert_eq!(refreshed.credit_epoch, 2);
        small.extend_credit(1, MAX_OPEN_EPOCHS);
        assert_eq!(
            small.take_owed(),
            None,
            "spent work was reset by the new epoch"
        );
    }

    #[test]
    fn the_counts_account_for_every_epoch_and_generation_a_sender_offered() {
        let mut intake = Intake::default();
        assert_eq!(intake.counts(), FecCounts::default());
        // No credit yet, so the epoch is refused, and a refusal never learns
        // how many generations it held.
        intake.open(&open_of(1, 0, 32, 1, 1, 1)).unwrap();
        assert_eq!(
            intake.counts(),
            FecCounts {
                offered: 0,
                coded: 0,
                decoded: 0,
                abandoned: 0,
                refused: 1,
            }
        );
        // One byte of staging is a decode budget of sixteen, against an epoch
        // of thirty-two one-byte generations. The refusal and the credit are
        // both owed to the sender; draining them leaves the loop below seeing
        // only what each generation produced.
        intake.extend_credit(1, MAX_OPEN_EPOCHS);
        assert!(matches!(intake.take_owed(), Some(Owed::Done(_))));
        assert!(matches!(intake.take_owed(), Some(Owed::Credit(_))));
        assert_eq!(intake.take_owed(), None);
        intake.open(&open_of(1, 0, 32, 1, 1, 1)).unwrap();
        assert_eq!(intake.counts().offered, 32);
        intake.open(&open_of(1, 0, 32, 1, 1, 1)).unwrap();
        assert_eq!(
            intake.counts().offered,
            32,
            "a repeated open is not a second offer"
        );
        // The repair symbol of a k = 1 generation completes it by
        // elimination, which spends one of the sixteen. Past that the
        // generation is dropped for the reliable path to repair.
        for generation in 0..32_u32 {
            let byte = u8::try_from(generation).unwrap();
            let joined = intake.symbol(&datagram(1, generation, 1, &[byte]));
            let decoded = generation < 16;
            assert_eq!(joined.is_some(), decoded, "generation {generation}");
            // One symbol completes a k = 1 generation, so none of them is
            // ever stored and only the abandoned ones report state, ahead of
            // the done that ends them.
            if !decoded {
                assert!(
                    matches!(intake.take_owed(), Some(Owed::State(_))),
                    "generation {generation} reports what it was missing"
                );
            }
            assert!(matches!(intake.take_owed(), Some(Owed::Done(_))));
        }
        assert_eq!(
            intake.counts(),
            FecCounts {
                offered: 32,
                // Every one of them took a symbol, including the sixteen
                // that then had nowhere to decode: a generation completing
                // on the symbol that opens it still carried it.
                coded: 32,
                decoded: 16,
                abandoned: 16,
                refused: 1,
            }
        );
    }

    #[test]
    fn the_credit_never_invites_more_epochs_than_there_is_room_for() {
        // An open epoch pins a pending bundle, so promising more epochs than
        // the receiver admits bundles is promising a refusal. A coded fetch
        // died of exactly that: eight epochs invited against four bundles.
        for capacity in 0..=u64::from(u8::try_from(MAX_OPEN_EPOCHS).unwrap()) + 4 {
            let mut intake = Intake::default();
            intake.extend_credit(1 << 20, capacity);
            let Some(Owed::Credit(credit)) = intake.take_owed() else {
                panic!("a first extension owes its credit");
            };
            assert!(
                credit.max_open_epochs <= capacity,
                "capacity {capacity} invited {}",
                credit.max_open_epochs
            );
            assert_eq!(credit.max_open_epochs, MAX_OPEN_EPOCHS.min(capacity));
        }
    }

    #[test]
    fn a_generation_reports_itself_once_at_the_symbol_that_opened_it() {
        let mut intake = Intake::default();
        intake.extend_credit(1 << 20, MAX_OPEN_EPOCHS);
        let _ = intake.take_owed();
        // k = 4, L = 2, cover of 24 bytes: three generations of 8, all full.
        intake.open(&open_of(3, 0, 24, 4, 2, 2)).unwrap();
        let plan = EpochPlan::new(3, 0, 24, Geometry::new(4, 2, 2).unwrap()).unwrap();
        let symbols = vot_fec::encode_generation(&plan, 0, &(0..8_u8).collect::<Vec<_>>()).unwrap();

        // The first symbol reports; the second does not, and the sequence
        // stays at one because a report is only built when one is sent.
        let (esi, symbol) = &symbols[0];
        assert!(intake.symbol(&datagram(3, 0, *esi, symbol)).is_none());
        assert_eq!(
            intake.take_owed(),
            Some(Owed::State(GenState {
                epoch: 3,
                generation: 0,
                sequence: 1,
                received: 1,
                missing_sources: vec![1, 2, 3],
            }))
        );
        let (esi, symbol) = &symbols[1];
        assert!(intake.symbol(&datagram(3, 0, *esi, symbol)).is_none());
        assert_eq!(intake.take_owed(), None, "only the symbol that opened it");
        assert_eq!(
            intake.receiver.report(3, 0).unwrap().sequence,
            2,
            "checking later symbols did not mint discarded reports"
        );
    }

    #[test]
    fn advisory_states_are_bounded_and_never_crowd_out_what_is_owed() {
        // A peer that stops reading leaves everything queued, and one state
        // is minted per generation opened, so the advisory ones are capped.
        // Nothing else is: a done is terminal for its generation and the
        // sender waits on it.
        let mut intake = Intake::default();
        intake.extend_credit(1 << 30, MAX_OPEN_EPOCHS);
        assert!(matches!(intake.take_owed(), Some(Owed::Credit(_))));
        // k = 2, L = 1: a two-byte generation, so one cover spans many.
        let generations = u32::try_from(MAX_OWED_STATES).unwrap() + 8;
        let length = u64::from(generations) * 2;
        intake.open(&open_of(1, 0, length, 2, 1, 1)).unwrap();
        for generation in 0..generations {
            // A single source symbol opens the generation and leaves it
            // short of its two, so each one queues a state and nothing else.
            assert!(
                intake.symbol(&datagram(1, generation, 0, &[7])).is_none(),
                "generation {generation} is not complete"
            );
        }
        assert_eq!(
            intake.owed.len(),
            MAX_OWED_STATES,
            "the advisory queue stops growing"
        );
        assert_eq!(
            intake
                .receiver
                .report(1, u32::try_from(MAX_OWED_STATES).unwrap())
                .unwrap()
                .sequence,
            1,
            "overflow generations did not mint discarded reports"
        );
        assert!(
            intake
                .owed
                .iter()
                .all(|owed| matches!(owed, Owed::State(_))),
            "everything queued here is a state"
        );
        // Settling states makes room for new ones again.
        for _ in 0..8 {
            intake.settle_owed();
        }
        intake.open(&open_of(2, 0, 2, 2, 1, 1)).unwrap();
        assert!(intake.symbol(&datagram(2, 0, 0, &[9])).is_none());
        assert!(
            intake
                .owed
                .iter()
                .any(|owed| matches!(owed, Owed::State(state) if state.epoch == 2)),
            "room freed is room reused"
        );
        // Credit still goes out with the queue at its cap, because the
        // sender's flow control waits on it. Last, because a narrower credit
        // is what stops new generations going live.
        intake.extend_credit(1 << 20, MAX_OPEN_EPOCHS);
        assert!(
            matches!(intake.owed.back(), Some(Owed::Credit(_))),
            "a credit is owed whatever the state queue holds"
        );
    }

    #[test]
    fn a_short_tail_generation_reports_itself_like_any_other() {
        // Its sources are counted as in hand from the start, so a report
        // gated on the count of symbols received would never fire for it.
        // 20 bytes at k = 4, L = 2 is two generations of 8 and a tail of 4,
        // which is two sources rather than four.
        let mut intake = Intake::default();
        intake.extend_credit(1 << 20, MAX_OPEN_EPOCHS);
        let _ = intake.take_owed();
        intake.open(&open_of(4, 0, 20, 4, 2, 2)).unwrap();
        let plan = EpochPlan::new(4, 0, 20, Geometry::new(4, 2, 2).unwrap()).unwrap();
        assert_eq!(plan.generation_count(), 3);
        assert_eq!(plan.sent_source_count(2), 2, "the tail is short");
        let symbols = vot_fec::encode_generation(&plan, 2, &[9_u8, 8, 7, 6]).unwrap();
        let (esi, symbol) = &symbols[0];
        assert!(intake.symbol(&datagram(4, 2, *esi, symbol)).is_none());
        let Some(Owed::State(state)) = intake.take_owed() else {
            panic!("the tail generation reports at its first symbol too");
        };
        assert_eq!(state.generation, 2);
        assert_eq!(state.sequence, 1);
        assert_eq!(
            state.received, 3,
            "one symbol in hand and the two sources past the tail counted with it"
        );
        assert_eq!(state.missing_sources, vec![1]);
    }

    #[test]
    fn rail_counts_add_field_by_field() {
        // Each field distinct in both terms, so a sum that reads one field
        // into another's place cannot pass.
        let left = FecCounts {
            offered: 1,
            coded: 2,
            decoded: 4,
            abandoned: 8,
            refused: 16,
        };
        let right = FecCounts {
            offered: 32,
            coded: 64,
            decoded: 128,
            abandoned: 256,
            refused: 512,
        };
        assert_eq!(
            left + right,
            FecCounts {
                offered: 33,
                coded: 66,
                decoded: 132,
                abandoned: 264,
                refused: 528,
            }
        );
        assert_eq!(left + FecCounts::default(), left);
        // Saturating, so a counter that ran away cannot panic a fetch that
        // was otherwise fine.
        let full = FecCounts {
            offered: u64::MAX,
            coded: u64::MAX,
            decoded: u64::MAX,
            abandoned: u64::MAX,
            refused: u64::MAX,
        };
        assert_eq!(full + right, full);
    }

    /// The last generation of an epoch holds whatever the length left over,
    /// which is often a single source symbol. Such a generation decodes on
    /// the symbol that opens it and is never stored, so a count taken from
    /// the stored outcome alone misses it and reports decoding more
    /// generations than were carried.
    #[test]
    fn a_generation_of_one_source_symbol_counts_as_carried() {
        let mut intake = Intake::default();
        intake.extend_credit(1 << 20, MAX_OPEN_EPOCHS);
        let _ = intake.take_owed();
        // k = 4, L = 2: 8 bytes a generation, and a length of 9 leaves the
        // second generation holding one byte, which is one source symbol.
        intake.open(&open_of(7, 0, 9, 4, 2, 2)).unwrap();
        assert_eq!(intake.counts().offered, 2);
        let plan = EpochPlan::new(7, 0, 9, Geometry::new(4, 2, 2).unwrap()).unwrap();
        let (esi, symbol) = vot_fec::encode_generation(&plan, 1, &[9_u8])
            .unwrap()
            .into_iter()
            .next()
            .expect("a geometry has symbols");
        assert!(
            intake.symbol(&datagram(7, 1, esi, &symbol)).is_some(),
            "one source symbol is the whole generation"
        );
        let counts = intake.counts();
        assert_eq!(counts.decoded, 1);
        assert_eq!(counts.coded, 1, "the generation it decoded was carried");
    }

    /// What the coded path carried and what it decoded are different
    /// questions: a generation nothing was sent for was answered reliably,
    /// and reading decoded against offered alone reports that as a decode
    /// that failed.
    #[test]
    fn a_generation_symbols_arrive_for_counts_as_carried_whether_it_decodes_or_not() {
        let mut intake = Intake::default();
        intake.extend_credit(1 << 20, MAX_OPEN_EPOCHS);
        let _ = intake.take_owed();
        // k = 4, L = 2: 8 bytes a generation, so 16 bytes is two of them.
        intake.open(&open_of(5, 0, 16, 4, 2, 2)).unwrap();
        assert_eq!(intake.counts().offered, 2);
        let bytes: Vec<u8> = (0..16_u8).collect();
        let plan = EpochPlan::new(5, 0, 16, Geometry::new(4, 2, 2).unwrap()).unwrap();

        // The first generation gets every symbol and decodes.
        for (esi, symbol) in vot_fec::encode_generation(&plan, 0, &bytes[..8]).unwrap() {
            let _ = intake.symbol(&datagram(5, 0, esi, &symbol));
        }
        // The second gets one, which carries it no further than stored.
        let (esi, symbol) = vot_fec::encode_generation(&plan, 1, &bytes[8..])
            .unwrap()
            .into_iter()
            .next()
            .expect("a geometry has symbols");
        assert!(intake.symbol(&datagram(5, 1, esi, &symbol)).is_none());

        let counts = intake.counts();
        assert_eq!(counts.coded, 2, "a symbol arrived for both");
        assert_eq!(counts.decoded, 1, "only one had enough of them");
        assert!(
            counts.coded <= counts.offered,
            "nothing is carried that was not offered"
        );
    }

    #[test]
    fn a_decoded_generation_is_placed_relative_to_its_cover() {
        let mut intake = Intake::default();
        intake.extend_credit(1 << 20, MAX_OPEN_EPOCHS);
        let _ = intake.take_owed();
        // Cover starts at 3 * 64 KiB; k = 4, L = 2: 8 bytes per generation.
        intake.open(&open_of(5, 3 * 65_536, 16, 4, 2, 2)).unwrap();
        let bytes: Vec<u8> = (0..16_u8).collect();
        let plan = EpochPlan::new(5, 3 * 65_536, 16, Geometry::new(4, 2, 2).unwrap()).unwrap();
        for (esi, symbol) in vot_fec::encode_generation(&plan, 1, &bytes[8..]).unwrap() {
            if let Some(joined) = intake.symbol(&datagram(5, 1, esi, &symbol)) {
                assert_eq!(joined.generation, 1);
                assert_eq!(joined.plaintext_offset, 3 * 65_536 + 8);
                assert_eq!(joined.bytes, bytes[8..].to_vec());
                assert_eq!(joined.cover.offset, 3 * 65_536);
                // The symbol that opened the generation reported it before
                // any of this: one state per generation, at its first symbol.
                assert_eq!(
                    intake.take_owed(),
                    Some(Owed::State(GenState {
                        epoch: 5,
                        generation: 1,
                        sequence: 1,
                        received: 1,
                        missing_sources: vec![1, 2, 3],
                    }))
                );
                assert_eq!(
                    intake.take_owed(),
                    Some(Owed::Done(GenDone {
                        epoch: 5,
                        generation: 1,
                        outcome: GenOutcome::Decoded
                    }))
                );
                // Held, then taken by its bundle and by nothing else.
                intake.hold_orphan(joined);
                assert!(
                    intake
                        .take_orphans(Cover {
                            root: [7; 32],
                            offset: 0,
                            length: 16
                        })
                        .is_empty()
                );
                let taken = intake.take_orphans(Cover {
                    root: [7; 32],
                    offset: 3 * 65_536,
                    length: 16,
                });
                assert_eq!(taken.len(), 1);
                assert_eq!(taken[0].plaintext_offset, 3 * 65_536 + 8);
                let record = record_of([9; 16], taken[0].clone());
                assert_eq!(record.record_index, 1);
                assert_eq!(record.plaintext_offset, 3 * 65_536 + 8);
                assert_eq!(record.plaintext_length, 8);
                assert_eq!(record.encoded, bytes[8..].to_vec());
                assert_eq!(record.compression, 0);
                return;
            }
        }
        panic!("the generation never decoded");
    }

    #[test]
    fn a_closed_epoch_takes_no_symbols_and_a_short_datagram_is_nothing() {
        let mut intake = Intake::default();
        intake.extend_credit(1 << 20, MAX_OPEN_EPOCHS);
        let _ = intake.take_owed();
        intake.open(&open_of(2, 0, 4, 1, 1, 4)).unwrap();
        intake.close(CodingEpochClose { epoch: 2 });
        assert_eq!(intake.symbol(&datagram(2, 0, 0, &[1, 2, 3, 4])), None);
        assert_eq!(intake.take_owed(), None);
        assert_eq!(
            intake.symbol(&[0, 0, 0, 2, 0]),
            None,
            "five bytes are no header"
        );
        assert_eq!(
            intake.symbol(&datagram(9, 0, 0, &[1, 2, 3, 4])),
            None,
            "unknown epoch"
        );
    }

    #[test]
    fn orphans_are_bounded_by_count_and_bytes_and_leave_with_their_epoch() {
        let mut intake = Intake::default();
        intake.extend_credit(1 << 20, MAX_OPEN_EPOCHS);
        let _ = intake.take_owed();
        // Orphans are bounded: the oldest goes first.
        for i in 0..=u32::try_from(MAX_ORPHAN_GENERATIONS).unwrap() {
            intake.hold_orphan(Joined {
                cover: Cover {
                    root: [1; 32],
                    offset: 0,
                    length: 1,
                },
                generation: i,
                plaintext_offset: 0,
                bytes: vec![0],
            });
        }
        let kept = intake.take_orphans(Cover {
            root: [1; 32],
            offset: 0,
            length: 1,
        });
        assert_eq!(kept.len(), MAX_ORPHAN_GENERATIONS);
        assert_eq!(kept[0].generation, 1, "generation 0 was dropped");
        assert_eq!(intake.orphan_bytes, 0);
        // Bytes bound too: two of half the cap, then one more evicts the first.
        let big = |generation: u32| Joined {
            cover: Cover {
                root: [2; 32],
                offset: 0,
                length: 1,
            },
            generation,
            plaintext_offset: 0,
            bytes: vec![0; MAX_ORPHAN_BYTES / 2],
        };
        intake.hold_orphan(big(0));
        intake.hold_orphan(big(1));
        assert_eq!(intake.orphan_bytes, MAX_ORPHAN_BYTES);
        intake.hold_orphan(big(2));
        assert_eq!(intake.orphan_bytes, MAX_ORPHAN_BYTES);
        let kept = intake.take_orphans(Cover {
            root: [2; 32],
            offset: 0,
            length: 1,
        });
        assert_eq!(
            kept.iter().map(|j| j.generation).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(intake.orphan_bytes, 0);
        // Exactly the cap is held; larger than the whole cap never is.
        intake.hold_orphan(Joined {
            cover: Cover {
                root: [2; 32],
                offset: 0,
                length: 1,
            },
            generation: 5,
            plaintext_offset: 0,
            bytes: vec![0; MAX_ORPHAN_BYTES],
        });
        assert_eq!(intake.orphan_bytes, MAX_ORPHAN_BYTES);
        let _ = intake.take_orphans(Cover {
            root: [2; 32],
            offset: 0,
            length: 1,
        });
        intake.hold_orphan(Joined {
            cover: Cover {
                root: [2; 32],
                offset: 0,
                length: 1,
            },
            generation: 0,
            plaintext_offset: 0,
            bytes: vec![0; MAX_ORPHAN_BYTES + 1],
        });
        assert_eq!(intake.orphan_bytes, 0);
        // A closed epoch takes its orphans with it.
        intake.open(&open_of(3, 0, 4, 1, 1, 4)).unwrap();
        intake.hold_orphan(Joined {
            cover: Cover::of(&open_of(3, 0, 4, 1, 1, 4)),
            generation: 0,
            plaintext_offset: 0,
            bytes: vec![0; 4],
        });
        assert_eq!(intake.orphan_bytes, 4);
        intake.close(CodingEpochClose { epoch: 3 });
        assert_eq!(intake.orphan_bytes, 0);
        assert!(
            intake
                .take_orphans(Cover::of(&open_of(3, 0, 4, 1, 1, 4)))
                .is_empty()
        );
    }
}
