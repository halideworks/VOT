//! Plan, receiver, and sender: the spec/fec.md section 9, 11, and 12 rules.

use super::*;

fn plan(epoch: u32, offset: u64, length: u64, k: usize, r: usize, l: usize) -> EpochPlan {
    EpochPlan::new(epoch, offset, length, Geometry::new(k, r, l).unwrap()).unwrap()
}

fn credit(open: u64, gens: u64, bytes: u64, work: u64) -> Credit {
    Credit {
        credit_epoch: 1,
        max_unretired_bytes: bytes,
        max_active_generations: gens,
        max_decode_work: work,
        max_open_epochs: open,
    }
}

fn ample() -> Credit {
    credit(8, 64, 1 << 30, 1 << 30)
}

/// Object bytes for a range: byte at absolute offset `o` is `(o * 7 + 1) % 253`.
fn object_bytes(offset: u64, length: u64) -> Vec<u8> {
    (offset..offset + length)
        .map(|o| u8::try_from((o * 7 + 1) % 253).unwrap())
        .collect()
}

fn symbols_of(plan: &EpochPlan, generation: u32) -> Vec<(u8, Vec<u8>)> {
    let (offset, length) = plan.generation_span(generation);
    encode_generation(plan, generation, &object_bytes(offset, length)).unwrap()
}

#[test]
fn a_plan_lays_generations_end_to_end_and_the_last_may_be_short() {
    // k = 4, L = 3: 12 bytes per generation over 27 bytes from offset 100.
    let plan = plan(1, 100, 27, 4, 2, 3);
    assert_eq!(plan.generation_bytes(), 12);
    assert_eq!(plan.generation_count(), 3);
    assert!(plan.holds(2));
    assert!(!plan.holds(3));
    assert_eq!(plan.generation_span(0), (100, 12));
    assert_eq!(plan.generation_span(1), (112, 12));
    assert_eq!(plan.generation_span(2), (124, 3), "27 - 24 bytes remain");
    // The short generation: source 0 carries the 3 bytes, sources 1..4 are
    // zero and never sent.
    assert_eq!(
        plan.source_span(2, 0),
        SourceSpan::Bytes {
            offset: 124,
            bytes: 3
        }
    );
    assert_eq!(plan.source_span(2, 1), SourceSpan::Zero);
    assert_eq!(plan.source_span(2, 3), SourceSpan::Zero);
    assert_eq!(plan.sent_source_count(2), 1);
    assert_eq!(plan.sent_source_count(0), 4);
    // A partial symbol: 28 bytes makes source 1 of generation 2 carry one.
    let plan = super::EpochPlan::new(1, 100, 28, Geometry::new(4, 2, 3).unwrap()).unwrap();
    assert_eq!(
        plan.source_span(2, 1),
        SourceSpan::Bytes {
            offset: 127,
            bytes: 1
        }
    );
    assert_eq!(plan.sent_source_count(2), 2);
    assert_eq!(plan.epoch(), 1);
    assert_eq!(plan.offset(), 100);
    assert_eq!(plan.length(), 28);
    assert_eq!(plan.geometry(), Geometry::new(4, 2, 3).unwrap());
}

#[test]
fn a_plan_refuses_an_empty_or_unaddressable_range() {
    let g = Geometry::new(1, 0, 1).unwrap();
    assert_eq!(EpochPlan::new(1, 0, 0, g), Err(Error::InvalidGeometry));
    assert_eq!(
        EpochPlan::new(1, u64::MAX, 1, g),
        Err(Error::InvalidGeometry)
    );
    assert_eq!(
        EpochPlan::new(1, 0, (1 << 32) + 1, g),
        Err(Error::InvalidGeometry),
        "one generation too many for u32"
    );
    assert!(EpochPlan::new(1, 0, 1 << 32, g).is_ok());
    assert!(EpochPlan::new(1, u64::MAX - 1, 1, g).is_ok());
}

#[test]
#[should_panic(expected = "generation past the epoch")]
fn a_span_past_the_epoch_is_a_caller_bug() {
    let _ = plan(1, 0, 12, 4, 0, 3).generation_span(1);
}

#[test]
fn encode_generation_pads_the_short_tail_and_sends_only_what_carries_bytes() {
    let plan = plan(3, 100, 27, 4, 2, 3);
    let full = symbols_of(&plan, 0);
    assert_eq!(full.len(), 6, "4 sources and 2 repair");
    assert_eq!(full[0], (0, object_bytes(100, 3)));
    assert_eq!(full[3].0, 3);
    assert_eq!(full[4].0, 4);
    assert_eq!(full[5].0, 5);
    let short = symbols_of(&plan, 2);
    assert_eq!(short.len(), 3, "one sent source and 2 repair");
    assert_eq!(short[0], (0, object_bytes(124, 3)));
    assert_eq!(short[1].0, 4);
    // Repair over the padded sources: the same as encoding the zeros by hand.
    let padded: Vec<Vec<u8>> = vec![object_bytes(124, 3), vec![0; 3], vec![0; 3], vec![0; 3]];
    let borrowed: Vec<&[u8]> = padded.iter().map(Vec::as_slice).collect();
    let repair = encode(plan.geometry(), &borrowed).unwrap();
    assert_eq!(short[1].1, repair[0]);
    assert_eq!(short[2].1, repair[1]);
    // Wrong byte count or a generation past the epoch.
    assert_eq!(
        encode_generation(&plan, 0, &[0; 11]),
        Err(Error::InvalidSymbol)
    );
    assert_eq!(
        encode_generation(&plan, 3, &[0; 12]),
        Err(Error::InvalidGeometry)
    );
}

#[test]
fn a_receiver_without_credit_opens_nothing_and_drops_everything() {
    let mut receiver = Receiver::new();
    let plan = plan(1, 0, 12, 4, 2, 3);
    assert_eq!(receiver.open(plan), Ok(Open::Refused));
    assert_eq!(receiver.open_epochs(), 0);
    assert_eq!(
        receiver.symbol(1, 0, 0, &[0; 3]),
        Symbol::Dropped(Drop::NoCredit)
    );
    assert!(receiver.credit(ample()));
    assert!(
        !receiver.credit(ample()),
        "an equal credit epoch is ignored"
    );
    assert!(
        !receiver.credit(Credit {
            credit_epoch: 0,
            ..ample()
        }),
        "an older one too"
    );
    assert_eq!(receiver.credit_held(), Some(ample()));
    assert_eq!(receiver.open(plan), Ok(Open::Opened));
    assert_eq!(receiver.open(plan), Ok(Open::Repeated));
    let other = EpochPlan::new(1, 0, 12, Geometry::new(4, 1, 3).unwrap()).unwrap();
    assert_eq!(
        receiver.open(other),
        Err(Error::InvalidGeometry),
        "a conflict"
    );
    assert_eq!(receiver.open_epochs(), 1);
}

#[test]
fn open_epochs_are_capped_and_a_refused_open_stays_unknown() {
    let mut receiver = Receiver::new();
    receiver.credit(credit(2, 64, 1 << 20, 1 << 20));
    assert_eq!(receiver.open(plan(1, 0, 12, 4, 2, 3)), Ok(Open::Opened));
    assert_eq!(receiver.open(plan(2, 0, 12, 4, 2, 3)), Ok(Open::Opened));
    assert_eq!(receiver.open(plan(3, 0, 12, 4, 2, 3)), Ok(Open::Refused));
    assert_eq!(
        receiver.symbol(3, 0, 0, &[0; 3]),
        Symbol::Dropped(Drop::UnknownEpoch)
    );
    assert!(receiver.close(1));
    assert!(!receiver.close(1), "forgotten");
    assert_eq!(receiver.open(plan(3, 0, 12, 4, 2, 3)), Ok(Open::Opened));
    assert_eq!(receiver.open_epochs(), 2);
}

#[test]
fn every_header_drop_row_is_a_drop() {
    let mut receiver = Receiver::new();
    receiver.credit(ample());
    let plan = plan(1, 100, 27, 4, 2, 3);
    receiver.open(plan).unwrap();
    assert_eq!(
        receiver.symbol(1, 0, 0, &[0; 4]),
        Symbol::Dropped(Drop::WrongLength)
    );
    assert_eq!(
        receiver.symbol(1, 0, 6, &[0; 3]),
        Symbol::Dropped(Drop::EsiOutOfRange)
    );
    assert_eq!(
        receiver.symbol(1, 3, 0, &[0; 3]),
        Symbol::Dropped(Drop::GenerationPastEpoch)
    );
    assert_eq!(
        receiver.symbol(1, 2, 1, &[0; 3]),
        Symbol::Dropped(Drop::ZeroSource),
        "source 1 of the short generation is never sent"
    );
    assert_eq!(receiver.symbol(1, 0, 4, &[0; 3]), Symbol::Stored);
    assert_eq!(
        receiver.symbol(1, 0, 4, &[0; 3]),
        Symbol::Dropped(Drop::Duplicate)
    );
    assert_eq!(receiver.active_generations(), 1);
    assert_eq!(receiver.unretired_bytes(), 12);
    // Nothing above changed accounting except the one stored symbol.
    assert!(receiver.close(1));
    assert_eq!(receiver.active_generations(), 0);
    assert_eq!(receiver.unretired_bytes(), 0);
    assert_eq!(
        receiver.symbol(1, 0, 4, &[0; 3]),
        Symbol::Dropped(Drop::UnknownEpoch),
        "closed is forgotten"
    );
}

#[test]
fn a_generation_with_every_source_assembles_without_elimination() {
    let mut receiver = Receiver::new();
    receiver.credit(credit(1, 1, 12, 0));
    let plan = plan(1, 100, 27, 4, 2, 3);
    receiver.open(plan).unwrap();
    let symbols = symbols_of(&plan, 1);
    for (esi, bytes) in &symbols[..3] {
        assert_eq!(receiver.symbol(1, 1, *esi, bytes), Symbol::Stored);
    }
    assert_eq!(
        receiver.report(1, 1),
        Some(Report {
            sequence: 1,
            received: 3,
            missing_sources: vec![3]
        })
    );
    let (esi, bytes) = &symbols[3];
    assert_eq!(
        receiver.symbol(1, 1, *esi, bytes),
        Symbol::Decoded(Decoded {
            generation: 1,
            offset: 112,
            bytes: object_bytes(112, 12),
        })
    );
    assert_eq!(receiver.decode_work_spent(), 0, "no elimination, no work");
    assert_eq!(receiver.active_generations(), 0, "retired on decode");
    assert_eq!(receiver.unretired_bytes(), 0);
    assert_eq!(
        receiver.report(1, 1),
        None,
        "done generations report nothing"
    );
    assert_eq!(
        receiver.symbol(1, 1, 4, &symbols[4].1),
        Symbol::Dropped(Drop::GenerationDone)
    );
}

#[test]
fn a_generation_missing_sources_is_eliminated_and_charged() {
    let mut receiver = Receiver::new();
    receiver.credit(credit(1, 4, 48, 12));
    let plan = plan(1, 100, 27, 4, 2, 3);
    receiver.open(plan).unwrap();
    let symbols = symbols_of(&plan, 0);
    // Sources 1 and 3 lost; both repair symbols arrive.
    for esi in [0_u8, 2, 4] {
        assert_eq!(
            receiver.symbol(1, 0, esi, &symbols[usize::from(esi)].1),
            Symbol::Stored
        );
    }
    assert_eq!(
        receiver.report(1, 0),
        Some(Report {
            sequence: 1,
            received: 3,
            missing_sources: vec![1, 3]
        })
    );
    assert_eq!(
        receiver.report(1, 0).unwrap().sequence,
        2,
        "each report is newer"
    );
    assert_eq!(
        receiver.symbol(1, 0, 5, &symbols[5].1),
        Symbol::Decoded(Decoded {
            generation: 0,
            offset: 100,
            bytes: object_bytes(100, 12),
        })
    );
    assert_eq!(receiver.decode_work_spent(), 12);
    // The budget is spent: the next generation that needs elimination is
    // abandoned, and one that does not still assembles.
    let g1 = symbols_of(&plan, 1);
    for esi in [0_u8, 1, 2] {
        assert_eq!(
            receiver.symbol(1, 1, esi, &g1[usize::from(esi)].1),
            Symbol::Stored
        );
    }
    assert_eq!(
        receiver.symbol(1, 1, 4, &g1[4].1),
        Symbol::Abandoned { generation: 1 }
    );
    assert_eq!(receiver.active_generations(), 0);
    assert_eq!(
        receiver.symbol(1, 1, 3, &g1[3].1),
        Symbol::Dropped(Drop::GenerationDone)
    );
    let g2 = symbols_of(&plan, 2);
    assert_eq!(
        receiver.symbol(1, 2, 0, &g2[0].1),
        Symbol::Decoded(Decoded {
            generation: 2,
            offset: 124,
            bytes: object_bytes(124, 3),
        }),
        "the short generation's one sent source is the whole of it"
    );
    // A newer credit epoch starts the budget over.
    assert!(receiver.credit(Credit {
        credit_epoch: 2,
        ..credit(1, 4, 48, 12)
    }));
    assert_eq!(receiver.decode_work_spent(), 0);
}

#[test]
fn a_short_generation_decodes_from_one_repair_symbol() {
    // 27 bytes: generation 2 has one sent source, three all-zero sources
    // counted as received from the start, and two repair symbols. Losing
    // the source, the first repair symbol alone completes k.
    let mut receiver = Receiver::new();
    receiver.credit(ample());
    let plan = plan(1, 100, 27, 4, 2, 3);
    receiver.open(plan).unwrap();
    let g2 = symbols_of(&plan, 2);
    assert_eq!(
        receiver.symbol(1, 2, 5, &g2[2].1),
        Symbol::Decoded(Decoded {
            generation: 2,
            offset: 124,
            bytes: object_bytes(124, 3),
        })
    );
    assert_eq!(receiver.decode_work_spent(), 12, "elimination was needed");
    // A full generation with one repair in hand reports the three sources
    // it still lacks and the zero sources it never will.
    assert_eq!(receiver.symbol(1, 0, 4, &[7; 3]), Symbol::Stored);
    assert_eq!(
        receiver.report(1, 0),
        Some(Report {
            sequence: 1,
            received: 1,
            missing_sources: vec![0, 1, 2, 3]
        })
    );
}

#[test]
fn credit_caps_active_generations_and_unretired_bytes() {
    let mut receiver = Receiver::new();
    receiver.credit(credit(1, 1, 24, 0));
    let plan = plan(1, 0, 36, 4, 2, 3);
    receiver.open(plan).unwrap();
    assert_eq!(receiver.symbol(1, 0, 0, &[1; 3]), Symbol::Stored);
    assert_eq!(
        receiver.symbol(1, 1, 0, &[1; 3]),
        Symbol::Dropped(Drop::PastCredit),
        "a second active generation"
    );
    assert!(receiver.abandon(1, 0));
    assert!(!receiver.abandon(1, 0), "already retired");
    assert!(!receiver.abandon(1, 5), "never opened");
    assert!(!receiver.abandon(9, 0), "unknown epoch");
    assert_eq!(receiver.active_generations(), 0);
    assert_eq!(receiver.symbol(1, 1, 0, &[1; 3]), Symbol::Stored);
    // Bytes: 24 allows two generations of 12, gens allows one; raise gens.
    receiver.credit(Credit {
        credit_epoch: 2,
        ..credit(1, 4, 24, 0)
    });
    assert_eq!(receiver.symbol(1, 2, 0, &[1; 3]), Symbol::Stored);
    assert_eq!(receiver.unretired_bytes(), 24);
    // Generation 0 is done, so a fourth would be the third active one.
    let mut wide = Receiver::new();
    wide.credit(credit(1, 4, 24, 0));
    wide.open(plan).unwrap();
    assert_eq!(wide.symbol(1, 0, 0, &[1; 3]), Symbol::Stored);
    assert_eq!(wide.symbol(1, 1, 0, &[1; 3]), Symbol::Stored);
    assert_eq!(
        wide.symbol(1, 2, 0, &[1; 3]),
        Symbol::Dropped(Drop::PastCredit)
    );
    assert!(wide.close(1));
    assert_eq!(wide.unretired_bytes(), 0);
    assert_eq!(wide.active_generations(), 0);
}

#[test]
fn a_report_needs_a_live_generation() {
    let mut receiver = Receiver::new();
    receiver.credit(ample());
    receiver.open(plan(1, 0, 12, 4, 2, 3)).unwrap();
    assert_eq!(receiver.report(2, 0), None, "unknown epoch");
    assert_eq!(receiver.report(1, 0), None, "no symbol yet");
    assert_eq!(receiver.report(1, 7), None, "past the epoch");
}

#[test]
fn a_sender_tracks_what_credit_lets_it_open_and_begin() {
    let mut sender = Sender::new();
    let plan1 = plan(1, 0, 24, 4, 2, 3);
    assert!(!sender.may_open());
    assert_eq!(sender.open(plan1), Err(Error::InvalidGeometry));
    assert!(sender.credit(credit(1, 1, 12, 0)));
    assert!(!sender.credit(credit(1, 1, 12, 0)));
    assert!(sender.may_open());
    assert_eq!(sender.open(plan1), Ok(()));
    assert_eq!(sender.open(plan1), Err(Error::InvalidGeometry), "in use");
    assert!(!sender.may_open(), "one epoch allowed");
    assert_eq!(
        sender.open(plan(2, 0, 24, 4, 2, 3)),
        Err(Error::InvalidGeometry)
    );
    assert!(sender.may_begin(1));
    assert!(!sender.may_begin(2), "unknown epoch");
    assert_eq!(
        sender.begin(1, 2),
        Err(Error::InvalidGeometry),
        "past the epoch"
    );
    assert_eq!(sender.begin(1, 0), Ok(()));
    assert_eq!(
        sender.begin(1, 0),
        Err(Error::InvalidGeometry),
        "already begun"
    );
    assert!(!sender.may_begin(1), "one active generation allowed");
    assert_eq!(sender.begin(1, 1), Err(Error::InvalidGeometry));
    assert_eq!(sender.active_generations(), 1);
    assert_eq!(sender.open_epochs(), 1);
    assert_eq!(sender.unretired_bytes(), 12);
    assert_eq!(sender.outcome(1, 0), Some(None));
    assert_eq!(sender.outcome(1, 1), None);
    // Feedback: a newer state is accepted once, done retires once.
    assert!(sender.state(1, 0, 1));
    assert!(!sender.state(1, 0, 1), "not newer");
    assert!(sender.state(1, 0, 3));
    assert!(!sender.state(1, 1, 1), "not begun");
    assert!(!sender.state(2, 0, 1), "unknown epoch");
    assert!(sender.done(1, 0, Done::Decoded));
    assert!(!sender.done(1, 0, Done::Decoded), "a repeat");
    assert!(!sender.done(1, 1, Done::Abandoned), "never begun");
    assert!(!sender.done(2, 0, Done::Abandoned), "unknown epoch");
    assert!(!sender.state(1, 0, 4), "done generations take no state");
    assert_eq!(sender.outcome(1, 0), Some(Some(Done::Decoded)));
    assert_eq!(sender.active_generations(), 0);
    assert_eq!(sender.unretired_bytes(), 0);
    assert!(sender.may_begin(1));
    assert_eq!(sender.begin(1, 1), Ok(()));
    // Bytes cap: 12 allows one generation even with room in the count.
    sender.credit(Credit {
        credit_epoch: 2,
        ..credit(1, 4, 12, 0)
    });
    assert!(!sender.may_begin(1));
    // Refused or closed: live generations retire and the epoch is spent.
    assert!(sender.refused(1));
    assert!(!sender.refused(1));
    assert_eq!(sender.active_generations(), 0);
    assert_eq!(sender.unretired_bytes(), 0);
    assert_eq!(sender.open_epochs(), 0);
    assert_eq!(sender.outcome(1, 1), None, "forgotten");
    let plan3 = plan(3, 0, 24, 4, 2, 3);
    assert_eq!(sender.open(plan3), Ok(()));
    assert_eq!(sender.begin(3, 0), Ok(()));
    assert!(sender.close(3));
    assert!(!sender.close(3));
    assert_eq!(sender.active_generations(), 0);
}

#[test]
fn a_sender_and_receiver_agree_on_a_lossy_epoch() {
    // Every generation loses two symbols; nothing crosses the reliable path.
    let plan = plan(9, 1000, 27, 4, 2, 3);
    let mut sender = Sender::new();
    let mut receiver = Receiver::new();
    let credit = credit(1, 3, 36, 1 << 20);
    sender.credit(credit);
    receiver.credit(credit);
    sender.open(plan).unwrap();
    assert_eq!(receiver.open(plan), Ok(Open::Opened));
    let mut recovered = Vec::new();
    for generation in 0..3 {
        sender.begin(9, generation).unwrap();
        let symbols = symbols_of(&plan, generation);
        let mut done = false;
        for (i, (esi, bytes)) in symbols.iter().enumerate() {
            // Lose the first two symbols of every generation.
            if i < 2 {
                continue;
            }
            match receiver.symbol(9, generation, *esi, bytes) {
                Symbol::Stored => {}
                Symbol::Decoded(decoded) => {
                    assert_eq!(decoded.generation, generation);
                    recovered.push((decoded.offset, decoded.bytes));
                    assert!(sender.done(9, generation, Done::Decoded));
                    done = true;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(done, "generation {generation}");
    }
    assert_eq!(
        recovered,
        vec![
            (1000, object_bytes(1000, 12)),
            (1012, object_bytes(1012, 12)),
            (1024, object_bytes(1024, 3)),
        ]
    );
    assert!(sender.close(9));
    assert!(receiver.close(9));
    assert_eq!(receiver.unretired_bytes(), 0);
    assert_eq!(sender.unretired_bytes(), 0);
}

#[test]
fn the_generation_count_binds_when_bytes_do_not() {
    let mut sender = Sender::new();
    sender.credit(credit(1, 2, 1 << 20, 0));
    sender.open(plan(1, 0, 36, 4, 2, 3)).unwrap();
    assert_eq!(sender.begin(1, 0), Ok(()));
    assert!(sender.may_begin(1));
    assert_eq!(sender.begin(1, 1), Ok(()));
    assert!(!sender.may_begin(1), "two active generations is the cap");
    assert_eq!(sender.begin(1, 2), Err(Error::InvalidGeometry));
    assert!(sender.done(1, 1, Done::Abandoned));
    assert!(sender.may_begin(1));
}
