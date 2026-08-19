//! Fetching one bundle over a session: opening it, validating the
//! manifest, and pipelining range requests into a bundle directory
//! `receive_bundle` consumes unchanged.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use vot_codec::frames::{
    self, MAX_MANIFEST_REQUEST_PAGES, MAX_REQUESTED_RANGE, ManifestRequest, PackageDescriptor,
    RangeRequest, TypedFrame,
};
use vot_codec::{DecodeLimits, Settings, error_code};
use vot_scheduler::session::{CompletedBundle, SessionReceiver};
use vot_scheduler::{FileSink, ReliableReceiver};
use vot_session::{Authentication, Session};
use vot_transport_api::{Event, MAX_CONTROL_FRAME_PAYLOAD, SubjectId, TransportAdapter};

use vot_resume::{ResumeStore, UnitRanges};

use crate::serve::is_backpressure;
use crate::{Error, MANIFEST_DIRECTORY, MANIFEST_SEAL, ManifestReader, PackageSummary, Storage};

mod coverage;
mod plan;
mod protocol;
mod proving;
mod sink;

pub(crate) use coverage::*;
pub(crate) use plan::*;
pub use protocol::BundleFetcher;
pub(crate) use protocol::*;
pub(crate) use proving::*;
pub(crate) use sink::*;

/// What one fetch pass left the session as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchStatus {
    /// The fetch is live; call again once the carrier reports an event.
    Active,
    /// The bundle is on disk, synced, and validated.
    Complete,
    /// The carrier ended the session before the bundle was whole.
    Disconnected,
    /// This end closed the session under a registered code.
    Closed(u16),
}

/// Why a frame could not be taken: server protocol fault, wrong package,
/// or local failure.
pub(crate) enum Fault {
    Peer(u16),
    Pin,
    Local(Error),
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Local(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{
        Loopback, built_bundle, control_event, decode_control, discard, noise, not_required,
        patterned, pump, pump_records_first,
    };
    use crate::tests::temporary;
    use crate::{BundleServer, KeyMaterial, ServeConnection, build_bundle, receive_bundle};
    use vot_transport_api::ConnectionId;

    /// A served session and its state, ready to answer a fetch.
    pub(crate) fn serving(bundle: &Path) -> (BundleServer, Session<Loopback>, ServeConnection) {
        let server = BundleServer::open(bundle).unwrap();
        let mut session = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            not_required(),
        );
        session.begin().unwrap();
        (server, session, ServeConnection::new())
    }

    /// Puts the handshake and the server's announcement on the fetcher's
    /// carrier, without the pass that takes them, and answers with the
    /// sequence the pump reached so a caller can go on pumping.
    pub(crate) fn announce(
        server: &BundleServer,
        serving: &mut Session<Loopback>,
        connection: &mut ServeConnection,
        fetcher: &mut BundleFetcher<Loopback>,
    ) -> u64 {
        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            serving.driver(),
            &mut sequence,
        );
        server.service(serving, connection).unwrap();
        pump(
            serving.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        sequence
    }

    /// One round of both engines and the pump, the way `run_to_end` runs it.
    pub(crate) fn round(
        server: &BundleServer,
        serving: &mut Session<Loopback>,
        connection: &mut ServeConnection,
        fetcher: &mut BundleFetcher<Loopback>,
        sequence: &mut u64,
    ) -> FetchStatus {
        let status = fetcher.service().unwrap();
        pump(fetcher.session_mut().driver(), serving.driver(), sequence);
        for _ in 0..ROUND_BUDGET {
            server.service(serving, connection).unwrap();
            if !connection.has_backlog() {
                break;
            }
        }
        pump(serving.driver(), fetcher.session_mut().driver(), sequence);
        status
    }

    /// Rounds a fetch may take before it is not progressing.
    ///
    /// Tight on purpose: a round of a stuck fetch re-fetches an object, so
    /// a generous budget means minutes of work before a failure surfaces.
    const ROUND_BUDGET: usize = 32;

    /// Runs both engines and the pump until the fetch reaches a terminal
    /// status, bounded by rounds rather than a clock.
    pub(crate) fn run_to_end(
        server: &BundleServer,
        serving: &mut Session<Loopback>,
        connection: &mut ServeConnection,
        fetcher: &mut BundleFetcher<Loopback>,
        corrupt_first_record: bool,
    ) -> Result<FetchStatus, Error> {
        let mut sequence = 0;
        let mut corrupted = corrupt_first_record;
        for _ in 0..ROUND_BUDGET {
            let status = fetcher.service()?;
            if status != FetchStatus::Active {
                return Ok(status);
            }
            pump(
                fetcher.session_mut().driver(),
                serving.driver(),
                &mut sequence,
            );
            for _ in 0..ROUND_BUDGET {
                server.service(serving, connection).unwrap();
                if !connection.has_backlog() {
                    break;
                }
            }
            if corrupted {
                if let Some((_, bytes)) = serving.driver().records.first_mut() {
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                    corrupted = false;
                }
            }
            pump(
                serving.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
        }
        panic!("the fetch did not settle within its round budget");
    }

    /// Recursively compares two directory trees by structure and bytes.
    ///
    /// The leaves a `send` keeps beside an object are skipped: they are a
    /// cache a serve rebuilds by reading the object, the manifest and seal do
    /// not cover them, and a fetch does not write them yet.
    pub(crate) fn assert_same_tree(left: &Path, right: &Path) {
        let names = |root: &Path| {
            let mut entries: Vec<_> = fs::read_dir(root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| !name.to_string_lossy().ends_with(".leaves"))
                .collect();
            entries.sort();
            entries
        };
        let left_entries = names(left);
        assert_eq!(left_entries, names(right), "differs under {left:?}");
        for name in left_entries {
            let (a, b) = (left.join(&name), right.join(&name));
            if a.is_dir() {
                assert_same_tree(&a, &b);
            } else {
                assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap(), "{a:?}");
            }
        }
    }

    #[test]
    pub(crate) fn a_bundle_round_trips_build_serve_fetch_receive() {
        // A packed pair, a direct object spanning several ranges, and an empty file.
        let source = temporary("trip-source");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("a.txt"), patterned(1000)).unwrap();
        fs::write(source.join("nested/b.bin"), patterned(150_000)).unwrap();
        fs::write(source.join("big.bin"), patterned(8_500_000)).unwrap();
        fs::write(source.join("empty.txt"), b"").unwrap();
        let bundle = temporary("trip-bundle");
        let built = build_bundle(&source, &bundle).unwrap();

        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("trip-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        assert_eq!(fetcher.package(), Some(built));
        assert!(!fetcher.has_backlog());

        assert_same_tree(&bundle, &output);

        let destination = temporary("trip-destination");
        let receipt = temporary("trip-receipt.cbor");
        // receive_bundle writes a JSON summary beside the receipt, which the
        // receipt's own guard does not know about.
        let _summary = crate::tests::guarded(receipt.with_extension("json"));
        let report = receive_bundle(
            &output,
            &destination,
            &receipt,
            &KeyMaterial::Shared(vec![7; 32]),
            "2026-08-06T00:00:00Z",
        )
        .unwrap();
        assert_eq!(report.package, built);
        assert_same_tree(&source, &destination);
        discard(&[&source, &bundle, &output, &destination, &receipt]);
    }

    /// Rounds one rail until its plan exists, which is where rails join.
    pub(crate) fn planned(
        server: &BundleServer,
        session: &mut Session<Loopback>,
        connection: &mut ServeConnection,
        fetcher: &mut BundleFetcher<Loopback>,
    ) -> SharedPlan {
        let mut sequence = 0;
        for _ in 0..ROUND_BUDGET {
            round(server, session, connection, fetcher, &mut sequence);
            if let Some(plan) = fetcher.plan.clone() {
                return plan;
            }
        }
        panic!("the fetch never planned");
    }

    #[test]
    pub(crate) fn two_rails_stripe_one_object_over_a_shared_plan() {
        // Two sessions striping one object: the primary's window is narrowed
        // to one span so a two-span object must stripe across both rails.
        let length = 2 * usize::try_from(MAX_REQUESTED_RANGE).unwrap();
        let (bundle, built) = built_bundle("striped", &[("big.bin", patterned(length))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut session1 = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            crate::harness::not_required(),
        );
        session1.begin().unwrap();
        let mut connection1 = ServeConnection::new();
        let mut session2 = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            crate::harness::not_required(),
        );
        session2.begin().unwrap();
        let mut connection2 = ServeConnection::new();

        let output = temporary("striped-fetched");
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        primary.rail.window_bytes = MAX_REQUESTED_RANGE;
        let plan = planned(&server, &mut session1, &mut connection1, &mut primary);
        let mut secondary = BundleFetcher::join(
            Loopback::default(),
            &output,
            Arc::clone(&plan),
            None,
            BTreeSet::new(),
        )
        .unwrap();

        let (mut seq1, mut seq2) = (0, 0);
        // Admit the rail before the primary settles, so the handout is deterministic.
        for _ in 0..ROUND_BUDGET {
            round(
                &server,
                &mut session2,
                &mut connection2,
                &mut secondary,
                &mut seq2,
            );
            if secondary.rail.taken_bytes > 0 {
                break;
            }
        }
        let mut settled = false;
        for _ in 0..ROUND_BUDGET {
            let one = round(
                &server,
                &mut session1,
                &mut connection1,
                &mut primary,
                &mut seq1,
            );
            let two = round(
                &server,
                &mut session2,
                &mut connection2,
                &mut secondary,
                &mut seq2,
            );
            if one == FetchStatus::Complete && two == FetchStatus::Complete {
                settled = true;
                break;
            }
        }
        assert!(settled, "the rails never finished the fetch");
        assert_eq!(primary.rail.taken_bytes, MAX_REQUESTED_RANGE);
        assert_eq!(secondary.rail.taken_bytes, MAX_REQUESTED_RANGE);
        assert!(!primary.has_backlog());
        assert!(!secondary.has_backlog());
        assert_eq!(primary.package(), Some(built));
        assert_eq!(secondary.package(), Some(built));
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn an_abandoned_plan_ends_every_rail_without_its_stall_budget() {
        // A failed rail marks the plan; the others end at their next pass
        // instead of waiting out a stall budget.
        let (bundle, _) = built_bundle("abandoned", &[("big.bin", patterned(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("abandoned-fetched");
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let plan = planned(&server, &mut session, &mut connection, &mut primary);
        let mut secondary = BundleFetcher::join(
            Loopback::default(),
            &output,
            Arc::clone(&plan),
            None,
            BTreeSet::new(),
        )
        .unwrap();

        abandon_plan(&plan);
        assert_eq!(primary.service().unwrap(), FetchStatus::Disconnected);
        assert!(!primary.has_backlog(), "an ended rail owes nothing");
        assert_eq!(secondary.service().unwrap(), FetchStatus::Disconnected);
        assert!(!secondary.has_backlog());
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_rail_paces_itself_and_refuses_inline_proving() {
        // A rail's window is its own account; inline proving would never earn it back.
        let (bundle, _) = built_bundle("railpace", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("railpace-fetched");
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let plan = planned(&server, &mut session, &mut connection, &mut primary);
        let mut secondary = BundleFetcher::join(
            Loopback::default(),
            &output,
            Arc::clone(&plan),
            None,
            BTreeSet::new(),
        )
        .unwrap();
        assert!(secondary.secondary, "a joined fetcher is a rail");
        assert_eq!(
            secondary.pin,
            Some(server.package().root),
            "the rail pins the plan's package"
        );
        assert!(
            secondary.set_proving_threads(0).is_err(),
            "a rail cannot prove inline"
        );
        assert!(
            secondary.set_proving_threads(2).is_ok(),
            "a narrower pool is the rail's to choose"
        );
        // Budgets are the pipeline depth (a product); a sum would be one bundle wide.
        // The depth counts the bundles a coded answer cuts each cover into,
        // not the covers alone: at the cover count a coded fetch spent the
        // budget on pieces and ended with `PendingBundlesExhausted`.
        assert_eq!(
            secondary.receiver.pending_bundle_limit(),
            PENDING_BUNDLE_DEPTH
        );
        assert_eq!(
            secondary.receiver.pending_byte_limit(),
            PENDING_BUNDLE_BYTES
        );
        assert_eq!(secondary.receiver.orphan_byte_limit(), ORPHAN_BUNDLE_BYTES);
        // The coded pipeline orphans records too, and an entry holds a few
        // generations rather than a whole piece, so the count is derived
        // from the byte budget and not from pieces.
        assert_eq!(
            secondary.receiver.orphan_bundle_limit(),
            ORPHAN_BUNDLE_DEPTH
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_rail_forgets_the_object_the_plan_moved_past() {
        // A partial account for a moved-past object is forgotten, or the
        // receiver keeps a reservation per object.
        let output = temporary("railforget");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let first = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [1; 32],
            length: 1000,
        });
        let second = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [2; 32],
            length: 2000,
        });
        let (s0, s1) = (subject_of(&first), subject_of(&second));
        let sink0 = Arc::new(
            CountingSink::create(
                &output.join("objects").join("a.obj"),
                first.object.length,
                None,
            )
            .unwrap(),
        );
        let sink1 = Arc::new(
            CountingSink::create(
                &output.join("objects").join("b.obj"),
                second.object.length,
                None,
            )
            .unwrap(),
        );
        fetcher.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: vec![first, second],
            current: 0,
            active: Some(sink0),
            placed_before: 0,
            carried_before: 0,
            next_offset: 0,
            covered: CoverageMap::new(),
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        })));
        fetcher.advance().unwrap();
        assert_eq!(
            fetcher.rail.admitted,
            Some((0, s0)),
            "the first object is this rail's"
        );

        // Another rail saw the first object whole and moved the plan on.
        {
            let mut plan = fetcher.locked_plan().unwrap();
            plan.current = 1;
            plan.active = Some(sink1);
        }
        fetcher.advance().unwrap();
        assert_eq!(
            fetcher.rail.admitted,
            Some((1, s1)),
            "the current object is admitted"
        );
        assert!(
            !fetcher.receiver.abandon(s0),
            "the partial first object was already forgotten"
        );
        discard(&[&output]);
    }

    #[test]
    pub(crate) fn a_finished_plan_is_left_exactly_as_it_is() {
        // A pass over a finished plan touches nothing; the directory is
        // gone to prove it.
        let output = temporary("finished-left");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 7,
                entries: 0,
            },
            objects: Vec::new(),
            current: 0,
            active: None,
            placed_before: 7,
            carried_before: 7,
            next_offset: 0,
            covered: CoverageMap::new(),
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: true,
        })));
        fs::remove_dir_all(&output).unwrap();
        fetcher.advance().unwrap();
        fetcher.note_placed();
        assert!(fetcher.complete());
        assert!(
            fetcher.first_moved().is_none(),
            "bytes from a prior run have no first-payload time in this run"
        );
    }

    #[test]
    pub(crate) fn the_handout_commits_forward() {
        let mut plan = FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: Vec::new(),
            current: 0,
            active: None,
            placed_before: 0,
            carried_before: 0,
            next_offset: 0,
            covered: CoverageMap::new(),
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        };
        plan.take(5, 5).unwrap();
        assert_eq!(plan.next_offset, 10, "a committed span moves the handout");
        plan.take(10, 5).unwrap();
        assert_eq!(plan.next_offset, 15);
    }

    #[test]
    #[should_panic(expected = "backwards")]
    #[cfg(debug_assertions)]
    pub(crate) fn a_span_behind_the_handout_panics_instead_of_spinning() {
        let mut plan = FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: Vec::new(),
            current: 0,
            active: None,
            placed_before: 0,
            carried_before: 0,
            next_offset: 0,
            covered: CoverageMap::new(),
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        };
        plan.take(0, 8).unwrap();
        let _ = plan.take(0, 8);
    }

    #[test]
    pub(crate) fn coverage_counts_every_byte_once() {
        // Coalescing counts each byte once, so a duplicate range cannot
        // complete an object with a hole.
        let mut plan = FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: Vec::new(),
            current: 0,
            active: None,
            placed_before: 0,
            carried_before: 0,
            next_offset: 0,
            covered: CoverageMap::new(),
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        };
        plan.cover(0, 10);
        assert_eq!(plan.covered.bytes(), 10);
        plan.cover(5, 10);
        assert_eq!(plan.covered.bytes(), 15, "the overlap counts once");
        plan.cover(5, 5);
        assert_eq!(plan.covered.bytes(), 15, "a duplicate counts never");
        plan.cover(20, 5);
        assert_eq!(plan.covered.bytes(), 20, "a gap stays a gap");
        plan.cover(15, 5);
        assert_eq!(plan.covered.bytes(), 25, "the gap filled exactly");
        assert_eq!(
            plan.covered.extents().iter().collect::<Vec<_>>(),
            vec![(&0, &25)],
            "adjacent extents coalesce to one"
        );
        plan.cover(0, 25);
        assert_eq!(plan.covered.bytes(), 25, "the whole again changes nothing");
        plan.cover(30, 0);
        assert_eq!(plan.covered.bytes(), 25, "an empty cover covers nothing");
        plan.cover(u64::MAX, 2);
        assert_eq!(plan.covered.bytes(), 25, "an overflowing cover is refused");
    }

    #[test]
    fn a_generation_that_loses_more_than_its_repair_count_arrives_reliably() {
        // Every eighth datagram goes. Interleaving spreads most losses across
        // the piece, but one generation still loses more than its eight repair
        // symbols. Such a generation decodes never and reports nothing, because
        // the receiver owes a GEN_DONE only for one it decoded or gave up on.
        // Before the serve closed a quiet epoch this hung until the fetch
        // spent its whole stall budget; the object now arrives over the
        // reliable path instead.
        let (bundle, built) = built_bundle("fec-past-repair", &[("big.bin", patterned(300_000))]);
        let fec = BTreeSet::from([vot_codec::extension_id::DATAGRAM_FEC]);
        let (client, mut serving) = crate::harness::duplex_pair();
        serving.drop_datagram_every = 8;
        let serving_bundle = bundle.to_path_buf();
        let serving_offer = fec.clone();
        let serving_thread = std::thread::spawn(move || {
            let mut server = BundleServer::open(&serving_bundle)?;
            server.automatic_fec = false;
            let mut answered = Some(serving);
            crate::drive::serve_sessions(Some(1), || {
                let carrier = answered.take().ok_or(Error::CarrierUnavailable)?;
                crate::drive::ServeSession::begin(
                    &server,
                    carrier,
                    crate::authz::Stance::open([7; 32]).offering(serving_offer.clone()),
                )
            })
        });
        let output = temporary("fec-past-repair-fetched");
        let mut fetcher =
            BundleFetcher::begin_with(client, &output, Some(built.root), None, fec.clone())
                .expect("a fetch offering the extension");
        assert_eq!(
            crate::drive::drive(&mut fetcher).expect("a driven fetch"),
            FetchStatus::Complete
        );
        assert_eq!(fetcher.package().expect("a package"), built);
        // 300000 bytes are five generations. Four decode from the interleaved
        // symbols and the one over its repair budget arrives reliably. The
        // sim's loss is periodic rather than sampled, so this count is the
        // same on every run.
        let counts = fetcher.fec_counts();
        assert_eq!(counts.decoded, 4, "one generation needed the fallback");
        assert_eq!(counts.offered, 5, "every generation was offered coded");
        assert_eq!(
            counts.abandoned, 0,
            "no generation reached its decode attempt, so none was given up on"
        );
        drop(fetcher);
        serving_thread
            .join()
            .expect("the serving thread")
            .expect("served");
    }

    #[test]
    pub(crate) fn a_transfer_in_process_rides_the_datagram_path_when_both_ends_offer_it() {
        // Both ends offer DATAGRAM_FEC over an in-process pair that loses
        // every ninth datagram: exactly eight of a full generation's 72, the
        // repair count, so every generation decodes with nothing to spare
        // and the fetch completes with the object having travelled as
        // symbols.
        let (bundle, built) = built_bundle("in-process-fec", &[("big.bin", patterned(1_500_000))]);
        let fec = BTreeSet::from([vot_codec::extension_id::DATAGRAM_FEC]);
        let (client, mut serving) = crate::harness::duplex_pair();
        serving.drop_datagram_every = 9;
        let serving_bundle = bundle.to_path_buf();
        let serving_thread = std::thread::spawn(move || {
            let mut server = BundleServer::open(&serving_bundle)?;
            assert!(
                server.automatic_fec,
                "the public server defaults to automatic FEC"
            );
            // This test pins the coded path rather than the automatic policy,
            // whose changing path samples are covered in the serve tests.
            server.automatic_fec = false;
            let mut answered = Some(serving);
            crate::drive::serve_sessions(Some(1), || {
                let carrier = answered.take().ok_or(Error::CarrierUnavailable)?;
                crate::drive::ServeSession::begin(
                    &server,
                    carrier,
                    crate::authz::Stance::open([7; 32]),
                )
            })
        });
        let output = temporary("in-process-fec-fetched");
        let mut fetcher = BundleFetcher::begin(client, &output, Some(built.root))
            .expect("a fetch offering the default extensions");
        assert_eq!(fetcher.extensions(), fec);
        assert_eq!(
            fetcher.fec_counts(),
            vot_scheduler::FecCounts::default(),
            "nothing yet"
        );
        assert_eq!(
            crate::drive::drive(&mut fetcher).expect("a driven fetch"),
            FetchStatus::Complete
        );
        assert_eq!(fetcher.package().expect("a package"), built);
        let counts = fetcher.fec_counts();
        assert!(
            counts.decoded >= 20,
            "the object's 23 generations came as symbols: {counts:?}"
        );
        // Every generation an epoch opened is accounted for, and this loss
        // rate spends no decode budget it does not have.
        assert!(
            counts.offered >= counts.decoded,
            "offered bounds decoded: {counts:?}"
        );
        assert_eq!(counts.abandoned, 0, "decode budget was never short");
        assert_eq!(counts.refused, 0, "credit admitted every epoch");
        drop(fetcher);
        serving_thread
            .join()
            .expect("the serving thread")
            .expect("served");
        // A fetch can explicitly offer nothing and decodes nothing.
        let (client, serving) = crate::harness::duplex_pair();
        let serving_bundle = bundle.to_path_buf();
        let serving_thread = std::thread::spawn(move || {
            let server = BundleServer::open(&serving_bundle)?;
            let mut answered = Some(serving);
            crate::drive::serve_sessions(Some(1), || {
                let carrier = answered.take().ok_or(Error::CarrierUnavailable)?;
                crate::drive::ServeSession::begin(
                    &server,
                    carrier,
                    crate::authz::Stance::open([7; 32]).offering(fec.clone()),
                )
            })
        });
        let output = temporary("in-process-plain-fetched");
        let mut plain =
            BundleFetcher::begin_offering(client, &output, Some(built.root), BTreeSet::new())
                .unwrap();
        assert!(plain.extensions().is_empty());
        assert_eq!(
            crate::drive::drive(&mut plain).expect("a driven fetch"),
            FetchStatus::Complete
        );
        assert_eq!(plain.fec_counts(), vot_scheduler::FecCounts::default());
        drop(plain);
        serving_thread
            .join()
            .expect("the serving thread")
            .expect("served");
    }

    #[test]
    pub(crate) fn a_capability_decides_a_transfer_in_process() {
        // The same thing the QUIC test asserts, over the in-process duplex.
        // `wire.rs` is not compiled without the carrier feature, so the QUIC
        // one measures nothing in the default mutation job, and the two hooks
        // that make a capability decide anything live here and in `drive`.
        use ed25519_dalek::SigningKey;

        let (bundle, built) =
            built_bundle("in-process-capability", &[("a.bin", patterned(60_000))]);
        let issuer = SigningKey::from_bytes(&[31; 32]);
        let holder_key = SigningKey::from_bytes(&[32; 32]);
        let requirement = crate::authz::Requirement::new(
            "you.example",
            crate::authz::key_id_of(&issuer.verifying_key()),
            issuer.verifying_key(),
            "them.example",
            built.root,
        );
        let token = crate::authz::issue(
            "you.example",
            "them.example",
            &issuer,
            holder_key.verifying_key().to_bytes(),
            built.root,
            crate::authz::now_seconds().expect("a clock"),
            3_600,
        )
        .expect("a token");
        let holder = Arc::new(
            crate::authz::Holder::new(token, holder_key).expect("a holder for that token"),
        );
        let channel_binding = vot_transport_api::ChannelBinding::from_bytes(
            [0x27; vot_transport_api::CHANNEL_BINDING_LEN],
        );

        // Holding the token: the serve grants and the bundle crosses.
        let (mut client, mut serving) = crate::harness::duplex_pair();
        client.set_channel_binding(channel_binding);
        serving.set_channel_binding(channel_binding);
        let serving_bundle = bundle.to_path_buf();
        let granting_requirement = requirement.clone();
        let granting = std::thread::spawn(move || {
            let server = BundleServer::open(&serving_bundle)?;
            let mut answered = Some(serving);
            crate::drive::serve_sessions(Some(1), || {
                let carrier = answered.take().ok_or(Error::CarrierUnavailable)?;
                crate::drive::ServeSession::begin(
                    &server,
                    carrier,
                    crate::authz::Stance::required(&granting_requirement, [7; 32]),
                )
            })
        });
        let output = temporary("in-process-granted");
        let mut fetcher = BundleFetcher::begin_with(
            client,
            &output,
            Some(built.root),
            Some(Arc::clone(&holder)),
            BTreeSet::new(),
        )
        .expect("a fetch holding the token");
        assert_eq!(
            crate::drive::drive(&mut fetcher).expect("a driven fetch"),
            FetchStatus::Complete,
            "the holder was refused"
        );
        assert_eq!(fetcher.package().expect("a package"), built);
        assert!(
            Arc::ptr_eq(&fetcher.holder().expect("the token"), &holder),
            "a rail would have opened its session with no capability"
        );
        drop(fetcher);
        granting
            .join()
            .expect("the granting thread")
            .expect("served");

        // Holding none: the fetch stops on the challenge rather than after a
        // transfer, and writes no bundle.
        let (mut client, mut serving) = crate::harness::duplex_pair();
        client.set_channel_binding(channel_binding);
        serving.set_channel_binding(channel_binding);
        let serving_bundle = bundle.to_path_buf();
        let refusing = std::thread::spawn(move || {
            let server = BundleServer::open(&serving_bundle)?;
            let mut answered = Some(serving);
            crate::drive::serve_sessions(Some(1), || {
                let carrier = answered.take().ok_or(Error::CarrierUnavailable)?;
                crate::drive::ServeSession::begin(
                    &server,
                    carrier,
                    crate::authz::Stance::required(&requirement, [8; 32]),
                )
            })
        });
        let refused_into = temporary("in-process-refused");
        let mut naked = BundleFetcher::begin(client, &refused_into, Some(built.root))
            .expect("a fetch with no token");
        assert_eq!(
            crate::drive::drive(&mut naked).expect("a driven fetch"),
            FetchStatus::Closed(vot_codec::error_code::AUTHENTICATION_FAILED),
            "a fetch with no capability was served, or refused for another reason"
        );
        assert!(naked.package().is_none(), "a bundle was written anyway");
        drop(naked);
        // The peer left mid-negotiation, which a bounded serve surfaces.
        assert!(
            refusing.join().expect("the refusing thread").is_err(),
            "a session whose peer never presented was reported as served"
        );
    }

    #[test]
    pub(crate) fn a_striped_fetch_over_threads_completes_and_spawns_its_rails() {
        // The connect count pins that the rail was spawned; width one
        // would pass every other assertion.
        use std::sync::Condvar;
        use std::sync::atomic::AtomicUsize;

        type Halves = Arc<(Mutex<VecDeque<crate::harness::Duplex>>, Condvar)>;

        // Small: striping distribution is the interleaved test's subject.
        let (bundle, built) = built_bundle("threaded", &[("big.bin", patterned(300_000))]);
        let output = temporary("threaded-fetched");
        let halves: Halves = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let serving_halves = Arc::clone(&halves);
        let serving_bundle = bundle.to_path_buf();
        let serving = std::thread::spawn(move || {
            let server = BundleServer::open(&serving_bundle)?;
            crate::drive::serve_sessions(Some(2), || {
                let (queue, arrived) = &*serving_halves;
                let queue = queue.lock().expect("the accept queue");
                // Bounded, so a fetch that never spawned its rail fails
                // this thread rather than hanging the suite on its join.
                let (mut queue, waited) = arrived
                    .wait_timeout_while(queue, std::time::Duration::from_secs(20), |waiting| {
                        waiting.is_empty()
                    })
                    .expect("the accept queue");
                if waited.timed_out() {
                    return Err(Error::CarrierUnavailable);
                }
                let carrier = queue.pop_front().expect("the wait held until one came");
                crate::drive::ServeSession::begin(&server, carrier, crate::harness::not_required())
            })
        });

        let connects = AtomicUsize::new(0);
        let connect = || {
            connects.fetch_add(1, Ordering::Relaxed);
            let (client, serving) = crate::harness::duplex_pair();
            let (queue, arrived) = &*halves;
            queue.lock().expect("the accept queue").push_back(serving);
            arrived.notify_all();
            Ok(client)
        };
        let mut fetcher = BundleFetcher::begin(connect().unwrap(), &output, None).unwrap();
        fetcher.rail.window_bytes = 0;
        let outcome = crate::drive::fetch_striped(fetcher, 2, connect).unwrap();
        assert_eq!(outcome.package, built);
        assert!(
            outcome.first_moved.is_some(),
            "the secondary rail's first payload is retained"
        );
        assert_eq!(
            connects.load(Ordering::Relaxed),
            2,
            "width two is the primary and exactly one spawned rail"
        );
        assert_same_tree(&bundle, &output);
        serving
            .join()
            .expect("the serving thread")
            .expect("both sessions served");
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_stride_crossing_flushes_once_and_arms_the_next() {
        // The crossing writer flushes once; the next mark is a stride
        // above what is placed.
        let output = temporary("stride");
        fs::create_dir_all(&output).unwrap();
        let stride = usize::try_from(FLUSH_STRIDE_BYTES).unwrap();
        let sink =
            CountingSink::create(&output.join("s.obj"), 4 * FLUSH_STRIDE_BYTES, None).unwrap();
        let chunk = vec![7u8; stride - 1];
        vot_scheduler::RangeSink::write_at(&sink, 0, &chunk).unwrap();
        assert_eq!(
            sink.flushes.load(Ordering::Relaxed),
            0,
            "one short of the stride flushes nothing"
        );
        vot_scheduler::RangeSink::write_at(&sink, FLUSH_STRIDE_BYTES - 1, &[7u8]).unwrap();
        assert_eq!(
            sink.flushes.load(Ordering::Relaxed),
            1,
            "the crossing flushes"
        );
        assert_eq!(
            sink.flush_due.load(Ordering::Relaxed),
            2 * FLUSH_STRIDE_BYTES,
            "and arms the next stride"
        );
        let wide = vec![7u8; 2 * stride];
        vot_scheduler::RangeSink::write_at(&sink, FLUSH_STRIDE_BYTES, &wide).unwrap();
        assert_eq!(
            sink.flushes.load(Ordering::Relaxed),
            2,
            "a write spanning strides flushes once"
        );
        assert_eq!(
            sink.flush_due.load(Ordering::Relaxed),
            4 * FLUSH_STRIDE_BYTES,
            "armed above what is placed, not one stride on"
        );
        discard(&[&output]);
    }

    #[test]
    pub(crate) fn a_killed_fetch_resumes_from_what_it_placed() {
        // Die after the first object is durable, then resume: the second
        // fetch asks only for the rest.
        let (bundle, built) = built_bundle(
            "killed",
            &[("a.bin", patterned(900_000)), ("b.bin", noise(900_000))],
        );
        let output = temporary("killed-fetched");

        // Fetch one: driven until the first object transitions, then
        // dropped where it stands, covers in flight and all.
        {
            let (server, mut session, mut connection) = serving(&bundle);
            let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            assert!(!fetcher.resuming, "a fresh destination is not a resume");
            let mut sequence = 0;
            let mut first_done = false;
            for _ in 0..ROUND_BUDGET {
                round(
                    &server,
                    &mut session,
                    &mut connection,
                    &mut fetcher,
                    &mut sequence,
                );
                if fetcher
                    .locked_plan()
                    .is_some_and(|plan| plan.placed_before > 0)
                {
                    first_done = true;
                    break;
                }
            }
            assert!(first_done, "the first object never completed");
        }
        assert!(
            output.join(RESUME_STORE).exists(),
            "the partial bundle carries its continuation state"
        );

        // Fetch two: continues instead of refusing, and asks only for
        // the second object.
        let (server, mut session, mut connection) = serving(&bundle);
        let mut resumed = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        assert!(resumed.resuming, "a store beside the bundle is a resume");
        assert!(
            resumed.set_proving_threads(0).is_err(),
            "a resumed fetch completes on coverage, which inline proving never feeds"
        );
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut resumed, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        assert_eq!(resumed.package(), Some(built));
        let second_length = resumed
            .locked_plan()
            .unwrap()
            .objects
            .iter()
            .map(|planned| planned.object.length)
            .max()
            .unwrap();
        assert_eq!(
            resumed.rail.taken_bytes, second_length,
            "the resumed fetch asked for the unplaced object and nothing more"
        );
        // What it placed is what it asked for, while what the bundle holds is
        // both objects. A throughput divided by this fetch's clock has to be
        // the first of those: the object the earlier fetch left behind never
        // crossed the wire on this one.
        assert_eq!(
            resumed.moved_bytes(),
            second_length,
            "the resumed fetch moved only the object that was missing"
        );
        assert!(
            resumed.first_moved().is_some(),
            "newly moved resume bytes have a first-payload time"
        );
        assert_eq!(
            resumed.placed_bytes(),
            built.logical_length,
            "the bundle holds both objects either way"
        );
        assert!(
            !output.join(RESUME_STORE).exists(),
            "completion removed the store"
        );
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_checkpoint_whose_file_is_gone_is_cleared_in_the_store_too() {
        // A stale checkpoint must be cleared in the store too, or a later
        // resume trusts bytes nobody placed.
        let (bundle, built) = built_bundle(
            "stale",
            &[("a.bin", patterned(900_000)), ("b.bin", noise(900_000))],
        );
        let output = temporary("stale-fetched");
        let first_root;
        {
            let (server, mut session, mut connection) = serving(&bundle);
            let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            let mut sequence = 0;
            let mut first_done = false;
            for _ in 0..ROUND_BUDGET {
                round(
                    &server,
                    &mut session,
                    &mut connection,
                    &mut fetcher,
                    &mut sequence,
                );
                if fetcher
                    .locked_plan()
                    .is_some_and(|plan| plan.placed_before > 0)
                {
                    first_done = true;
                    break;
                }
            }
            assert!(first_done, "the first object never completed");
            first_root = fetcher.locked_plan().unwrap().objects[0].object.root;
        }
        // The checkpointed file vanishes between the fetches.
        fs::remove_file(output.join("objects").join(crate::object_name(&first_root))).unwrap();

        let (server, mut session, mut connection) = serving(&bundle);
        let mut resumed = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let mut sequence = 0;
        for _ in 0..ROUND_BUDGET {
            round(
                &server,
                &mut session,
                &mut connection,
                &mut resumed,
                &mut sequence,
            );
            if resumed
                .locked_plan()
                .is_some_and(|plan| plan.active.is_some())
            {
                break;
            }
        }
        let first_subject = resumed
            .locked_plan()
            .map(|plan| subject_of(&plan.objects[0]))
            .unwrap();
        assert!(
            ResumeStore::open(output.join(RESUME_STORE))
                .unwrap()
                .checkpointed(first_subject)
                .is_none_or(vot_resume::UnitRanges::is_empty),
            "the stale claim was cleared in the store, not only locally"
        );
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut resumed, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        let total: u64 = resumed
            .locked_plan()
            .unwrap()
            .objects
            .iter()
            .map(|planned| planned.object.length)
            .sum();
        assert_eq!(
            resumed.rail.taken_bytes, total,
            "everything was re-requested, the stale claim bought nothing"
        );
        assert_eq!(resumed.package(), Some(built));
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_partial_bundle_without_a_store_is_refused_and_identity_is_held() {
        // Without a store, nothing is safe to continue. With one, its
        // sentinel is the resume pin.
        let occupied = temporary("resume-nostore");
        fs::create_dir_all(occupied.join(MANIFEST_DIRECTORY)).unwrap();
        assert!(matches!(
            BundleFetcher::begin(Loopback::default(), &occupied, None),
            Err(Error::DestinationExists)
        ));

        let bound = temporary("resume-bound");
        fs::create_dir_all(bound.join(MANIFEST_DIRECTORY)).unwrap();
        let mut store = ResumeStore::create(bound.join(RESUME_STORE)).unwrap();
        store
            .reserve_many([(package_sentinel([7; 32]), 1)])
            .unwrap();
        drop(store);
        assert!(
            matches!(
                BundleFetcher::begin(Loopback::default(), &bound, Some([9; 32])),
                Err(Error::RootMismatch)
            ),
            "a pin that disagrees with the store is refused before a byte"
        );
        let agreed = BundleFetcher::begin(Loopback::default(), &bound, None).unwrap();
        assert_eq!(
            agreed.pin,
            Some([7; 32]),
            "the store's identity is the pin a resume is held to"
        );
        drop(agreed);
        let matching = BundleFetcher::begin(Loopback::default(), &bound, Some([7; 32])).unwrap();
        assert_eq!(
            matching.pin,
            Some([7; 32]),
            "a pin that agrees with the store is no refusal"
        );
        discard(&[&occupied, &bound]);
    }

    #[test]
    pub(crate) fn checkpoint_units_and_extents_convert_by_whole_units_only() {
        // Only whole units may be checkpointed; stored units come back
        // clipped to the object.
        let unit = vot_scheduler::RANGE_UNIT_BYTES;
        let length = 3 * unit + 100;
        assert_eq!(total_units_of(length), 4, "the tail unit counts");
        assert_eq!(total_units_of(3 * unit), 3, "an exact fit adds none");

        let mut covered = BTreeMap::new();
        covered.insert(0, unit + 1);
        assert_eq!(
            durable_units(&covered, length).units().collect::<Vec<_>>(),
            vec![0],
            "a byte into the next unit checkpoints only the whole one"
        );
        let mut covered = BTreeMap::new();
        covered.insert(1, unit);
        assert!(
            durable_units(&covered, length).is_empty(),
            "a unit missing its first byte is not durable"
        );
        let mut covered = BTreeMap::new();
        covered.insert(3 * unit, 100);
        assert_eq!(
            durable_units(&covered, length).units().collect::<Vec<_>>(),
            vec![3],
            "the tail unit is whole at the object's end"
        );

        let mut covered = BTreeMap::new();
        covered.insert(0, 2 * unit + 5);
        assert_eq!(
            durable_units(&covered, 4 * unit)
                .units()
                .collect::<Vec<_>>(),
            vec![0, 1],
            "the boundary is a division, not a remainder"
        );

        let mut units = UnitRanges::new();
        units.extend_units([0, 3]);
        let extents = resumed_extents(&units, length);
        assert_eq!(
            extents.iter().collect::<Vec<_>>(),
            vec![(&0, &unit), (&(3 * unit), &100)],
            "stored units come back clipped to the object"
        );
        let mut units = UnitRanges::new();
        units.extend_units([3]);
        assert!(
            resumed_extents(&units, 3 * unit).is_empty(),
            "a unit starting at the object's end stands for no bytes"
        );
    }

    #[test]
    pub(crate) fn store_refusals_map_to_the_fetchs_own_errors() {
        // The identity refusal is the wrong-pin refusal; a broken store
        // file is its own I/O; everything else is a bundle problem.
        assert!(matches!(
            resume_failure(vot_resume::Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied
            ))),
            Error::Io(_)
        ));
        assert!(matches!(
            resume_failure(vot_resume::Error::IdentityMismatch),
            Error::RootMismatch
        ));
        assert!(matches!(
            resume_failure(vot_resume::Error::Corrupt),
            Error::InvalidBundle
        ));
    }

    #[test]
    pub(crate) fn only_whole_nonempty_objects_reserve_and_resume_whole() {
        // Reservations exclude zero-length objects; fully_resumed needs a
        // nonempty object fully covered.
        let empty = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [1; 32],
            length: 0,
        });
        let stored = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [2; 32],
            length: 100,
        });
        assert_eq!(
            reservations_of(&[empty.clone(), stored.clone()]),
            vec![(subject_of(&stored), 1)],
            "the empty object reserves nothing, the stored one its units"
        );

        assert!(!empty.fully_resumed(), "an empty object is never resumed");
        assert!(!stored.fully_resumed(), "nothing placed is not whole");
        let mut partial = stored.clone();
        partial.resumed.insert(0, 99);
        assert!(!partial.fully_resumed(), "one byte short is short");
        let mut whole = stored;
        whole.resumed.insert(0, 100);
        assert!(whole.fully_resumed());
    }

    #[test]
    pub(crate) fn the_stride_crossing_is_exact_at_its_edges() {
        assert_eq!(stride_after(0), FLUSH_STRIDE_BYTES);
        assert_eq!(stride_after(1), FLUSH_STRIDE_BYTES);
        assert_eq!(stride_after(FLUSH_STRIDE_BYTES - 1), FLUSH_STRIDE_BYTES);
        assert_eq!(stride_after(FLUSH_STRIDE_BYTES), 2 * FLUSH_STRIDE_BYTES);
        assert_eq!(stride_after(FLUSH_STRIDE_BYTES + 1), 2 * FLUSH_STRIDE_BYTES);
    }

    #[test]
    pub(crate) fn a_resumed_sinks_flush_mark_starts_past_what_is_placed() {
        // The seed arms the next stride above resumed bytes, so the first
        // flush is new work.
        let output = temporary("resume-seed");
        fs::create_dir_all(&output).unwrap();
        let path = output.join("s.obj");
        drop(CountingSink::create(&path, 4 * FLUSH_STRIDE_BYTES, None).unwrap());

        let mid = CountingSink::resume(&path, 4 * FLUSH_STRIDE_BYTES, 100, None).unwrap();
        assert_eq!(mid.placed(), 100, "the seed is what was placed");
        assert_eq!(
            mid.flush_due.load(Ordering::Relaxed),
            FLUSH_STRIDE_BYTES,
            "a seed inside the first stride arms the first mark"
        );
        let exact =
            CountingSink::resume(&path, 4 * FLUSH_STRIDE_BYTES, FLUSH_STRIDE_BYTES, None).unwrap();
        assert_eq!(
            exact.flush_due.load(Ordering::Relaxed),
            2 * FLUSH_STRIDE_BYTES,
            "a seed on the mark arms the one after it"
        );
        let past =
            CountingSink::resume(&path, 4 * FLUSH_STRIDE_BYTES, FLUSH_STRIDE_BYTES + 5, None)
                .unwrap();
        assert_eq!(
            past.flush_due.load(Ordering::Relaxed),
            2 * FLUSH_STRIDE_BYTES,
            "a seed past the mark arms the whole stride above it"
        );
        discard(&[&output]);
    }

    #[test]
    pub(crate) fn a_stride_flush_checkpoints_the_covered_units_of_its_own_object() {
        // Matching coverage becomes checkpointed units after sync; a
        // moved-past object checkpoints nothing.
        let unit = vot_scheduler::RANGE_UNIT_BYTES;
        let output = temporary("hook");
        fs::create_dir_all(&output).unwrap();
        let object = frames::ObjectId {
            suite: 1,
            root: [5; 32],
            length: 4 * unit,
        };
        let planned = PlannedObject::fresh(object);
        let subject = subject_of(&planned);
        let store = Arc::new(Mutex::new(
            ResumeStore::create(output.join(RESUME_STORE)).unwrap(),
        ));
        store
            .lock()
            .unwrap()
            .reserve_many([(subject, total_units_of(object.length))])
            .unwrap();
        let mut covered = BTreeMap::new();
        covered.insert(0, 2 * unit + 5);
        let plan = Arc::new(Mutex::new(FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: vec![planned],
            current: 0,
            active: None,
            placed_before: 0,
            carried_before: 0,
            next_offset: 0,
            covered: CoverageMap::seeded(covered),
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: Some(Arc::clone(&store)),
            finished: false,
        }));
        let sink = CountingSink::create(
            &output.join("h.obj"),
            object.length,
            Some(DurableHook {
                plan: Arc::downgrade(&plan),
                store: Arc::clone(&store),
                subject,
            }),
        )
        .unwrap();

        sink.durable.as_ref().unwrap().flush(&sink.file);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .checkpointed(subject)
                .unwrap()
                .units()
                .collect::<Vec<_>>(),
            vec![0, 1],
            "the whole units inside the snapshot, and no more"
        );

        // The plan moves on; a late flush of the old sink claims nothing.
        let other = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [6; 32],
            length: unit,
        });
        {
            let mut plan = plan.lock().unwrap();
            plan.objects.push(other);
            plan.current = 1;
            plan.covered = CoverageMap::new();
            plan.covered.insert(0, unit);
        }
        let before = store.lock().unwrap().checkpointed(subject).unwrap().count();
        sink.durable.as_ref().unwrap().flush(&sink.file);
        assert_eq!(
            store.lock().unwrap().checkpointed(subject).unwrap().count(),
            before,
            "another object's coverage is not this sink's to claim"
        );
        discard(&[&output]);
    }

    #[test]
    pub(crate) fn the_handout_walks_around_what_is_already_placed() {
        // The handout never asks inside a resumed extent or overlaps one.
        let object = frames::ObjectId {
            suite: 1,
            root: [3; 32],
            length: 3 * MAX_REQUESTED_RANGE,
        };
        let mut skip = BTreeMap::new();
        // A resumed hole pattern: the middle span is durable.
        skip.insert(MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE);
        // Held for the test, not for the expression that makes the sink: the
        // guard removes the directory when it goes, and the sink needs it.
        let output = temporary("handout-skip");
        fs::create_dir_all(&output).unwrap();
        let plan = FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: vec![PlannedObject::fresh(object)],
            current: 0,
            active: Some(Arc::new(
                CountingSink::create(&output.join("s.obj"), object.length, None).unwrap(),
            )),
            placed_before: 0,
            carried_before: 0,
            next_offset: 0,
            covered: CoverageMap::new(),
            syncing: false,
            abandoned: false,
            skip,
            store: None,
            finished: false,
        };
        let (_, offset, length) = plan.next_span().unwrap().unwrap();
        assert_eq!(
            (offset, length),
            (0, MAX_REQUESTED_RANGE),
            "clipped at the hole"
        );
        let mut plan = plan;
        plan.take(offset, length).unwrap();
        let (_, offset, length) = plan.next_span().unwrap().unwrap();
        assert_eq!(
            (offset, length),
            (2 * MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE),
            "the walk lands past the durable middle"
        );
        plan.take(offset, length).unwrap();
        assert!(plan.next_span().unwrap().is_none(), "nothing more is owed");
    }

    #[test]
    pub(crate) fn the_crossing_is_the_quantum_after_what_is_placed() {
        assert_eq!(crossing(999_999, 1_000_000, 1_000_000), None);
        assert_eq!(
            crossing(1_000_000, 1_000_000, 1_000_000),
            Some(2_000_000),
            "reaching the crossing is crossing it"
        );
        assert_eq!(crossing(1_200_000, 1_000_000, 1_000_000), Some(2_000_000));
        assert_eq!(
            crossing(2_500_000, 1_000_000, 1_000_000),
            Some(3_000_000),
            "a pass spanning quanta owes one report and the next whole crossing"
        );
        assert_eq!(
            crossing(u64::MAX, 1, 1),
            Some(u64::MAX),
            "the top saturates rather than wraps"
        );
    }

    #[test]
    pub(crate) fn placed_bytes_report_at_their_quantum_and_only_there() {
        // One report per quantum crossing; total is present once the
        // manifest settles.
        const QUANTUM: u64 = 1_000_000;
        type Seen = Arc<std::sync::Mutex<Vec<(u64, Option<u64>)>>>;
        let source = temporary("placed-source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("big.bin"), patterned(8_500_000)).unwrap();
        let bundle = temporary("placed-bundle");
        let built = build_bundle(&source, &bundle).unwrap();

        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("placed-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        assert!(
            fetcher.report_placed(0, Box::new(|_, _| {})).is_err(),
            "a zero quantum is a report per pass, refused"
        );
        let seen: Seen = Seen::default();
        let observed = Arc::clone(&seen);
        fetcher
            .report_placed(
                QUANTUM,
                Box::new(move |placed, total| observed.lock().unwrap().push((placed, total))),
            )
            .unwrap();
        assert!(fetcher.first_moved().is_none());
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        assert!(fetcher.first_moved().is_some());

        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty(), "8.5 MB against a 1 MB quantum reports");
        assert!(
            seen.len() <= 8,
            "more reports than crossings: {}",
            seen.len()
        );
        let mut crossed = 0;
        for (placed, total) in seen.iter() {
            assert!(
                *placed >= crossed + QUANTUM,
                "a report inside an already-reported quantum: {placed} after {crossed}"
            );
            crossed = placed - placed % QUANTUM;
            assert_eq!(
                *total,
                Some(built.logical_length),
                "the total is the manifest's"
            );
        }
        discard(&[&source, &bundle, &output]);
    }

    #[test]
    pub(crate) fn the_pool_reports_room_and_business_from_what_is_out() {
        // Both read `in_flight`; each has an off-by-one that only shows at the bound.
        let mut pool = ProvingPool::start(2);
        assert!(!pool.busy(), "an idle pool owes nothing");
        assert!(pool.has_room(), "an idle pool can take work");
        pool.in_flight = 3;
        assert!(pool.has_room(), "one below the bound still has room");
        assert!(pool.busy(), "anything out with a prover is busy");
        pool.in_flight = 4;
        assert!(!pool.has_room(), "twice the width is the bound");
        assert!(pool.busy());
        pool.in_flight = 0;
    }

    #[test]
    pub(crate) fn dropping_the_pool_ends_its_provers() {
        // The drop joins every prover, so nothing survives it.
        let pool = ProvingPool::start(2);
        let probe = std::sync::Arc::downgrade(&pool.taking);
        drop(pool);
        assert!(
            probe.upgrade().is_none(),
            "a prover outlived the pool that owned it"
        );
    }

    #[test]
    pub(crate) fn a_pass_with_a_witness_owed_books_it_before_returning() {
        // A pass that hands a bundle to a prover settles it in the same pass.
        let (bundle, _) = built_bundle("witness", &[("big.bin", patterned(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("witness-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        // Rounds until the fetch has planned and asked, because until then
        // every control frame is one `service` has to dispatch itself.
        let mut sequence = 0;
        for _ in 0..ROUND_BUDGET {
            fetcher.service().unwrap();
            pump(
                fetcher.session_mut().driver(),
                session.driver(),
                &mut sequence,
            );
            for _ in 0..ROUND_BUDGET {
                server.service(&mut session, &mut connection).unwrap();
                if !connection.has_backlog() {
                    break;
                }
            }
            pump(
                session.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
            if fetcher.plan.is_some() && fetcher.rail.next_request > 0 {
                break;
            }
        }
        assert!(fetcher.plan.is_some(), "the fetch never planned");

        // Then answers only, polled outside `service`, so a completed
        // bundle is parked for the pump below to be the first to see.
        for _ in 0..ROUND_BUDGET {
            for _ in 0..ROUND_BUDGET {
                server.service(&mut session, &mut connection).unwrap();
                if !connection.has_backlog() {
                    break;
                }
            }
            pump(
                session.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
            while fetcher.receiver.poll().unwrap().is_some() {}
            if fetcher.receiver.completed_bundles() > 0 {
                break;
            }
        }
        assert!(
            fetcher.receiver.completed_bundles() > 0,
            "no cover completed within the round budget"
        );

        // The decisive pass must wait, not spin; set now so the earlier
        // rounds are not slowed.
        fetcher.proving.wait = std::time::Duration::from_secs(5);
        fetcher.pump_provers().unwrap();
        let pool = fetcher
            .proving
            .pool
            .as_ref()
            .expect("the pass started the pool");
        assert!(
            pool.witnesses >= 1,
            "the pass that handed a bundle out did not book its witness"
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn the_proving_width_sets_the_deferred_bound_and_nothing_else_does() {
        let (bundle, _) = built_bundle("width", &[("a.txt", patterned(1000))]);
        let output = temporary("width-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        // The default width, wired through the same call a caller uses.
        assert_eq!(fetcher.proving.width, DEFAULT_PROVING_THREADS);
        assert_eq!(
            fetcher.receiver.deferred_limit(),
            DEFAULT_PROVING_THREADS + 1
        );
        // Budgets are the pipeline depth (a product); a sum would be one bundle wide.
        assert_eq!(fetcher.receiver.pending_byte_limit(), PENDING_BUNDLE_BYTES);
        assert_eq!(fetcher.receiver.orphan_byte_limit(), ORPHAN_BUNDLE_BYTES);
        assert_eq!(fetcher.receiver.orphan_bundle_limit(), ORPHAN_BUNDLE_DEPTH);
        // A narrower pool: the bound follows the width.
        fetcher.set_proving_threads(2).unwrap();
        assert_eq!(fetcher.proving.width, 2);
        assert_eq!(fetcher.receiver.deferred_limit(), 3);
        // Inline: the width is recorded and the bound is left alone, since
        // nothing is deferred to be bounded.
        fetcher.set_proving_threads(0).unwrap();
        assert_eq!(fetcher.proving.width, 0);
        assert_eq!(fetcher.receiver.deferred_limit(), 3, "no width, no change");
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn records_arriving_before_their_proofs_do_not_exhaust_the_receiver() {
        // Records can land before their proofs (the data lane outruns the
        // control stream). Each orphan occupies the receiver's budget; a
        // budget below the pipeline depth fails with
        // `PendingBundlesExhausted`. Noise, not a pattern, so the byte
        // budget is exercised along with the count.
        let (bundle, built) = built_bundle("orphans", &[("big.bin", noise(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("orphans-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        // Inline proving is the slower poll, which is what lets a real
        // carrier queue this deep; the reordering itself is the pump's.
        fetcher.set_proving_threads(0).unwrap();

        let mut sequence = 0;
        let mut status = FetchStatus::Active;
        for _ in 0..ROUND_BUDGET {
            status = fetcher.service().unwrap();
            if status != FetchStatus::Active {
                break;
            }
            pump(
                fetcher.session_mut().driver(),
                session.driver(),
                &mut sequence,
            );
            // Drained fully, so every answered cover is queued at once and
            // the reordering below moves all their records ahead of all
            // their proofs.
            for _ in 0..ROUND_BUDGET {
                server.service(&mut session, &mut connection).unwrap();
                if !connection.has_backlog() {
                    break;
                }
            }
            pump_records_first(
                session.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
        }
        assert_eq!(status, FetchStatus::Complete);
        assert_eq!(fetcher.package(), Some(built));
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_pinned_fetch_refuses_another_package() {
        let (bundle, _) = built_bundle("pinned", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("pinned-fetched");
        let mut fetcher =
            BundleFetcher::begin(Loopback::default(), &output, Some([9; 32])).unwrap();
        let outcome = run_to_end(&server, &mut session, &mut connection, &mut fetcher, false);
        assert!(matches!(outcome, Err(Error::RootMismatch)));
        assert_eq!(
            fetcher.session_mut().driver().closed,
            Some(error_code::OBJECT_IDENTITY_MISMATCH)
        );
        // And the pinned root it wanted is accepted when it matches.
        let (server, mut session, mut connection) = serving(&bundle);
        let accepted = temporary("pinned-accepted");
        let mut fetcher =
            BundleFetcher::begin(Loopback::default(), &accepted, Some(server.package().root))
                .unwrap();
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        discard(&[&bundle, &output, &accepted]);
    }

    #[test]
    pub(crate) fn a_tampered_record_ends_the_fetch_as_proof_invalid() {
        // Three covers, so the fetch still has one outstanding when the
        // proof fails.
        let (bundle, _) = built_bundle("tampered", &[("big.bin", patterned(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("tampered-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let outcome = run_to_end(&server, &mut session, &mut connection, &mut fetcher, true);
        assert!(matches!(outcome, Err(Error::Scheduler(_))));
        assert_eq!(
            fetcher.session_mut().driver().closed,
            Some(error_code::PROOF_INVALID)
        );
        assert!(!fetcher.has_backlog(), "a closed fetch owes nothing");
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn this_ends_own_failures_do_not_close_as_a_bad_proof() {
        // Local failures must not close as PROOF_INVALID; that blames the
        // server wrongly.
        assert_eq!(
            refusal_code(&vot_scheduler::Error::Sink),
            error_code::STORAGE_WRITE_FAILED
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::PendingBundlesExhausted),
            error_code::RESOURCE_LIMIT
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::RangeFragmentsExhausted),
            error_code::RESOURCE_LIMIT
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::AlreadyReceiving),
            error_code::RESOURCE_LIMIT
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::CodingEpochConflict),
            error_code::CODING_EPOCH_CONFLICT
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::MalformedFecFrame),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::Staging(
                vot_transport_api::Error::StagingExhausted
            )),
            error_code::RESOURCE_LIMIT
        );
        // And a proof the server could not back still is its fault.
        assert_eq!(
            refusal_code(&vot_scheduler::Error::ProofInvalid),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::RootMismatch),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::LengthMismatch),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::UnknownObject),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::RecordTooLarge),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::LengthExceeded),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::UnsupportedCompression),
            error_code::PROOF_INVALID
        );
    }

    #[test]
    pub(crate) fn a_zero_length_stored_object_is_written_rather_than_asked_for() {
        // A manifest can name an empty object; the receiver refuses to
        // begin one, so the fetch writes it.
        let (_, summary) = built_bundle("emptyobj", &[("a.txt", patterned(1000))]);
        let output = temporary("emptyobj-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let empty = frames::ObjectId {
            suite: 1,
            root: *blake3::hash(&[]).as_bytes(),
            length: 0,
        };
        fetcher.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary,
            objects: vec![PlannedObject::fresh(empty)],
            current: 0,
            active: None,
            placed_before: 0,
            carried_before: 0,
            next_offset: 0,
            covered: CoverageMap::new(),
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        })));
        fetcher.advance().unwrap();

        let path = output.join("objects").join(crate::object_name(&empty.root));
        assert!(fs::read(&path).unwrap().is_empty(), "the empty object is");
        assert!(fetcher.complete(), "and the plan is done with it");
        assert!(
            !fetcher.has_backlog(),
            "nothing was asked for on its account"
        );
        discard(&[&output]);
    }

    #[test]
    pub(crate) fn control_frames_that_are_not_answers_are_refused_or_skipped() {
        let (bundle, _) = built_bundle("frames", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("frames-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();

        // A well-formed frame this end does not consume is not an answer,
        // and not a fault either.
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [3; 16],
                    manifest_id: [4; 16],
                    first_page: 0,
                    page_count: 1,
                },
            )));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);

        // Bytes past the frame the envelope declared are malformed.
        let mut trailing = Vec::new();
        frames::encode(
            &TypedFrame::PackageDescriptor(fetcher.manifest.descriptor.clone().expect("announced")),
            &mut trailing,
        )
        .unwrap();
        trailing.push(0);
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(Event::Control(vot_transport_api::shared_payload(&trailing)));
        assert_eq!(
            fetcher.service().unwrap(),
            FetchStatus::Closed(error_code::MALFORMED_FRAME)
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_conflicting_announcement_ends_the_fetch() {
        let (bundle, _) = built_bundle("conflict", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("conflict-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        // Handshake and announcement arrive.
        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        fetcher.service().unwrap();
        let descriptor = fetcher.manifest.descriptor.clone().expect("announced");

        // An exact duplicate descriptor is idempotent.
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::PackageDescriptor(
                descriptor.clone(),
            )));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);

        // A conflicting one is not.
        let mut conflicting = descriptor;
        conflicting.page_count += 1;
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::PackageDescriptor(conflicting)));
        let status = fetcher.service().unwrap();
        assert_eq!(status, FetchStatus::Closed(error_code::MANIFEST_INVALID));
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_close_forgets_the_requests_the_carrier_never_took() {
        // The queue holds a request the carrier refused; left there it would
        // keep a dead session serviced.
        let (bundle, _) = built_bundle("forget", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("forget-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);

        fetcher.session_mut().driver().refuse_sends = usize::MAX;
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert!(fetcher.has_backlog(), "the manifest request is held");

        let mut conflicting = fetcher.manifest.descriptor.clone().expect("announced");
        conflicting.page_count += 1;
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::PackageDescriptor(conflicting)));
        assert_eq!(
            fetcher.service().unwrap(),
            FetchStatus::Closed(error_code::MANIFEST_INVALID)
        );
        assert!(!fetcher.has_backlog(), "a closed fetch holds nothing");
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_page_the_seal_never_committed_ends_the_fetch() {
        let (bundle, _) = built_bundle("badpage", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("badpage-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        fetcher.service().unwrap();
        assert!(fetcher.manifest.seal_bytes.is_some(), "announcement taken");

        // A well-formed page from a different manifest fails the digest.
        let (other, _) = built_bundle("badpage-other", &[("b.txt", patterned(2000))]);
        let foreign = fs::read(other.join("manifest").join(format!("{:016}.cbor", 0))).unwrap();
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestPage(foreign)));
        let status = fetcher.service().unwrap();
        assert_eq!(status, FetchStatus::Closed(error_code::MANIFEST_INVALID));
        discard(&[&bundle, &output, &other]);
    }

    #[test]
    pub(crate) fn a_disconnect_mid_fetch_is_reported() {
        let (bundle, _) = built_bundle("dropped", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("dropped-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        // Ready and announced, then the carrier goes away.
        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        fetcher.service().unwrap();
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(Event::Disconnected(ConnectionId(3)));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Disconnected);
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Disconnected);
        assert!(!fetcher.has_backlog(), "and nothing is still owed");
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_disconnect_that_arrives_with_the_last_bytes_still_completes() {
        // Records and disconnect arrive in one pass; the bundle is whole
        // and must complete.
        let (bundle, _) = built_bundle("lastgasp", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("lastgasp-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        let mut sequence = announce(&server, &mut session, &mut connection, &mut fetcher);
        let mut answered = false;
        for _ in 0..ROUND_BUDGET {
            let status = round(
                &server,
                &mut session,
                &mut connection,
                &mut fetcher,
                &mut sequence,
            );
            assert_eq!(status, FetchStatus::Active);
            // Everything asked for, and its answer waiting to be taken.
            if !fetcher.has_backlog() && fetcher.locked_plan().is_some_and(|p| p.active.is_some()) {
                answered = true;
                break;
            }
        }
        assert!(answered, "the object was never asked for in full");

        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(Event::Disconnected(ConnectionId(3)));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Complete);
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    /// The request the fetcher queued, decoded.
    pub(crate) fn queued_manifest_request(
        fetcher: &mut BundleFetcher<Loopback>,
    ) -> ManifestRequest {
        let frame = fetcher
            .rail
            .pending
            .pop_front()
            .expect("a request was queued");
        match decode_control(&frame) {
            TypedFrame::ManifestRequest(request) => request,
            other => panic!("not a manifest request: {other:?}"),
        }
    }

    #[test]
    pub(crate) fn manifest_spans_are_requested_one_at_a_time_in_arrival_order() {
        // More than 8,192 pages takes multiple requests; the cursor is
        // driven directly.
        let output = temporary("manifest-spans");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.manifest.descriptor = Some(PackageDescriptor {
            package: frames::ObjectId {
                suite: 1,
                root: [4; 32],
                length: 9,
            },
            manifest_id: [5; 16],
            page_count: 2 * MAX_MANIFEST_REQUEST_PAGES + 3,
        });
        fetcher.manifest.spans = manifest_spans(2 * MAX_MANIFEST_REQUEST_PAGES + 3);
        assert_eq!(fetcher.manifest.spans.len(), 3);

        // The first span is asked for, and nothing beyond it.
        fetcher.request_pages().map_err(|_| ()).unwrap();
        let first = queued_manifest_request(&mut fetcher);
        assert_eq!(first.manifest_id, [5; 16]);
        assert_eq!(
            (first.first_page, first.page_count),
            fetcher.manifest.spans[0]
        );
        fetcher.request_pages().map_err(|_| ()).unwrap();
        assert!(
            fetcher.rail.pending.is_empty(),
            "the next span waits on the pages of this one"
        );

        // The next span waits for prior pages (arrival order indexes the digest check).
        fetcher.manifest.pages_received = MAX_MANIFEST_REQUEST_PAGES - 1;
        fetcher.request_pages().map_err(|_| ()).unwrap();
        assert!(
            fetcher.rail.pending.is_empty(),
            "one page short is still short"
        );
        fetcher.manifest.pages_received = MAX_MANIFEST_REQUEST_PAGES;
        fetcher.request_pages().map_err(|_| ()).unwrap();
        let second = queued_manifest_request(&mut fetcher);
        assert_eq!(
            (second.first_page, second.page_count),
            fetcher.manifest.spans[1]
        );
        assert_ne!(second.request_id, first.request_id, "identities are fresh");

        // And the short final span, after which nothing more is owed.
        fetcher.manifest.pages_received = 2 * MAX_MANIFEST_REQUEST_PAGES;
        fetcher.request_pages().map_err(|_| ()).unwrap();
        let third = queued_manifest_request(&mut fetcher);
        assert_eq!(
            (third.first_page, third.page_count),
            fetcher.manifest.spans[2]
        );
        fetcher.manifest.pages_received = fetcher.manifest.descriptor.as_ref().unwrap().page_count;
        fetcher.request_pages().map_err(|_| ()).unwrap();
        assert!(
            fetcher.rail.pending.is_empty(),
            "the manifest is fully asked for"
        );
        discard(&[&output]);
    }

    #[test]
    pub(crate) fn a_seal_must_answer_the_descriptor_in_every_field() {
        // Each field the seal and descriptor share must agree, or the fetch
        // lands on an unpinned manifest.
        let (bundle, _) = built_bundle("sealfields", &[("a.txt", patterned(1000))]);
        let seal_bytes = fs::read(bundle.join(MANIFEST_DIRECTORY).join(MANIFEST_SEAL)).unwrap();
        let seal = vot_manifest::decode_seal(&seal_bytes).unwrap();
        let truth = PackageDescriptor {
            package: frames::ObjectId {
                suite: seal.package.suite,
                root: seal.package.root,
                length: seal.package.length,
            },
            manifest_id: seal.manifest_id,
            page_count: seal.final_page_count,
        };

        let mut wrong_manifest = truth.clone();
        wrong_manifest.manifest_id[0] ^= 1;
        let mut wrong_pages = truth.clone();
        wrong_pages.page_count += 1;
        let mut wrong_root = truth.clone();
        wrong_root.package.root[0] ^= 1;
        let mut wrong_length = truth.clone();
        wrong_length.package.length += 1;
        for (name, descriptor) in [
            ("manifest", wrong_manifest),
            ("pages", wrong_pages),
            ("root", wrong_root),
            ("length", wrong_length),
        ] {
            let output = temporary(&format!("sealfields-{name}"));
            let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            fetcher.manifest.descriptor = Some(descriptor);
            let outcome = fetcher.take_seal(seal_bytes.clone());
            assert!(
                matches!(outcome, Err(Fault::Peer(code)) if code == error_code::MANIFEST_INVALID),
                "a seal answering a different {name} was taken"
            );
        }

        // And the descriptor it does answer is taken, pages and all.
        let output = temporary("sealfields-answered");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.manifest.descriptor = Some(truth);
        assert!(fetcher.take_seal(seal_bytes).is_ok());
        assert!(fetcher.has_backlog(), "the manifest is asked for");
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_repeated_seal_is_idempotent_and_a_conflicting_one_ends_the_fetch() {
        let (bundle, _) = built_bundle("seal", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("seal-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();
        let seal = fetcher.manifest.seal_bytes.clone().expect("announced");
        let asked = fetcher.session_mut().driver().control.len();
        assert!(asked > 0, "the manifest was asked for");

        // The same seal again asks for nothing further.
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::Seal(seal)));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert_eq!(
            fetcher.session_mut().driver().control.len(),
            asked,
            "a repeated seal asked for the manifest twice"
        );

        // A different one is a different package under the same session.
        let (other, _) = built_bundle("seal-other", &[("b.txt", patterned(2000))]);
        let foreign = fs::read(other.join(MANIFEST_DIRECTORY).join(MANIFEST_SEAL)).unwrap();
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::Seal(foreign)));
        assert_eq!(
            fetcher.service().unwrap(),
            FetchStatus::Closed(error_code::MANIFEST_INVALID)
        );
        discard(&[&bundle, &output, &other]);
    }

    #[test]
    pub(crate) fn manifest_pages_are_taken_in_order_and_only_once() {
        // Two pages, so a page can arrive both twice and early. One entry
        // past the per-page cap is what spills a manifest.
        let files: Vec<(String, Vec<u8>)> = (0..=vot_manifest::MAX_ENTRIES_PER_PAGE)
            .map(|index| {
                (
                    format!("f{index:05}"),
                    vec![u8::try_from(index % 251).unwrap()],
                )
            })
            .collect();
        let named: Vec<(&str, Vec<u8>)> = files
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.clone()))
            .collect();
        let (bundle, _) = built_bundle("pageorder", &named);
        let discarded = bundle.to_path_buf();
        let pages: Vec<Vec<u8>> = (0..2)
            .map(|index| {
                fs::read(crate::manifest_page_path(
                    &bundle.join(MANIFEST_DIRECTORY),
                    index,
                ))
                .unwrap()
            })
            .collect();

        // A page before its predecessor is a server-side gap.
        let (server, mut session, mut connection) = serving(&bundle);
        let early = temporary("pageorder-early");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &early, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();
        assert_eq!(fetcher.manifest.pages_received, 0);
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestPage(pages[1].clone())));
        assert_eq!(
            fetcher.service().unwrap(),
            FetchStatus::Closed(error_code::MANIFEST_INVALID)
        );

        // The first page twice is the same page twice, and counts once.
        let (server, mut session, mut connection) = serving(&bundle);
        let twice = temporary("pageorder-twice");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &twice, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();
        for _ in 0..2 {
            fetcher
                .session_mut()
                .driver()
                .events
                .push_back(control_event(&TypedFrame::ManifestPage(pages[0].clone())));
        }
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert_eq!(fetcher.manifest.pages_received, 1, "the repeat was counted");
        assert!(fetcher.plan.is_none(), "a page short of the manifest");
        discard(&[&discarded, &early, &twice]);
    }

    #[test]
    pub(crate) fn a_send_failure_that_is_not_backpressure_surfaces() {
        // Backpressure holds a request; anything else is a failure that
        // must surface.
        let (bundle, _) = built_bundle("sendfail", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("sendfail-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.session_mut().driver().fail_sends_with = Some(vot_transport_api::Error::Backend);
        let outcome = fetcher.service();
        assert!(matches!(outcome, Err(Error::Session(_))));
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn no_more_is_asked_for_than_may_be_outstanding() {
        // The bound is asked-for minus placed; queue bounding instead would
        // fetch an object in full before any cover lands.
        let (bundle, summary) = built_bundle("inflight", &[("a.txt", patterned(1000))]);
        let output = temporary("inflight-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let object = frames::ObjectId {
            suite: 1,
            root: [3; 32],
            length: 40 * MAX_REQUESTED_RANGE,
        };
        let sink = Arc::new(
            CountingSink::create(&output.join("objects").join("held.obj"), 0, None).unwrap(),
        );
        fetcher.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary,
            objects: vec![PlannedObject::fresh(object)],
            current: 0,
            active: Some(Arc::clone(&sink)),
            placed_before: 0,
            carried_before: 0,
            next_offset: 0,
            covered: CoverageMap::new(),
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        })));

        // However many passes, and however readily the carrier takes them.
        for _ in 0..16 {
            fetcher.issue_ranges().unwrap();
            fetcher.rail.pending.clear();
        }
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            OUTSTANDING_REQUEST_BYTES,
            "asked for more than may be outstanding"
        );

        // Pacing is per rail; asking on another's arrivals overdraws both receivers.
        sink.placed.store(MAX_REQUESTED_RANGE, Ordering::Relaxed);
        fetcher.rail.settled_bytes = MAX_REQUESTED_RANGE;
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            OUTSTANDING_REQUEST_BYTES + MAX_REQUESTED_RANGE,
            "a settled cover did not buy the next request"
        );
        // Placing counts as progress, so a driving loop keeps a slow transfer alive.
        assert!(fetcher.progress() >= MAX_REQUESTED_RANGE);

        // A span is committed only once its frame is queued, or a failure
        // leaves a hole nobody re-requests.
        fetcher.rail.settled_bytes = 2 * MAX_REQUESTED_RANGE;
        let owed = fetcher.locked_plan().unwrap().next_offset;
        fetcher.rail.next_request = u64::MAX;
        assert!(
            fetcher.issue_ranges().is_err(),
            "the identifier space ended"
        );
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            owed,
            "a span whose frame never queued was consumed"
        );

        // The shared sink is not this rail's account; a full window blocks
        // regardless of placement.
        fetcher.rail.next_request = 0;
        fetcher.rail.settled_bytes = MAX_REQUESTED_RANGE;
        sink.placed
            .store(40 * MAX_REQUESTED_RANGE, Ordering::Relaxed);
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            owed,
            "the shared sink paid for a rail's spans"
        );

        // Inline proving has no witnesses, so the sink's placement is the pace.
        fetcher.set_proving_threads(0).unwrap();
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            owed + OUTSTANDING_REQUEST_BYTES,
            "an inline fetch paces on what its own sink placed"
        );

        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn an_existing_destination_is_refused() {
        let existing = temporary("occupied");
        fs::create_dir_all(&existing).unwrap();
        let outcome = BundleFetcher::begin(Loopback::default(), &existing, None);
        assert!(matches!(outcome, Err(Error::DestinationExists)));
        discard(&[&existing]);
    }

    #[test]
    pub(crate) fn a_backpressured_request_is_held_and_sent() {
        let (bundle, _) = built_bundle("held", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("held-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );

        // The pass that takes the seal wants to send the manifest request;
        // a refusing carrier holds it rather than losing it.
        fetcher.session_mut().driver().refuse_sends = usize::MAX;
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert!(fetcher.has_backlog(), "the request is held");
        assert!(fetcher.session_mut().driver().control.is_empty());

        fetcher.session_mut().driver().refuse_sends = 0;
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert!(!fetcher.has_backlog(), "and sent when the carrier takes it");
        assert!(!fetcher.session_mut().driver().control.is_empty());
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn spans_chunk_by_the_codec_bounds() {
        assert_eq!(manifest_spans(1), vec![(0, 1)]);
        assert_eq!(
            manifest_spans(MAX_MANIFEST_REQUEST_PAGES),
            vec![(0, MAX_MANIFEST_REQUEST_PAGES)]
        );
        assert_eq!(
            manifest_spans(MAX_MANIFEST_REQUEST_PAGES + 1),
            vec![
                (0, MAX_MANIFEST_REQUEST_PAGES),
                (MAX_MANIFEST_REQUEST_PAGES, 1),
            ]
        );
        // Bounded by the length, so a non-advancing span ends the walk
        // instead of filling memory.
        let walk = |length: u64| {
            let mut spans = Vec::new();
            let mut offset = 0;
            for _ in 0..=length.div_ceil(MAX_REQUESTED_RANGE) {
                let Some((at, take)) = range_span(offset, length) else {
                    break;
                };
                spans.push((at, take));
                offset = at + take;
            }
            spans
        };
        assert_eq!(walk(0), vec![]);
        assert_eq!(walk(1), vec![(0, 1)]);
        assert_eq!(walk(MAX_REQUESTED_RANGE), vec![(0, MAX_REQUESTED_RANGE)]);
        assert_eq!(
            walk(MAX_REQUESTED_RANGE + 1),
            vec![(0, MAX_REQUESTED_RANGE), (MAX_REQUESTED_RANGE, 1)]
        );
        assert_eq!(
            walk(3 * MAX_REQUESTED_RANGE - 1),
            vec![
                (0, MAX_REQUESTED_RANGE),
                (MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE),
                (2 * MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE - 1),
            ]
        );
    }
}
