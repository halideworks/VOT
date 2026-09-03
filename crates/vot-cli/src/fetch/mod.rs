//! Fetching one bundle over a session: opening it, validating the
//! manifest, and pipelining range requests into a bundle directory
//! `receive_bundle` consumes unchanged.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use crate::{
    EntryRecord, Error, MANIFEST_DIRECTORY, MANIFEST_SEAL, ManifestReader, PackageSummary, Storage,
};

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
pub use sink::CountingSink;
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
    /// The caller cancelled after this many transfer objects were finished.
    Cancelled(usize),
}

/// Identifies one receive session across all of its seam callbacks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReceiveSessionId(u64);

/// One unique stored object and every manifest entry that references it.
#[derive(Clone, Debug)]
pub struct ReceiveObject {
    pub object: frames::ObjectId,
    pub entries: Vec<EntryRecord>,
}

/// A verified-range destination with explicit completion and abandonment.
pub trait ReceiveSink: vot_scheduler::RangeSink {
    fn flush(&self) -> Result<(), Error>;
    fn discard_partial(&self) -> Result<(), Error>;
}

impl<S: ReceiveSink + ?Sized> ReceiveSink for Arc<S> {
    fn flush(&self) -> Result<(), Error> {
        (**self).flush()
    }

    fn discard_partial(&self) -> Result<(), Error> {
        (**self).discard_partial()
    }
}

/// A cloneable, thread-safe request to stop one receive.
#[derive(Clone, Default)]
pub struct CancellationHandle(Arc<AtomicBool>);

impl CancellationHandle {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub type ManifestHook = Arc<
    dyn Fn(ReceiveSessionId, PackageSummary, &[EntryRecord]) -> Result<(), Error> + Send + Sync,
>;
pub type SinkFactory = Arc<
    dyn Fn(ReceiveSessionId, &ReceiveObject) -> Result<Option<Box<dyn ReceiveSink>>, Error>
        + Send
        + Sync,
>;
pub type CompletionHook =
    Arc<dyn Fn(ReceiveSessionId, &ReceiveObject) -> Result<(), Error> + Send + Sync>;

/// Optional receive integration points. Missing hooks retain directory behavior.
#[derive(Clone, Default)]
pub struct ReceiveSeams {
    pub manifest: Option<ManifestHook>,
    pub sink: Option<SinkFactory>,
    pub complete: Option<CompletionHook>,
    pub cancellation: CancellationHandle,
}

impl ReceiveSeams {
    #[must_use]
    pub fn new(cancellation: CancellationHandle) -> Self {
        Self {
            cancellation,
            ..Self::default()
        }
    }
}

/// Why a frame could not be taken: server protocol fault, wrong package,
/// or local failure.
pub(crate) enum Fault {
    Peer(u16),
    Reported(u16),
    Pin,
    Local(Error),
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Local(error)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::harness::{
        Loopback, built_bundle, control_event, decode_control, discard, noise, not_required,
        patterned, pump, pump_records_first,
    };
    use crate::tests::temporary;
    use crate::{BundleServer, KeyMaterial, ServeConnection, build_bundle, receive_bundle};
    use vot_transport_api::ConnectionId;

    fn active(subject: SubjectId, sink: Arc<CountingSink>) -> ActiveObject {
        ActiveObject {
            sink,
            complete: None,
            receive_session: ReceiveSessionId(0),
            subject,
            next_offset: 0,
            covered: CoverageMap::new(),
            skip: BTreeMap::new(),
            syncing: false,
        }
    }

    /// A sink of `length` bytes that keeps what it is given and nothing else.
    fn seam_sink(length: u64) -> Arc<CountingSink> {
        Arc::new(CountingSink::custom(Box::new(Arc::new(SeamSink {
            bytes: Mutex::new(vec![0; usize::try_from(length).unwrap()]),
            flushed: AtomicBool::new(false),
            discarded: AtomicBool::new(false),
        }))))
    }

    /// `count` planned objects of `length`, each with its own root.
    fn planned_objects(count: u8, length: u64) -> Vec<PlannedObject> {
        (0..count)
            .map(|root| {
                PlannedObject::fresh(frames::ObjectId {
                    suite: 1,
                    root: [root + 1; 32],
                    length,
                })
            })
            .collect()
    }

    /// A plan holding one object of `length` in its window, on a sink that
    /// keeps nothing: what these tests are about is the accounts.
    fn windowed(length: u64) -> FetchPlan {
        let planned = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [9; 32],
            length,
        });
        let subject = subject_of(&planned);
        let sink = seam_sink(length);
        FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: vec![planned],
            active: BTreeMap::from([(0, active(subject, sink))]),
            low: 0,
            next_open: 1,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: None,
            finished: false,
        }
    }

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
            if corrupted && let Some((_, bytes)) = serving.driver().records.first_mut() {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                corrupted = false;
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

    struct SeamSink {
        bytes: Mutex<Vec<u8>>,
        flushed: AtomicBool,
        discarded: AtomicBool,
    }

    impl vot_scheduler::RangeSink for SeamSink {
        fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), vot_scheduler::SinkError> {
            let mut bytes = self.bytes.lock().map_err(|_| vot_scheduler::SinkError)?;
            let at = usize::try_from(offset).map_err(|_| vot_scheduler::SinkError)?;
            bytes[at..at + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    impl ReceiveSink for SeamSink {
        fn flush(&self) -> Result<(), Error> {
            self.flushed.store(true, Ordering::Release);
            Ok(())
        }

        fn discard_partial(&self) -> Result<(), Error> {
            self.bytes.lock().map_err(|_| Error::InvalidBundle)?.clear();
            self.discarded.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[test]
    fn receive_seams_see_the_manifest_object_entries_and_flushed_completion() {
        let payload = patterned(8_500_000);
        let (bundle, _) = built_bundle(
            "receive-seams",
            &[("a.bin", payload.clone()), ("b.bin", payload.clone())],
        );
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("receive-seams-output");
        let sink = Arc::new(SeamSink {
            bytes: Mutex::new(vec![0; payload.len()]),
            flushed: AtomicBool::new(false),
            discarded: AtomicBool::new(false),
        });
        let manifest_calls = Arc::new(AtomicU64::new(0));
        let completion_calls = Arc::new(AtomicU64::new(0));
        let mut seams = ReceiveSeams::default();
        let seen_manifest = Arc::clone(&manifest_calls);
        seams.manifest = Some(Arc::new(move |_, _, entries| {
            assert_eq!(entries.len(), 2);
            seen_manifest.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }));
        let placed = Arc::clone(&sink);
        seams.sink = Some(Arc::new(move |_, object| {
            assert_eq!(object.entries.len(), 2);
            Ok(Some(Box::new(Arc::clone(&placed))))
        }));
        let completed_sink = Arc::clone(&sink);
        let completed = Arc::clone(&completion_calls);
        seams.complete = Some(Arc::new(move |_, object| {
            assert_eq!(object.entries.len(), 2);
            assert!(completed_sink.flushed.load(Ordering::Acquire));
            completed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }));
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.set_receive_seams(seams);
        assert_eq!(
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap(),
            FetchStatus::Complete
        );
        assert_eq!(*sink.bytes.lock().unwrap(), payload);
        assert_eq!(manifest_calls.load(Ordering::Relaxed), 1);
        assert_eq!(completion_calls.load(Ordering::Relaxed), 1);
        assert!(!sink.discarded.load(Ordering::Relaxed));
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_manifest_seam_refusal_precedes_every_range_request() {
        let (bundle, _) = built_bundle("receive-refused", &[("a.bin", patterned(200_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("receive-refused-output");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let seams = ReceiveSeams {
            manifest: Some(Arc::new(|_, _, _| Err(Error::InvalidArguments))),
            ..ReceiveSeams::default()
        };
        fetcher.set_receive_seams(seams);
        assert_eq!(
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap(),
            FetchStatus::Closed(error_code::ADMISSION_DENIED)
        );
        assert_eq!(
            fetcher.rail.taken_bytes, 0,
            "admission runs before any object range"
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_failed_completion_hook_does_not_commit_the_object_cursor() {
        let (bundle, _) = built_bundle("completion-refused", &[("a.bin", patterned(200_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("completion-refused-output");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.set_receive_seams(ReceiveSeams {
            complete: Some(Arc::new(|_, _| Err(Error::InvalidArguments))),
            ..ReceiveSeams::default()
        });
        assert!(run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).is_err());
        let plan = fetcher.locked_plan().unwrap();
        assert_eq!(plan.low, 0);
        assert!(!plan.active[&0].syncing);
        assert!(plan.abandoned);
        assert!(plan.active.contains_key(&0));
        discard(&[&bundle, &output]);
    }

    #[test]
    fn cancellation_discards_the_partial_and_bounds_queued_answers() {
        let (bundle, _) = built_bundle(
            "receive-cancelled",
            &[
                ("first.bin", patterned(300_001)),
                ("second.bin", patterned(8_500_000)),
            ],
        );
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("receive-cancelled-output");
        let sinks = Arc::new(Mutex::new(Vec::<Arc<SeamSink>>::new()));
        let cancellation = CancellationHandle::default();
        let mut seams = ReceiveSeams::new(cancellation.clone());
        let placed = Arc::clone(&sinks);
        seams.sink = Some(Arc::new(move |_, object| {
            let sink = Arc::new(SeamSink {
                bytes: Mutex::new(vec![0; usize::try_from(object.object.length).unwrap()]),
                flushed: AtomicBool::new(false),
                discarded: AtomicBool::new(false),
            });
            placed.lock().unwrap().push(Arc::clone(&sink));
            Ok(Some(Box::new(sink)))
        }));
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.set_receive_seams(seams);
        let _ = planned(&server, &mut session, &mut connection, &mut fetcher);
        let mut sequence = 0;
        for _ in 0..ROUND_BUDGET {
            if fetcher.locked_plan().unwrap().low == 1 {
                break;
            }
            round(
                &server,
                &mut session,
                &mut connection,
                &mut fetcher,
                &mut sequence,
            );
        }
        assert_eq!(fetcher.locked_plan().unwrap().low, 1);
        assert!(fetcher.locked_plan().unwrap().active.contains_key(&1));

        // Remove answers already handed to the fake carrier, then put a
        // fresh answer request immediately ahead of GOAWAY. This isolates
        // the contract for queued-but-not-handed answers.
        session.driver().control.clear();
        session.driver().records.clear();
        session.driver().datagrams.clear();
        fetcher.session_mut().driver().events.clear();
        let second = server
            .object_indices
            .iter()
            .find_map(|(root, index)| (*index == 1).then_some(server.objects[root].object))
            .unwrap();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [0xff; 16],
                object: second,
                offset: 0,
                length: second.length.min(65_536),
            })));
        cancellation.cancel();
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Cancelled(1));
        let held = sinks.lock().unwrap();
        assert_eq!(held.len(), 2);
        assert_eq!(*held[0].bytes.lock().unwrap(), patterned(300_001));
        assert!(held[0].flushed.load(Ordering::Acquire));
        assert!(!held[0].discarded.load(Ordering::Acquire));
        assert!(held[1].discarded.load(Ordering::Acquire));
        assert!(held[1].bytes.lock().unwrap().is_empty());
        drop(held);
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(connection.goaway_cursor, Some(1));
        assert_eq!(connection.pending_answer_bytes(), 0);
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        let after_goaway = fetcher.session_mut().poll().unwrap();
        assert!(
            after_goaway.is_none(),
            "an answer queued ahead of GOAWAY reached the carrier: {after_goaway:?}"
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_skipped_object_is_never_requested_or_completed() {
        let (bundle, _) = built_bundle(
            "receive-skipped",
            &[
                ("a.bin", patterned(300_001)),
                ("b.bin", vec![2; 300_002]),
                ("c.bin", vec![3; 300_003]),
            ],
        );
        let (server, mut session, mut connection) = serving(&bundle);
        let skipped = server
            .object_indices
            .iter()
            .find_map(|(root, index)| (*index == 1).then_some(*root))
            .unwrap();
        let expected_requested: u64 = server
            .objects
            .iter()
            .filter(|(root, _)| **root != skipped)
            .map(|(_, object)| object.object.length)
            .sum();
        let output = temporary("receive-skipped-output");
        let destination = output.to_path_buf();
        let completions = Arc::new(AtomicU64::new(0));
        let completed = Arc::clone(&completions);
        let seams = ReceiveSeams {
            sink: Some(Arc::new(move |_, object| {
                if object.object.root == skipped {
                    return Ok(None);
                }
                let path = destination
                    .join("objects")
                    .join(crate::object_name(&object.object.root));
                Ok(Some(Box::new(CountingSink::at(
                    &path,
                    object.object.length,
                )?)))
            })),
            complete: Some(Arc::new(move |_, _| {
                completed.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })),
            ..ReceiveSeams::default()
        };
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.set_receive_seams(seams);
        assert_eq!(
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap(),
            FetchStatus::Complete
        );
        assert_eq!(fetcher.rail.taken_bytes, expected_requested);
        assert_eq!(completions.load(Ordering::Relaxed), 2);
        assert!(
            !output
                .join("objects")
                .join(crate::object_name(&skipped))
                .exists()
        );
        discard(&[&bundle, &output]);
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
        let callbacks = Arc::new(Mutex::new(Vec::new()));
        let selected = Arc::clone(&callbacks);
        let completed = Arc::clone(&callbacks);
        let destination = output.to_path_buf();
        primary.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |session, object| {
                selected.lock().unwrap().push(("selected", session));
                let path = destination
                    .join("objects")
                    .join(crate::object_name(&object.object.root));
                Ok(Some(Box::new(CountingSink::at(
                    &path,
                    object.object.length,
                )?)))
            })),
            complete: Some(Arc::new(move |session, _| {
                completed.lock().unwrap().push(("completed", session));
                Ok(())
            })),
            ..ReceiveSeams::default()
        });
        primary.rail.window_bytes = MAX_REQUESTED_RANGE;
        let plan = planned(&server, &mut session1, &mut connection1, &mut primary);
        primary.advance().unwrap();
        assert!(plan.lock().unwrap().active.contains_key(&0));
        let mut secondary = BundleFetcher::join(
            Loopback::default(),
            &output,
            Arc::clone(&plan),
            None,
            BTreeSet::new(),
        )
        .unwrap();
        let wrong = Arc::clone(&callbacks);
        secondary.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |session, _| {
                wrong.lock().unwrap().push(("wrong sink", session));
                Ok(None)
            })),
            complete: Some(Arc::new(move |session, _| {
                panic!("the joining rail completed the selected sink: {session:?}")
            })),
            ..ReceiveSeams::default()
        });

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
        // Each rail's window closed on its own arrivals: the two accounts
        // agree per rail, so neither asked on the other's bytes.
        assert_eq!(
            primary.receiver.arrived_range_bytes(),
            MAX_REQUESTED_RANGE,
            "the primary's arrivals are its own span"
        );
        assert_eq!(
            secondary.receiver.arrived_range_bytes(),
            MAX_REQUESTED_RANGE,
            "the rail's arrivals are its own span"
        );
        assert!(!primary.has_backlog());
        assert!(!secondary.has_backlog());
        assert_eq!(primary.package(), Some(built));
        assert_eq!(secondary.package(), Some(built));
        let callbacks = callbacks.lock().unwrap();
        assert_eq!(callbacks.len(), 2);
        assert_eq!(callbacks[0].0, "selected");
        assert_eq!(callbacks[1].0, "completed");
        assert_eq!(callbacks[0].1, callbacks[1].1);
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn an_abandoned_plan_ends_every_rail_without_its_stall_budget() {
        // A failed rail marks the plan; the others end at their next pass
        // instead of waiting out a stall budget, whatever their window
        // holds when it happens.
        let (bundle, _) = built_bundle(
            "abandoned",
            &[
                ("a.bin", noise(262_145)),
                ("b.bin", noise(262_146)),
                ("c.bin", noise(262_147)),
            ],
        );
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("abandoned-fetched");
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        primary.set_object_window(4);
        let plan = planned(&server, &mut session, &mut connection, &mut primary);
        assert!(
            plan.lock().unwrap().active.len() > 1,
            "the window never held more than one object"
        );
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
            active: BTreeMap::from([(0, active(s0, sink0))]),
            low: 0,
            next_open: 1,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: None,
            finished: false,
        })));
        fetcher.advance().unwrap();
        assert_eq!(
            fetcher.rail.admitted,
            BTreeMap::from([(0, s0)]),
            "the first object is this rail's"
        );

        // Another rail saw the first object whole and moved the plan on.
        {
            let mut plan = fetcher.locked_plan().unwrap();
            plan.objects[0].done = true;
            plan.low = 1;
            plan.next_open = 2;
            plan.active = BTreeMap::from([(1, active(s1, sink1))]);
        }
        fetcher.advance().unwrap();
        assert_eq!(
            fetcher.rail.admitted,
            BTreeMap::from([(1, s1)]),
            "the object in the window is admitted"
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
            active: BTreeMap::new(),
            low: 0,
            next_open: 0,
            window: 1,
            placed_before: 7,
            carried_before: 7,
            abandoned: false,
            sealing: false,
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
        let mut plan = windowed(0);
        plan.take(0, 5, 5).unwrap();
        assert_eq!(
            plan.active[&0].next_offset, 10,
            "a committed span moves the handout"
        );
        plan.take(0, 10, 5).unwrap();
        assert_eq!(plan.active[&0].next_offset, 15);
        assert!(
            plan.take(1, 0, 5).is_err(),
            "a span for an object outside the window commits nothing"
        );
    }

    #[test]
    #[should_panic(expected = "backwards")]
    #[cfg(debug_assertions)]
    pub(crate) fn a_span_behind_the_handout_panics_instead_of_spinning() {
        let mut plan = windowed(0);
        plan.take(0, 0, 8).unwrap();
        let _ = plan.take(0, 0, 8);
    }

    #[test]
    pub(crate) fn coverage_counts_every_byte_once() {
        // Coalescing counts each byte once, so a duplicate range cannot
        // complete an object with a hole.
        let mut plan = windowed(0);
        plan.cover(0, 0, 10);
        assert_eq!(plan.active[&0].covered.bytes(), 10);
        plan.cover(0, 5, 10);
        assert_eq!(
            plan.active[&0].covered.bytes(),
            15,
            "the overlap counts once"
        );
        plan.cover(0, 5, 5);
        assert_eq!(
            plan.active[&0].covered.bytes(),
            15,
            "a duplicate counts never"
        );
        plan.cover(0, 20, 5);
        assert_eq!(plan.active[&0].covered.bytes(), 20, "a gap stays a gap");
        plan.cover(0, 15, 5);
        assert_eq!(
            plan.active[&0].covered.bytes(),
            25,
            "the gap filled exactly"
        );
        assert_eq!(
            plan.active[&0].covered.extents().iter().collect::<Vec<_>>(),
            vec![(&0, &25)],
            "adjacent extents coalesce to one"
        );
        plan.cover(0, 0, 25);
        assert_eq!(
            plan.active[&0].covered.bytes(),
            25,
            "the whole again changes nothing"
        );
        plan.cover(0, 30, 0);
        assert_eq!(
            plan.active[&0].covered.bytes(),
            25,
            "an empty cover covers nothing"
        );
        plan.cover(0, u64::MAX, 2);
        assert_eq!(
            plan.active[&0].covered.bytes(),
            25,
            "an overflowing cover is refused"
        );
        plan.cover(1, 0, 10);
        assert_eq!(
            plan.active[&0].covered.bytes(),
            25,
            "a cover for an object outside the window books nowhere"
        );
    }

    #[test]
    pub(crate) fn the_cursor_advances_only_over_the_in_order_durable_prefix() {
        // The cursor is the prefix, not the count of what is done: an
        // object durable above a hole waits for the hole, so a `GOAWAY`
        // never names an object this fetch does not have.
        let mut plan = windowed(0);
        plan.active.clear();
        plan.next_open = 0;
        plan.objects = (0..3)
            .map(|root| {
                PlannedObject::fresh(frames::ObjectId {
                    suite: 1,
                    root: [root; 32],
                    length: 1,
                })
            })
            .collect();

        plan.objects[1].done = true;
        plan.advance_cursor();
        assert_eq!(plan.low, 0, "an object done above a hole is not the cursor");

        plan.objects[0].done = true;
        plan.advance_cursor();
        assert_eq!(plan.low, 2, "closing the hole takes the whole prefix");

        plan.objects[2].done = true;
        plan.advance_cursor();
        assert_eq!(plan.low, 3, "and the last one reaches the object count");
    }

    #[test]
    pub(crate) fn the_object_window_is_two_a_rail_and_never_past_the_budget() {
        // Two objects a rail, so a rail has another to take spans from
        // while one syncs, and never more than the staging budget holds.
        for (rails, window) in [
            (0, 1),
            (1, 2),
            (4, 8),
            (8, MAX_OBJECT_WINDOW),
            (9, MAX_OBJECT_WINDOW),
            (usize::MAX, MAX_OBJECT_WINDOW),
        ] {
            assert_eq!(protocol::object_window(rails), window);
        }
        let output = temporary("object-window");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        assert_eq!(fetcher.window, 1, "a fetch that names no window holds one");
        for (asked, held) in [
            (0, 1),
            (1, 1),
            (4, 4),
            (MAX_OBJECT_WINDOW, MAX_OBJECT_WINDOW),
            (MAX_OBJECT_WINDOW + 1, MAX_OBJECT_WINDOW),
        ] {
            fetcher.set_object_window(asked);
            assert_eq!(fetcher.window, held, "asked for {asked}");
        }
        discard(&[&output]);
    }

    #[test]
    pub(crate) fn the_staging_budget_holds_the_window_and_the_whole_credit() {
        // Every admitted object holds a verifier reservation for as long
        // as it is in flight, and advertised credit is what is left of the
        // staging budget: sized for one object, a window of admissions
        // comes out of the credit the rails run on.
        let mut receiver =
            ReliableReceiver::new(FETCH_STAGING_BYTES, FETCH_CREDIT_BYTES, FETCH_CREDIT_BYTES)
                .unwrap();
        for index in 0..MAX_OBJECT_WINDOW {
            let subject = SubjectId::try_from(frames::ObjectId {
                suite: 1,
                root: [u8::try_from(index).unwrap(); 32],
                length: u64::try_from(vot_verifier::GROUP_SIZE).unwrap(),
            })
            .unwrap();
            receiver
                .begin_ranges(
                    subject,
                    Box::new(seam_sink(u64::try_from(vot_verifier::GROUP_SIZE).unwrap())),
                )
                .unwrap();
        }
        assert_eq!(
            receiver.advertised_credit(),
            FETCH_CREDIT_BYTES,
            "the window's reservations came out of the credit"
        );
    }

    #[test]
    pub(crate) fn next_span_hands_out_from_the_lowest_active_object_with_work() {
        // The handout walks the window in index order and steps over an
        // object with nothing left, so a rail takes from whichever object
        // still owes bytes instead of stalling on the lowest.
        let mut plan = windowed(128);
        let second = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [7; 32],
            length: 64,
        });
        let subject = subject_of(&second);
        plan.objects.push(second);
        plan.active.insert(1, active(subject, seam_sink(64)));
        plan.next_open = 2;
        plan.window = 2;

        let (at, object, offset, length) = plan.next_span().unwrap().unwrap();
        assert_eq!((at, offset, length), (0, 0, 128));
        assert_eq!(object.root, [9; 32]);
        plan.take(at, offset, length).unwrap();

        let (at, object, offset, length) = plan.next_span().unwrap().unwrap();
        assert_eq!((at, offset, length), (1, 0, 64));
        assert_eq!(object.root, [7; 32], "the span came from the wrong object");
        plan.take(at, offset, length).unwrap();
        assert!(plan.next_span().unwrap().is_none());
    }

    #[test]
    pub(crate) fn the_fill_opens_no_object_past_the_window() {
        // The window is a bound on the fill: four objects and a window of
        // two, and one advance opens exactly two of them.
        let output = temporary("fill-window");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let destination = output.to_path_buf();
        fetcher.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |_, object| {
                let path = destination
                    .join("objects")
                    .join(crate::object_name(&object.object.root));
                Ok(Some(Box::new(CountingSink::at(
                    &path,
                    object.object.length,
                )?)))
            })),
            ..ReceiveSeams::default()
        });
        let mut plan = windowed(1024);
        plan.active.clear();
        plan.next_open = 0;
        plan.window = 2;
        plan.objects = planned_objects(4, 1024);
        fetcher.plan = Some(Arc::new(Mutex::new(plan)));

        fetcher.advance().unwrap();
        let held = fetcher.locked_plan().unwrap();
        assert_eq!(held.active.len(), 2, "the fill went past the window");
        assert_eq!(held.next_open, 2);
        drop(held);
        discard(&[&output]);
    }

    /// Twenty transfer objects of mixed sizes: eleven small files each
    /// alone in its own pack, because the large file after it flushes the
    /// packer, and ten large files stored directly. Two of the small ones
    /// are empty, and a zero-length pack is a zero-length object; both
    /// name the same root, so they are one transfer object with two
    /// entries.
    fn mixed_objects() -> Vec<(String, Vec<u8>)> {
        let small = [
            0, 1, 17, 4_096, 40_000, 65_536, 100_000, 150_000, 200_000, 262_144, 0,
        ];
        let large = [
            262_145, 262_146, 262_147, 262_148, 262_149, 262_150, 262_151, 300_000, 1_000_000,
            3_145_728,
        ];
        let mut files = Vec::new();
        for (index, length) in small.iter().enumerate() {
            files.push((format!("f{:02}.bin", index * 2), patterned(*length)));
            if let Some(length) = large.get(index) {
                files.push((format!("f{:02}.bin", index * 2 + 1), noise(*length)));
            }
        }
        files
    }

    fn borrowed(files: &[(String, Vec<u8>)]) -> Vec<(&str, Vec<u8>)> {
        files
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.clone()))
            .collect()
    }

    #[test]
    pub(crate) fn a_window_of_objects_lands_every_one_of_them() {
        // Twenty objects, empty ones and one whole from a previous fetch
        // among them, at a window of eight: they complete in whatever
        // order they finish in and every one of them lands byte for byte.
        let files = mixed_objects();
        let (bundle, built) = built_bundle("window-many", &borrowed(&files));
        let output = temporary("window-many-fetched");

        // One object made durable by an earlier fetch, which the window
        // fetch then finds whole and never asks for.
        {
            let (server, mut session, mut connection) = serving(&bundle);
            let mut first = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            let mut sequence = 0;
            let mut carried = false;
            for _ in 0..ROUND_BUDGET {
                round(
                    &server,
                    &mut session,
                    &mut connection,
                    &mut first,
                    &mut sequence,
                );
                if first
                    .locked_plan()
                    .is_some_and(|plan| plan.placed_before > 0)
                {
                    carried = true;
                    break;
                }
            }
            assert!(carried, "the first fetch made nothing durable");
        }

        let (server, mut session, mut connection) = serving(&bundle);
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.set_object_window(8);
        assert_eq!(
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap(),
            FetchStatus::Complete
        );
        assert_eq!(fetcher.package(), Some(built));
        let plan = fetcher.locked_plan().unwrap();
        assert_eq!(plan.objects.len(), 20, "the fixture is not twenty objects");
        assert_eq!(plan.window, 8);
        assert_eq!(plan.low, 20, "the cursor is the whole manifest");
        assert!(
            plan.objects
                .iter()
                .any(|planned| planned.object.length == 0),
            "the fixture has no empty object"
        );
        drop(plan);
        assert!(
            fetcher.placed_bytes() > fetcher.moved_bytes(),
            "nothing was carried from the earlier fetch"
        );
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_killed_window_resumes_over_two_rails() {
        // Two rails at a window of four, killed with several objects in
        // flight: the resume asks for what is missing and the bundle
        // lands byte for byte.
        let files: Vec<(&str, Vec<u8>)> = vec![
            ("a.bin", patterned(300_001)),
            ("b.bin", noise(300_002)),
            ("c.bin", patterned(300_003)),
            ("d.bin", noise(300_004)),
            ("e.bin", patterned(300_005)),
            ("f.bin", noise(300_006)),
            ("g.bin", patterned(300_007)),
            ("h.bin", noise(300_008)),
        ];
        let (bundle, built) = built_bundle("killed-window", &files);
        let output = temporary("killed-window-fetched");

        for phase in ["kill", "resume"] {
            let server = BundleServer::open(&bundle).unwrap();
            let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            primary.set_object_window(4);
            let (mut serving_one, mut connection_one) = (
                Session::server(
                    Loopback::default(),
                    Settings::default(),
                    BTreeSet::new(),
                    crate::harness::not_required(),
                ),
                ServeConnection::new(),
            );
            serving_one.begin().unwrap();
            let plan = planned(&server, &mut serving_one, &mut connection_one, &mut primary);
            assert_eq!(plan.lock().unwrap().window, 4);
            let mut secondary = BundleFetcher::join(
                Loopback::default(),
                &output,
                Arc::clone(&plan),
                None,
                BTreeSet::new(),
            )
            .unwrap();
            let (mut serving_two, mut connection_two) = (
                Session::server(
                    Loopback::default(),
                    Settings::default(),
                    BTreeSet::new(),
                    crate::harness::not_required(),
                ),
                ServeConnection::new(),
            );
            serving_two.begin().unwrap();

            let (mut one, mut two) = (0, 0);
            let mut ended = false;
            for _ in 0..ROUND_BUDGET {
                let first = round(
                    &server,
                    &mut serving_one,
                    &mut connection_one,
                    &mut primary,
                    &mut one,
                );
                let second = round(
                    &server,
                    &mut serving_two,
                    &mut connection_two,
                    &mut secondary,
                    &mut two,
                );
                if phase == "kill" {
                    // Dropped where it stands, with the rest of the
                    // window still in flight.
                    let held = plan.lock().unwrap();
                    let killable = held.low > 0 && held.active.len() > 1;
                    drop(held);
                    if killable {
                        ended = true;
                        break;
                    }
                } else if first == FetchStatus::Complete && second == FetchStatus::Complete {
                    ended = true;
                    break;
                }
            }
            assert!(ended, "the {phase} phase never settled");
            if phase == "kill" {
                assert!(
                    output.join(RESUME_STORE).exists(),
                    "the partial bundle carries its continuation state"
                );
            } else {
                assert_eq!(primary.package(), Some(built));
                assert!(
                    !output.join(RESUME_STORE).exists(),
                    "completion removed the store"
                );
            }
        }
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn cancelling_a_window_keeps_the_prefix_and_discards_the_rest() {
        // Cancellation reports the objects durable in manifest order,
        // discards every partial above them, and clears their
        // checkpoints, so a resume asks for those objects again.
        let files: Vec<(&str, Vec<u8>)> = (0..8)
            .map(|index| match index {
                0 => ("a.bin", noise(262_145)),
                1 => ("b.bin", noise(262_146)),
                2 => ("c.bin", noise(262_147)),
                3 => ("d.bin", noise(262_148)),
                4 => ("e.bin", noise(262_149)),
                5 => ("f.bin", noise(262_150)),
                6 => ("g.bin", noise(262_151)),
                _ => ("h.bin", noise(262_152)),
            })
            .collect();
        let (bundle, _) = built_bundle("cancel-many", &files);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("cancel-many-fetched");
        let cancellation = CancellationHandle::default();
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.set_receive_seams(ReceiveSeams::new(cancellation.clone()));
        fetcher.set_object_window(4);
        let plan = planned(&server, &mut session, &mut connection, &mut fetcher);
        let mut sequence = 0;
        for _ in 0..ROUND_BUDGET {
            let held = plan.lock().unwrap();
            let settled = held
                .objects
                .iter()
                .take_while(|planned| planned.done)
                .count();
            let flying = held.active.len();
            drop(held);
            if settled > 0 && flying > 1 {
                break;
            }
            round(
                &server,
                &mut session,
                &mut connection,
                &mut fetcher,
                &mut sequence,
            );
        }
        let (prefix, subjects) = {
            let held = plan.lock().unwrap();
            let prefix = held
                .objects
                .iter()
                .take_while(|planned| planned.done)
                .count();
            let subjects: Vec<SubjectId> =
                held.active.values().map(|active| active.subject).collect();
            assert!(prefix > 0, "no object was durable before the cancel");
            assert!(subjects.len() > 1, "the window held one object");
            (prefix, subjects)
        };
        cancellation.cancel();
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Cancelled(prefix));

        let held = plan.lock().unwrap();
        assert_eq!(held.low, prefix, "the cursor is not the durable prefix");
        assert!(held.active.is_empty(), "cancellation left the window open");
        let store = held.store.clone().unwrap();
        drop(held);
        for subject in subjects {
            assert!(
                store
                    .lock()
                    .unwrap()
                    .checkpointed(subject)
                    .is_none_or(UnitRanges::is_empty),
                "a cancelled partial kept its checkpoint"
            );
            assert!(
                !output
                    .join("objects")
                    .join(crate::object_name(&subject.root()))
                    .exists(),
                "a cancelled partial was left on disk"
            );
        }
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_cancel_during_an_open_discards_the_chosen_sink() {
        // A rail that dropped the plan lock for a sink factory holds the
        // only reference to what the factory chose, and cancellation
        // drains a window that does not hold it yet. The rail discards it
        // itself, and the room the window has left buys no further open.
        let (bundle, _) = built_bundle(
            "cancel-open",
            &[("a.bin", patterned(1024)), ("b.bin", noise(2048))],
        );
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("cancel-during-open");
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let plan = planned(&server, &mut session, &mut connection, &mut primary);

        // A rail on the same plan, driven only as far as a session that
        // can carry a `GOAWAY`: one round puts the server's answer on its
        // carrier and one pass takes it. The window is one here, so the
        // rail opens nothing of its own.
        let mut serving_rail = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            crate::harness::not_required(),
        );
        serving_rail.begin().unwrap();
        let mut rail_connection = ServeConnection::new();
        let cancellation = CancellationHandle::default();
        let mut rail = BundleFetcher::join(
            Loopback::default(),
            &output,
            Arc::clone(&plan),
            None,
            BTreeSet::new(),
        )
        .unwrap();
        rail.set_receive_seams(ReceiveSeams::new(cancellation.clone()));
        let mut sequence = 0;
        round(
            &server,
            &mut serving_rail,
            &mut rail_connection,
            &mut rail,
            &mut sequence,
        );
        rail.service().unwrap();

        // The plan put back to just before the first object is opened,
        // with room in the window for a second.
        let first = plan.lock().unwrap().objects[0].object.root;
        let path = output.join("objects").join(crate::object_name(&first));
        {
            let mut held = plan.lock().unwrap();
            held.active.clear();
            held.next_open = 0;
            held.low = 0;
            held.window = 2;
        }
        fs::remove_file(&path).unwrap();

        // (reached the factory, released from it)
        let gate = Arc::new((Mutex::new((false, false)), std::sync::Condvar::new()));
        let calls = Arc::new(AtomicU64::new(0));
        let factory_gate = Arc::clone(&gate);
        let factory_calls = Arc::clone(&calls);
        let destination = output.to_path_buf();
        primary.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |_, object| {
                factory_calls.fetch_add(1, Ordering::Release);
                let path = destination
                    .join("objects")
                    .join(crate::object_name(&object.object.root));
                let chosen = CountingSink::at(&path, object.object.length)?;
                let (state, waiters) = &*factory_gate;
                let mut state = state.lock().map_err(|_| Error::InvalidBundle)?;
                state.0 = true;
                waiters.notify_all();
                while !state.1 {
                    state = waiters.wait(state).map_err(|_| Error::InvalidBundle)?;
                }
                Ok(Some(Box::new(chosen)))
            })),
            ..ReceiveSeams::default()
        });
        let opening = std::thread::spawn(move || {
            primary.advance().unwrap();
            primary
        });
        {
            let (state, waiters) = &*gate;
            let mut held = state.lock().unwrap();
            while !held.0 {
                let (next, timeout) = waiters
                    .wait_timeout(held, std::time::Duration::from_secs(10))
                    .unwrap();
                held = next;
                assert!(!timeout.timed_out(), "the open never reached the factory");
            }
        }
        cancellation.cancel();
        assert_eq!(rail.service().unwrap(), FetchStatus::Cancelled(0));
        {
            let (state, waiters) = &*gate;
            state.lock().unwrap().1 = true;
            waiters.notify_all();
        }
        let mut primary = opening.join().unwrap();
        {
            let held = plan.lock().unwrap();
            assert!(
                held.active.is_empty(),
                "a cancelled open left an object in the window"
            );
            assert_eq!(held.next_open, 1, "one index was taken and no other");
        }
        assert!(
            !path.exists(),
            "the sink the factory chose was not discarded"
        );
        primary.advance().unwrap();
        assert_eq!(
            plan.lock().unwrap().next_open,
            1,
            "an abandoned plan opened another object"
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_cancel_during_an_empty_objects_hook_keeps_it_done() {
        // Past its completion hook an object is durable and told to its
        // consumer, so a cancel under the hook cannot take it back off the
        // cursor.
        let (bundle, summary) = built_bundle("cancel-empty-hook", &[("a.txt", patterned(1000))]);
        let (server, mut serving_rail, mut rail_connection) = serving(&bundle);
        let output = temporary("cancel-empty-hook-fetched");
        let empty = frames::ObjectId {
            suite: 1,
            root: *blake3::hash(&[]).as_bytes(),
            length: 0,
        };
        let plan: SharedPlan = Arc::new(Mutex::new(FetchPlan {
            summary,
            objects: vec![PlannedObject::fresh(empty)],
            active: BTreeMap::new(),
            low: 0,
            // Opened as far as the window allows, so the rail's round below
            // opens nothing and the primary is the one that opens it.
            next_open: 1,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: None,
            finished: false,
        }));

        // A rail on the same plan, driven only as far as a session that can
        // carry a `GOAWAY`.
        let cancellation = CancellationHandle::default();
        let mut rail = BundleFetcher::join(
            Loopback::default(),
            &output,
            Arc::clone(&plan),
            None,
            BTreeSet::new(),
        )
        .unwrap();
        rail.set_receive_seams(ReceiveSeams::new(cancellation.clone()));
        let mut sequence = 0;
        round(
            &server,
            &mut serving_rail,
            &mut rail_connection,
            &mut rail,
            &mut sequence,
        );
        rail.service().unwrap();
        plan.lock().unwrap().next_open = 0;

        // (reached the hook, released from it)
        let gate = Arc::new((Mutex::new((false, false)), std::sync::Condvar::new()));
        let hook_gate = Arc::clone(&gate);
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        primary.plan = Some(Arc::clone(&plan));
        primary.set_receive_seams(ReceiveSeams {
            complete: Some(Arc::new(move |_, _| {
                let (state, waiters) = &*hook_gate;
                let mut state = state.lock().map_err(|_| Error::InvalidBundle)?;
                state.0 = true;
                waiters.notify_all();
                while !state.1 {
                    state = waiters.wait(state).map_err(|_| Error::InvalidBundle)?;
                }
                Ok(())
            })),
            ..ReceiveSeams::default()
        });
        let completing = std::thread::spawn(move || primary.advance().unwrap());
        {
            let (state, waiters) = &*gate;
            let mut held = state.lock().unwrap();
            while !held.0 {
                let (next, timeout) = waiters
                    .wait_timeout(held, std::time::Duration::from_secs(10))
                    .unwrap();
                held = next;
                assert!(
                    !timeout.timed_out(),
                    "the empty object never reached a hook"
                );
            }
        }
        cancellation.cancel();
        assert_eq!(rail.service().unwrap(), FetchStatus::Cancelled(0));
        {
            let (state, waiters) = &*gate;
            state.lock().unwrap().1 = true;
            waiters.notify_all();
        }
        completing.join().unwrap();

        assert!(
            plan.lock().unwrap().objects[0].done,
            "the cancel left a durable object undone"
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn a_cancel_discards_the_partials_behind_a_sink_that_cannot() {
        // The first failing discard is what the cancel reports, and every
        // partial behind it still comes off disk.
        use super::sink::tests::FailingSink;

        let output = temporary("cancel-discard-all");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let cancellation = CancellationHandle::default();
        fetcher.set_receive_seams(ReceiveSeams::new(cancellation.clone()));
        let watched = Arc::new(SeamSink {
            bytes: Mutex::new(vec![0; 8]),
            flushed: AtomicBool::new(false),
            discarded: AtomicBool::new(false),
        });
        let mut plan = windowed(8);
        let second = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [10; 32],
            length: 8,
        });
        let first = subject_of(&plan.objects[0]);
        plan.active.insert(
            0,
            active(first, Arc::new(CountingSink::custom(Box::new(FailingSink)))),
        );
        plan.active.insert(
            1,
            active(
                subject_of(&second),
                Arc::new(CountingSink::custom(Box::new(Arc::clone(&watched)))),
            ),
        );
        plan.objects.push(second);
        plan.next_open = 2;
        fetcher.plan = Some(Arc::new(Mutex::new(plan)));
        cancellation.cancel();

        assert!(
            fetcher.service().is_err(),
            "the failing discard went unreported"
        );
        assert!(
            watched.discarded.load(Ordering::Acquire),
            "a partial behind the failing sink was left on disk"
        );
        discard(&[&output]);
    }

    #[test]
    pub(crate) fn a_cancel_reports_what_is_durable_not_what_the_cursor_reached() {
        // A rail that completed an object marks it done and moves the
        // cursor on its next pass. A cancel landing between the two would
        // report one object fewer than this fetch has durable, and the
        // cursor is the only thing that says what it has.
        let (bundle, _) = built_bundle(
            "cancel-gap",
            &[("a.bin", patterned(1024)), ("b.bin", noise(2048))],
        );
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("cancel-cursor-gap");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let cancellation = CancellationHandle::default();
        fetcher.set_receive_seams(ReceiveSeams::new(cancellation.clone()));
        let plan = planned(&server, &mut session, &mut connection, &mut fetcher);
        {
            // Exactly what the rail that completed the first object
            // leaves behind before its next pass moves the cursor.
            let mut held = plan.lock().unwrap();
            held.active.clear();
            held.objects[0].done = true;
            held.low = 0;
            held.next_open = 1;
        }
        cancellation.cancel();

        assert_eq!(fetcher.service().unwrap(), FetchStatus::Cancelled(1));
        assert_eq!(fetcher.locked_plan().unwrap().low, 1);
        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn cancellation_waits_for_a_reserved_transition() {
        // A rail syncing an object or sealing the bundle owns a transition
        // the cursor is about to move; cancelling through it would name a
        // cursor that is already stale.
        for (syncing, sealing) in [(true, false), (false, true)] {
            let output = temporary(&format!("cancel-waits-{syncing}-{sealing}"));
            let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            let cancellation = CancellationHandle::default();
            fetcher.set_receive_seams(ReceiveSeams::new(cancellation.clone()));
            let mut plan = windowed(8);
            plan.active.get_mut(&0).unwrap().syncing = syncing;
            plan.sealing = sealing;
            fetcher.plan = Some(Arc::new(Mutex::new(plan)));
            cancellation.cancel();

            assert_eq!(
                fetcher.service().unwrap(),
                FetchStatus::Active,
                "cancellation ran through a reserved transition"
            );
            assert!(fetcher.cancelled.is_none());
            assert!(
                !fetcher.locked_plan().unwrap().abandoned,
                "the plan was abandoned before the transition settled"
            );
            assert!(
                fetcher.locked_plan().unwrap().active.contains_key(&0),
                "the window was drained before the transition settled"
            );
            discard(&[&output]);
        }
    }

    #[test]
    fn a_generation_past_its_repair_decodes_from_a_targeted_resend() {
        // Every eighth datagram goes. Interleaving spreads most losses
        // across the cover, but one generation still loses past its repair
        // symbols. The repair round's fresh state names exactly what it is
        // missing, and the serve's targeted repair resends those sources
        // within a round trip (ADR-0042 decision 4), so the generation
        // decodes without touching the reliable path or the quiet grace.
        let (bundle, built) = built_bundle("fec-past-repair", &[("big.bin", patterned(300_000))]);
        let fec = BTreeSet::from([
            vot_codec::extension_id::DATAGRAM_FEC,
            vot_codec::extension_id::FEC_COVER_EPOCHS,
        ]);
        let (client, mut serving) = crate::harness::duplex_pair();
        serving.drop_datagram_every = 8;
        let serving_bundle = bundle.to_path_buf();
        let serving_offer = fec.clone();
        let serving_thread = std::thread::spawn(move || {
            let mut server = BundleServer::open(&serving_bundle)?;
            server.set_automatic_fec(false);
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
        // 300000 bytes are five generations. Four decode from the
        // interleaved symbols and the fifth from the targeted resend. The
        // sim's loss is periodic rather than sampled, so this count is the
        // same on every run.
        let counts = fetcher.fec_counts();
        assert_eq!(counts.decoded, 5, "the targeted resend completed the fifth");
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
        // every twelfth datagram: about six of a full generation's 72, and
        // the short last generation's skipped sources shift the pattern by
        // at most one, so every generation stays within its eight repairs
        // and the fetch completes with the object having travelled as
        // symbols.
        let (bundle, built) = built_bundle("in-process-fec", &[("big.bin", patterned(1_500_000))]);
        let fec = BTreeSet::from([
            vot_codec::extension_id::DATAGRAM_FEC,
            vot_codec::extension_id::FEC_COVER_EPOCHS,
        ]);
        let (client, mut serving) = crate::harness::duplex_pair();
        serving.drop_datagram_every = 12;
        let serving_bundle = bundle.to_path_buf();
        let serving_thread = std::thread::spawn(move || {
            let mut server = BundleServer::open(&serving_bundle)?;
            assert!(
                server.automatic_fec,
                "the public server defaults to automatic FEC"
            );
            // This test pins the coded path rather than the automatic policy,
            // whose changing path samples are covered in the serve tests.
            server.set_automatic_fec(false);
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
        assert_eq!(
            counts.decoded, 23,
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
    fn a_push_uses_the_same_engines_with_the_holder_as_client() {
        use ed25519_dalek::SigningKey;

        let (bundle, built) = built_bundle("in-process-push", &[("a.bin", patterned(60_000))]);
        let issuer = SigningKey::from_bytes(&[41; 32]);
        let holder_key = SigningKey::from_bytes(&[42; 32]);
        let descriptor = match decode_control(&BundleServer::open(&bundle).unwrap().announcement[0])
        {
            TypedFrame::PackageDescriptor(descriptor) => descriptor.package,
            _ => panic!("the announcement descriptor"),
        };
        let package_length = descriptor.length;
        let requirement = crate::authz::PushRequirement::new(
            "issuer.example",
            crate::authz::key_id_of(&issuer.verifying_key()),
            issuer.verifying_key(),
            "receiver.example",
        );
        let token = crate::authz::issue_push(
            "issuer.example",
            "receiver.example",
            &issuer,
            holder_key.verifying_key().to_bytes(),
            built.root,
            package_length,
            crate::authz::now_seconds().unwrap(),
            3_600,
        )
        .unwrap();
        let holder = Arc::new(crate::authz::Holder::new(token, holder_key).unwrap());
        let binding = vot_transport_api::ChannelBinding::from_bytes(
            [0x37; vot_transport_api::CHANNEL_BINDING_LEN],
        );
        let (mut client, mut receiver) = crate::harness::duplex_pair();
        client.set_channel_binding(binding);
        receiver.set_channel_binding(binding);

        let serving_bundle = bundle.to_path_buf();
        let pushing = std::thread::spawn(move || {
            let server = BundleServer::open(&serving_bundle)?;
            let extensions = BTreeSet::from([vot_codec::extension_id::PUSH]);
            let session = Session::client(
                client,
                vot_codec::Settings::default(),
                extensions,
                vot_session::Authentication::Presenting,
            );
            let mut push = crate::ServeSession::begin_push_session(&server, session, holder)?;
            crate::drive(&mut push)
        });

        let extensions = BTreeSet::from([vot_codec::extension_id::PUSH]);
        let mut session = Session::server(
            receiver,
            vot_codec::Settings::default(),
            extensions,
            vot_session::Authentication::Capability {
                challenge: requirement.challenge([9; 32]),
            },
        );
        session.begin().unwrap();
        let scope = loop {
            if let Some((challenge, open)) = session.pending_authorization() {
                let scope = requirement
                    .decide(
                        challenge,
                        open,
                        binding,
                        crate::authz::now_seconds().unwrap(),
                    )
                    .expect("the push capability");
                session
                    .grant(vot_capability::encode_scope(&scope).unwrap())
                    .unwrap();
                break scope;
            }
            let _ = session.poll().unwrap();
            session.flush().unwrap();
            session
                .driver()
                .wait_for_event(std::time::Duration::from_millis(10));
        };
        let output = temporary("in-process-pushed");
        assert_eq!(
            (scope.suite, scope.root, scope.length),
            (descriptor.suite, descriptor.root, Some(descriptor.length))
        );
        let mut fetcher = BundleFetcher::from_started_session(session, &output, Some(scope.root))
            .expect("a receiver");
        assert_eq!(crate::drive(&mut fetcher).unwrap(), FetchStatus::Complete);
        assert_eq!(fetcher.package(), Some(built));
        drop(fetcher);
        assert_eq!(
            pushing.join().unwrap().unwrap(),
            crate::ServeStatus::Disconnected,
        );
        discard(&[&output]);
    }

    #[test]
    fn a_push_descriptor_must_match_the_granted_scope_before_any_object() {
        let push = BTreeSet::from([vot_codec::extension_id::PUSH]);
        let client_adapter = Loopback::default();
        let server_adapter = Loopback::default();
        let mut client = Session::client(
            client_adapter,
            Settings::default(),
            push.clone(),
            Authentication::Presenting,
        );
        let challenge = vot_codec::frames::AuthContext {
            nonce: vec![7; 32],
            binding: vot_codec::frames::Binding::None,
            formats: vec![3],
        };
        let mut server = Session::server(
            server_adapter,
            Settings::default(),
            push,
            Authentication::Capability {
                challenge: challenge.clone(),
            },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        let mut sequence = 0;
        pump(client.driver(), server.driver(), &mut sequence);
        server.poll().unwrap();
        pump(server.driver(), client.driver(), &mut sequence);
        client.poll().unwrap();
        let scope = crate::authz::push_scope([8; 32], 10);
        client
            .present(vot_codec::frames::SessionOpen {
                session_id: [2; 16],
                capability_format: 3,
                capability: vec![1],
                requested_scope: Vec::new(),
                binding_proof: Vec::new(),
            })
            .unwrap();
        pump(client.driver(), server.driver(), &mut sequence);
        server.poll().unwrap();
        server
            .grant(vot_capability::encode_scope(&scope).unwrap())
            .unwrap();
        let output = temporary("push-descriptor-mismatch");
        let mut fetcher = BundleFetcher::from_started_session(server, &output, None).unwrap();
        let reported = fetcher
            .dispatch(
                &encoded(&TypedFrame::Error(frames::ErrorFrame {
                    code: error_code::ADMISSION_DENIED,
                    detail: b"refused".to_vec(),
                }))
                .unwrap(),
            )
            .unwrap_err();
        assert!(matches!(
            reported,
            Fault::Reported(error_code::ADMISSION_DENIED)
        ));
        let descriptor = PackageDescriptor {
            package: frames::ObjectId {
                suite: 1,
                root: [9; 32],
                length: 10,
            },
            manifest_id: [0; 16],
            page_count: 1,
        };
        let fault = fetcher
            .dispatch(&encoded(&TypedFrame::PackageDescriptor(descriptor)).unwrap())
            .unwrap_err();
        assert!(matches!(
            &fault,
            Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH)
        ));
        assert_eq!(
            fetcher.fail(fault).unwrap(),
            FetchStatus::Closed(error_code::OBJECT_IDENTITY_MISMATCH)
        );
        pump(
            fetcher.session_mut().driver(),
            client.driver(),
            &mut sequence,
        );
        let mut reported = false;
        for _ in 0..4 {
            match client.poll() {
                Ok(Some(Event::Control(bytes))) => {
                    reported = matches!(
                        decode_control(&bytes),
                        TypedFrame::Error(frames::ErrorFrame {
                            code,
                            detail,
                        }) if code == error_code::OBJECT_IDENTITY_MISMATCH
                            && detail.is_empty()
                    );
                    break;
                }
                Ok(Some(_) | None) => {}
                Err(_) => break,
            }
        }
        assert!(reported, "the descriptor mismatch sent no ERROR frame");
        assert!(
            fs::read_dir(output.join("objects"))
                .unwrap()
                .next()
                .is_none()
        );
        discard(&[&output]);
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
        crate::create_private_directory(&output).unwrap();
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
    fn custom_sinks_do_not_inherit_the_directory_resume_map() {
        let (bundle, _) = built_bundle(
            "custom-resume",
            &[("a.bin", patterned(300_001)), ("b.bin", noise(300_002))],
        );
        let output = temporary("custom-resume-old");
        let skipped;
        {
            let (server, mut session, mut connection) = serving(&bundle);
            let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            let mut sequence = 0;
            for _ in 0..ROUND_BUDGET {
                round(
                    &server,
                    &mut session,
                    &mut connection,
                    &mut fetcher,
                    &mut sequence,
                );
                if fetcher.locked_plan().is_some_and(|plan| plan.low == 1) {
                    break;
                }
            }
            assert_eq!(fetcher.locked_plan().unwrap().low, 1);
            skipped = fetcher.locked_plan().unwrap().objects[0].object.root;
        }

        let custom = temporary("custom-resume-new");
        crate::create_private_directory(&custom).unwrap();
        let destination = custom.to_path_buf();
        let seams = ReceiveSeams {
            sink: Some(Arc::new(move |_, object| {
                if object.object.root == skipped {
                    return Ok(None);
                }
                Ok(Some(Box::new(CountingSink::at(
                    &destination.join(crate::object_name(&object.object.root)),
                    object.object.length,
                )?)))
            })),
            ..ReceiveSeams::default()
        };
        let (server, mut session, mut connection) = serving(&bundle);
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        assert!(fetcher.resuming);
        fetcher.set_receive_seams(seams);
        assert_eq!(
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap(),
            FetchStatus::Complete
        );
        let plan = fetcher.locked_plan().unwrap();
        let requested: u64 = plan
            .objects
            .iter()
            .filter(|object| object.object.root != skipped)
            .map(|object| object.object.length)
            .sum();
        assert_eq!(fetcher.rail.taken_bytes, requested);
        assert!(plan.objects.iter().all(|object| object.resumed.is_empty()));
        assert!(plan.objects.iter().all(|object| {
            let name = crate::object_name(&object.object.root);
            !output.join("objects").join(&name).exists()
                && custom.join(name).exists() == (object.object.root != skipped)
        }));
        discard(&[&bundle, &output, &custom]);
    }

    #[test]
    fn a_custom_rail_restarts_partial_and_whole_directory_resumes() {
        for (name, whole) in [("partial", false), ("whole", true)] {
            let (bundle, _) = built_bundle(name, &[("a.bin", patterned(300_001))]);
            let (server, mut session, mut connection) = serving(&bundle);
            let output = temporary(&format!("mixed-resume-{name}"));
            let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            let plan = planned(&server, &mut session, &mut connection, &mut primary);
            let object = plan.lock().unwrap().objects[0].object;
            let length = object.length;
            {
                let mut held = plan.lock().unwrap();
                held.active.clear();
                held.next_open = 0;
                held.objects[0]
                    .resumed
                    .insert(0, if whole { length } else { length / 2 });
            }

            let custom = temporary(&format!("mixed-resume-custom-{name}"));
            crate::create_private_directory(&custom).unwrap();
            let destination = custom.to_path_buf();
            let mut secondary = BundleFetcher::join(
                Loopback::default(),
                &output,
                Arc::clone(&plan),
                None,
                BTreeSet::new(),
            )
            .unwrap();
            secondary.manifest.descriptor = primary.manifest.descriptor.clone();
            secondary.set_receive_seams(ReceiveSeams {
                sink: Some(Arc::new(move |_, object| {
                    Ok(Some(Box::new(CountingSink::at(
                        &destination.join(crate::object_name(&object.object.root)),
                        object.object.length,
                    )?)))
                })),
                ..ReceiveSeams::default()
            });
            secondary.advance().unwrap();
            secondary.issue_ranges().unwrap();

            let held = plan.lock().unwrap();
            assert!(held.objects[0].resumed.is_empty());
            assert!(held.active[&0].covered.extents().is_empty());
            assert!(held.active[&0].skip.is_empty());
            assert_eq!(secondary.rail.taken_bytes, length);
            assert!(
                !output
                    .join("objects")
                    .join(crate::object_name(&object.root))
                    .exists()
            );
            drop(held);
            discard(&[&bundle, &output, &custom]);
        }
    }

    #[cfg(unix)]
    #[test]
    fn custom_sink_selection_never_removes_a_replacement_staging_file() {
        let (bundle, _) = built_bundle("custom-replacement", &[("a.bin", patterned(300_001))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("custom-replacement-output");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let plan = planned(&server, &mut session, &mut connection, &mut fetcher);
        let object = plan.lock().unwrap().objects[0].object;
        let path = output
            .join("objects")
            .join(crate::object_name(&object.root));
        let renamed = path.with_extension("stale");
        fs::write(&path, b"stale").unwrap();
        {
            let mut held = plan.lock().unwrap();
            held.active.clear();
            held.next_open = 0;
        }
        let replaced = path.clone();
        fetcher.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |_, _| {
                fs::rename(&replaced, &renamed)?;
                fs::write(&replaced, b"replacement")?;
                Ok(None)
            })),
            ..ReceiveSeams::default()
        });

        assert!(fetcher.advance().is_err());
        assert!(plan.lock().unwrap().abandoned);
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        discard(&[&bundle, &output]);
    }

    #[cfg(unix)]
    #[test]
    fn custom_sink_selection_rejects_an_invalid_staging_file() {
        let (bundle, _) = built_bundle("custom-invalid-staging", &[("a.bin", patterned(8))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("custom-invalid-staging-output");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let plan = planned(&server, &mut session, &mut connection, &mut fetcher);
        let object = plan.lock().unwrap().objects[0].object;
        let path = output
            .join("objects")
            .join(crate::object_name(&object.root));
        {
            let mut held = plan.lock().unwrap();
            held.active.clear();
            held.next_open = 0;
        }
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&path, &path).unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let factory_called = Arc::clone(&called);
        fetcher.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |_, _| {
                factory_called.store(true, Ordering::Relaxed);
                Ok(None)
            })),
            ..ReceiveSeams::default()
        });

        assert!(fetcher.advance().is_err());
        assert!(plan.lock().unwrap().abandoned);
        assert!(!called.load(Ordering::Relaxed));
        discard(&[&bundle, &output]);
    }

    #[cfg(unix)]
    #[test]
    fn same_path_custom_sink_does_not_inherit_resume_extents() {
        let (bundle, _) = built_bundle("custom-same-path-resume", &[("a.bin", patterned(300_001))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("custom-same-path-resume-output");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let plan = planned(&server, &mut session, &mut connection, &mut fetcher);
        let object = plan.lock().unwrap().objects[0].object;
        let path = output
            .join("objects")
            .join(crate::object_name(&object.root));
        {
            let mut held = plan.lock().unwrap();
            held.active.clear();
            held.next_open = 0;
            held.objects[0].resumed.insert(0, object.length / 2);
        }
        fs::remove_file(&path).unwrap();
        let destination = path.clone();
        let mut secondary = BundleFetcher::join(
            Loopback::default(),
            &output,
            Arc::clone(&plan),
            None,
            BTreeSet::new(),
        )
        .unwrap();
        secondary.manifest.descriptor = fetcher.manifest.descriptor.clone();
        secondary.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |_, object| {
                Ok(Some(Box::new(CountingSink::at(
                    &destination,
                    object.object.length,
                )?)))
            })),
            ..ReceiveSeams::default()
        });

        secondary.advance().unwrap();
        secondary.issue_ranges().unwrap();
        let held = plan.lock().unwrap();
        assert!(held.objects[0].resumed.is_empty());
        assert!(held.active[&0].covered.extents().is_empty());
        assert!(held.active[&0].skip.is_empty());
        assert_eq!(secondary.rail.taken_bytes, object.length);
        drop(held);
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
                .is_some_and(|plan| !plan.active.is_empty())
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

        for (length, resumed, stored, expected) in [
            (0, false, false, true),
            (0, false, true, true),
            (1, false, false, false),
            (1, false, true, false),
            (1, true, false, false),
            (1, true, true, true),
        ] {
            assert_eq!(
                protocol::custom_flush_due(length, resumed, stored),
                expected
            );
        }
    }

    #[test]
    pub(crate) fn the_pass_budget_covers_opening_and_completing_every_object() {
        // Two passes an object, one to open it and one to complete it,
        // and one that finds nothing left: a budget below that would fail
        // a plan that is moving.
        for (objects, passes) in [(0, 1), (1, 3), (4, 9)] {
            assert_eq!(protocol::advance_passes(objects), passes);
        }
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
        crate::create_private_directory(&output).unwrap();
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
        crate::create_private_directory(&output).unwrap();
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
            active: BTreeMap::new(),
            low: 0,
            next_open: 1,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: Some(Arc::clone(&store)),
            finished: false,
        }));
        let sink = Arc::new(
            CountingSink::create(
                &output.join("h.obj"),
                object.length,
                Some(DurableHook {
                    plan: Arc::downgrade(&plan),
                    store: Arc::clone(&store),
                    subject,
                }),
            )
            .unwrap(),
        );
        {
            let mut held = plan.lock().unwrap();
            let mut entry = active(subject, Arc::clone(&sink));
            entry.covered = CoverageMap::seeded(covered);
            held.active.insert(0, entry);
        }

        sink.durable.as_ref().unwrap().flush(sink.sink.as_ref());
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

        // The window moves on; a late flush of the old sink claims nothing,
        // and the object that took its place is not its to claim either.
        let other = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [6; 32],
            length: unit,
        });
        let other_subject = subject_of(&other);
        {
            let mut plan = plan.lock().unwrap();
            plan.objects.push(other);
            plan.objects[0].done = true;
            plan.low = 1;
            plan.next_open = 2;
            plan.active.clear();
            let mut entry = active(other_subject, Arc::clone(&sink));
            entry.covered.insert(0, unit);
            plan.active.insert(1, entry);
        }
        let before = store.lock().unwrap().checkpointed(subject).unwrap().count();
        sink.durable.as_ref().unwrap().flush(sink.sink.as_ref());
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
        crate::create_private_directory(&output).unwrap();
        let planned = PlannedObject::fresh(object);
        let mut entry = active(
            subject_of(&planned),
            Arc::new(CountingSink::create(&output.join("s.obj"), object.length, None).unwrap()),
        );
        entry.skip = skip;
        let mut plan = FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: vec![planned],
            active: BTreeMap::from([(0, entry)]),
            low: 0,
            next_open: 1,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: None,
            finished: false,
        };
        let (at, _, offset, length) = plan.next_span().unwrap().unwrap();
        assert_eq!(
            (at, offset, length),
            (0, 0, MAX_REQUESTED_RANGE),
            "clipped at the hole"
        );
        plan.take(at, offset, length).unwrap();
        let (at, _, offset, length) = plan.next_span().unwrap().unwrap();
        assert_eq!(
            (at, offset, length),
            (0, 2 * MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE),
            "the walk lands past the durable middle"
        );
        plan.take(at, offset, length).unwrap();
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
            fetcher.proving.wait, TEST_PROVER_WAIT,
            "a test round waits for the witness it is owed"
        );
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
            active: BTreeMap::new(),
            low: 0,
            next_open: 0,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
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

        let skipped_output = temporary("emptyobj-skipped");
        let mut skipped = BundleFetcher::begin(Loopback::default(), &skipped_output, None).unwrap();
        skipped.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary,
            objects: vec![PlannedObject::fresh(empty)],
            active: BTreeMap::new(),
            low: 0,
            next_open: 0,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: None,
            finished: false,
        })));
        let factory_calls = Arc::new(AtomicU64::new(0));
        let called = Arc::clone(&factory_calls);
        skipped.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |_, object| {
                assert_eq!(object.object, empty);
                called.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            })),
            ..ReceiveSeams::default()
        });
        skipped.advance().unwrap();
        assert_eq!(factory_calls.load(Ordering::Relaxed), 1);
        assert!(skipped.complete());
        assert!(
            !skipped_output
                .join("objects")
                .join(crate::object_name(&empty.root))
                .exists()
        );

        let custom_output = temporary("emptyobj-custom");
        let mut custom = BundleFetcher::begin(Loopback::default(), &custom_output, None).unwrap();
        custom.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary,
            objects: vec![PlannedObject::fresh(empty)],
            active: BTreeMap::new(),
            low: 0,
            next_open: 0,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: None,
            finished: false,
        })));
        let sink = Arc::new(SeamSink {
            bytes: Mutex::new(Vec::new()),
            flushed: AtomicBool::new(false),
            discarded: AtomicBool::new(false),
        });
        let placed = Arc::clone(&sink);
        custom.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |_, _| {
                Ok(Some(Box::new(Arc::clone(&placed))))
            })),
            ..ReceiveSeams::default()
        });
        custom.advance().unwrap();
        assert!(sink.flushed.load(Ordering::Acquire));
        assert!(custom.complete());
        assert!(
            !custom_output
                .join("objects")
                .join(crate::object_name(&empty.root))
                .exists()
        );

        let resumed_output = temporary("resumed-custom");
        let mut resumed = BundleFetcher::begin(Loopback::default(), &resumed_output, None).unwrap();
        let object = frames::ObjectId {
            suite: 1,
            root: *blake3::hash(&[1]).as_bytes(),
            length: 1,
        };
        let mut planned = PlannedObject::fresh(object);
        planned.resumed.insert(0, 1);
        let path = resumed_output
            .join("objects")
            .join(crate::object_name(&object.root));
        fs::write(&path, [1]).unwrap();
        let sink = Arc::new(SeamSink {
            bytes: Mutex::new(vec![0]),
            flushed: AtomicBool::new(false),
            discarded: AtomicBool::new(false),
        });
        let placed = Arc::clone(&sink);
        resumed.set_receive_seams(ReceiveSeams {
            sink: Some(Arc::new(move |_, _| {
                Ok(Some(Box::new(Arc::clone(&placed))))
            })),
            ..ReceiveSeams::default()
        });
        resumed.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary,
            objects: vec![planned],
            active: BTreeMap::new(),
            low: 0,
            next_open: 0,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: None,
            finished: false,
        })));
        resumed.advance().unwrap();
        resumed.issue_ranges().unwrap();
        assert!(!sink.flushed.load(Ordering::Acquire));
        assert!(!resumed.complete());
        assert!(resumed.locked_plan().unwrap().objects[0].resumed.is_empty());
        assert!(!path.exists());
        assert_eq!(resumed.rail.taken_bytes, 1);
        discard(&[&output, &skipped_output, &custom_output, &resumed_output]);
    }

    #[test]
    pub(crate) fn control_frames_that_are_not_answers_are_refused_or_skipped() {
        let (bundle, _) = built_bundle("frames", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("frames-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();

        // A well-formed bidirectional frame this end does not consume is not
        // an answer, and not a fault either.
        let progress = fetcher.report.progress;
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::Capacity(frames::Capacity {
                epoch: 3,
                available_bytes: 4,
                bdp_target_bytes: 5,
                max_inflight_bytes: 6,
            })));
        let mut ping = Vec::new();
        vot_codec::encode_frame(vot_codec::frame_type::PING, &[], &mut ping).unwrap();
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(Event::Control(vot_transport_api::shared_payload(&ping)));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert_eq!(fetcher.report.progress, progress);

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
            if !fetcher.has_backlog() && fetcher.locked_plan().is_some_and(|p| !p.active.is_empty())
            {
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
    pub(crate) fn a_landed_cover_buys_the_next_request_before_its_proof() {
        // The whole point of the change: credit returns as a cover's records
        // land. The serve's proofs are dropped on its own carrier and
        // `pump_provers` never runs, so nothing is verified, placed or
        // covered, and the only account that can advance the handout is what
        // arrived.
        let length = 3 * usize::try_from(MAX_REQUESTED_RANGE).unwrap();
        let (bundle, _) = built_bundle("landed", &[("big.bin", patterned(length))]);
        let output = temporary("landed-fetched");
        let (server, mut session, mut connection) = serving(&bundle);
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        // Two spans of window against a three-span object, so the third span
        // is owed and only room can buy it.
        fetcher.rail.window_bytes = 2 * MAX_REQUESTED_RANGE;
        let mut sequence = announce(&server, &mut session, &mut connection, &mut fetcher);

        // Manifest rounds, stopping on the pass that asks for spans and
        // before its requests reach the serve.
        let mut asked = false;
        for _ in 0..ROUND_BUDGET {
            fetcher.service().unwrap();
            if fetcher.rail.taken_bytes > 0 {
                asked = true;
                break;
            }
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
        }
        assert!(asked, "the rail never asked for a span");
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0].next_offset,
            2 * MAX_REQUESTED_RANGE,
            "the window is what it asked for"
        );

        // The serve answers, and its proofs are thrown away before the pump.
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
        assert!(
            !session.driver().control.is_empty(),
            "the serve had proofs to withhold"
        );
        session.driver().control.clear();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );

        // Taken off the carrier, and bounded by the events there are.
        for _ in 0..ROUND_BUDGET {
            if fetcher.receiver.poll().unwrap().is_none() {
                break;
            }
        }
        assert!(fetcher.receiver.arrived_range_bytes() > 0, "records landed");
        assert_eq!(
            fetcher.placed_bytes(),
            0,
            "no proof held, so nothing placed"
        );

        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0].next_offset,
            3 * MAX_REQUESTED_RANGE,
            "an arrived cover did not buy the next request"
        );
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0]
                .covered
                .extents()
                .len(),
            0,
            "coverage advanced without a witness"
        );

        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn no_more_is_asked_for_than_may_be_outstanding() {
        // The bound is asked-for minus arrived; queue bounding instead would
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
            active: BTreeMap::from([(
                0,
                active(SubjectId::try_from(object).unwrap(), Arc::clone(&sink)),
            )]),
            low: 0,
            next_open: 1,
            window: 1,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: None,
            finished: false,
        })));

        // However many passes, and however readily the carrier takes them.
        for _ in 0..16 {
            fetcher.issue_ranges().unwrap();
            fetcher.rail.pending.clear();
        }
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0].next_offset,
            OUTSTANDING_REQUEST_BYTES,
            "asked for more than may be outstanding"
        );

        // Nothing has arrived, so the window is exactly full and the edge
        // holds from the closed side.
        assert_eq!(fetcher.rail.taken_bytes, OUTSTANDING_REQUEST_BYTES);
        assert_eq!(fetcher.receiver.arrived_range_bytes(), 0);
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0].next_offset,
            OUTSTANDING_REQUEST_BYTES,
            "a full window bought a request"
        );

        // One byte of arrival is one span's worth of room: the gap is
        // asked-for minus arrived, so lowering what was asked for is the
        // same lever from the other side. The edge holds from the open
        // side too, and no witness has settled anywhere.
        fetcher.rail.taken_bytes = OUTSTANDING_REQUEST_BYTES - 1;
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0].next_offset,
            OUTSTANDING_REQUEST_BYTES + MAX_REQUESTED_RANGE,
            "a byte of room did not buy the next request"
        );
        // Placing counts as progress, so a driving loop keeps a slow transfer alive.
        sink.placed.store(MAX_REQUESTED_RANGE, Ordering::Relaxed);
        assert!(fetcher.progress() >= MAX_REQUESTED_RANGE);

        // A span is committed only once its frame is queued, or a failure
        // leaves a hole nobody re-requests.
        fetcher.rail.taken_bytes = 0;
        let owed = fetcher.locked_plan().unwrap().active[&0].next_offset;
        fetcher.rail.next_request = u64::MAX;
        assert!(
            fetcher.issue_ranges().is_err(),
            "the identifier space ended"
        );
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0].next_offset,
            owed,
            "a span whose frame never queued was consumed"
        );

        // The shared sink is not this rail's account; a full window blocks
        // regardless of placement, and inline proving is paced the same way
        // rather than on a count every rail writes into.
        fetcher.rail.next_request = 0;
        fetcher.rail.taken_bytes = OUTSTANDING_REQUEST_BYTES;
        sink.placed
            .store(40 * MAX_REQUESTED_RANGE, Ordering::Relaxed);
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0].next_offset,
            owed,
            "the shared sink paid for a rail's spans"
        );
        fetcher.set_proving_threads(0).unwrap();
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().active[&0].next_offset,
            owed,
            "an inline fetch paced on the shared sink"
        );

        discard(&[&bundle, &output]);
    }

    #[test]
    pub(crate) fn an_existing_destination_is_refused() {
        let empty = temporary("empty-destination");
        crate::create_private_directory(&empty).unwrap();
        drop(BundleFetcher::begin(Loopback::default(), &empty, None).unwrap());

        let existing = temporary("occupied");
        crate::create_private_directory(&existing).unwrap();
        fs::write(existing.join("occupied"), []).unwrap();
        let outcome = BundleFetcher::begin(Loopback::default(), &existing, None);
        assert!(matches!(outcome, Err(Error::DestinationExists)));
        discard(&[&empty, &existing]);
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
