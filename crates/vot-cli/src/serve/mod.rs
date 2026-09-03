//! Serving one bundle over a session.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[cfg(test)]
use vot_codec::frames::DataRecordRef;
use vot_codec::frames::{
    self, DataRecord, ManifestRequest, PackageDescriptor, ProofBundle, RangeRequest, TypedFrame,
};
use vot_codec::{DecodeLimits, error_code, frame_type};
use vot_object::{ObjectBuilder, PreparedObject};
use vot_session::{ErrorKind, Session};
#[cfg(test)]
use vot_transport_api::shared_payload;
use vot_transport_api::{Event, MAX_CONTROL_FRAME_PAYLOAD, Payload, StreamId, TransportAdapter};
use vot_verifier::{GROUP_SIZE, Suite};

use crate::{Error, MANIFEST_DIRECTORY, MANIFEST_SEAL, ManifestReader, PackageSummary, Storage};

mod connection;
mod object;
pub(crate) mod server;

#[cfg(test)]
use connection::{OUTBOUND_BUDGET_BYTES, REMEMBERED_REQUESTS};

pub(crate) use connection::OpenedEpoch;
pub use connection::ServeConnection;
pub(crate) use object::*;
pub use server::{BundleServer, ServedSource};

/// The reliable lane every data record rides.
pub(crate) const RECORD_LANE: StreamId = StreamId(1);

/// What one service pass left the session as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeStatus {
    /// The session is live; call again once the carrier reports an event.
    Active,
    /// The carrier ended the session.
    Disconnected,
    /// This end closed the session under a registered code.
    Closed(u16),
    /// The receiver acknowledged every transfer object with a final-cursor
    /// `GOAWAY`, so this end concluded the session and let its carrier close.
    Completed,
}

/// Why an answer could not be built: the peer broke protocol under a
/// registered close code, or this end failed on its own.
pub(crate) enum Fault {
    Peer(u16),
    Local(Error),
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Local(error)
    }
}

/// Ends a failed dispatch: a peer fault closes the session under its code,
/// and a mutated bundle tells the peer why before erring locally.
pub(crate) fn fail<A: TransportAdapter>(
    fault: Fault,
    session: &mut Session<A>,
    connection: &mut ServeConnection,
) -> Result<ServeStatus, Error> {
    match fault {
        Fault::Peer(code) => {
            // The session cannot close itself; the carrier does.
            let _ = session.driver().close(code);
            connection.close_with(code);
            Ok(ServeStatus::Closed(code))
        }
        Fault::Local(error) => {
            if matches!(error, Error::SourceMutation) {
                // Tell the peer why before the local error surfaces.
                let _ = session.driver().close(error_code::SOURCE_MUTATED);
                connection.close_with(error_code::SOURCE_MUTATED);
            }
            Err(error)
        }
    }
}

/// Whether a session refusal means "retry after the backend drains".
pub(crate) fn is_backpressure(error: &vot_session::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Transport(vot_transport_api::Error::OutboundQueueFull)
            | ErrorKind::HandshakeUnsent { .. }
    )
}

pub(crate) fn encoded(frame: &TypedFrame) -> Result<Payload, Error> {
    let mut wire = Vec::new();
    frames::encode(frame, &mut wire)?;
    Ok(Payload::from(wire))
}

#[cfg(test)]
mod tests {
    /// A two-object bundle moved out of bundle shape: each object copied to
    /// a path of the host's choosing, with the leaves `send` kept for the
    /// first and nothing for the second.
    fn scattered(
        name: &str,
    ) -> (
        crate::tests::Temporary,
        crate::PackageSummary,
        std::collections::BTreeMap<[u8; 32], crate::ServedSource>,
        crate::tests::Temporary,
    ) {
        let (bundle, built) = crate::harness::built_bundle(
            name,
            &[
                ("one.bin", crate::harness::patterned(300_000)),
                ("two.bin", crate::harness::patterned(400_000)),
            ],
        );
        let elsewhere = crate::tests::temporary(&format!("{name}-elsewhere"));
        std::fs::create_dir_all(&elsewhere).unwrap();
        let objects = bundle.join("objects");
        let opened = BundleServer::open(&bundle).unwrap();
        let suite = crate::parse_suite("sha256").unwrap();
        let mut sources = std::collections::BTreeMap::new();
        for (index, (root, object)) in opened.objects.iter().enumerate() {
            let path = elsewhere.join(format!("host-{index}.bin"));
            std::fs::copy(objects.join(crate::object_name(root)), &path).unwrap();
            let leaves = (index == 0).then(|| {
                crate::package::proof_cache::read(&objects, root, suite, object.object.length)
                    .expect("send kept the leaves")
            });
            sources.insert(*root, crate::ServedSource { path, leaves });
        }
        (bundle, built, sources, elsewhere)
    }

    #[test]
    fn an_assembled_server_serves_from_where_the_host_keeps_its_objects() {
        let (bundle, built, sources, elsewhere) = scattered("assemble");
        // The bundle's own objects go away: only the manifest remains there.
        std::fs::remove_dir_all(bundle.join("objects")).unwrap();
        let server = BundleServer::assemble(&bundle, sources).unwrap();
        assert_eq!(server.package(), built);
        assert_eq!(server.object_count(), 2);
        // Leaves prepared the first object without a read; the second was
        // read, so it needs no first-serve hashing.
        let prepared: Vec<bool> = server
            .objects
            .values()
            .map(|object| object.verified.is_some())
            .collect();
        assert_eq!(prepared.iter().filter(|kept| **kept).count(), 1);

        let (client, serving) = crate::harness::duplex_pair();
        let serving_thread = std::thread::spawn(move || {
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
        let output = crate::tests::temporary("assemble-fetched");
        let mut fetcher =
            crate::BundleFetcher::begin(client, &output, Some(built.root)).expect("a fetch");
        assert_eq!(
            crate::drive::drive(&mut fetcher).expect("a driven fetch"),
            crate::FetchStatus::Complete
        );
        assert_eq!(fetcher.package().expect("a package"), built);
        drop(fetcher);
        serving_thread
            .join()
            .expect("the serving thread")
            .expect("served");
        crate::harness::discard(&[&bundle, &elsewhere, &output]);
    }

    #[test]
    fn an_assembled_server_reads_a_one_group_object_whatever_its_leaves() {
        // One small file packs into one stored object of a group or less,
        // which has no tree to rebuild: it is read, and leaves handed in
        // for it are not a claim that can fail. Both a small file and one
        // of exactly a group: the bound is the group size, inclusive.
        for (name, bytes) in [("tiny", 1_000), ("group", super::GROUP_SIZE)] {
            let (bundle, built) = crate::harness::built_bundle(
                &format!("assemble-small-{name}"),
                &[("small.bin", vec![3; bytes])],
            );
            let opened = BundleServer::open(&bundle).unwrap();
            assert_eq!(opened.object_count(), 1);
            let (root, object) = opened.objects.iter().next().unwrap();
            assert_eq!(object.object.length, bytes as u64, "{name}: stored as is");
            let elsewhere = crate::tests::temporary(&format!("assemble-small-{name}-elsewhere"));
            std::fs::create_dir_all(&elsewhere).unwrap();
            let path = elsewhere.join("host.bin");
            std::fs::copy(bundle.join("objects").join(crate::object_name(root)), &path).unwrap();
            let sources = std::collections::BTreeMap::from([(
                *root,
                crate::ServedSource {
                    path,
                    leaves: Some(vec![[0; 32]]),
                },
            )]);
            let server = BundleServer::assemble(&bundle, sources)
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(server.package(), built);
            assert!(
                server.objects.values().next().unwrap().verified.is_none(),
                "{name}: the object was prepared from leaves that describe nothing"
            );
            crate::harness::discard(&[&bundle, &elsewhere]);
        }
    }

    #[test]
    fn an_assembled_server_refuses_leaves_that_name_another_object() {
        let (bundle, _built, mut sources, elsewhere) = scattered("assemble-wrong-leaves");
        // The first object's leaves handed in for the second object's file.
        let roots: Vec<[u8; 32]> = sources.keys().copied().collect();
        let leaves = sources.get(&roots[0]).unwrap().leaves.clone().unwrap();
        let mut swapped = sources.clone();
        swapped.get_mut(&roots[0]).unwrap().leaves = None;
        swapped.get_mut(&roots[1]).unwrap().leaves = Some(leaves.clone());
        assert!(matches!(
            BundleServer::assemble(&bundle, swapped),
            Err(Error::RootMismatch)
        ));
        // The right file with one middle leaf altered: the first and last
        // groups still hold, so only the rebuilt root tells.
        let mut altered = leaves;
        assert!(altered.len() > 2, "a middle leaf needs at least three");
        let middle = altered.len() / 2;
        altered[middle][0] ^= 0xff;
        sources.get_mut(&roots[0]).unwrap().leaves = Some(altered);
        assert!(matches!(
            BundleServer::assemble(&bundle, sources),
            Err(Error::RootMismatch)
        ));
        crate::harness::discard(&[&bundle, &elsewhere]);
    }

    #[test]
    fn an_assembled_server_refuses_a_truncated_object_behind_valid_leaves() {
        let (bundle, _built, sources, elsewhere) = scattered("assemble-truncated");
        let roots: Vec<[u8; 32]> = sources.keys().copied().collect();
        let path = sources.get(&roots[0]).unwrap().path.clone();
        let original = std::fs::read(&path).unwrap();
        // Bytes appended: every sampled group still holds, so only the
        // length tells.
        let mut longer = original.clone();
        longer.extend_from_slice(b"appended");
        std::fs::write(&path, &longer).unwrap();
        assert!(matches!(
            BundleServer::assemble(&bundle, sources.clone()),
            Err(Error::RootMismatch)
        ));
        // Truncated: the length check answers first, and the last group
        // could not be read either.
        std::fs::write(&path, &original[..299_000]).unwrap();
        assert!(matches!(
            BundleServer::assemble(&bundle, sources),
            Err(Error::RootMismatch)
        ));
        crate::harness::discard(&[&bundle, &elsewhere]);
    }

    #[test]
    fn an_assembled_server_refuses_a_missing_or_unnamed_source() {
        let (bundle, _built, sources, elsewhere) = scattered("assemble-sources");
        let roots: Vec<[u8; 32]> = sources.keys().copied().collect();
        let mut missing = sources.clone();
        missing.remove(&roots[1]);
        assert!(matches!(
            BundleServer::assemble(&bundle, missing),
            Err(Error::InvalidBundle)
        ));
        let mut extra = sources;
        let stray = elsewhere.join("stray.bin");
        std::fs::write(&stray, b"not in the manifest").unwrap();
        extra.insert(
            [9; 32],
            crate::ServedSource {
                path: stray,
                leaves: None,
            },
        );
        assert!(matches!(
            BundleServer::assemble(&bundle, extra),
            Err(Error::InvalidBundle)
        ));
        crate::harness::discard(&[&bundle, &elsewhere]);
    }

    #[test]
    fn a_serve_prepares_from_the_leaves_beside_the_object_and_falls_back_without_them() {
        // Preparation reads every byte of every object, about 1.4 seconds a
        // gigabyte, so `send` keeps the leaves and a serve prepares from
        // them. They are a cache: anything unreadable, stale, or describing
        // another object is ignored in favour of reading the object, and
        // every one of those cases still serves.
        use std::fs;

        // Stored directly rather than packed, and more than one piece, or
        // there is nothing to keep leaves for.
        let (bundle, _) = built_bundle(
            "leafcache",
            &[("big.bin", patterned(vot_pack::CANDIDATE_MAX + 200_000))],
        );
        let objects = bundle.join("objects");
        let cache = fs::read_dir(&objects)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().is_some_and(|kind| kind == "leaves"))
            .expect("send kept the leaves");
        let kept = fs::read(&cache).unwrap();
        let served = BundleServer::open(&bundle).unwrap();
        let object = served.objects.values().next().unwrap();
        let honest = object.layer.prove(0, 65_536).unwrap();

        let reopen = |bundle: &std::path::Path| {
            let opened = BundleServer::open(bundle).unwrap();
            let object = opened.objects.values().next().unwrap().object;
            let proof = opened
                .objects
                .values()
                .next()
                .unwrap()
                .layer
                .prove(0, 65_536)
                .unwrap();
            (object, proof)
        };

        // The cache in place proves exactly what reading the object proves,
        // and it is the cache that answered rather than the object.
        let (identity, proof) = reopen(&bundle);
        assert_eq!(proof.proof(), honest.proof());
        assert!(
            super::object::prepared_from_cache(
                &objects,
                identity.root,
                crate::parse_suite("sha256").unwrap(),
                identity.length,
            )
            .is_some(),
            "the leaves beside the object were not used"
        );

        // A mutated tail is caught by the sample too, which is what makes
        // the check read the object's last group and not its first twice.
        {
            let object = fs::read_dir(&objects)
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| path.extension().is_some_and(|kind| kind == "obj"))
                .expect("the object");
            let original = fs::read(&object).unwrap();
            let mut tail_flipped = original.clone();
            let last = tail_flipped.len() - 1;
            tail_flipped[last] ^= 0xff;
            fs::write(&object, &tail_flipped).unwrap();
            assert!(
                super::object::prepared_from_cache(
                    &objects,
                    identity.root,
                    crate::parse_suite("sha256").unwrap(),
                    identity.length,
                )
                .is_none(),
                "a mutated last group was prepared from"
            );
            fs::write(&object, &original).unwrap();
        }

        // Corrupt, truncated, for another object, and absent: all still open
        // and prove the same, because each falls back to reading it.
        let corrupt = {
            let mut bytes = kept.clone();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            bytes
        };
        for (case, bytes) in [
            ("corrupt", Some(corrupt)),
            ("truncated", Some(kept[..kept.len() / 2].to_vec())),
            ("header only", Some(kept[..8].to_vec())),
            ("absent", None),
        ] {
            match bytes {
                Some(bytes) => fs::write(&cache, bytes).unwrap(),
                None => fs::remove_file(&cache).unwrap(),
            }
            assert!(
                super::object::prepared_from_cache(
                    &objects,
                    identity.root,
                    crate::parse_suite("sha256").unwrap(),
                    identity.length,
                )
                .is_none(),
                "{case} was prepared from rather than ignored"
            );
            let (again, proof) = reopen(&bundle);
            assert_eq!(again, identity, "{case} changed what the bundle serves");
            assert_eq!(proof.proof(), honest.proof(), "{case} changed a proof");
        }
        crate::harness::discard(&[&bundle]);
    }

    use super::*;
    use crate::build_bundle_with_suite;
    use crate::harness::{
        Loopback, built_bundle, control_event, decode_control, not_required, patterned,
    };
    use crate::tests::temporary;
    use std::collections::BTreeSet;
    use std::fs;
    use vot_codec::Settings;
    use vot_manifest::StorageRef;
    use vot_scheduler::ReliableReceiver;
    use vot_transport_api::SubjectId;

    #[test]
    fn an_encoded_record_keeps_its_allocation_as_a_payload() {
        let encoded = vec![0xaa; RECORD_PLAINTEXT_BYTES];
        let record = DataRecordRef {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: encoded.len() as u64,
            compression: 0,
            encoded: &encoded,
        };
        let mut wire = Vec::new();
        frames::encode_data_record(record, &mut wire).unwrap();
        assert_eq!(wire.capacity(), wire.len());
        let allocation = wire.as_ptr();
        assert_eq!(Payload::from(wire).as_ptr(), allocation);
    }

    fn forced_fec_server(bundle: &std::path::Path) -> BundleServer {
        let mut server = BundleServer::open(bundle).unwrap();
        server.set_automatic_fec(false);
        server
    }

    /// A ready server session with handshake replies cleared.
    pub(crate) fn ready_session() -> Session<Loopback> {
        ready_session_with(Settings::default())
    }

    /// The same under the peer settings a test needs.
    pub(crate) fn ready_session_with(peer: Settings) -> Session<Loopback> {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            not_required(),
        );
        server.begin().unwrap();
        push_handshake_with(&mut server, peer);
        assert_eq!(server.poll().unwrap(), None);
        assert!(server.is_ready());
        server.driver().control.clear();
        server
    }

    /// Queues a client's opening frames into the server's carrier.
    pub(crate) fn push_handshake(server: &mut Session<Loopback>) {
        push_handshake_with(server, Settings::default());
    }

    pub(crate) fn push_handshake_with(server: &mut Session<Loopback>, peer: Settings) {
        let mut client =
            Session::client(Loopback::default(), peer, BTreeSet::new(), not_required());
        client.begin().unwrap();
        for frame in std::mem::take(&mut client.driver().control) {
            server
                .driver()
                .events
                .push_back(Event::Control(shared_payload(&frame)));
        }
    }

    /// Pairs proof bundles with their records, consumed in wire order.
    pub(crate) fn served_answers(
        session: &mut Session<Loopback>,
    ) -> Vec<(ProofBundle, Vec<DataRecord>)> {
        let control = std::mem::take(&mut session.driver().control);
        let records = std::mem::take(&mut session.driver().records);
        let mut answers: Vec<(ProofBundle, Vec<DataRecord>)> = Vec::new();
        for frame in &control {
            if let TypedFrame::ProofBundle(bundle) = decode_control(frame) {
                answers.push((bundle, Vec::new()));
            }
        }
        let mut stream = records.iter();
        for (bundle, carried) in &mut answers {
            for _ in 0..bundle.data_record_count {
                let (lane, bytes) = stream.next().expect("a bundle short of its records");
                assert_eq!(*lane, RECORD_LANE, "records ride the record lane");
                let TypedFrame::DataRecord(record) = decode_control(bytes) else {
                    panic!("the record lane carried something else");
                };
                assert_eq!(record.bundle_id, bundle.bundle_id);
                carried.push(record);
            }
        }
        assert!(stream.next().is_none(), "records past every bundle");
        answers
    }

    /// Verifies an answer against the object root and returns its bytes.
    pub(crate) fn verified_bytes(
        object: frames::ObjectId,
        bundle: &ProofBundle,
        records: &[DataRecord],
    ) -> Vec<u8> {
        let subject = SubjectId::try_from(object).unwrap();
        let borrowed = records
            .iter()
            .map(frames::DataRecordRef::from)
            .collect::<Vec<_>>();
        ReliableReceiver::verify_typed_bundle(subject, bundle, &borrowed).unwrap();
        let mut ordered: Vec<&DataRecord> = records.iter().collect();
        ordered.sort_by_key(|record| record.record_index);
        let mut assembled = Vec::new();
        for record in ordered {
            assembled.extend_from_slice(&record.encoded);
        }
        assembled
    }

    /// The stored objects the served pages name: direct objects and packs.
    pub(crate) fn stored_objects(
        pages: &[Vec<u8>],
    ) -> (BTreeMap<[u8; 32], frames::ObjectId>, bool, bool) {
        let mut objects = BTreeMap::new();
        let (mut saw_direct, mut saw_pack) = (false, false);
        for bytes in pages {
            let page = vot_manifest::decode_page(bytes).unwrap();
            for entry in page.entries {
                let stored = match entry.storage.unwrap() {
                    StorageRef::Direct(object) => {
                        saw_direct = true;
                        object
                    }
                    StorageRef::Pack { pack, .. } => {
                        saw_pack = true;
                        pack
                    }
                };
                objects.insert(
                    stored.root,
                    frames::ObjectId {
                        suite: stored.suite,
                        root: stored.root,
                        length: stored.length,
                    },
                );
            }
        }
        (objects, saw_direct, saw_pack)
    }

    #[test]
    pub(crate) fn a_ready_session_is_announced_and_a_whole_bundle_is_served() {
        let (bundle, summary) = built_bundle(
            "whole",
            &[
                ("a.txt", patterned(1000)),
                ("nested/b.bin", patterned(150_000)),
                ("big.bin", patterned(300_000)),
            ],
        );
        let server = BundleServer::open(&bundle).unwrap();
        assert_eq!(server.package(), summary);
        let mut session = ready_session();
        let mut connection = ServeConnection::new();

        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert_eq!(connection.pending_answer_bytes(), 0);
        let sent = std::mem::take(&mut session.driver().control);
        assert_eq!(sent.len(), 2, "the announcement is the descriptor and seal");
        let TypedFrame::PackageDescriptor(descriptor) = decode_control(&sent[0]) else {
            panic!("the descriptor leads");
        };
        assert_eq!(descriptor.package.root, summary.root);
        assert_eq!(descriptor.package.suite, 1);
        assert_eq!(descriptor.package.length, summary.logical_length);
        assert_eq!(descriptor.manifest_id, summary.root[..16]);
        let TypedFrame::Seal(seal_bytes) = decode_control(&sent[1]) else {
            panic!("the seal follows");
        };
        assert_eq!(
            seal_bytes,
            fs::read(bundle.join("manifest/seal.cbor")).unwrap()
        );

        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [1; 16],
                    manifest_id: descriptor.manifest_id,
                    first_page: 0,
                    page_count: descriptor.page_count,
                },
            )));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        let sent = std::mem::take(&mut session.driver().control);
        assert_eq!(sent.len() as u64, descriptor.page_count);
        let mut pages = Vec::new();
        for (index, frame) in sent.iter().enumerate() {
            let TypedFrame::ManifestPage(bytes) = decode_control(frame) else {
                panic!("a page answer that is not a page");
            };
            assert_eq!(
                bytes,
                fs::read(bundle.join(format!("manifest/{index:016}.cbor"))).unwrap(),
                "the served page is the disk page"
            );
            pages.push(bytes);
        }

        let (objects, saw_direct, saw_pack) = stored_objects(&pages);
        assert!(saw_direct && saw_pack, "both storage kinds are exercised");
        for (request_index, object) in objects.values().enumerate() {
            let identifier = u8::try_from(10 + request_index).unwrap();
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [identifier; 16],
                    object: *object,
                    offset: 0,
                    length: object.length,
                })));
            let status = server.service(&mut session, &mut connection).unwrap();
            assert_eq!(status, ServeStatus::Active);
            let answers = served_answers(&mut session);
            assert_eq!(answers.len(), 1);
            let (bundle_frame, records) = &answers[0];
            assert_eq!(bundle_frame.request_id, [identifier; 16]);
            let assembled = verified_bytes(*object, bundle_frame, records);
            let expected = fs::read(
                bundle
                    .join("objects")
                    .join(crate::object_name(&object.root)),
            )
            .unwrap();
            assert_eq!(assembled, expected, "the whole object arrived verified");
        }
        assert!(session.driver().closed.is_none());
    }

    /// A ready session with `DATAGRAM_FEC` negotiated at both ends and the
    /// peer's credit already extended.
    pub(crate) fn ready_session_fec(credit: frames::DatagramCredit) -> Session<Loopback> {
        ready_session_offering(
            BTreeSet::from([
                vot_codec::extension_id::DATAGRAM_FEC,
                vot_codec::extension_id::FEC_COVER_EPOCHS,
            ]),
            credit,
        )
    }

    fn ready_session_offering(
        fec: BTreeSet<u64>,
        credit: frames::DatagramCredit,
    ) -> Session<Loopback> {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            fec.clone(),
            not_required(),
        );
        server.begin().unwrap();
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            fec,
            not_required(),
        );
        client.begin().unwrap();
        for frame in std::mem::take(&mut client.driver().control) {
            server
                .driver()
                .events
                .push_back(Event::Control(shared_payload(&frame)));
        }
        assert_eq!(server.poll().unwrap(), None);
        assert!(server.is_ready());
        server.driver().control.clear();
        server
            .driver()
            .events
            .push_back(control_event(&TypedFrame::DatagramCredit(credit)));
        server
    }

    fn ample_credit() -> frames::DatagramCredit {
        frames::DatagramCredit {
            credit_epoch: 1,
            max_unretired_bytes: 1 << 24,
            max_active_generations: 64,
            max_decode_work: 1 << 30,
            max_open_epochs: 4,
        }
    }

    fn ample_receiver_credit() -> vot_fec::Credit {
        vot_fec::Credit {
            credit_epoch: 1,
            max_unretired_bytes: 1 << 24,
            max_active_generations: 64,
            max_decode_work: 1 << 30,
            max_open_epochs: 4,
        }
    }

    fn path_sample(lost: u64, spurious: u64, sent: u64) -> vot_transport_api::PathStats {
        vot_transport_api::PathStats {
            lost_packets: Some(lost),
            spurious_lost_packets: Some(spurious),
            packets_sent: Some(sent),
            ..vot_transport_api::PathStats::default()
        }
    }

    fn path_sample_at_rtt(
        lost: u64,
        spurious: u64,
        sent: u64,
        rtt_us: u64,
    ) -> vot_transport_api::PathStats {
        vot_transport_api::PathStats {
            smoothed_rtt_us: Some(rtt_us),
            ..path_sample(lost, spurious, sent)
        }
    }

    #[test]
    fn repair_count_tracks_recent_real_loss_after_startup() {
        let repair = |lost, spurious, sent| {
            let mut policy = connection::FecPolicy::default();
            policy.observe(Some(path_sample(0, 0, 0)));
            policy.observe(Some(path_sample(lost, spurious, sent)));
            policy.repair_symbols()
        };
        let mut startup = connection::FecPolicy::default();
        startup.observe(None);
        startup.observe(Some(vot_transport_api::PathStats::default()));
        assert_eq!(startup.repair_symbols(), 16);
        assert_eq!(repair(0, 0, 8192), 2, "a clean sample keeps the floor");
        assert_eq!(repair(40, 0, 8192), 3);
        assert_eq!(repair(164, 0, 8192), 6);
        assert_eq!(repair(410, 0, 8192), 14);
        assert_eq!(repair(984, 0, 8192), 16, "the spec's ceiling binds");
        assert_eq!(
            repair(410, 409, 8192),
            2,
            "spurious losses do not buy repair"
        );
    }

    #[test]
    fn automatic_fec_decides_first_from_a_covers_worth_of_packets() {
        // The first verdict closes at 256 packets so a short transfer is
        // covered rather than mostly issued before a full window closes
        // (ADR-0042). The bar is ten percent, a shade under the loss rate
        // where coding was measured to start paying for itself.
        let worthwhile = |lost, spurious, sent| {
            let mut policy = connection::FecPolicy::default();
            policy.observe(Some(path_sample(0, 0, 0)));
            policy.observe(Some(path_sample(lost, spurious, sent)));
            policy.coding()
        };
        assert!(!worthwhile(26, 0, 255), "below the first sample");
        assert!(!worthwhile(25, 0, 256), "under ten percent");
        assert!(worthwhile(26, 0, 256));
        assert!(!worthwhile(26, 1, 256), "spurious losses do not count");
    }

    #[test]
    fn automatic_fec_accumulates_subwindow_counter_deltas() {
        let mut policy = connection::FecPolicy::default();
        for sent in [0, 64, 128, 192] {
            policy.observe(Some(path_sample(u64::from(sent > 0) * 26, 0, sent)));
            assert!(!policy.coding());
            assert_eq!(policy.repair_symbols(), 16);
        }
        policy.observe(Some(path_sample(26, 0, 256)));
        assert!(policy.coding());
        assert_eq!(
            policy.repair_symbols(),
            16,
            "repair saturates below the engagement bar, so an engaged path always takes the ceiling"
        );
    }

    #[test]
    fn automatic_fec_follows_recent_loss_with_hysteresis() {
        // The verdict reads the smoothed rate, so the 7.5-10% dips inside
        // a steadily lossy run keep coding on where per-window hysteresis
        // was measured flapping it off half the time, and one clean
        // window softens the rate rather than ending the engagement.
        let mut policy = connection::FecPolicy::default();
        for (lost, sent, coding) in [
            (0, 0, false),
            (1024, 8192, true),
            (1843, 16_384, true),
            (2457, 24_576, true),
            (3071, 32_768, true),
            (3890, 40_960, true),
            (4914, 49_152, true),
        ] {
            policy.observe(Some(path_sample(lost, 0, sent)));
            assert_eq!(policy.coding(), coding, "at {lost} losses of {sent}");
        }
        policy.observe(None);
        assert!(policy.coding(), "missing telemetry keeps the last verdict");

        policy.observe(Some(path_sample(4914, 0, 57_344)));
        assert!(
            policy.coding(),
            "one clean window softens the rate, it does not end coding"
        );
        policy.observe(Some(path_sample(4914, 0, 65_536)));
        assert!(
            !policy.coding(),
            "a sustained clean run disables coding through the smoothing"
        );
        // One window further down, past where the repair count saturates,
        // so the count is the smoothed rate's and not the clamp's.
        policy.observe(Some(path_sample(4914, 0, 73_728)));
        assert_eq!(
            policy.repair_symbols(),
            12,
            "repair follows the smoothed rate"
        );
    }

    /// One whole decode sample, `failed` of it generations the receiver
    /// could not decode.
    fn decode_sample(policy: &mut connection::FecPolicy, failed: u64) {
        code_generations(policy, connection::FEC_DECODE_SAMPLE, failed);
    }

    /// Half a sample of failures, which is the shape the shaped
    /// bottleneck's reports arrive in.
    const HALF_SAMPLE: u64 = connection::FEC_DECODE_SAMPLE / 2;

    /// Resolves `resolved` coded generations past the policy, `failed` of
    /// which the receiver could not decode.
    fn code_generations(policy: &mut connection::FecPolicy, resolved: u64, failed: u64) {
        for index in 0..resolved {
            if index < failed {
                policy.note_repaired();
            } else {
                policy.note_decoded();
            }
        }
    }

    #[test]
    fn coding_that_cannot_decode_disengages_and_stays_off_for_its_hold() {
        // Loss the sender caused itself is loss coding cannot answer: the
        // repair symbols drop in the same queue as the sources. Nothing
        // about the path tells the two apart, so the policy reads whether
        // the coding worked.
        let mut policy = connection::FecPolicy::default();
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(1024, 0, 8192)));
        assert!(policy.coding(), "a lossy path engages");

        // Half of every sample failing is the shaped bottleneck's own
        // measurement. Smoothed, it takes three samples to be believed.
        decode_sample(&mut policy, HALF_SAMPLE);
        decode_sample(&mut policy, HALF_SAMPLE);
        assert!(policy.coding(), "two samples are not yet a verdict");
        decode_sample(&mut policy, HALF_SAMPLE);
        assert!(!policy.coding(), "sustained failure ends coding");

        // The loss is still there, and it is exactly what must not
        // re-engage coding while the hold runs.
        for window in 1..=4_u64 {
            policy.observe(Some(path_sample(
                1024 * (window + 1),
                0,
                8192 * (window + 1),
            )));
            assert!(!policy.coding(), "held off at window {window}");
        }
        policy.observe(Some(path_sample(6144, 0, 49_152)));
        assert!(
            policy.coding(),
            "past the hold the path is judged on its loss again"
        );
    }

    #[test]
    fn a_path_that_keeps_failing_is_retried_less_and_less() {
        // The signal arrives late: a generation that never gathers enough
        // symbols owes no GEN_DONE, so this end learns the truth at the
        // epoch's quiet retirement. A fixed hold therefore pays a fresh
        // sample plus that lag for every retry, which measured as half the
        // cost of not discriminating at all. Each failure doubles the next
        // hold, to a cap that outlasts a transfer.
        let mut policy = connection::FecPolicy::default();
        let mut sent = 0_u64;
        let mut lossy = |policy: &mut connection::FecPolicy, windows: u64| {
            for _ in 0..windows {
                sent += 8192;
                policy.observe(Some(path_sample(sent / 8, 0, sent)));
            }
        };
        lossy(&mut policy, 2);
        assert!(policy.coding(), "a lossy path engages");

        for (failure, expected_hold) in [(1_u32, 4_u64), (2, 8), (3, 16), (4, 32)] {
            // Every generation failing: one sample is a verdict on its own
            // at that rate, so each retry costs exactly one sample.
            decode_sample(&mut policy, connection::FEC_DECODE_SAMPLE);
            assert!(!policy.coding(), "failure {failure} ends coding");
            // Held through exactly the windows this failure earned, then
            // judged on loss again by the next one.
            lossy(&mut policy, expected_hold);
            assert!(
                !policy.coding(),
                "failure {failure} holds through {expected_hold} windows"
            );
            lossy(&mut policy, 1);
            assert!(
                policy.coding(),
                "failure {failure} releases after {expected_hold}"
            );
        }
    }

    #[test]
    fn a_lossy_path_keeps_coding_through_bursts_of_failures() {
        // The case this must not break, and the one a raw per-sample
        // verdict did break. Failures arrive in lumps, because an epoch's
        // quiet retirement reports every generation under it at once, so a
        // path failing 2% overall still shows whole samples at half. On a
        // real 4 GiB transfer at 5% loss, nine of 359 raw samples crossed a
        // quarter on their own while the fetch decoded 100% of what it
        // coded, and acting on them cost that arm coding it should have
        // kept.
        let mut policy = connection::FecPolicy::default();
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(1024, 0, 8192)));
        assert!(policy.coding());

        for lump in 1..=8 {
            decode_sample(&mut policy, HALF_SAMPLE);
            for _ in 0..8 {
                decode_sample(&mut policy, 0);
            }
            assert!(
                policy.coding(),
                "a lump at {lump} among decoding samples is not a verdict"
            );
        }
    }

    #[test]
    fn only_a_generations_first_decoded_word_is_counted() {
        // The decode policy's denominator. A repeat says nothing new, and
        // an abandoned generation belongs to the numerator, counted where
        // it is repaired.
        assert!(server::first_decode(true, vot_fec::Done::Decoded));
        assert!(!server::first_decode(false, vot_fec::Done::Decoded));
        assert!(!server::first_decode(true, vot_fec::Done::Abandoned));
        assert!(!server::first_decode(false, vot_fec::Done::Abandoned));
    }

    #[test]
    fn a_sample_in_progress_survives_the_windows_under_it() {
        // Loss windows close far more often than decode samples fill, and
        // only a fresh engagement clears the sample. Clearing it on any
        // other window would mean a verdict that never arrives, because
        // the outcomes would never accumulate to a full sample.
        let mut policy = connection::FecPolicy::default();
        let mut sent = 0_u64;
        let mut lossy = |policy: &mut connection::FecPolicy, windows: u64| {
            for _ in 0..windows {
                sent += 8192;
                policy.observe(Some(path_sample(sent / 8, 0, sent)));
            }
        };
        lossy(&mut policy, 2);
        assert!(policy.coding(), "a lossy path engages");

        // One sample's worth of failures with a loss window between every
        // one of them. The engagement pauses for the odd unaided look
        // along the way, which is a separate mechanism; what this pins is
        // that the decode sample keeps accumulating across all of it.
        for _ in 0..connection::FEC_DECODE_SAMPLE - 1 {
            policy.note_repaired();
            lossy(&mut policy, 1);
        }
        // The engagement pauses for the odd unaided look along the way,
        // which is a separate mechanism and takes the decode verdict with
        // it while it runs. Wait for coding to be back, bounded, then
        // close a sample under it.
        for _ in 0..32 {
            if policy.coding() {
                break;
            }
            lossy(&mut policy, 1);
        }
        assert!(policy.coding(), "the lossy path is coded between looks");
        for _ in 0..connection::FEC_DECODE_SAMPLE {
            policy.note_repaired();
        }
        assert!(
            !policy.coding(),
            "the sample accumulated across the windows and was judged"
        );
        assert!(
            !policy.quiet_path(),
            "and the path itself was never the reason"
        );
    }

    #[test]
    fn a_loss_window_does_not_clear_the_decode_sample() {
        let mut policy = connection::FecPolicy::default();
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(1024, 0, 8192)));
        assert!(policy.coding(), "a lossy path engages");

        code_generations(
            &mut policy,
            connection::FEC_DECODE_SAMPLE - 1,
            connection::FEC_DECODE_SAMPLE - 1,
        );
        policy.observe(Some(path_sample(2048, 0, 16_384)));
        policy.note_repaired();

        assert!(!policy.coding(), "the full failing sample is judged");
    }

    #[test]
    fn a_retry_is_judged_on_the_path_it_retries() {
        // The reports of an epoch coded before the verdict keep arriving
        // all through the hold. They resolve into their own sample, which
        // is the previous attempt's tail and must not lengthen its hold,
        // and they must not decide the retry either.
        let mut policy = connection::FecPolicy::default();
        let mut sent = 0_u64;
        let mut lossy = |policy: &mut connection::FecPolicy, windows: u64| {
            for _ in 0..windows {
                sent += 8192;
                policy.observe(Some(path_sample(sent / 8, 0, sent)));
            }
        };
        lossy(&mut policy, 2);
        assert!(policy.coding(), "a lossy path engages");
        decode_sample(&mut policy, connection::FEC_DECODE_SAMPLE);
        assert!(!policy.coding(), "a sample that wholly failed ends coding");

        // The tail of what was already in flight, arriving with nothing
        // coding behind it. Whole samples of it: an epoch's quiet
        // retirement reports every generation still under it at once, and
        // an epoch carries about twice a sample's worth.
        for _ in 0..connection::FEC_DECODE_SAMPLE * 2 {
            policy.note_repaired();
        }
        lossy(&mut policy, 5);
        assert!(policy.coding(), "the hold is spent and the path is lossy");

        // The retried path decodes everything it is given, and that is
        // what decides it.
        decode_sample(&mut policy, 0);
        assert!(policy.coding(), "a clean retry survives its first sample");
    }

    #[test]
    fn a_retry_does_not_inherit_how_badly_the_last_one_failed() {
        // The smoothed rate is above the bar by construction whenever it
        // disengages, and it only decays a quarter a sample, so a run that
        // climbed well past the bar before failing would spend the retry's
        // first clean sample crossing it again.
        let mut policy = connection::FecPolicy::default();
        let mut sent = 0_u64;
        let mut lossy = |policy: &mut connection::FecPolicy, windows: u64| {
            for _ in 0..windows {
                sent += 8192;
                policy.observe(Some(path_sample(sent / 8, 0, sent)));
            }
        };
        lossy(&mut policy, 2);
        assert!(policy.coding(), "a lossy path engages");

        // Climb well past the bar before the verdict: two half-failing
        // samples and then a whole one.
        decode_sample(&mut policy, HALF_SAMPLE);
        decode_sample(&mut policy, HALF_SAMPLE);
        decode_sample(&mut policy, connection::FEC_DECODE_SAMPLE);
        assert!(!policy.coding(), "sustained failure ends coding");

        lossy(&mut policy, 5);
        assert!(policy.coding(), "the hold is spent and the path is lossy");
        decode_sample(&mut policy, 0);
        assert!(
            policy.coding(),
            "the retry decoded everything and is not judged on the last attempt"
        );
    }

    #[test]
    fn a_few_failures_a_sample_never_end_coding() {
        // A steady trickle inside the repair budget: the smoothed rate
        // settles under the share and stays there however long it runs.
        let mut policy = connection::FecPolicy::default();
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(1024, 0, 8192)));
        assert!(policy.coding());

        for sample in 1..=64 {
            decode_sample(&mut policy, connection::FEC_DECODE_SAMPLE / 8);
            assert!(policy.coding(), "an eighth failing at sample {sample}");
        }
    }

    #[test]
    fn decode_failures_alone_never_engage_coding() {
        // The decode verdict only ever takes coding away. A path with no
        // loss codes nothing, so it reports nothing, and a stray repair
        // must not be readable as a reason to start.
        let mut policy = connection::FecPolicy::default();
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(0, 0, 8192)));
        assert!(!policy.coding(), "a clean path codes nothing");
        code_generations(&mut policy, 256, 256);
        assert!(!policy.coding(), "and is not engaged by decode counts");
    }

    /// Closes `windows` on a path whose loss depends on whether this end
    /// is coding, which is the real shape: a bottleneck the sender is
    /// filling drops far more when redundancy is added to it. Measured on
    /// a real path, 6.5% while coding against 2.29% without.
    fn feedback_windows(
        policy: &mut connection::FecPolicy,
        st: &mut (u64, u64),
        windows: u64,
        coded_ppm: u64,
        unaided_ppm: u64,
    ) {
        for _ in 0..windows {
            let ppm = if policy.coding() {
                coded_ppm
            } else {
                unaided_ppm
            };
            st.0 += 8192;
            st.1 += 8192 * ppm / 1_000_000;
            policy.observe(Some(path_sample(st.1, 0, st.0)));
        }
    }

    /// Engages the policy the way a burst does, and returns the counters.
    fn engaged_policy() -> (connection::FecPolicy, (u64, u64)) {
        let mut policy = connection::FecPolicy::default();
        let mut st = (0_u64, 0_u64);
        for _ in 0..6 {
            st.0 += 8192;
            st.1 += 8192 * 200_000 / 1_000_000;
            policy.observe(Some(path_sample(st.1, 0, st.0)));
        }
        assert!(policy.coding(), "a lossy path engages, as it always did");
        (policy, st)
    }

    #[test]
    fn a_pause_reads_the_path_and_a_quiet_one_stops_being_coded() {
        // The case that costs 30% of a real transfer: coding itself holds
        // the measured loss above the bar, so the engagement sustains
        // itself and no reading taken while it runs can say otherwise.
        // The policy stops adding for a moment and looks.
        let (mut policy, mut st) = engaged_policy();
        for _ in 0..600 {
            feedback_windows(&mut policy, &mut st, 1, 162_500, 50_000);
            if policy.quiet_path() {
                break;
            }
        }
        assert!(
            policy.quiet_path(),
            "the look found {} of 65536 with nothing added",
            policy.unaided_loss()
        );
        assert!(!policy.coding(), "so the path is not coded");

        // And it stays that way, now on evidence that keeps arriving
        // because nothing is being added to the path.
        feedback_windows(&mut policy, &mut st, 32, 162_500, 50_000);
        assert!(!policy.coding(), "a path that does not need coding is left");
    }

    #[test]
    fn a_flapping_engagement_is_still_audited() {
        // The real path's shape, and the one the probe exists for: the
        // engagement flaps, seventy-five times over a 12 GiB transfer,
        // because each of the controller's probe cycles crosses the bar
        // and falls back. Coded windows therefore arrive in short
        // episodes, and the count toward the next look has to carry
        // across them or the look never happens on the very path it is
        // for.
        let mut policy = connection::FecPolicy::default();
        let mut st = (0_u64, 0_u64);
        let mut fired = false;
        for window in 0..600_u64 {
            // Bursts every fourth window keep the recent rate crossing
            // the bar; underneath, the path is quiet.
            let ppm = if policy.coding() {
                162_500
            } else if window % 4 == 0 {
                225_000
            } else {
                0
            };
            st.0 += 8192;
            st.1 += 8192 * ppm / 1_000_000;
            policy.observe(Some(path_sample(st.1, 0, st.0)));
            if policy.quiet_path() {
                fired = true;
                break;
            }
        }
        assert!(
            fired,
            "the look never happened on a flapping engagement (unaided {})",
            policy.unaided_loss()
        );
        assert!(!policy.coding(), "and it ended the coding");
    }

    #[test]
    fn the_looks_two_edges_are_where_they_are_said_to_be() {
        // Both edges sit at the engagement rate: a look asks whether the
        // path would engage coding on its own merits, measured with
        // nothing added. They are not offset, because a gap between them
        // would let a path engage once on a burst and then be ratified
        // forever by looks reading against a lower bar.
        let quiet_at = |ppm: u64| {
            let (mut policy, mut st) = engaged_policy();
            for _ in 0..800 {
                feedback_windows(&mut policy, &mut st, 1, 200_000, ppm);
                if policy.quiet_path() {
                    break;
                }
            }
            policy.quiet_path()
        };
        assert!(quiet_at(50_000), "five percent unaided is not a lossy path");
        assert!(
            quiet_at(75_000),
            "nor is seven and a half, under the engagement rate"
        );
        assert!(
            !quiet_at(200_000),
            "twenty percent unaided is the path's own loss"
        );

        // And the same edge from the other side: once armed, a path is
        // coded again exactly when its unaided rate reaches the bar.
        let (mut policy, mut st) = engaged_policy();
        for _ in 0..200 {
            feedback_windows(&mut policy, &mut st, 1, 162_500, 50_000);
            if policy.quiet_path() {
                break;
            }
        }
        assert!(policy.quiet_path(), "armed on a quiet path");
        feedback_windows(&mut policy, &mut st, 32, 162_500, 97_500);
        assert!(
            policy.quiet_path(),
            "just under the bar does not earn coding back ({} of 65536)",
            policy.unaided_loss()
        );
        feedback_windows(&mut policy, &mut st, 32, 162_500, 102_500);
        assert!(
            !policy.quiet_path(),
            "and just over it does ({} of 65536)",
            policy.unaided_loss()
        );
    }

    #[test]
    fn the_bar_a_look_reads_against_has_an_exact_edge() {
        assert!(connection::under_probe_bar(0));
        assert!(connection::under_probe_bar(connection::PROBE_BAR - 1));
        assert!(!connection::under_probe_bar(connection::PROBE_BAR));
        assert!(!connection::under_probe_bar(u64::MAX));
    }

    #[test]
    fn the_policys_four_rates_are_the_percentages_they_are_said_to_be() {
        // Every rate the policy reads is a fraction of RATE_ONE = 65,536,
        // so a stored rate r is 100r/65536 percent. The four are pinned
        // here as percentages, to the nearest hundredth, because the
        // percentages are what a rig measured and an expression can be
        // edited into a different number without any other test noticing
        // (ADR-0044's 2026-08-25 amendment).
        let hundredths = |units: u64| (units * 20_000 + 65_536) / (2 * 65_536);
        // The smallest rate that engages and the smallest that keeps an
        // engagement, since both are tests rather than stored constants.
        for (what, units, want) in [
            ("engage", 6554, 1000),
            ("stay engaged", 4096, 625),
            ("pause bar", connection::PROBE_BAR, 1000),
            ("seed ceiling", connection::SEED_CEILING, 2500),
        ] {
            assert_eq!(hundredths(units), want, "{what} at {units} of 65536");
        }

        // Both edges from both sides, one unit wide.
        assert!(!connection::engages(6553));
        assert!(connection::engages(6554));
        assert!(!connection::stays_engaged(4095));
        assert!(connection::stays_engaged(4096));
        assert!(connection::stays_engaged(6554), "engaging keeps coding on");

        // ADR-0042 decision 3: a first window of a genuinely lossy path
        // engages on that one sample. It is seeded at the ceiling, so the
        // ceiling has to clear the engagement rate rather than sit on it.
        // At RATE_ONE / 10 it would be 6,553 and miss by a single unit.
        assert!(
            connection::engages(connection::SEED_CEILING),
            "a seeded first window can still engage"
        );
        const {
            assert!(
                connection::SEED_CEILING > 6554,
                "and the ceiling sits well past the rate, not on it"
            );
        }
    }

    #[test]
    fn a_coded_window_is_not_evidence_about_the_path() {
        // The whole point: what the path does while this end is adding
        // redundancy to it says as much about the redundancy as the path.
        // Read the path's rate on a quiet stretch first, so there is a
        // value the coded windows could move.
        let (mut policy, mut st) = engaged_policy();
        for _ in 0..600 {
            feedback_windows(&mut policy, &mut st, 1, 162_500, 50_000);
            if policy.quiet_path() {
                break;
            }
        }
        let before = policy.unaided_loss();
        assert!(before > 0, "the quiet stretch was measured");

        // Now hand it coded windows at fifty percent, stopping short of
        // the arming that would reset the reading anyway.
        feedback_windows(&mut policy, &mut st, 24, 50_000, 500_000);
        assert!(policy.coding(), "the path turned lossy and is coded again");
        let coded_before = policy.unaided_loss();
        for _ in 0..3 {
            st.0 += 8192;
            st.1 += 8192 * 500_000 / 1_000_000;
            policy.observe(Some(path_sample(st.1, 0, st.0)));
        }
        assert_eq!(
            policy.unaided_loss(),
            coded_before,
            "fifty percent under coding moved the path's own rate"
        );
    }

    #[test]
    fn one_pause_is_one_look() {
        // The verdict lands when the pause ends, not on each window of
        // it: a look that carried on pushes the next one out once, from
        // eight coded windows to sixteen, and not six times.
        let (mut policy, mut st) = engaged_policy();
        for _ in 0..400 {
            feedback_windows(&mut policy, &mut st, 1, 200_000, 200_000);
            let (pausing, _, _, interval) = policy.probe_state();
            if pausing == 0 && interval > connection::PROBE_FIRST_INTERVAL {
                break;
            }
        }
        let (_, _, _, interval) = policy.probe_state();
        assert_eq!(
            interval,
            connection::PROBE_FIRST_INTERVAL * 2,
            "one look doubled the interval once"
        );
    }

    #[test]
    fn a_pause_on_a_lossy_path_resumes_coding() {
        // The other verdict. Here the loss is the path's own, so removing
        // coding does not remove it and the look says carry on.
        let (mut policy, mut st) = engaged_policy();
        // Well past the first look, and landing outside a pause so the
        // steady state is what is read.
        for _ in 0..600 {
            feedback_windows(&mut policy, &mut st, 1, 200_000, 200_000);
            let (pausing, _, since, _) = policy.probe_state();
            if pausing == 0 && since > 0 {
                break;
            }
        }
        assert!(!policy.quiet_path(), "the look found the path's own loss");
        assert!(policy.coding(), "and coding carried on");
    }

    #[test]
    fn repair_uses_the_paths_unaided_loss_after_a_look() {
        let (mut policy, mut st) = engaged_policy();
        for _ in 0..600 {
            feedback_windows(&mut policy, &mut st, 1, 200_000, 125_000);
            let (pausing, _, since, interval) = policy.probe_state();
            if pausing == 0 && since > 0 && interval > connection::PROBE_FIRST_INTERVAL {
                break;
            }
        }

        assert!(
            policy.coding(),
            "twelve and a half percent of path loss keeps coding on"
        );
        // The repair count cannot say which rate was read: every rate that
        // keeps coding on is past where repair saturates at the spec's 16.
        // So assert the quantity the sizing branch selects instead, which
        // is the path's own rate and not the twenty percent measured under
        // coding.
        let unaided = policy.unaided_loss();
        assert!(
            (7000..=9400).contains(&unaided),
            "the look read the path's own twelve and a half percent, got {unaided} of 65536"
        );
        assert_eq!(policy.repair_symbols(), 16, "and repair takes the ceiling");
    }

    #[test]
    fn fresh_loss_does_not_size_repair_from_old_clean_windows() {
        let mut policy = connection::FecPolicy::default();
        let mut sent = 0_u64;
        policy.observe(Some(path_sample(0, 0, sent)));
        for _ in 0..16 {
            sent += 8192;
            policy.observe(Some(path_sample(0, 0, sent)));
        }

        sent += 8192;
        policy.observe(Some(path_sample(1024, 0, sent)));

        assert!(policy.coding(), "fresh loss engages coding");
        assert_eq!(
            policy.repair_symbols(),
            16,
            "old clean windows do not dilute fresh repair, which would read three"
        );
    }

    #[test]
    fn a_probe_cannot_settle_faster_than_the_round_trip() {
        let mut policy = connection::FecPolicy::default();
        let mut sent = 0_u64;
        let mut lost = 0_u64;
        policy.observe(Some(path_sample_at_rtt(0, 0, 0, 10_000_000)));
        for _ in 0..32 {
            sent += 8192;
            lost += 1024;
            policy.observe(Some(path_sample_at_rtt(lost, 0, sent, 10_000_000)));
            if policy.probe_state().0 > 0 {
                break;
            }
        }
        let began = policy.probe_state();
        assert!(began.0 > 0, "the probe began");
        assert_eq!(began.0, 4, "only measurement windows follow the RTT");

        for _ in 0..32 {
            sent += 8192;
            lost += 1024;
            policy.observe(Some(path_sample_at_rtt(lost, 0, sent, 10_000_000)));
        }

        assert_eq!(
            policy.probe_state(),
            began,
            "packet windows inside one RTT cannot consume the pause"
        );
        assert!(!policy.coding(), "the probe stays unaided while it drains");
    }

    #[test]
    fn a_probe_without_an_rtt_skips_three_settling_windows() {
        let (mut policy, mut st) = engaged_policy();
        for _ in 0..32 {
            if policy.probe_state().0 > 0 {
                break;
            }
            feedback_windows(&mut policy, &mut st, 1, 200_000, 125_000);
        }
        assert_eq!(policy.probe_state().0, 7, "the fallback pause began");

        for _ in 0..3 {
            feedback_windows(&mut policy, &mut st, 1, 200_000, 125_000);
            assert_eq!(policy.probe_state().1, 0, "coded flight is not evidence");
        }
        feedback_windows(&mut policy, &mut st, 1, 200_000, 125_000);
        assert_eq!(policy.probe_state().1, 1, "the first clean window counts");
    }

    #[test]
    fn a_quiet_path_that_turns_lossy_is_served_again() {
        // Once it stops coding nothing is being added, so the evidence
        // arrives on its own and no pause is needed to notice a change.
        let (mut policy, mut st) = engaged_policy();
        for _ in 0..600 {
            feedback_windows(&mut policy, &mut st, 1, 162_500, 50_000);
            if policy.quiet_path() {
                break;
            }
        }
        assert!(policy.quiet_path(), "not needed, and not coded");

        feedback_windows(&mut policy, &mut st, 24, 200_000, 200_000);
        assert!(!policy.quiet_path(), "the path turned lossy and it saw");
        assert!(policy.coding(), "and it is served again");
    }

    #[test]
    fn a_freak_first_window_cannot_pin_a_clean_path_into_coding() {
        // A 50% burst in the tiny first sample seeds at the ceiling, not
        // its raw rate, so a path that is clean ever after disengages
        // within five windows instead of thirteen.
        let mut policy = connection::FecPolicy::default();
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(128, 0, 256)));
        assert!(policy.coding(), "a lossy first sample engages");
        for window in 1..=4_u64 {
            policy.observe(Some(path_sample(128, 0, 256 + window * 8192)));
            assert!(policy.coding(), "still decaying at clean window {window}");
        }
        policy.observe(Some(path_sample(128, 0, 256 + 5 * 8192)));
        assert!(
            !policy.coding(),
            "the fifth clean window crosses the off-hysteresis"
        );
    }

    #[test]
    fn a_counter_reset_clears_the_looks_state_too() {
        // A reset is a new path, and what the old one was measured to
        // need says nothing about it.
        // A carry-on look first, so the cadence has moved off its
        // starting value and the reset has something to undo.
        let (mut policy, mut st) = engaged_policy();
        for _ in 0..400 {
            feedback_windows(&mut policy, &mut st, 1, 200_000, 200_000);
            let (_, _, _, interval) = policy.probe_state();
            if interval > connection::PROBE_FIRST_INTERVAL {
                break;
            }
        }
        let (_, _, _, interval) = policy.probe_state();
        assert!(
            interval > connection::PROBE_FIRST_INTERVAL,
            "a look carried on"
        );
        for _ in 0..600 {
            feedback_windows(&mut policy, &mut st, 1, 162_500, 50_000);
            if policy.quiet_path() {
                break;
            }
        }
        assert!(policy.quiet_path(), "armed on the old path");

        policy.observe(Some(path_sample(0, 0, 0)));
        assert!(!policy.quiet_path(), "the verdict went with the counters");
        assert_eq!(
            policy.probe_state(),
            (0, 0, 0, connection::PROBE_FIRST_INTERVAL),
            "and so did the cadence and the evidence"
        );
    }

    #[test]
    fn a_path_counter_reset_starts_a_new_fec_sample() {
        let mut policy = connection::FecPolicy::default();
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(1024, 0, 4096)));
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(0, 0, 8192)));
        assert!(!policy.coding());
        assert_eq!(policy.repair_symbols(), 2);
        policy.observe(Some(path_sample(1024, 0, 16_384)));
        assert!(policy.coding());
        assert_eq!(policy.repair_symbols(), 16);
    }

    #[test]
    fn quiet_grace_follows_the_paths_round_trip() {
        for (rtt_us, expected_ms) in [
            (None, 500),
            (Some(1_000), 500),
            (Some(125_000), 500),
            (Some(200_000), 800),
            (Some(216_000), 864),
            (Some(1_000_000), 2_000),
        ] {
            assert_eq!(
                server::quiet_grace(rtt_us),
                std::time::Duration::from_millis(expected_ms),
                "at {rtt_us:?}"
            );
        }
    }

    #[test]
    fn each_service_pass_derives_the_quiet_grace_from_path_rtt() {
        let (bundle, _) = built_bundle("quiet-grace", &[("one.bin", patterned(65_536))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        session.driver().path_stats = Some(vot_transport_api::PathStats {
            smoothed_rtt_us: Some(200_000),
            ..vot_transport_api::PathStats::default()
        });
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            connection.quiet_grace,
            std::time::Duration::from_millis(800)
        );
        session.driver().path_stats = None;
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(connection.quiet_grace, server::EPOCH_QUIET_GRACE);
    }

    #[test]
    fn automatic_fec_keeps_clean_ranges_reliable_then_codes_lossy_ranges() {
        let (bundle, _) = built_bundle("automatic-fec", &[("two-groups.bin", patterned(131_072))]);
        let server = BundleServer::open(&bundle).unwrap();
        assert!(
            server.automatic_fec,
            "the public server defaults to automatic FEC"
        );
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        session.driver().path_stats = Some(path_sample(0, 0, 0));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        for (request_id, offset, lost, sent, coded) in
            [(1, 0, 0, 8192, false), (2, 65_536, 1024, 16_384, true)]
        {
            session.driver().path_stats = Some(path_sample(lost, 0, sent));
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [request_id; 16],
                    object,
                    offset,
                    length: 65_536,
                })));
            server.service(&mut session, &mut connection).unwrap();
            assert_eq!(!session.driver().datagrams.is_empty(), coded);
            assert_eq!(session.driver().records.is_empty(), coded);
            session.driver().control.clear();
            session.driver().records.clear();
            session.driver().datagrams.clear();
        }
    }

    #[test]
    fn each_service_pass_uses_its_path_sample_for_new_epochs() {
        let (bundle, _) = built_bundle("adaptive-fec", &[("two-groups.bin", patterned(131_072))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        session.driver().path_stats = Some(path_sample(0, 0, 0));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        for (request_id, offset, lost, sent, expected_repair) in
            [(1, 0, 0, 8192, 2), (2, 65_536, 246, 16_384, 9)]
        {
            session.driver().path_stats = Some(path_sample(lost, 0, sent));
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [request_id; 16],
                    object,
                    offset,
                    length: 65_536,
                })));
            server.service(&mut session, &mut connection).unwrap();
            let frames = fec_frames(&mut session);
            let TypedFrame::CodingEpochOpen(open) = &frames[1] else {
                panic!("proof then coding epoch open, got {frames:?}");
            };
            // The geometry always declares the spec's whole repair count;
            // the sample sizes what the first pass transmits, and the gap
            // is the reserve (ADR-0042).
            assert_eq!(open.geometry.repair_count(), server::FEC_REPAIR_SYMBOLS);
            assert_eq!(session.driver().datagrams.len(), 64 + expected_repair);
            assert_eq!(
                decoded_generations(&mut session, open, ample_receiver_credit()).len(),
                1
            );
        }
    }

    /// Decodes every queued symbol datagram through a receiver and returns
    /// each generation's bytes by generation.
    fn decoded_generations(
        session: &mut Session<Loopback>,
        open: &frames::CodingEpochOpen,
        credit: vot_fec::Credit,
    ) -> BTreeMap<u32, Vec<u8>> {
        let mut receiver = vot_fec::Receiver::new();
        receiver.credit(credit);
        let plan =
            vot_fec::EpochPlan::new(open.epoch, open.offset, open.length, open.geometry).unwrap();
        assert_eq!(receiver.open(plan), Ok(vot_fec::Open::Opened));
        let mut out = BTreeMap::new();
        for datagram in std::mem::take(&mut session.driver().datagrams) {
            let (header, symbol) = frames::decode_symbol(&datagram, open.geometry).unwrap();
            if let vot_fec::Symbol::Decoded(decoded) =
                receiver.symbol(header.epoch, header.generation, header.esi, symbol)
            {
                out.insert(decoded.generation, decoded.bytes);
            }
        }
        out
    }

    fn fec_frames(session: &mut Session<Loopback>) -> Vec<TypedFrame> {
        std::mem::take(&mut session.driver().control)
            .iter()
            .map(|frame| decode_control(frame))
            .collect()
    }

    #[test]
    pub(crate) fn a_negotiated_credited_session_is_answered_over_the_datagram_path() {
        let (bundle, _) = built_bundle("coded", &[("big.bin", patterned(300_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        // The whole object: 300000 bytes is five 64 KiB groups, the last short.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [7; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let [
            TypedFrame::ProofBundle(bundle_frame),
            TypedFrame::CodingEpochOpen(open),
        ] = &frames[..]
        else {
            panic!("bundle then open, got {frames:?}");
        };
        assert_eq!(
            bundle_frame.data_record_count, 5,
            "one record per generation"
        );
        assert_eq!(open.offset, bundle_frame.covered_offset);
        assert_eq!(open.length, bundle_frame.covered_length);
        assert_eq!(open.object, object);
        assert_eq!(
            open.geometry,
            vot_fec::Geometry::new(64, server::FEC_REPAIR_SYMBOLS, 1024).unwrap()
        );
        assert!(
            session.driver().records.is_empty(),
            "nothing rode the record lane"
        );
        assert_eq!(
            session.driver().datagrams.len(),
            4 * (64 + server::FEC_REPAIR_SYMBOLS)
                + (server::FEC_REPAIR_SYMBOLS + 300_000_usize.div_ceil(1024) - 4 * 64),
            "every sent source and every repair symbol, the short tail's zero sources omitted"
        );
        let first_ten: Vec<u32> = session.driver().datagrams[..10]
            .iter()
            .map(|datagram| {
                frames::decode_symbol(datagram, open.geometry)
                    .unwrap()
                    .0
                    .generation
            })
            .collect();
        assert_eq!(
            first_ten,
            vec![0, 1, 2, 3, 4, 0, 1, 2, 3, 4],
            "symbols are interleaved across generations before the next ESI"
        );
        // Decoded through a receiver, the generations are the bundle's records
        // and verify against its proof.
        let generations = decoded_generations(&mut session, open, ample_receiver_credit());
        assert_eq!(generations.len(), 5);
        let records: Vec<DataRecord> = generations
            .iter()
            .map(|(generation, bytes)| DataRecord {
                bundle_id: bundle_frame.bundle_id,
                record_index: u64::from(*generation),
                plaintext_offset: u64::from(*generation) * server::FEC_GENERATION_BYTES,
                plaintext_length: bytes.len() as u64,
                compression: 0,
                encoded: bytes.clone(),
            })
            .collect();
        let assembled = verified_bytes(object, bundle_frame, &records);
        assert_eq!(assembled, patterned(300_000));
        // Feedback: decoded generations settle; the last one closes the epoch.
        for generation in 0..5 {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                    epoch: open.epoch,
                    generation,
                    outcome: frames::GenOutcome::Decoded,
                })));
        }
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            fec_frames(&mut session),
            vec![TypedFrame::CodingEpochClose(frames::CodingEpochClose {
                epoch: open.epoch
            })]
        );
        assert!(connection.fec.epochs.is_empty());
        assert!(session.driver().records.is_empty());
    }

    #[test]
    pub(crate) fn an_abandoned_or_refused_generation_is_resent_reliably() {
        let (bundle, _) = built_bundle("resend", &[("big.bin", patterned(200_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [8; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let [
            TypedFrame::ProofBundle(bundle_frame),
            TypedFrame::CodingEpochOpen(open),
        ] = &frames[..]
        else {
            panic!("bundle then open");
        };
        assert_eq!(bundle_frame.data_record_count, 4);
        session.driver().datagrams.clear();
        // Generation 2 abandoned: its record rides the record lane, index 2,
        // absolute offset, and the epoch stays open for the rest.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                epoch: open.epoch,
                generation: 2,
                outcome: frames::GenOutcome::Abandoned,
            })));
        server.service(&mut session, &mut connection).unwrap();
        assert!(fec_frames(&mut session).is_empty(), "no close yet");
        let records = std::mem::take(&mut session.driver().records);
        assert_eq!(records.len(), 1);
        let TypedFrame::DataRecord(record) = decode_control(&records[0].1) else {
            panic!("a record");
        };
        assert_eq!(record.bundle_id, bundle_frame.bundle_id);
        assert_eq!(record.record_index, 2);
        assert_eq!(record.plaintext_offset, 2 * server::FEC_GENERATION_BYTES);
        assert_eq!(record.plaintext_length, server::FEC_GENERATION_BYTES);
        assert_eq!(
            record.encoded,
            patterned(200_000)[131_072..196_608].to_vec()
        );
        // A repeat with another outcome is the peer's fault.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                epoch: open.epoch,
                generation: 2,
                outcome: frames::GenOutcome::Decoded,
            })));
        assert_eq!(
            server.service(&mut session, &mut connection).unwrap(),
            ServeStatus::Closed(error_code::MALFORMED_FRAME)
        );

        // Refused: a second session whose open the receiver would not hold.
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [9; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let TypedFrame::CodingEpochOpen(open) = &frames[1] else {
            panic!("an open");
        };
        session.driver().datagrams.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                epoch: open.epoch,
                generation: 0,
                outcome: frames::GenOutcome::Refused,
            })));
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            fec_frames(&mut session),
            vec![TypedFrame::CodingEpochClose(frames::CodingEpochClose {
                epoch: open.epoch
            })]
        );
        let records = std::mem::take(&mut session.driver().records);
        assert_eq!(records.len(), 4, "every generation rides reliably");
        assert!(connection.fec.epochs.is_empty());
        // The identifier is spent: the next answer opens a higher epoch.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [10; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let TypedFrame::CodingEpochOpen(next) = &frames[1] else {
            panic!("an open");
        };
        assert!(next.epoch > open.epoch);
    }

    #[test]
    fn an_epoch_is_retired_only_after_it_has_gone_quiet_itself() {
        // The budget is that epoch's own silence, not the connection's. A
        // transfer is never silent, so measuring the connection never fires
        // and an epoch holding one generation that cannot decode keeps its
        // slot to the end of the run.
        let (bundle, _) = built_bundle("quiet", &[("big.bin", patterned(1_500_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        // Two requests, so two epochs with clocks of their own: one of 17
        // generations and one of 6.
        for (id, offset, length) in [
            (21, 0, server::FEC_PIECE_BYTES),
            (
                22,
                server::FEC_PIECE_BYTES,
                object.length - server::FEC_PIECE_BYTES,
            ),
        ] {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [id; 16],
                    object,
                    offset,
                    length,
                })));
        }
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(connection.fec.epochs.len(), 2, "an epoch per request");

        // The first quiet pass starts the clock rather than spending it.
        let began = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, began).is_ok());
        assert_eq!(connection.fec.epochs.len(), 2);
        assert!(
            server
                .retire_quiet_epochs(&mut connection, began + server::EPOCH_QUIET_GRACE / 2)
                .is_ok()
        );
        assert_eq!(
            connection.fec.epochs.len(),
            2,
            "inside the grace both are kept"
        );

        // A report about one epoch clears that epoch's clock and no other's,
        // which is what stops a receiver working through an epoch from ever
        // reaching the grace.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenState(frames::GenState {
                epoch: 0,
                generation: 0,
                sequence: 1,
                received: 1,
                missing_sources: vec![1, 2, 3],
            })));
        server.service(&mut session, &mut connection).unwrap();
        // The report restarts that epoch's clock, so its deadline is later
        // than the one nothing was said about. A receiver reporting each
        // generation as its first symbol lands therefore never reaches the
        // grace while it is still working.
        let reported = connection.fec.epochs[&0]
            .quiet_until
            .expect("armed by the pass that read the report");
        let silent = connection.fec.epochs[&1]
            .quiet_until
            .expect("armed by the first quiet pass");
        assert!(
            reported > silent,
            "the reported epoch's clock restarted and the silent one's did not"
        );

        // A done restarts the clock the same way. This is the reset that
        // carries an epoch through its decode tail, when the states have
        // stopped and only outcomes are still arriving.
        let before_done = connection.fec.epochs[&0].quiet_until.expect("armed above");
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                epoch: 0,
                generation: 0,
                outcome: frames::GenOutcome::Decoded,
            })));
        server.service(&mut session, &mut connection).unwrap();
        assert!(
            connection.fec.epochs[&0]
                .quiet_until
                .expect("armed by the pass that read the done")
                > before_done,
            "an outcome restarts its epoch's clock"
        );

        // Silence past the grace retires them and their generations come
        // back as reliable records: 16 left of the first piece and 6 of the
        // tail, the decoded one having settled.
        session.driver().records.clear();
        // Both deadlines are armed already, so measure against the later of
        // them: an epoch is kept right up to its deadline and goes once it
        // arrives, and neither half depends on how long the passes above
        // really took.
        let armed = connection
            .fec
            .epochs
            .values()
            .filter_map(|opened| opened.quiet_until)
            .max()
            .expect("both are armed");
        assert!(
            server
                .retire_quiet_epochs(
                    &mut connection,
                    armed
                        .checked_sub(server::EPOCH_QUIET_GRACE / 2)
                        .expect("the deadline sits a whole grace past a recent instant"),
                )
                .is_ok()
        );
        assert_eq!(
            connection.fec.epochs.len(),
            2,
            "inside the grace both are kept"
        );
        assert!(server.retire_quiet_epochs(&mut connection, armed).is_ok());
        assert!(connection.fec.epochs.is_empty(), "both are past the grace");
        connection.drain(&mut session).unwrap();
        assert_eq!(
            session.driver().records.len(),
            22,
            "every live generation of both came back reliably"
        );
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn the_first_quiet_deadline_answers_with_the_reserve_and_the_second_retires() {
        // A lossy sample sizes the transmitted repairs under the declared
        // count, so the epoch holds a reserve. The first quiet deadline
        // sends it as symbols and re-arms the clock; only the second
        // deadline retires the generations reliably (ADR-0042).
        let (bundle, _) = built_bundle("ladder", &[("big.bin", patterned(200_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        session.driver().path_stats = Some(path_sample(0, 0, 0));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        // 246 of 16384 sizes five transmitted repairs against sixteen
        // declared, leaving an eleven-symbol reserve.
        session.driver().path_stats = Some(path_sample(246, 0, 16_384));
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [41; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let opened = connection.fec.epochs.values().next().expect("an epoch");
        assert_eq!(opened.transmitted_repairs, 5);
        assert!(!opened.symbol_repaired);
        let live = opened.live.len();
        assert_eq!(live, 4, "200000 bytes are four generations");
        session.driver().datagrams.clear();
        session.driver().records.clear();

        // With no word from the receiver the rung is not taken: reserve
        // symbols cannot decode a generation the receiver may hold nothing
        // of, so silence goes straight to the reliable backstop. One
        // accepted state is the evidence that flips it.
        let idle = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, idle).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, idle + server::MAX_QUIET_GRACE)
                .is_ok()
        );
        connection.drain(&mut session).unwrap();
        assert!(
            connection.fec.epochs.is_empty(),
            "no accepted state, so the first deadline retires reliably"
        );
        assert_eq!(session.driver().records.len(), live);
        assert!(session.driver().datagrams.is_empty());
        session.driver().records.clear();

        // The same request again, now with the receiver reporting one
        // generation: the rung fires first.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [42; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let epoch = *connection.fec.epochs.keys().next().expect("reopened");
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenState(frames::GenState {
                epoch,
                generation: 0,
                sequence: 1,
                received: 1,
                missing_sources: vec![1, 2, 3],
            })));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().datagrams.clear();
        session.driver().records.clear();

        // First deadline: reserve symbols out, epoch still open, re-armed.
        let began = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, began).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, began + server::MAX_QUIET_GRACE)
                .is_ok()
        );
        connection.drain(&mut session).unwrap();
        assert_eq!(
            session.driver().datagrams.len(),
            live * (server::FEC_REPAIR_SYMBOLS - 5),
            "the reserve ESIs of every live generation"
        );
        for (at, datagram) in session.driver().datagrams.iter().enumerate() {
            let esi = datagram[8];
            assert!(
                usize::from(esi) >= 64 + 5,
                "a reserve symbol, not a repeat of the first pass: esi {esi}"
            );
            // ESI-major across the generations, like the first pass: each
            // run of `live` datagrams shares one ESI across all four.
            assert_eq!(usize::from(esi), 64 + 5 + at / live, "interleaved");
        }
        assert!(
            session.driver().records.is_empty(),
            "no reliable records yet"
        );
        let renewed = connection.fec.epochs.values().next().expect("still open");
        assert!(renewed.symbol_repaired);
        assert!(
            renewed.quiet_until.is_none(),
            "the clock re-arms from the next quiet pass"
        );
        session.driver().datagrams.clear();

        // Second deadline: the reliable backstop, exactly as before.
        let again = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, again).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, again + server::MAX_QUIET_GRACE)
                .is_ok()
        );
        connection.drain(&mut session).unwrap();
        assert!(connection.fec.epochs.is_empty(), "retired at the second");
        assert_eq!(session.driver().records.len(), live);
        assert!(session.driver().datagrams.is_empty(), "the rung was spent");

        // An epoch whose first pass transmitted the whole declared repair
        // count holds no reserve, so even an accepted state cannot make the
        // rung worth taking: the first deadline retires reliably.
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [43; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let full = connection.fec.epochs.values().next().expect("an epoch");
        assert_eq!(full.transmitted_repairs, server::FEC_REPAIR_SYMBOLS);
        let live = full.live.len();
        let epoch = *connection.fec.epochs.keys().next().expect("named");
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenState(frames::GenState {
                epoch,
                generation: 0,
                sequence: 1,
                received: 1,
                missing_sources: vec![1],
            })));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().datagrams.clear();
        session.driver().records.clear();
        let bare = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, bare).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, bare + server::MAX_QUIET_GRACE)
                .is_ok()
        );
        connection.drain(&mut session).unwrap();
        assert!(connection.fec.epochs.is_empty(), "no reserve, no rung");
        assert_eq!(session.driver().records.len(), live);
        assert!(session.driver().datagrams.is_empty());
    }

    #[test]
    fn an_epoch_is_retired_while_this_end_is_still_sending() {
        // What decides is whether this epoch's symbols have left, not
        // whether the queue behind them is empty. A transfer that keeps the
        // carrier busy never empties it, and every generation that never
        // decoded then held its bundle part-built until the fetch ran out of
        // admission.
        let (bundle, _) = built_bundle("busy", &[("big.bin", patterned(1_500_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [23; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(connection.fec.epochs.len(), 1, "one epoch per request");
        let mark = connection.fec.epochs[&0].queued_through;
        assert!(
            connection.outbound.taken() >= mark,
            "the carrier took this epoch's symbols"
        );

        // An answer of this end's own, queued behind them and still waiting.
        connection.queue_record(
            encoded(&TypedFrame::DataRecord(DataRecord {
                bundle_id: [9; 16],
                record_index: 0,
                plaintext_offset: 0,
                plaintext_length: 8,
                compression: 0,
                encoded: vec![7; 8],
            }))
            .unwrap(),
        );
        assert!(!connection.outbound.is_empty(), "still sending");

        let began = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, began).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, began + server::EPOCH_QUIET_GRACE)
                .is_ok()
        );
        assert!(
            connection.fec.epochs.is_empty(),
            "a busy queue is not the receiver's silence"
        );
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn an_epoch_is_not_retired_until_the_carrier_takes_its_symbols() {
        // The mark an epoch keeps is the position its last symbol sits at,
        // so it is what the queue had taken plus what it still holds. A
        // carrier that takes nothing leaves the epoch unretirable however
        // long the receiver stays silent.
        let (bundle, _) = built_bundle("held", &[("big.bin", patterned(1_500_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().refuse_sends = usize::MAX;
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [25; 16],
                object,
                offset: 0,
                length: server::FEC_PIECE_BYTES,
            })));
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [26; 16],
                object,
                offset: server::FEC_PIECE_BYTES,
                length: object.length - server::FEC_PIECE_BYTES,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let opened = connection.fec.epochs.len();
        assert!(opened > 0, "an epoch to hold");
        let last = *connection.fec.epochs.keys().last().expect("an epoch");
        assert!(
            connection.fec.epochs[&0].queued_through > 0
                && connection.fec.epochs[&last].queued_through
                    <= connection.outbound.taken() + connection.outbound.bytes(),
            "a mark is a real queue position"
        );
        assert!(
            connection.fec.epochs[&0].queued_through < connection.fec.epochs[&last].queued_through,
            "the epoch queued second sits behind the epoch queued first"
        );
        assert!(
            connection.outbound.taken() < connection.fec.epochs[&0].queued_through,
            "the carrier has taken none of them"
        );

        let began = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, began).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, began + server::EPOCH_QUIET_GRACE * 4)
                .is_ok()
        );
        assert_eq!(
            connection.fec.epochs.len(),
            opened,
            "silence about an epoch this end has not sent is not the receiver's"
        );

        // The carrier takes them, and the same silence now counts.
        session.driver().refuse_sends = 0;
        connection.drain(&mut session).unwrap();
        let sent = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, sent).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, sent + server::EPOCH_QUIET_GRACE)
                .is_ok()
        );
        assert!(
            connection.fec.epochs.is_empty(),
            "retired once its symbols had left"
        );
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn a_deferred_verdict_waits_for_the_receivers_word() {
        // The queue the retirement hands its verdict to. Nothing is judged
        // inside the wait, the receiver's word takes a generation out of
        // it, a repeat says nothing new, and what no word ever came for is
        // judged once when the wait is up.
        let mut fec = connection::FecSender::default();
        let now = std::time::Instant::now();
        let due = now + server::EPOCH_QUIET_GRACE;
        assert_eq!(
            fec.defer(0, due, 7, (0..4).collect()),
            0,
            "nothing is evicted"
        );
        assert_eq!(fec.overdue(0, now), 0, "inside the wait nothing is judged");
        assert!(fec.settle(0, 7, 1), "the receiver's word settles one");
        assert!(!fec.settle(0, 7, 1), "and a repeat of it settles nothing");
        assert!(!fec.settle(0, 8, 0), "an epoch nothing was deferred for");
        assert_eq!(fec.overdue(0, due), 3, "the rest are what no word came for");
        assert_eq!(fec.overdue(0, due), 0, "and they are judged once");
    }

    #[test]
    fn a_burst_of_retirements_cannot_grow_the_deferred_queue() {
        // The wait drains the queue on this connection's grace, so the cap
        // only bounds a burst of retirements inside one of them.
        let mut fec = connection::FecSender::default();
        let due = std::time::Instant::now() + server::MAX_QUIET_GRACE;
        for epoch in 0..u32::try_from(connection::MAX_DEFERRED_EPOCHS).unwrap() {
            assert_eq!(fec.defer(0, due, epoch, (0..2).collect()), 0);
        }
        assert_eq!(
            fec.defer(0, due, 99, (0..2).collect()),
            2,
            "the oldest is judged to make room"
        );
    }

    #[test]
    fn a_verdict_deferred_before_a_re_engagement_never_votes_after_it() {
        // A fresh engagement zeroes the decode sample, because it is judged
        // on its own outcomes. The deferred verdicts have to go with it: they
        // belong to the engagement that ended, because a pass sets
        // `fec_coding` from `coding()` once and opening an epoch is gated on
        // it, so nothing was coded in between, and one retired epoch's
        // unheard generations folded onto a zeroed base are a whole sample of
        // failures that meets the quarter bar on equality.
        let (bundle, _) = built_bundle("stale", &[("small.bin", patterned(1024))]);
        let server = forced_fec_server(&bundle);
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        session.driver().path_stats = Some(path_sample(0, 0, 0));
        server.service(&mut session, &mut connection).unwrap();
        assert!(!connection.fec_policy.coding(), "not engaged yet");

        // A whole sample of unheard generations, already past its wait.
        let due = std::time::Instant::now();
        let whole = u32::try_from(connection::FEC_DECODE_SAMPLE).unwrap();
        let base = connection.fec_policy.failure_base();
        assert_eq!(connection.fec.defer(base, due, 3, (0..whole).collect()), 0);

        session.driver().path_stats = Some(path_sample(1024, 0, 8192));
        server.service(&mut session, &mut connection).unwrap();
        assert!(connection.fec_policy.coding(), "the lossy sample engages");
        assert!(
            connection.fec.pending_verdicts.is_empty(),
            "the ended engagement's verdicts went with it"
        );
        assert_eq!(
            connection.fec_policy.decode_sample(),
            (0, 0),
            "so none of them voted on the fresh sample"
        );

        // Only a zeroing drops them. A verdict deferred while the
        // engagement runs belongs to it and survives the passes under it,
        // and its wait is put far past any deadline a pass could reach so
        // that the clear is the only thing under test here.
        let far = std::time::Instant::now() + std::time::Duration::from_hours(1);
        let base = connection.fec_policy.failure_base();
        assert_eq!(connection.fec.defer(base, far, 4, (0..whole).collect()), 0);
        session.driver().path_stats = Some(path_sample(2048, 0, 16_384));
        server.service(&mut session, &mut connection).unwrap();
        assert!(connection.fec_policy.coding(), "still the same engagement");
        assert_eq!(
            connection.fec.pending_verdicts.len(),
            1,
            "so its own deferred verdict still stands"
        );
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn a_verdict_deferred_before_a_counter_reset_never_votes_after_it() {
        // The other place the failure share is zeroed. A counter reset is
        // a new baseline, so what the old counters' windows smoothed into
        // the share describes a path this one no longer is; the verdicts
        // deferred to be judged against that share go with it, or one
        // retired epoch's unheard generations fill a whole sample at 100%
        // on the fresh zero and meet the quarter bar on equality.
        let mut policy = connection::FecPolicy::default();
        let mut fec = connection::FecSender::default();
        policy.observe(Some(path_sample(0, 0, 0)));
        policy.observe(Some(path_sample(3277, 0, 8192)));
        assert!(policy.coding(), "a 40% window engages");
        policy.note_repaired();
        policy.note_repaired();
        policy.note_repaired();
        assert_eq!(policy.decode_sample(), (3, 3), "a sample under way");
        let now = std::time::Instant::now();
        let base = policy.failure_base();
        assert_eq!(fec.defer(base, now, 3, (0..3).collect()), 0);

        policy.observe(Some(path_sample(0, 0, 0)));
        assert_ne!(policy.failure_base(), base, "the reset zeroed the share");
        assert_eq!(
            policy.decode_sample(),
            (0, 0),
            "and the sample that was filling it"
        );
        for _ in 0..fec.overdue(policy.failure_base(), now) {
            policy.note_repaired();
        }
        assert_eq!(
            policy.decode_sample(),
            (0, 0),
            "so nothing deferred before the reset voted after it"
        );
        assert!(fec.pending_verdicts.is_empty(), "and none of it is held");

        // One deferred after the reset belongs to the new baseline and is
        // judged the way it always was.
        let base = policy.failure_base();
        assert_eq!(fec.defer(base, now, 4, (0..3).collect()), 0);
        for _ in 0..fec.overdue(base, now) {
            policy.note_repaired();
        }
        assert_eq!(policy.decode_sample(), (3, 3), "which this one is");
    }

    #[test]
    fn a_verdict_deferred_before_a_fresh_engagement_never_votes_after_it() {
        // The same property at the other zeroing site, without a session
        // around it: the engagement that ended leaves its retirements
        // deferred, coding stops, and the next engagement zeroes the share
        // to judge its own outcomes. What the last one deferred cannot be
        // the first thing the new one reads.
        let mut policy = connection::FecPolicy::default();
        let mut fec = connection::FecSender::default();
        let mut lost = 0;
        let mut sent = 0;
        let mut window = |policy: &mut connection::FecPolicy, window_lost: u64| {
            lost += window_lost;
            sent += 8192;
            policy.observe(Some(path_sample(lost, 0, sent)));
        };
        policy.observe(Some(path_sample(0, 0, 0)));
        window(&mut policy, 3277);
        assert!(policy.coding(), "a 40% window engages");
        let mut clean = 0;
        while policy.coding() && clean < 64 {
            window(&mut policy, 0);
            clean += 1;
        }
        assert!(!policy.coding(), "and clean windows end the engagement");

        let now = std::time::Instant::now();
        let base = policy.failure_base();
        assert_eq!(fec.defer(base, now, 3, (0..3).collect()), 0);
        let mut lossy = 0;
        while !policy.coding() && lossy < 64 {
            window(&mut policy, 3277);
            lossy += 1;
        }
        assert!(policy.coding(), "the path turns lossy again");
        assert_ne!(
            policy.failure_base(),
            base,
            "the fresh engagement zeroed the share"
        );
        for _ in 0..fec.overdue(policy.failure_base(), now) {
            policy.note_repaired();
        }
        assert_eq!(
            policy.decode_sample(),
            (0, 0),
            "so nothing the last engagement deferred voted on this one"
        );

        // One deferred inside the engagement is its own outcome and votes.
        let base = policy.failure_base();
        assert_eq!(fec.defer(base, now, 4, (0..3).collect()), 0);
        for _ in 0..fec.overdue(base, now) {
            policy.note_repaired();
        }
        assert_eq!(policy.decode_sample(), (3, 3), "as it always did");
    }

    #[test]
    fn what_a_resend_says_about_coding_depends_on_why_it_happened() {
        // The table. A resend is delivery, and only two of the three ways
        // one happens are the receiver's word about decoding. A quiet
        // retirement is this end's silence budget running out: measured on
        // a 12 GiB emulated transfer at 7% loss each way, 3,964 of the
        // 4,740 generations a retirement gave up on reported `Decoded`
        // afterwards, against 392 the receiver truly could not decode.
        let (bundle, _) = built_bundle("causes", &[("big.bin", patterned(200_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        session.driver().path_stats = Some(path_sample(0, 0, 0));
        server.service(&mut session, &mut connection).unwrap();

        // The receiver's word that a generation did not decode: counted
        // where it lands, because there is nothing further to wait for.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [51; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let epoch = *connection.fec.epochs.keys().last().expect("an epoch");
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                epoch,
                generation: 0,
                outcome: frames::GenOutcome::Abandoned,
            })));
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(connection.fec_policy.decode_sample(), (1, 1));

        // And its word that the whole epoch is refused, the same way.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                epoch,
                generation: 0,
                outcome: frames::GenOutcome::Refused,
            })));
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            connection.fec_policy.decode_sample(),
            (4, 4),
            "the three still live under the refused epoch"
        );

        // A quiet retirement is not a word. The records go now and the
        // verdict waits.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [52; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let epoch = *connection.fec.epochs.keys().last().expect("an epoch");
        let live = connection.fec.epochs[&epoch].live.len();
        assert_eq!(live, 4, "200000 bytes are four generations");
        session.driver().records.clear();
        let retired = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, retired).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, retired + server::MAX_QUIET_GRACE)
                .is_ok()
        );
        connection.drain(&mut session).unwrap();
        assert!(connection.fec.epochs.is_empty(), "retired");
        assert_eq!(session.driver().records.len(), live, "and repaired now");
        assert_eq!(
            connection.fec_policy.decode_sample(),
            (4, 4),
            "the timeout judged none of them"
        );
        let wait = connection.quiet_grace;
        assert!(
            server
                .retire_quiet_epochs(
                    &mut connection,
                    retired + server::MAX_QUIET_GRACE + wait / 2
                )
                .is_ok()
        );
        assert_eq!(
            connection.fec_policy.decode_sample(),
            (4, 4),
            "and the wait runs from the retirement, not before it"
        );

        // The word the retirement did not wait for still decides, and which
        // word it is decides which way. A generation the receiver decoded is
        // not coding failing.
        // Dispatched rather than serviced: a service pass reads the wall
        // clock, and a stall past the deferral's own deadline would drain
        // the queue before these land.
        for (generation, outcome, sample) in [
            (0, frames::GenOutcome::Decoded, (5, 4)),
            (1, frames::GenOutcome::Abandoned, (6, 5)),
        ] {
            let wire = encoded(&TypedFrame::GenDone(frames::GenDone {
                epoch,
                generation,
                outcome,
            }))
            .unwrap();
            assert!(server.dispatch(&wire, &mut connection, 16).is_ok());
            assert_eq!(
                connection.fec_policy.decode_sample(),
                sample,
                "the receiver's late word about generation {generation}"
            );
        }

        // The two nothing was ever said about are the failures, once the
        // wait is up.
        assert!(
            server
                .retire_quiet_epochs(
                    &mut connection,
                    retired + server::MAX_QUIET_GRACE * 2 + wait
                )
                .is_ok()
        );
        assert_eq!(connection.fec_policy.decode_sample(), (8, 7));
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn goaway_may_narrow_but_never_increase_its_cursor() {
        let (bundle, _) = built_bundle("goaway-cursor", &[("a.bin", patterned(10))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut connection = ServeConnection::new();
        for cursor in [1, 0, 0] {
            let wire = encoded(&TypedFrame::GoAway(frames::GoAway { cursor })).unwrap();
            assert!(server.dispatch(&wire, &mut connection, 16).is_ok());
            assert_eq!(connection.goaway_cursor, Some(cursor));
        }
        let wire = encoded(&TypedFrame::GoAway(frames::GoAway { cursor: 1 })).unwrap();
        assert!(server.dispatch(&wire, &mut connection, 16).is_err());
        let mut fresh = ServeConnection::new();
        let wire = encoded(&TypedFrame::GoAway(frames::GoAway { cursor: 2 })).unwrap();
        assert!(server.dispatch(&wire, &mut fresh, 16).is_err());
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn a_final_cursor_goaway_completes_the_serve() {
        let (bundle, _) = built_bundle("goaway-complete", &[("a.bin", patterned(10))]);
        let server = BundleServer::open(&bundle).unwrap();
        assert_eq!(server.object_count(), 1);

        // A cursor short of the object count leaves the session live.
        let mut partial = ready_session();
        let mut connection = ServeConnection::new();
        partial
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GoAway(frames::GoAway {
                cursor: 0,
            })));
        let status = server.service(&mut partial, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert_eq!(connection.goaway_cursor, Some(0));

        // The final cursor is the receiver's completion acknowledgement, so
        // the session concludes.
        let mut final_session = ready_session();
        let mut connection = ServeConnection::new();
        final_session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GoAway(frames::GoAway {
                cursor: 1,
            })));
        let status = server.service(&mut final_session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Completed);
        assert_eq!(connection.goaway_cursor, Some(1));
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn goaway_cursor_answers_only_earlier_known_objects() {
        for (index, cursor, expected) in [
            (None, 1, false),
            (Some(0), 0, false),
            (Some(0), 1, true),
            (Some(1), 1, false),
            (Some(2), 1, false),
        ] {
            assert_eq!(server::range_blocked_by_cursor(index, cursor), !expected);
        }
    }

    #[test]
    fn a_reported_error_is_terminal_to_the_server() {
        let (bundle, _) = built_bundle("reported-error", &[("a.bin", patterned(10))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut connection = ServeConnection::new();
        let wire = encoded(&TypedFrame::Error(frames::ErrorFrame {
            code: error_code::ADMISSION_DENIED,
            detail: Vec::new(),
        }))
        .unwrap();
        assert!(matches!(
            server.dispatch(&wire, &mut connection, 16),
            Err(Fault::Peer(error_code::ADMISSION_DENIED))
        ));
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn an_epoch_whose_symbols_are_still_queued_is_never_retired() {
        // The other half: silence about an epoch this end has not finished
        // sending says nothing about the receiver, however long it lasts.
        let (bundle, _) = built_bundle("unsent", &[("big.bin", patterned(1_500_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [24; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        // As if the carrier had taken nothing of this epoch yet.
        let unsent = connection.outbound.taken() + 1;
        for opened in connection.fec.epochs.values_mut() {
            opened.queued_through = unsent;
            opened.quiet_until = None;
        }

        let began = std::time::Instant::now();
        assert!(server.retire_quiet_epochs(&mut connection, began).is_ok());
        assert!(
            server
                .retire_quiet_epochs(&mut connection, began + server::EPOCH_QUIET_GRACE * 4)
                .is_ok()
        );
        assert_eq!(
            connection.fec.epochs.len(),
            1,
            "symbols still queued, so the grace never starts"
        );
        assert!(
            connection
                .fec
                .epochs
                .values()
                .all(|opened| opened.quiet_until.is_none()),
            "no clock is armed for an epoch this end is still sending"
        );
        crate::harness::discard(&[&bundle]);
    }

    #[test]
    pub(crate) fn a_long_range_is_coded_in_pieces_of_at_most_seventeen_generations() {
        // 1500000 bytes is 23 generations: a piece of 17 and a piece of 6,
        // each its own bundle and proof, the request partitioned between
        // them, under one epoch spanning the whole cover (ADR-0042).
        let (bundle, _) = built_bundle("pieces", &[("big.bin", patterned(1_500_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [14; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let [
            TypedFrame::ProofBundle(first),
            TypedFrame::ProofBundle(second),
            TypedFrame::CodingEpochOpen(open),
        ] = &frames[..]
        else {
            panic!("two bundles then one open, got {frames:?}");
        };
        assert_eq!(first.data_record_count, 17);
        assert_eq!(second.data_record_count, 6);
        assert_ne!(first.bundle_id, second.bundle_id);
        assert_eq!(first.request_id, [14; 16]);
        assert_eq!(second.request_id, [14; 16]);
        assert_eq!(first.requested_offset, 0);
        assert_eq!(first.requested_length, server::FEC_PIECE_BYTES);
        assert_eq!(second.requested_offset, server::FEC_PIECE_BYTES);
        assert_eq!(second.requested_length, 1_500_000 - server::FEC_PIECE_BYTES);
        assert_eq!(first.covered_length, server::FEC_PIECE_BYTES);
        assert_eq!(second.covered_offset, server::FEC_PIECE_BYTES);
        assert_eq!(open.epoch, 0);
        assert_eq!(open.offset, 0);
        assert_eq!(open.length, 1_500_000);
        assert!(session.driver().records.is_empty());
        // Every symbol of the epoch decodes into records that verify under
        // the bundle whose covered range contains them.
        let mut receiver = vot_fec::Receiver::new();
        receiver.credit(vot_fec::Credit {
            credit_epoch: 1,
            max_unretired_bytes: 1 << 24,
            max_active_generations: 64,
            max_decode_work: 1 << 30,
            max_open_epochs: 4,
        });
        let plan =
            vot_fec::EpochPlan::new(open.epoch, open.offset, open.length, open.geometry).unwrap();
        assert_eq!(receiver.open(plan), Ok(vot_fec::Open::Opened));
        let mut decoded: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for datagram in std::mem::take(&mut session.driver().datagrams) {
            let (header, symbol) = frames::decode_symbol(&datagram, open.geometry).unwrap();
            if let vot_fec::Symbol::Decoded(done) =
                receiver.symbol(header.epoch, header.generation, header.esi, symbol)
            {
                decoded.insert(done.generation, done.bytes);
            }
        }
        assert_eq!(decoded.len(), 23);
        for (bundle_frame, first_generation) in [(first, 0_u32), (second, 17)] {
            let records: Vec<DataRecord> = decoded
                .range(first_generation..)
                .take(usize::try_from(bundle_frame.data_record_count).unwrap())
                .map(|(generation, bytes)| DataRecord {
                    bundle_id: bundle_frame.bundle_id,
                    record_index: u64::from(*generation - first_generation),
                    plaintext_offset: u64::from(*generation) * server::FEC_GENERATION_BYTES,
                    plaintext_length: bytes.len() as u64,
                    compression: 0,
                    encoded: bytes.clone(),
                })
                .collect();
            let assembled = verified_bytes(object, bundle_frame, &records);
            let start = usize::try_from(bundle_frame.covered_offset).unwrap();
            assert_eq!(
                assembled,
                patterned(1_500_000)[start..start + assembled.len()].to_vec()
            );
        }
        assert_eq!(connection.fec.epochs.len(), 1);
        // A request starting inside the first window is cut at the same
        // window boundary, so the first piece stays inside the record bound.
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [16; 16],
                object,
                offset: 65_536 + 100,
                length: object.length - 65_536 - 100,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let [
            TypedFrame::ProofBundle(first),
            TypedFrame::ProofBundle(second),
            TypedFrame::CodingEpochOpen(_),
        ] = &frames[..]
        else {
            panic!("two pieces, got {frames:?}");
        };
        assert_eq!(first.requested_offset, 65_536 + 100);
        assert_eq!(
            first.requested_length,
            server::FEC_PIECE_BYTES - 65_536 - 100
        );
        assert_eq!(first.covered_offset, 65_536);
        assert_eq!(first.data_record_count, 16);
        assert_eq!(second.requested_offset, server::FEC_PIECE_BYTES);
        assert_eq!(second.data_record_count, 6);
    }

    #[test]
    pub(crate) fn a_repeated_abandon_resends_once() {
        let (bundle, _) = built_bundle("once", &[("big.bin", patterned(200_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [15; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let TypedFrame::CodingEpochOpen(open) = &frames[1] else {
            panic!("an open");
        };
        session.driver().datagrams.clear();
        for _ in 0..3 {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                    epoch: open.epoch,
                    generation: 1,
                    outcome: frames::GenOutcome::Abandoned,
                })));
        }
        // And one for a generation this end never coded (none here: all four
        // were), so a fifth generation is past the epoch and the peer's fault.
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            session.driver().records.len(),
            1,
            "one record for three repeats"
        );
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                epoch: open.epoch,
                generation: 4,
                outcome: frames::GenOutcome::Abandoned,
            })));
        assert_eq!(
            server.service(&mut session, &mut connection).unwrap(),
            ServeStatus::Closed(error_code::MALFORMED_FRAME)
        );
    }

    #[test]
    pub(crate) fn without_credit_or_generation_room_the_answer_rides_reliably() {
        let (bundle, _) = built_bundle("plain", &[("big.bin", patterned(200_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        // Negotiated, but the peer never extended credit: the reliable answer.
        let mut session = ready_session_fec(frames::DatagramCredit {
            credit_epoch: 1,
            max_unretired_bytes: 0,
            max_active_generations: 0,
            max_decode_work: 0,
            max_open_epochs: 0,
        });
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [11; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 1);
        assert!(session.driver().datagrams.is_empty());
        assert!(connection.fec.epochs.is_empty());
        // The uncoded answer keeps the plain request-derived bundle identity.
        let request_bytes = encoded(&TypedFrame::RangeRequest(RangeRequest {
            request_id: [11; 16],
            object,
            offset: 0,
            length: object.length,
        }))
        .unwrap();
        assert_eq!(
            answers[0].0.bundle_id,
            blake3::hash(&request_bytes).as_bytes()[..16]
        );
        // One generation of credit: the first rides coded, the other three
        // reliably under the same bundle.
        let mut session = ready_session_fec(frames::DatagramCredit {
            credit_epoch: 1,
            max_unretired_bytes: 1 << 24,
            max_active_generations: 1,
            max_decode_work: 1 << 30,
            max_open_epochs: 4,
        });
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [12; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let [
            TypedFrame::ProofBundle(bundle_frame),
            TypedFrame::CodingEpochOpen(_),
        ] = &frames[..]
        else {
            panic!("bundle then open");
        };
        assert_eq!(bundle_frame.data_record_count, 4);
        assert_eq!(
            session.driver().datagrams.len(),
            64 + server::FEC_REPAIR_SYMBOLS
        );
        let indexes: Vec<u64> = session
            .driver()
            .records
            .iter()
            .map(|(_, bytes)| match decode_control(bytes) {
                TypedFrame::DataRecord(record) => record.record_index,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(indexes, vec![1, 2, 3]);
        assert_eq!(connection.fec.epochs.len(), 1);
        // GEN_STATE is taken as feedback: one for a generation past the epoch
        // is the peer's fault, one inside it is quiet.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenState(frames::GenState {
                epoch: 0,
                generation: 0,
                sequence: 1,
                received: 3,
                missing_sources: vec![0, 1],
            })));
        assert_eq!(
            server.service(&mut session, &mut connection).unwrap(),
            ServeStatus::Active
        );
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenState(frames::GenState {
                epoch: 0,
                generation: 9,
                sequence: 2,
                received: 0,
                missing_sources: vec![],
            })));
        assert_eq!(
            server.service(&mut session, &mut connection).unwrap(),
            ServeStatus::Closed(error_code::MALFORMED_FRAME)
        );
    }

    #[test]
    fn without_cover_epochs_negotiated_the_answer_rides_reliably() {
        // A peer offering only `DATAGRAM_FEC` maps an epoch to one bundle's
        // exact covered range; the cover-sized epochs this serve opens need
        // `FEC_COVER_EPOCHS`, so without it nothing is coded.
        let (bundle, _) = built_bundle("uncovered", &[("big.bin", patterned(200_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_offering(
            BTreeSet::from([vot_codec::extension_id::DATAGRAM_FEC]),
            ample_credit(),
        );
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [31; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(served_answers(&mut session).len(), 1, "one reliable bundle");
        assert!(session.driver().datagrams.is_empty());
        assert!(connection.fec.epochs.is_empty());
    }

    #[test]
    fn credit_spent_generations_ride_under_their_own_piece() {
        // One generation of credit against a two-piece cover: everything
        // past the first generation rides reliably, each record indexed
        // relative to its own piece's bundle.
        let (bundle, _) = built_bundle("spent-credit", &[("big.bin", patterned(1_500_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(frames::DatagramCredit {
            credit_epoch: 1,
            max_unretired_bytes: 1 << 24,
            max_active_generations: 1,
            max_decode_work: 1 << 30,
            max_open_epochs: 4,
        });
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [33; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let [
            TypedFrame::ProofBundle(first),
            TypedFrame::ProofBundle(second),
            TypedFrame::CodingEpochOpen(_),
        ] = &frames[..]
        else {
            panic!("two bundles then one open, got {frames:?}");
        };
        let records: Vec<DataRecord> = std::mem::take(&mut session.driver().records)
            .iter()
            .map(|(_, bytes)| match decode_control(bytes) {
                TypedFrame::DataRecord(record) => record,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(records.len(), 22, "all but the coded first generation");
        for record in &records {
            let generation = record.plaintext_offset / server::FEC_GENERATION_BYTES;
            if generation < 17 {
                assert_eq!(record.bundle_id, first.bundle_id);
                assert_eq!(record.record_index, generation);
            } else {
                assert_eq!(record.bundle_id, second.bundle_id);
                assert_eq!(record.record_index, generation - 17);
            }
        }
    }

    #[test]
    fn a_burst_of_short_states_repairs_every_generation_it_names() {
        // The receiver re-states every short generation in one flush, so
        // the states arrive back to back in a single dispatch pass. Each
        // must get its own targeted repair: the first repair queuing bytes
        // gated all its siblings out until the symbols mark was split from
        // the retire mark.
        let (bundle, _) = built_bundle("burst", &[("big.bin", patterned(300_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        session.driver().path_stats = Some(path_sample(0, 0, 0));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        // A lossy sample sizes five transmitted repairs, leaving a reserve.
        session.driver().path_stats = Some(path_sample(246, 0, 16_384));
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [51; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let epoch = *connection.fec.epochs.keys().next().expect("an epoch");
        assert!(
            connection.outbound.taken() >= connection.fec.epochs[&epoch].symbols_queued_through,
            "the loopback carrier took the first pass"
        );
        session.driver().datagrams.clear();
        // Three short generations report at once, each missing six sources,
        // one past what the five transmitted repairs could fill.
        for generation in [0_u32, 1, 3] {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::GenState(frames::GenState {
                    epoch,
                    generation,
                    sequence: 2,
                    received: 58,
                    missing_sources: vec![5, 9, 11, 13, 17, 19],
                })));
        }
        server.service(&mut session, &mut connection).unwrap();
        connection.drain(&mut session).unwrap();
        // Every named generation got the six missing sources plus the
        // eleven-symbol reserve, none was gated out by a sibling's bytes.
        let mut per_generation: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for datagram in &session.driver().datagrams {
            let generation = u32::from_be_bytes(datagram[4..8].try_into().unwrap());
            per_generation
                .entry(generation)
                .or_default()
                .push(datagram[8]);
        }
        assert_eq!(
            per_generation.keys().copied().collect::<Vec<_>>(),
            vec![0, 1, 3],
            "every sibling was answered"
        );
        for (generation, esis) in &per_generation {
            let mut expected: Vec<u8> = vec![5, 9, 11, 13, 17, 19];
            expected.extend(64 + 5..64 + 16);
            let mut got = esis.clone();
            got.sort_unstable();
            assert_eq!(
                got, expected,
                "generation {generation}: the missing sources and the reserve, exactly"
            );
        }
        // A repeat with a newer sequence repairs nothing: once each.
        session.driver().datagrams.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenState(frames::GenState {
                epoch,
                generation: 0,
                sequence: 3,
                received: 58,
                missing_sources: vec![5, 9, 11, 13, 17, 19],
            })));
        server.service(&mut session, &mut connection).unwrap();
        connection.drain(&mut session).unwrap();
        assert!(session.driver().datagrams.is_empty(), "once per generation");
    }

    #[test]
    fn a_short_state_is_answered_only_inside_its_window() {
        // The gate from all sides: under half the sources the symbols may
        // still be in flight, at or past the whole count nothing is short,
        // and a missing list the five transmitted repairs can fill needs
        // nothing, so only a generation missing past that margin is
        // answered. Each state's counts are a receiver's real shape:
        // received plus missing is the source count.
        let (bundle, _) = built_bundle("window", &[("big.bin", patterned(200_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        session.driver().path_stats = Some(path_sample(0, 0, 0));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session.driver().path_stats = Some(path_sample(246, 0, 16_384));
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [52; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let epoch = *connection.fec.epochs.keys().next().expect("an epoch");
        session.driver().datagrams.clear();
        let mut sequence = 1;
        let mut expect = |session: &mut Session<Loopback>,
                          connection: &mut ServeConnection,
                          generation: u32,
                          received: u8,
                          answered: bool| {
            sequence += 1;
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::GenState(frames::GenState {
                    epoch,
                    generation,
                    sequence,
                    received,
                    missing_sources: (0..64 - received).collect(),
                })));
            server.service(session, connection).unwrap();
            connection.drain(session).unwrap();
            let got = !session.driver().datagrams.is_empty();
            session.driver().datagrams.clear();
            assert_eq!(got, answered, "generation {generation} received {received}");
        };
        expect(&mut session, &mut connection, 0, 31, false);
        expect(&mut session, &mut connection, 0, 32, true);
        expect(&mut session, &mut connection, 1, 58, true);
        expect(&mut session, &mut connection, 2, 59, false);
        expect(&mut session, &mut connection, 3, 63, false);
        expect(&mut session, &mut connection, 3, 64, false);
    }

    #[test]
    fn a_resend_in_a_later_piece_rides_that_piece_bundle() {
        // An epoch spans two pieces; an abandoned generation of the second
        // comes back under the second bundle, indexed relative to it.
        let (bundle, _) = built_bundle("later-piece", &[("big.bin", patterned(1_500_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [32; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let [
            TypedFrame::ProofBundle(_),
            TypedFrame::ProofBundle(second),
            TypedFrame::CodingEpochOpen(open),
        ] = &frames[..]
        else {
            panic!("two bundles then one open, got {frames:?}");
        };
        session.driver().records.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::GenDone(frames::GenDone {
                epoch: open.epoch,
                generation: 18,
                outcome: frames::GenOutcome::Abandoned,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let records = std::mem::take(&mut session.driver().records);
        assert_eq!(records.len(), 1);
        let TypedFrame::DataRecord(record) = decode_control(&records[0].1) else {
            panic!("a record");
        };
        assert_eq!(record.bundle_id, second.bundle_id);
        assert_eq!(record.record_index, 1, "relative to the second piece");
        assert_eq!(record.plaintext_offset, 18 * server::FEC_GENERATION_BYTES);
        assert_eq!(record.plaintext_length, server::FEC_GENERATION_BYTES);
    }

    #[test]
    pub(crate) fn a_range_starting_on_a_later_group_is_coded_from_that_group() {
        let (bundle, _) = built_bundle("later", &[("big.bin", patterned(200_000))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        // The second and third groups only.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [13; 16],
                object,
                offset: 65_536,
                length: 131_072,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let frames = fec_frames(&mut session);
        let [
            TypedFrame::ProofBundle(bundle_frame),
            TypedFrame::CodingEpochOpen(open),
        ] = &frames[..]
        else {
            panic!("bundle then open, got {frames:?}");
        };
        assert_eq!(bundle_frame.covered_offset, 65_536);
        assert_eq!(bundle_frame.data_record_count, 2);
        assert_eq!(open.offset, 65_536);
        let generations = decoded_generations(
            &mut session,
            open,
            vot_fec::Credit {
                credit_epoch: 1,
                max_unretired_bytes: 1 << 24,
                max_active_generations: 64,
                max_decode_work: 1 << 30,
                max_open_epochs: 4,
            },
        );
        assert_eq!(generations.len(), 2);
        assert_eq!(
            generations[&0],
            patterned(200_000)[65_536..131_072].to_vec()
        );
        assert_eq!(
            generations[&1],
            patterned(200_000)[131_072..196_608].to_vec()
        );
    }

    #[test]
    pub(crate) fn an_unaligned_range_is_proved_under_its_group_cover() {
        let (bundle, _) = built_bundle("cover", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        // Mid-object: cover snaps to group boundaries.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 70_000,
                length: 50_000,
            })));
        // Tail: cover clipped to object end.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [2; 16],
                object,
                offset: 250_000,
                length: 50_000,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 2);
        let disk = fs::read(
            bundle
                .join("objects")
                .join(crate::object_name(&object.root)),
        )
        .unwrap();

        let (mid, mid_records) = &answers[0];
        assert_eq!(mid.covered_offset, 65_536);
        assert_eq!(mid.covered_length, 65_536);
        let bytes = verified_bytes(object, mid, mid_records);
        assert_eq!(bytes, disk[65_536..131_072]);

        let (tail, tail_records) = &answers[1];
        assert_eq!(tail.covered_offset, 196_608);
        assert_eq!(tail.covered_length, 300_000 - 196_608);
        let bytes = verified_bytes(object, tail, tail_records);
        assert_eq!(bytes, disk[196_608..]);
    }

    #[test]
    pub(crate) fn an_exact_duplicate_is_reanswered_and_a_conflict_ends_the_session() {
        let (bundle, _) = built_bundle("replay", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        let request = TypedFrame::RangeRequest(RangeRequest {
            request_id: [3; 16],
            object,
            offset: 0,
            length: 100_000,
        });
        session.driver().events.push_back(control_event(&request));
        session.driver().events.push_back(control_event(&request));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 2, "an exact replay is answered again");
        assert_eq!(
            answers[0].0, answers[1].0,
            "identically: the identity derives from the request"
        );

        let conflicting = TypedFrame::RangeRequest(RangeRequest {
            request_id: [3; 16],
            object,
            offset: 65_536,
            length: 100_000,
        });
        session
            .driver()
            .events
            .push_back(control_event(&conflicting));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            status,
            ServeStatus::Closed(error_code::REPLAY_REJECTED),
            "the same identifier with different content is a protocol error"
        );
        assert_eq!(session.driver().closed, Some(error_code::REPLAY_REJECTED));
        // The close is remembered without another look at the carrier.
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::REPLAY_REJECTED));
    }

    #[test]
    pub(crate) fn a_request_for_an_object_not_served_ends_the_session() {
        let (bundle, _) = built_bundle("unknown", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [4; 16],
                object: frames::ObjectId {
                    suite: 2,
                    root: [9; 32],
                    length: 100,
                },
                offset: 0,
                length: 100,
            })));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            status,
            ServeStatus::Closed(error_code::OBJECT_IDENTITY_MISMATCH)
        );

        // The right root under the wrong identity is not the same object.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [5; 16],
                object: frames::ObjectId {
                    length: object.length + 1,
                    ..object
                },
                offset: 0,
                length: 100,
            })));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            status,
            ServeStatus::Closed(error_code::OBJECT_IDENTITY_MISMATCH)
        );
    }

    #[test]
    pub(crate) fn a_manifest_request_beyond_the_seal_ends_the_session() {
        let (bundle, _) = built_bundle("pages", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [6; 16],
                    manifest_id: [0xaa; 16],
                    first_page: 0,
                    page_count: 1,
                },
            )));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::MANIFEST_INVALID));

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [7; 16],
                    manifest_id: server.manifest_id,
                    first_page: server.page_count,
                    page_count: 1,
                },
            )));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::MANIFEST_INVALID));
    }

    #[test]
    pub(crate) fn control_frames_that_are_not_requests_are_refused_or_skipped() {
        let (bundle, _) = built_bundle("frames", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();

        // Bytes that decode to nothing end the session.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&[0xff; 8])));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::MALFORMED_FRAME));

        // Trailing bytes after one whole frame are not a second frame.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        let mut wire = Vec::new();
        frames::encode(
            &TypedFrame::ManifestRequest(ManifestRequest {
                request_id: [8; 16],
                manifest_id: server.manifest_id,
                first_page: 0,
                page_count: 1,
            }),
            &mut wire,
        )
        .unwrap();
        wire.push(0);
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&wire)));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::MALFORMED_FRAME));

        // An unknown critical frame is refused under its own code.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        let mut wire = Vec::new();
        vot_codec::encode_frame(0x7fff, &[], &mut wire).unwrap();
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&wire)));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            status,
            ServeStatus::Closed(error_code::UNKNOWN_CRITICAL_FRAME)
        );

        // An unknown optional frame is skipped and the session lives on.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        let mut wire = Vec::new();
        vot_codec::encode_frame(0x7ffe, &[], &mut wire).unwrap();
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&wire)));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert!(session.driver().closed.is_none());
    }

    #[test]
    pub(crate) fn handing_an_answer_to_the_carrier_is_progress() {
        let (bundle, _) = built_bundle("slow-peer", &[("big.bin", patterned(4_300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        for identifier in 0..4u8 {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [identifier; 16],
                    object,
                    offset: 0,
                    length: 4_194_304,
                })));
        }
        session.driver().refuse_sends = usize::MAX;
        server.service(&mut session, &mut connection).unwrap();
        assert!(connection.pending_answer_bytes() >= OUTBOUND_BUDGET_BYTES);
        // No more requests to read; any progress change is handover only.
        session.driver().events.clear();
        connection.deferred.clear();

        let stalled = connection.progress();
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            connection.progress(),
            stalled,
            "a carrier that takes nothing is not progress"
        );

        let taken = |session: &mut Session<Loopback>| {
            session.driver().records.len() + session.driver().control.len()
        };
        let before = taken(&mut session);
        session.driver().refuse_sends = 0;
        server.service(&mut session, &mut connection).unwrap();
        let moved = taken(&mut session) - before;
        assert!(moved > 0, "the carrier took answers");
        assert_eq!(
            connection.progress() - stalled,
            moved as u64,
            "every answer handed over counts once"
        );
    }

    #[test]
    pub(crate) fn backpressure_holds_answers_without_blocking_carrier_states() {
        let (bundle, _) = built_bundle("budget", &[("big.bin", patterned(4_300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        for identifier in 0..4u8 {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [identifier; 16],
                    object,
                    offset: 0,
                    length: 4_194_304,
                })));
        }
        for context in 0..70 {
            session.driver().events.push_back(Event::DatagramState {
                context,
                state: vot_transport_api::DatagramSendState::Sent,
            });
        }
        // Carrier refuses all sends; the budget stops dispatching requests.
        session.driver().refuse_sends = usize::MAX;
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert!(connection.pending_answer_bytes() >= OUTBOUND_BUDGET_BYTES);
        assert_eq!(
            session.driver().events.len(),
            0,
            "carrier states behind the deferred request were drained"
        );
        assert_eq!(connection.deferred.len(), 1, "one request was deferred");

        session.driver().refuse_sends = 0;
        let mut passes = 0;
        while session.driver().events.front().is_some() || connection.has_backlog() {
            let status = server.service(&mut session, &mut connection).unwrap();
            assert_eq!(status, ServeStatus::Active);
            passes += 1;
            assert!(passes <= 8, "draining must converge");
        }
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 4, "every request was answered exactly once");
        let disk = fs::read(
            bundle
                .join("objects")
                .join(crate::object_name(&object.root)),
        )
        .unwrap();
        for (bundle_frame, records) in &answers {
            assert_eq!(
                records.len(),
                17,
                "a full-size request fills the codec's record cap"
            );
            let bytes = verified_bytes(object, bundle_frame, records);
            assert_eq!(bytes, disk[..4_194_304]);
        }
    }

    #[test]
    fn too_many_deferred_requests_close_under_the_resource_limit() {
        let (bundle, _) = built_bundle("deferred-limit", &[("a.bin", patterned(65_536))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        connection.budget = 0;
        connection.deferred.extend(std::iter::repeat_n(
            shared_payload(&[]),
            REMEMBERED_REQUESTS,
        ));
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [19; 16],
                object,
                offset: 0,
                length: object.length,
            })));

        assert_eq!(
            server.service(&mut session, &mut connection).unwrap(),
            ServeStatus::Closed(error_code::RESOURCE_LIMIT)
        );
    }

    #[test]
    fn a_deferred_request_does_not_stop_a_silent_epoch_clock() {
        let (bundle, _) = built_bundle("deferred-quiet", &[("a.bin", patterned(65_536))]);
        let server = forced_fec_server(&bundle);
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session_fec(ample_credit());
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [20; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        connection.deferred.push_back(
            encoded(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [21; 16],
                object,
                offset: 0,
                length: object.length,
            }))
            .unwrap(),
        );
        connection.budget = 0;

        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(connection.deferred.len(), 1);
        assert!(!connection.fec.epochs.is_empty());
        assert!(
            connection
                .fec
                .epochs
                .values()
                .all(|epoch| epoch.quiet_until.is_some())
        );
    }

    #[test]
    fn only_answer_requests_are_deferred() {
        let request = encoded(&TypedFrame::ManifestRequest(ManifestRequest {
            request_id: [1; 16],
            manifest_id: [2; 16],
            first_page: 0,
            page_count: 1,
        }))
        .unwrap();
        let feedback = encoded(&TypedFrame::DatagramCredit(ample_credit())).unwrap();

        assert!(server::answer_request(&request));
        assert!(!server::answer_request(&feedback));
        assert!(!server::answer_request(&[0xff]));
    }

    #[test]
    fn malformed_request_is_refused_instead_of_deferred_under_backpressure() {
        let (bundle, _) = built_bundle("malformed-deferred", &[("a.bin", patterned(1))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        connection.budget = 0;
        let mut malformed_request = Vec::new();
        vot_codec::encode_frame(
            frame_type::RANGE_REQUEST,
            &vec![0; 1024 * 1024],
            &mut malformed_request,
        )
        .unwrap();
        assert!(!server::answer_request(&malformed_request));
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&malformed_request)));

        assert_eq!(
            server.service(&mut session, &mut connection).unwrap(),
            ServeStatus::Closed(error_code::MALFORMED_FRAME)
        );
        assert!(connection.deferred.is_empty());
    }

    #[test]
    pub(crate) fn the_announcement_precedes_an_answer_arriving_in_the_same_pass() {
        let (bundle, _) = built_bundle("order", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            not_required(),
        );
        session.begin().unwrap();
        push_handshake(&mut session);
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: 1,
            })));

        let mut connection = ServeConnection::new();
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        let mut kinds = Vec::new();
        for frame in &session.driver().control {
            match frames::decode(
                frame,
                DecodeLimits {
                    max_unknown_payload: MAX_CONTROL_FRAME_PAYLOAD,
                    max_frames: 1,
                },
            ) {
                Ok((TypedFrame::PackageDescriptor(_), _)) => kinds.push("descriptor"),
                Ok((TypedFrame::Seal(_), _)) => kinds.push("seal"),
                Ok((TypedFrame::ProofBundle(_), _)) => kinds.push("bundle"),
                _ => {}
            }
        }
        assert_eq!(kinds, ["descriptor", "seal", "bundle"]);
    }

    #[test]
    pub(crate) fn a_blake3_bundle_round_trips_the_same_way() {
        let source = temporary("blake3-source");
        let bundle = temporary("blake3-bundle");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("big.bin"), patterned(300_000)).unwrap();
        build_bundle_with_suite(&source, &bundle, Suite::Blake3Bao64).unwrap();
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        assert_eq!(object.suite, 1);

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 1);
        let bytes = verified_bytes(object, &answers[0].0, &answers[0].1);
        let disk = fs::read(
            bundle
                .join("objects")
                .join(crate::object_name(&object.root)),
        )
        .unwrap();
        assert_eq!(bytes, disk);
    }

    #[test]
    pub(crate) fn open_refuses_an_object_that_is_not_what_its_name_claims() {
        let (bundle, _) = built_bundle("mutated", &[("big.bin", patterned(300_000))]);
        let objects = bundle.join("objects");
        // The object itself, not the leaves kept beside it: what this test
        // mutates is the bytes the bundle names.
        let path = fs::read_dir(&objects)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().is_some_and(|kind| kind == "obj"))
            .expect("the object");
        let original = fs::read(&path).unwrap();

        let mut flipped = original.clone();
        flipped[0] ^= 1;
        fs::write(&path, &flipped).unwrap();
        assert!(matches!(
            BundleServer::open(&bundle),
            Err(Error::RootMismatch)
        ));

        fs::write(&path, &original[..100_000]).unwrap();
        assert!(matches!(
            BundleServer::open(&bundle),
            Err(Error::SourceMutation)
        ));

        let mut extended = original.clone();
        extended.push(0);
        fs::write(&path, &extended).unwrap();
        assert!(matches!(
            BundleServer::open(&bundle),
            Err(Error::RootMismatch)
        ));

        fs::remove_file(&path).unwrap();
        assert!(matches!(BundleServer::open(&bundle), Err(Error::Io(_))));

        fs::write(&path, &original).unwrap();
        assert!(BundleServer::open(&bundle).is_ok());
    }

    #[test]
    pub(crate) fn a_page_mutated_after_open_is_not_served() {
        let (bundle, _) = built_bundle("page-mutated", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let page = bundle.join("manifest").join(format!("{0:016}.cbor", 0));
        let mut bytes = fs::read(&page).unwrap();
        bytes[0] ^= 1;
        fs::write(&page, &bytes).unwrap();

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [9; 16],
                    manifest_id: server.manifest_id,
                    first_page: 0,
                    page_count: 1,
                },
            )));
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
        // The peer is told why before the local error surfaces.
        assert_eq!(session.driver().closed, Some(error_code::SOURCE_MUTATED));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::SOURCE_MUTATED));
    }

    #[test]
    pub(crate) fn a_manifest_answer_is_paced_by_the_outbound_budget() {
        let (bundle, _) = built_bundle("paced", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        connection.budget = 1;

        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [1; 16],
                    manifest_id: server.manifest_id,
                    first_page: 0,
                    page_count: server.page_count,
                },
            )));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        let sent = std::mem::take(&mut session.driver().control);
        assert_eq!(
            sent.len(),
            2,
            "the announcement went out, the pages are still owed"
        );
        assert!(connection.has_backlog(), "the cursor holds the answer");

        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        let sent = std::mem::take(&mut session.driver().control);
        assert_eq!(sent.len(), 1, "one page per pass under a one-byte budget");
        let TypedFrame::ManifestPage(bytes) = decode_control(&sent[0]) else {
            panic!("the owed page arrived");
        };
        assert_eq!(
            bytes,
            fs::read(bundle.join(format!("manifest/{:016}.cbor", 0))).unwrap()
        );
        assert!(!connection.has_backlog(), "nothing further is owed");

        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert!(session.driver().control.is_empty(), "and nothing repeats");
    }

    #[test]
    pub(crate) fn answers_the_peer_cannot_carry_close_the_session() {
        let (bundle, _) = built_bundle("narrow", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        // Peer's record limit too small for this server's answers.
        let mut session = ready_session_with(Settings {
            max_data_record_payload: 64 * 1024,
            ..Settings::default()
        });
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::FRAME_TOO_LARGE));
        assert_eq!(session.driver().closed, Some(error_code::FRAME_TOO_LARGE));
        assert!(
            !connection.has_backlog(),
            "nothing stays owed after a close"
        );
    }

    #[test]
    pub(crate) fn a_send_failure_that_is_not_backpressure_surfaces() {
        let (bundle, _) = built_bundle("failing", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();

        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: 100,
            })));
        session.driver().fail_sends_with = Some(vot_transport_api::Error::Backend);
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::Session(_))));
    }

    #[test]
    pub(crate) fn the_replay_window_evicts_the_oldest_request() {
        let (bundle, _) = built_bundle("window", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        // One more distinct request than the window holds.
        for identifier in 0..=u8::try_from(REMEMBERED_REQUESTS).unwrap() {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [identifier; 16],
                    object,
                    offset: 0,
                    length: 1,
                })));
        }
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert_eq!(served_answers(&mut session).len(), REMEMBERED_REQUESTS + 1);

        // The first identifier was evicted, so different content under it is
        // a new request rather than a conflict.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [0; 16],
                object,
                offset: 0,
                length: 2,
            })));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert_eq!(served_answers(&mut session).len(), 1);
        assert!(session.driver().closed.is_none());
    }

    #[test]
    pub(crate) fn a_conflict_on_an_older_remembered_request_is_still_caught() {
        let (bundle, _) = built_bundle("older", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        // Two distinct requests, then a conflict on the older one: the
        // window has to hold more than the newest entry to catch it.
        for (identifier, length) in [([1; 16], 1u64), ([2; 16], 1), ([1; 16], 2)] {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: identifier,
                    object,
                    offset: 0,
                    length,
                })));
        }
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::REPLAY_REJECTED));
        assert!(!connection.has_backlog(), "a close forgets what was owed");
    }

    #[test]
    pub(crate) fn entries_sharing_one_stored_object_are_served_from_one_layer() {
        // Identical files name the same direct object; open has to read that
        // as one served object, not a conflict.
        let (bundle, _) = built_bundle(
            "shared",
            &[
                ("a.bin", patterned(300_000)),
                ("copy.bin", patterned(300_000)),
            ],
        );
        let server = BundleServer::open(&bundle).unwrap();
        let objects: Vec<frames::ObjectId> = server
            .objects
            .values()
            .map(|served| served.object)
            .collect();
        let direct: Vec<&frames::ObjectId> = objects
            .iter()
            .filter(|object| object.length == 300_000)
            .collect();
        assert_eq!(direct.len(), 1, "two identical entries, one stored object");

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object: *direct[0],
                offset: 0,
                length: direct[0].length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 1);
        let bytes = verified_bytes(*direct[0], &answers[0].0, &answers[0].1);
        assert_eq!(bytes, patterned(300_000));
    }

    #[test]
    pub(crate) fn a_spilled_manifest_is_served_page_by_page_in_order() {
        // One entry past the per-page cap spills the manifest to two pages.
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
        let (bundle, _) = built_bundle("spilled", &named);
        let server = BundleServer::open(&bundle).unwrap();
        assert_eq!(server.page_count, 2, "the manifest spilled");

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        connection.budget = 1;
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [1; 16],
                    manifest_id: server.manifest_id,
                    first_page: 0,
                    page_count: 2,
                },
            )));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        assert!(connection.has_backlog(), "both pages are still owed");

        // One page per pass under a one-byte budget, in index order.
        for index in 0..2u64 {
            server.service(&mut session, &mut connection).unwrap();
            let sent = std::mem::take(&mut session.driver().control);
            assert_eq!(sent.len(), 1, "page {index} arrives alone");
            let TypedFrame::ManifestPage(bytes) = decode_control(&sent[0]) else {
                panic!("a page answer that is not a page");
            };
            assert_eq!(
                bytes,
                fs::read(bundle.join(format!("manifest/{index:016}.cbor"))).unwrap()
            );
        }
        assert!(!connection.has_backlog(), "nothing further is owed");
        server.service(&mut session, &mut connection).unwrap();
        assert!(session.driver().control.is_empty(), "and nothing repeats");
    }

    #[test]
    pub(crate) fn a_disconnect_ends_the_pass() {
        let (bundle, _) = built_bundle("gone", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(Event::Disconnected(vot_transport_api::ConnectionId(9)));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Disconnected);
    }

    #[test]
    pub(crate) fn a_peer_fault_in_the_session_is_recorded_with_its_code() {
        let (bundle, _) = built_bundle("fault", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        // Garbage before readiness; the session closes.
        let mut session = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            not_required(),
        );
        session.begin().unwrap();
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&[0xff; 8])));
        let mut connection = ServeConnection::new();
        let status = server.service(&mut session, &mut connection).unwrap();
        let carrier_code = session.driver().closed.expect("the session closed");
        assert_eq!(status, ServeStatus::Closed(carrier_code));
        assert_eq!(carrier_code, error_code::MALFORMED_FRAME);
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(carrier_code));
    }

    #[test]
    pub(crate) fn an_object_truncated_after_open_is_reported_and_closed() {
        let (bundle, _) = built_bundle("shrunk", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let path = bundle
            .join("objects")
            .join(crate::object_name(&object.root));
        let original = fs::read(&path).unwrap();
        fs::write(&path, &original[..100]).unwrap();

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
        assert_eq!(session.driver().closed, Some(error_code::SOURCE_MUTATED));
    }

    /// Writes a test may make before a file's modification time reports one.
    const REWRITE_ATTEMPTS: usize = 1024;

    #[test]
    pub(crate) fn an_untouched_file_is_served_without_rehashing_it() {
        // The witness stands in for hashing; an empty layer still serves.
        let (bundle, _) = built_bundle("untouched", &[("big.bin", patterned(150_000))]);
        let mut server = BundleServer::open(&bundle).unwrap();
        let stored = server.objects.values_mut().next().unwrap();
        assert!(
            stored
                .witness
                .reports_untouched(&Witness::of(&File::open(&stored.path).unwrap()).unwrap()),
            "nothing has touched the file"
        );
        stored.layer = ObjectBuilder::new(Suite::Blake3Bao64, Some(0))
            .unwrap()
            .finish()
            .unwrap();

        let bytes = server
            .objects
            .values()
            .next()
            .unwrap()
            .read_covered(0, GROUP_SIZE as u64)
            .unwrap();
        assert_eq!(bytes.len(), GROUP_SIZE);

        // And once the metadata cannot vouch for it, the content decides.
        let stored = server.objects.values_mut().next().unwrap();
        stored.witness.modified = None;
        let outcome = server
            .objects
            .values()
            .next()
            .unwrap()
            .read_covered(0, GROUP_SIZE as u64);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
    }

    #[test]
    fn a_cache_prepared_read_hashes_a_group_once_and_remembers_it() {
        // Stored rather than packed, so `send` keeps leaves beside it and
        // the serve prepares from them without reading the object.
        let (bundle, _) = built_bundle(
            "groupset",
            &[("big.bin", patterned(vot_pack::CANDIDATE_MAX + 1))],
        );
        let mut server = BundleServer::open(&bundle).unwrap();
        let stored = server.objects.values_mut().next().unwrap();
        assert!(stored.verified.is_some(), "the leaves prepared it");

        // A layer holding nothing stands in for bytes that do not match.
        let refusing = || {
            ObjectBuilder::new(Suite::Blake3Bao64, Some(0))
                .unwrap()
                .finish()
                .unwrap()
        };

        // Nothing has read the bytes yet, so the first read hashes them.
        let honest = std::mem::replace(&mut stored.layer, refusing());
        let outcome = stored.read_covered(0, GROUP_SIZE as u64);
        assert!(matches!(outcome, Err(Error::SourceMutation)));

        // Read once against the layer it was prepared with, and that group
        // is served again without consulting the layer at all.
        stored.layer = honest;
        stored
            .read_covered(0, GROUP_SIZE as u64)
            .expect("the first group");
        let honest = std::mem::replace(&mut stored.layer, refusing());
        stored
            .read_covered(0, GROUP_SIZE as u64)
            .expect("the group it already checked");

        // A group nothing has read is still hashed, so the same layer stops
        // it. The set remembers what was served, not the whole object.
        let outcome = stored.read_covered(GROUP_SIZE as u64, GROUP_SIZE as u64);
        assert!(matches!(outcome, Err(Error::SourceMutation)));

        // And once the file is touched, a remembered group is hashed again.
        stored.layer = honest;
        stored
            .read_covered(GROUP_SIZE as u64, GROUP_SIZE as u64)
            .expect("the second group");
        stored.witness.modified = None;
        stored.layer = refusing();
        let outcome = stored.read_covered(0, GROUP_SIZE as u64);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
    }

    #[test]
    fn a_prepared_read_verifies_groups_split_across_destination_parts() {
        let source = patterned(vot_pack::CANDIDATE_MAX + 1);
        let (bundle, _) = built_bundle("split-read", &[("big.bin", source.clone())]);
        let server = BundleServer::open(&bundle).unwrap();
        let stored = server.objects.values().next().unwrap();
        assert!(stored.verified.is_some(), "the leaves prepared it");

        let mut first = vec![0; GROUP_SIZE - 1];
        let mut second = vec![0; GROUP_SIZE + 1];
        stored
            .read_covered_into(0, &mut [first.as_mut_slice(), second.as_mut_slice()])
            .unwrap();
        first.extend_from_slice(&second);
        assert_eq!(first, source[..GROUP_SIZE * 2]);

        assert!(!stored.holds_parts(0, 0, &[]));
    }

    #[test]
    pub(crate) fn an_object_removed_after_open_is_reported_and_closed() {
        // An object removed between open and the request.
        let (bundle, _) = built_bundle("removed", &[("big.bin", patterned(150_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        fs::remove_file(
            bundle
                .join("objects")
                .join(crate::object_name(&object.root)),
        )
        .unwrap();

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
        assert_eq!(session.driver().closed, Some(error_code::SOURCE_MUTATED));
    }

    #[test]
    pub(crate) fn a_witness_reports_a_file_that_changed() {
        let directory = temporary("witness");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("f.bin");
        fs::write(&path, patterned(1000)).unwrap();
        let file = File::open(&path).unwrap();
        let taken = Witness::of(&file).unwrap();
        assert!(taken.reports_untouched(&Witness::of(&file).unwrap()));

        fs::write(&path, patterned(2000)).unwrap();
        let after = Witness::of(&File::open(&path).unwrap()).unwrap();
        assert_ne!(taken, after);
        assert!(!taken.reports_untouched(&after));

        // No modification time means the witness proves nothing.
        let silent = Witness {
            length: taken.length,
            modified: None,
        };
        assert!(!silent.reports_untouched(&silent));
    }

    #[test]
    pub(crate) fn an_object_rewritten_in_place_after_open_is_reported_and_closed() {
        // Length-preserving rewrite; change in the second group.
        let (bundle, _) = built_bundle("rewritten", &[("big.bin", patterned(150_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let path = bundle
            .join("objects")
            .join(crate::object_name(&object.root));
        let mut rewritten = fs::read(&path).unwrap();
        rewritten[100_000] ^= 1;
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        // Retry writes until the modification time moves; a write may land
        // in the same tick.
        let mut reported = false;
        for _ in 0..REWRITE_ATTEMPTS {
            fs::write(&path, &rewritten).unwrap();
            if fs::metadata(&path).unwrap().modified().unwrap() != before {
                reported = true;
                break;
            }
        }
        assert!(reported, "the modification time never moved");
        assert_eq!(fs::metadata(&path).unwrap().len(), object.length);

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
        assert_eq!(session.driver().closed, Some(error_code::SOURCE_MUTATED));
        assert!(
            session.driver().records.is_empty(),
            "no byte of the rewritten object was served"
        );
    }

    #[test]
    pub(crate) fn a_cover_is_held_to_the_groups_it_starts_at() {
        // Indexed by the cover's own offset, not zero-based.
        let (bundle, _) = built_bundle("indexed", &[("big.bin", patterned(200_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let stored = server.objects.values().next().unwrap();
        let bytes = fs::read(
            bundle
                .join("objects")
                .join(crate::object_name(&stored.object.root)),
        )
        .unwrap();
        let group = GROUP_SIZE as u64;

        assert!(stored.layer.holds(0, &bytes[..GROUP_SIZE]));
        assert!(
            stored
                .layer
                .holds(group, &bytes[GROUP_SIZE..2 * GROUP_SIZE])
        );
        assert!(stored.layer.holds(2 * group, &bytes[2 * GROUP_SIZE..]));
        assert!(stored.layer.holds(0, &bytes));
        // The second group's bytes, offered as the first, are not it.
        assert!(!stored.layer.holds(0, &bytes[GROUP_SIZE..2 * GROUP_SIZE]));
        // A cover that does not start on a group boundary names no group.
        assert!(!stored.layer.holds(1, &bytes[..GROUP_SIZE]));
    }
}
