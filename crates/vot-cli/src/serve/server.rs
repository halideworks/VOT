//! The bundle server and its service loop.

use super::{
    BTreeMap, DataRecord, DecodeLimits, Error, Event, Fault, MANIFEST_DIRECTORY, MANIFEST_SEAL,
    MAX_CONTROL_FRAME_PAYLOAD, ManifestReader, ManifestRequest, OpenedEpoch, PackageDescriptor,
    PackageSummary, Path, PathBuf, Payload, ProofBundle, RECORD_PLAINTEXT_BYTES, RangeRequest,
    ServeConnection, ServeStatus, ServedObject, Session, Storage, Suite, TransportAdapter,
    TypedFrame, encoded, error_code, fail, frame_type, frames,
};

/// One bundle, opened and proved once, answering any number of sessions.
pub struct BundleServer {
    pub(crate) package: PackageSummary,
    pub(crate) manifest_id: [u8; 16],
    pub(crate) page_count: u64,
    /// Page digest by index, to check pages read later against the seal.
    pub(crate) page_digests: Vec<[u8; 32]>,
    pub(crate) manifest_directory: PathBuf,
    /// The descriptor and seal frames, encoded once, announced at readiness.
    pub(crate) announcement: [Payload; 2],
    pub(crate) objects: BTreeMap<[u8; 32], ServedObject>,
    /// Whether new range answers wait for measured loss before using FEC.
    pub(crate) automatic_fec: bool,
}

struct CodedGeneration<'a> {
    generation: u32,
    source: std::borrow::Cow<'a, [u8]>,
    repair: Vec<Vec<u8>>,
}

impl BundleServer {
    /// Opens a bundle for serving: the chain walk `receive_bundle` trusts,
    /// then a proving layer per stored object, built once.
    pub fn open(bundle: &Path) -> Result<Self, Error> {
        let package = crate::scan_manifest(bundle)?;
        let manifest_directory = bundle.join(MANIFEST_DIRECTORY);
        // Bounded by the SEAL frame limit: a larger seal could never be announced.
        let seal_limit = vot_codec::registered_payload_limit(vot_codec::frame_type::SEAL)
            .unwrap_or(vot_manifest::MAX_PAGE_BYTES);
        let seal_bytes =
            crate::read_bounded_file(&manifest_directory.join(MANIFEST_SEAL), seal_limit)?;
        let seal = vot_manifest::decode_seal(&seal_bytes).map_err(|_| Error::InvalidBundle)?;
        let page_digests = crate::seal_page_digests(&seal)?;

        // Map manifest entries to their stored objects.
        let mut reader = ManifestReader::open(bundle)?;
        let mut wanted: BTreeMap<[u8; 32], (Suite, u64)> = BTreeMap::new();
        while let Some(record) = reader.next_record()? {
            let (root, length) = match record.storage {
                Storage::Direct => (record.logical_root, record.logical_length),
                Storage::Pack { root, length, .. } => (root, length),
            };
            match wanted.entry(root) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((record.suite, length));
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if *entry.get() != (record.suite, length) {
                        return Err(Error::InvalidBundle);
                    }
                }
            }
        }
        let objects_directory = bundle.join("objects");
        let mut objects = BTreeMap::new();
        for (root, (suite, length)) in wanted {
            objects.insert(
                root,
                ServedObject::build(&objects_directory, root, suite, length)?,
            );
        }

        let descriptor = TypedFrame::PackageDescriptor(PackageDescriptor {
            package: frames::ObjectId {
                suite: seal.package.suite,
                root: seal.package.root,
                length: seal.package.length,
            },
            manifest_id: seal.manifest_id,
            page_count: seal.final_page_count,
        });
        let announcement = [
            encoded(&descriptor)?,
            encoded(&TypedFrame::Seal(seal_bytes))?,
        ];
        Ok(Self {
            package,
            manifest_id: seal.manifest_id,
            page_count: seal.final_page_count,
            page_digests,
            manifest_directory,
            announcement,
            objects,
            automatic_fec: true,
        })
    }

    /// The package this server answers for.
    #[must_use]
    pub const fn package(&self) -> PackageSummary {
        self.package
    }

    /// One non-blocking pass: drains queued answers, reads events up to the
    /// outbound budget, and answers every request.
    pub fn service<A: TransportAdapter>(
        &self,
        session: &mut Session<A>,
        connection: &mut ServeConnection,
    ) -> Result<ServeStatus, Error> {
        if let Some(code) = connection.closed {
            return Ok(ServeStatus::Closed(code));
        }
        connection.drain(session)?;
        let path = session.adapter().path_stats();
        connection.fec_policy.observe(path);
        let repair_symbols = connection.fec_policy.repair_symbols();
        connection.fec_coding = !self.automatic_fec || connection.fec_policy.coding();
        loop {
            if let Some(code) = connection.closed {
                return Ok(ServeStatus::Closed(code));
            }
            if let Err(fault) = self.pump_manifest(connection) {
                return fail(fault, session, connection);
            }
            connection.fec_negotiated =
                session.extension_negotiated(vot_codec::extension_id::DATAGRAM_FEC);
            let over_budget = connection.outbound.bytes() >= connection.budget;
            let polled = if over_budget || connection.deferred.is_empty() {
                session.poll()
            } else {
                Ok(connection.deferred.pop_front().map(Event::Control))
            };
            match polled {
                Ok(Some(Event::Control(bytes))) => {
                    if let (true, true) = (over_budget, answer_request(&bytes)) {
                        if connection.deferred.len() == super::connection::REMEMBERED_REQUESTS {
                            return fail(
                                Fault::Peer(error_code::RESOURCE_LIMIT),
                                session,
                                connection,
                            );
                        }
                        connection.deferred.push_back(bytes);
                        continue;
                    }
                    // Announce before the first answer.
                    self.ensure_announced(connection, session.is_ready());
                    if let Err(fault) = self.dispatch(&bytes, connection, repair_symbols) {
                        return fail(fault, session, connection);
                    }
                }
                Ok(Some(Event::Disconnected(_))) => return Ok(ServeStatus::Disconnected),
                Ok(Some(_)) => {}
                Ok(None) => {
                    self.ensure_announced(connection, session.is_ready());
                    break;
                }
                Err(error) => {
                    if error.kind().is_peer_fault() {
                        // The session already closed; record the code.
                        let code = error.close_code();
                        connection.closed = Some(code);
                        return Ok(ServeStatus::Closed(code));
                    }
                    return Err(error.into());
                }
            }
        }
        connection.drain(session)?;
        if let Some(code) = connection.closed {
            return Ok(ServeStatus::Closed(code));
        }
        if let Err(fault) = self.retire_quiet_epochs(connection, std::time::Instant::now()) {
            return fail(fault, session, connection);
        }
        connection.drain(session)?;
        if let Some(code) = connection.closed {
            return Ok(ServeStatus::Closed(code));
        }
        session.flush()?;
        Ok(ServeStatus::Active)
    }

    /// Ends an epoch the receiver has stopped answering for.
    ///
    /// A symbol is a datagram, so one can be dropped anywhere between the two
    /// ends, and a generation short of its source count decodes never and
    /// reports nothing: the receiver owes a `GEN_DONE` only for a generation
    /// it decoded or gave up on. Waiting for that outcome forever is what
    /// leaves the fetch with a record that never comes, so an epoch whose
    /// symbols are all on the carrier and which has drawn nothing from the
    /// receiver for [`EPOCH_QUIET_GRACE`] is repaired reliably and closed,
    /// which is what `spec/fec.md` section 11 already says a close means:
    /// every generation under it with no `GEN_DONE` retires as abandoned.
    ///
    /// The instant to measure against is the caller's, so a test spends the
    /// grace without waiting for it. The service loop drains carrier feedback
    /// before calling this even while answer requests are deferred.
    ///
    /// The budget is per epoch and is reset by anything the receiver says
    /// about that epoch: a `GEN_STATE`, which it sends as each generation's
    /// first symbol lands, or a `GEN_DONE`. So it measures one epoch's own
    /// progress rather than the connection's silence.
    ///
    /// Measuring silence instead does not work in either direction. Counting
    /// every pass retires epochs whose outcomes are still in flight, because
    /// the carrier's wait returns the moment anything is queued and a budget
    /// of passes is microseconds on a busy connection. Requiring the whole
    /// outbound queue to be empty never fires during a transfer that fills a
    /// path: measured over a 4 GB coded fetch across a 216 ms path at 1%
    /// loss, no epoch was ever retired, the generations that never decoded
    /// held their bundles part-built, and the fetch died of
    /// `PendingBundlesExhausted` with a third of the object still to place.
    ///
    /// So the wait is per epoch and it is a queue position, not an empty
    /// queue: an epoch's symbols are all queued in one pass, and once the
    /// carrier has taken that many bytes this end has handed all of them
    /// over. After that, silence about the epoch is the receiver's silence,
    /// whatever else this connection is sending.
    pub(crate) fn retire_quiet_epochs(
        &self,
        connection: &mut ServeConnection,
        now: std::time::Instant,
    ) -> Result<(), Fault> {
        if connection.fec.epochs.is_empty() {
            return Ok(());
        }
        let taken = connection.outbound.taken();
        let mut spent = Vec::new();
        for (epoch, opened) in &mut connection.fec.epochs {
            if taken < opened.queued_through {
                // Symbols still waiting in this end's own queue, so silence
                // about the epoch says nothing about the receiver yet.
                continue;
            }
            let since = *opened.quiet_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= EPOCH_QUIET_GRACE {
                spent.push(*epoch);
            }
        }
        for epoch in spent {
            // The budget bounds this the way it bounds the request loop: a
            // retirement queues a whole epoch of records, and every open
            // epoch at once would put megabytes past it in a single pass.
            if connection.outbound.bytes() >= connection.budget {
                break;
            }
            let opened = connection
                .fec
                .epochs
                .remove(&epoch)
                .expect("named by the pass above");
            for generation in &opened.live {
                self.resend_generation(&opened, *generation, connection)?;
            }
            connection.fec.sender.close(epoch);
            connection.queue_control(encoded(&TypedFrame::CodingEpochClose(
                frames::CodingEpochClose { epoch },
            ))?);
        }
        Ok(())
    }

    pub(crate) fn ensure_announced(&self, connection: &mut ServeConnection, ready: bool) {
        if connection.announced || !ready {
            return;
        }
        for frame in &self.announcement {
            connection.queue_control(frame.clone());
        }
        connection.announced = true;
    }

    /// Answers one control frame, or ignores one that is not a request.
    pub(crate) fn dispatch(
        &self,
        bytes: &[u8],
        connection: &mut ServeConnection,
        repair_symbols: usize,
    ) -> Result<(), Fault> {
        let limits = DecodeLimits {
            max_unknown_payload: MAX_CONTROL_FRAME_PAYLOAD,
            max_frames: 1,
        };
        let (frame, consumed) = match frames::decode(bytes, limits) {
            Ok(decoded) => decoded,
            // An unknown optional frame is skipped, per `spec/wire.md`.
            Err(frames::Error::WrongFrameType(_)) => return Ok(()),
            Err(frames::Error::Envelope(error)) => {
                return Err(Fault::Peer(error.protocol_code()));
            }
            Err(_) => return Err(Fault::Peer(error_code::MALFORMED_FRAME)),
        };
        if consumed != bytes.len() {
            // One event carries one frame; trailing bytes are a protocol error.
            return Err(Fault::Peer(error_code::MALFORMED_FRAME));
        }
        match frame {
            TypedFrame::ManifestRequest(request) => {
                connection.admit_request(
                    frame_type::MANIFEST_REQUEST,
                    request.request_id,
                    bytes,
                )?;
                self.answer_manifest(&request, connection)
            }
            TypedFrame::RangeRequest(request) => {
                connection.admit_request(frame_type::RANGE_REQUEST, request.request_id, bytes)?;
                self.answer_range(&request, bytes, connection, repair_symbols)
            }
            // The receiver's side of datagram FEC (spec/fec.md section 11).
            TypedFrame::DatagramCredit(credit) => {
                connection.fec.sender.credit(vot_fec::Credit {
                    credit_epoch: credit.credit_epoch,
                    max_unretired_bytes: credit.max_unretired_bytes,
                    max_active_generations: credit.max_active_generations,
                    max_decode_work: credit.max_decode_work,
                    max_open_epochs: credit.max_open_epochs,
                });
                Ok(())
            }
            TypedFrame::GenState(state) => {
                // The receiver is working on this epoch, which is what the
                // close budget measures the absence of.
                if let Some(opened) = connection.fec.epochs.get_mut(&state.epoch) {
                    opened.quiet_since = None;
                }
                connection
                    .fec
                    .sender
                    .state(
                        state.epoch,
                        state.generation,
                        vot_fec::State {
                            sequence: state.sequence,
                            received: state.received,
                            missing_sources: &state.missing_sources,
                        },
                    )
                    .map_err(|_| Fault::Peer(error_code::MALFORMED_FRAME))?;
                Ok(())
            }
            TypedFrame::GenDone(done) => self.generation_done(&done, connection),
            // A well-formed frame this engine does not answer yet.
            _ => Ok(()),
        }
    }

    /// `GEN_DONE` from the receiver: a decoded generation is settled, an
    /// abandoned one is re-sent as a reliable record of the same bundle, a
    /// refused epoch is closed and every generation of it re-sent, and an
    /// epoch with nothing live left is closed.
    fn generation_done(
        &self,
        done: &frames::GenDone,
        connection: &mut ServeConnection,
    ) -> Result<(), Fault> {
        let Some(opened) = connection.fec.epochs.get(&done.epoch).cloned() else {
            // An epoch this end does not have open: ignored (section 12).
            return Ok(());
        };
        match done.outcome {
            frames::GenOutcome::Refused => {
                connection.fec.sender.refused(done.epoch);
                connection.fec.epochs.remove(&done.epoch);
                for generation in &opened.live {
                    self.resend_generation(&opened, *generation, connection)?;
                }
                connection.queue_control(encoded(&TypedFrame::CodingEpochClose(
                    frames::CodingEpochClose { epoch: done.epoch },
                ))?);
                Ok(())
            }
            outcome => {
                let verdict = match outcome {
                    frames::GenOutcome::Decoded => vot_fec::Done::Decoded,
                    _ => vot_fec::Done::Abandoned,
                };
                let first = connection
                    .fec
                    .sender
                    .done(done.epoch, done.generation, verdict)
                    .map_err(|_| Fault::Peer(error_code::MALFORMED_FRAME))?;
                // A repeat is idempotent (spec/fec.md section 11): the record
                // went out on the first.
                if first && verdict == vot_fec::Done::Abandoned {
                    self.resend_generation(&opened, done.generation, connection)?;
                }
                let epoch = connection
                    .fec
                    .epochs
                    .get_mut(&done.epoch)
                    .expect("cloned above");
                epoch.quiet_since = None;
                epoch.live.remove(&done.generation);
                if epoch.live.is_empty() {
                    connection.fec.sender.close(done.epoch);
                    connection.fec.epochs.remove(&done.epoch);
                    connection.queue_control(encoded(&TypedFrame::CodingEpochClose(
                        frames::CodingEpochClose { epoch: done.epoch },
                    ))?);
                }
                Ok(())
            }
        }
    }

    /// One generation of an epoch as the reliable record it would have been.
    fn resend_generation(
        &self,
        opened: &OpenedEpoch,
        generation: u32,
        connection: &mut ServeConnection,
    ) -> Result<(), Fault> {
        let served = self
            .objects
            .get(&opened.root)
            .ok_or(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH))?;
        if !opened.plan.holds(generation) {
            return Ok(());
        }
        let (offset, length) = opened.plan.generation_span(generation);
        let plaintext = served.read_covered(offset, length)?;
        connection.queue_record(encoded(&TypedFrame::DataRecord(DataRecord {
            bundle_id: opened.bundle_id,
            record_index: u64::from(generation),
            plaintext_offset: offset,
            plaintext_length: length,
            compression: 0,
            encoded: plaintext,
        }))?);
        Ok(())
    }

    pub(crate) fn answer_manifest(
        &self,
        request: &ManifestRequest,
        connection: &mut ServeConnection,
    ) -> Result<(), Fault> {
        if request.manifest_id != self.manifest_id {
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        let end = request
            .first_page
            .checked_add(request.page_count)
            .ok_or(Fault::Peer(error_code::MANIFEST_INVALID))?;
        if end > self.page_count {
            // Asking past the announced page count.
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        // A cursor, not queued frames: pages are paced by the budget.
        connection.manifest_cursor = Some((request.first_page, end));
        Ok(())
    }

    /// Queues owed manifest pages while the outbound budget lasts.
    pub(crate) fn pump_manifest(&self, connection: &mut ServeConnection) -> Result<(), Fault> {
        while let Some((next, end)) = connection.manifest_cursor {
            if connection.outbound.bytes() >= connection.budget {
                break;
            }
            let bytes = crate::read_bounded_file(
                &crate::manifest_page_path(&self.manifest_directory, next),
                vot_manifest::MAX_PAGE_BYTES,
            )?;
            let slot = usize::try_from(next).map_err(|_| Error::InvalidBundle)?;
            if self.page_digests.get(slot) != Some(blake3::hash(&bytes).as_bytes()) {
                // Page changed on disk since the seal.
                return Err(Fault::Local(Error::SourceMutation));
            }
            connection.queue_control(encoded(&TypedFrame::ManifestPage(bytes))?);
            let following = next.checked_add(1).ok_or(Error::InvalidBundle)?;
            connection.manifest_cursor = if following == end {
                None
            } else {
                Some((following, end))
            };
        }
        Ok(())
    }

    pub(crate) fn answer_range(
        &self,
        request: &RangeRequest,
        request_bytes: &[u8],
        connection: &mut ServeConnection,
        repair_symbols: usize,
    ) -> Result<(), Fault> {
        let served = self
            .objects
            .get(&request.object.root)
            .ok_or(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH))?;
        if served.object != request.object {
            return Err(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH));
        }
        // Bundle identity derives from the request bytes, for replay detection.
        let mut bundle_id = [0u8; 16];
        bundle_id.copy_from_slice(&blake3::hash(request_bytes).as_bytes()[..16]);
        if !connection.fec_negotiated || !connection.fec_coding || !connection.fec.sender.may_open()
        {
            return Self::answer_reliably(
                served,
                request.request_id,
                bundle_id,
                request.offset,
                request.length,
                connection,
            );
        }
        // Coded, in pieces of at most `MAX_DATA_RECORDS_PER_BUNDLE`
        // generations, each its own bundle and epoch: a bundle carries one
        // record per generation and the wire bounds records per bundle. The
        // request's sub-ranges partition it, and the receiver deduplicates
        // on request and range identity, so several bundles may answer one
        // request. A piece the peer's credit no longer admits an epoch for
        // rides reliably.
        // Pieces are the object's fixed FEC_PIECE_BYTES windows cut to the
        // request, so a piece's group cover never exceeds the record bound.
        let request_end = request.offset.saturating_add(request.length);
        let mut sub_offset = request.offset;
        let mut index: u16 = 0;
        while sub_offset < request_end {
            let piece_end = (sub_offset / FEC_PIECE_BYTES)
                .saturating_add(1)
                .saturating_mul(FEC_PIECE_BYTES)
                .min(request_end);
            if piece_end <= sub_offset {
                return Err(Error::InvalidBundle.into());
            }
            let sub_length = piece_end - sub_offset;
            let mut piece_id = bundle_id;
            piece_id[14..].copy_from_slice(&index.to_be_bytes());
            if connection.fec.sender.may_open() {
                Self::answer_coded(
                    served,
                    request.request_id,
                    piece_id,
                    sub_offset,
                    sub_length,
                    connection,
                    repair_symbols,
                )?;
            } else {
                Self::answer_reliably(
                    served,
                    request.request_id,
                    piece_id,
                    sub_offset,
                    sub_length,
                    connection,
                )?;
            }
            sub_offset = piece_end;
            index = index.checked_add(1).ok_or(Error::InvalidBundle)?;
        }
        Ok(())
    }

    /// The reliable answer: the cover's proof and its bytes as records.
    fn answer_reliably(
        served: &ServedObject,
        request_id: [u8; 16],
        bundle_id: [u8; 16],
        offset: u64,
        length: u64,
        connection: &mut ServeConnection,
    ) -> Result<(), Fault> {
        // The codec bounded the request; the cover expands it to group boundaries.
        let (covered_offset, covered_length, proof) = served
            .layer
            .prove(offset, length)
            .map_err(Error::from)?
            .into_parts();
        let plaintext = served.read_covered(covered_offset, covered_length)?;
        let chunks = plaintext.chunks(RECORD_PLAINTEXT_BYTES);
        let bundle = TypedFrame::ProofBundle(ProofBundle {
            request_id,
            bundle_id,
            object: served.object,
            requested_offset: offset,
            requested_length: length,
            covered_offset,
            covered_length,
            data_record_count: chunks.len() as u64,
            total_plaintext_length: covered_length,
            proof,
        });
        connection.queue_control(encoded(&bundle)?);
        let mut record_offset = covered_offset;
        for (index, chunk) in plaintext.chunks(RECORD_PLAINTEXT_BYTES).enumerate() {
            let record = TypedFrame::DataRecord(DataRecord {
                bundle_id,
                record_index: index as u64,
                plaintext_offset: record_offset,
                plaintext_length: chunk.len() as u64,
                compression: 0,
                encoded: chunk.to_vec(),
            });
            connection.queue_record(encoded(&record)?);
            record_offset = record_offset.saturating_add(chunk.len() as u64);
        }
        Ok(())
    }

    /// The coded answer for one piece: the same bundle with one record per
    /// generation, then the epoch open, then each generation's symbols, or
    /// its record when the peer's generation credit is spent.
    fn answer_coded(
        served: &ServedObject,
        request_id: [u8; 16],
        bundle_id: [u8; 16],
        offset: u64,
        length: u64,
        connection: &mut ServeConnection,
        repair_symbols: usize,
    ) -> Result<(), Fault> {
        let (covered_offset, covered_length, proof) = served
            .layer
            .prove(offset, length)
            .map_err(Error::from)?
            .into_parts();
        let epoch = connection
            .fec
            .sender
            .next_epoch()
            .ok_or(Error::InvalidBundle)?;
        let plan = vot_fec::EpochPlan::new(
            epoch,
            covered_offset,
            covered_length,
            fec_geometry(repair_symbols),
        )
        .map_err(|_| Error::InvalidBundle)?;
        let generations = plan.generation_count();
        debug_assert!(generations <= vot_codec::frames::MAX_DATA_RECORDS_PER_BUNDLE as u64);
        let plaintext = served.read_covered(covered_offset, covered_length)?;
        let object = served.object;
        connection.queue_control(encoded(&TypedFrame::ProofBundle(ProofBundle {
            request_id,
            bundle_id,
            object,
            requested_offset: offset,
            requested_length: length,
            covered_offset,
            covered_length,
            data_record_count: generations,
            total_plaintext_length: covered_length,
            proof,
        }))?);
        connection
            .fec
            .sender
            .open(plan)
            .map_err(|_| Error::InvalidBundle)?;
        connection.queue_control(encoded(&TypedFrame::CodingEpochOpen(
            frames::CodingEpochOpen {
                epoch: plan.epoch(),
                object,
                offset: covered_offset,
                length: covered_length,
                geometry: plan.geometry(),
            },
        ))?);
        let mut live = std::collections::BTreeSet::new();
        let mut coded = Vec::new();
        for generation in 0..u32::try_from(generations).map_err(|_| Error::InvalidBundle)? {
            let (gen_offset, gen_length) = plan.generation_span(generation);
            let start =
                usize::try_from(gen_offset - covered_offset).map_err(|_| Error::InvalidBundle)?;
            let end = start + usize::try_from(gen_length).map_err(|_| Error::InvalidBundle)?;
            let bytes = &plaintext[start..end];
            if connection
                .fec
                .sender
                .begin(plan.epoch(), generation)
                .is_ok()
            {
                let geometry = plan.geometry();
                let source_bytes = geometry.source_count() * geometry.symbol_length();
                let source = if bytes.len() == source_bytes {
                    std::borrow::Cow::Borrowed(bytes)
                } else {
                    let mut padded = vec![0; source_bytes];
                    padded[..bytes.len()].copy_from_slice(bytes);
                    std::borrow::Cow::Owned(padded)
                };
                let mut borrowed = [&[][..]; vot_fec::MAX_SOURCE_SYMBOLS];
                for (slot, symbol) in borrowed
                    .iter_mut()
                    .zip(source.chunks_exact(geometry.symbol_length()))
                {
                    *slot = symbol;
                }
                let repair = vot_fec::encode(geometry, &borrowed[..geometry.source_count()])
                    .map_err(|_| Error::InvalidBundle)?;
                coded.push(CodedGeneration {
                    generation,
                    source,
                    repair,
                });
                live.insert(generation);
            } else {
                // Past the peer's generation credit: this one rides reliably
                // under the same bundle.
                connection.queue_record(encoded(&TypedFrame::DataRecord(DataRecord {
                    bundle_id,
                    record_index: u64::from(generation),
                    plaintext_offset: gen_offset,
                    plaintext_length: gen_length,
                    compression: 0,
                    encoded: bytes.to_vec(),
                }))?);
            }
        }
        // Spread each ESI across the piece before sending the next one. A
        // dropped UDP segmentation burst then costs a few symbols from each
        // generation instead of enough adjacent symbols to defeat its repair
        // budget outright.
        for esi in 0..plan.geometry().symbol_count() {
            for generation in &coded {
                let geometry = plan.geometry();
                let symbol = if esi < geometry.source_count() {
                    if esi >= plan.sent_source_count(generation.generation) {
                        continue;
                    }
                    let start = esi * geometry.symbol_length();
                    &generation.source[start..start + geometry.symbol_length()]
                } else {
                    &generation.repair[esi - geometry.source_count()]
                };
                let mut datagram = Vec::with_capacity(
                    vot_codec::frames::SYMBOL_HEADER_LEN + geometry.symbol_length(),
                );
                frames::encode_symbol(
                    frames::SymbolHeader {
                        epoch: plan.epoch(),
                        generation: generation.generation,
                        esi: u8::try_from(esi).expect("inside the geometry"),
                    },
                    geometry,
                    symbol,
                    &mut datagram,
                )
                .map_err(|_| Error::InvalidBundle)?;
                connection.queue_datagram(Payload::from(datagram));
            }
        }
        if live.is_empty() {
            connection.fec.sender.close(plan.epoch());
            connection.queue_control(encoded(&TypedFrame::CodingEpochClose(
                frames::CodingEpochClose {
                    epoch: plan.epoch(),
                },
            ))?);
        } else {
            let queued_through = connection.outbound.queued_through();
            connection.fec.epochs.insert(
                plan.epoch(),
                OpenedEpoch {
                    root: object.root,
                    bundle_id,
                    plan,
                    live,
                    queued_through,
                    quiet_since: None,
                },
            );
        }
        Ok(())
    }
}

/// Whether consuming this frame can add a new answer batch.
pub(super) fn answer_request(bytes: &[u8]) -> bool {
    let limits = DecodeLimits {
        max_unknown_payload: MAX_CONTROL_FRAME_PAYLOAD,
        max_frames: 1,
    };
    if !vot_codec::peek_envelope(bytes, limits).is_ok_and(|frame| {
        matches!(
            frame.frame_type,
            frame_type::MANIFEST_REQUEST | frame_type::RANGE_REQUEST
        )
    }) {
        return false;
    }
    frames::decode(bytes, limits).is_ok_and(|(frame, consumed)| {
        matches!(
            (consumed == bytes.len(), frame),
            (
                true,
                TypedFrame::ManifestRequest(_) | TypedFrame::RangeRequest(_)
            )
        )
    })
}

/// The shipped FEC profile (spec/fec.md section 9): one generation is one
/// 64 KiB integrity group and 64 sources of 1024 bytes. Eight repairs are the
/// conservative startup/fallback profile; measured paths may use fewer.
pub(crate) const FEC_GENERATION_BYTES: u64 = 65_536;
pub(crate) const FEC_REPAIR_SYMBOLS: usize = 8;

/// How long an epoch may draw nothing from the receiver before this end
/// repairs its remaining generations reliably and closes it.
///
/// Measured per epoch and reset by any `GEN_STATE` or `GEN_DONE` naming it,
/// so it is that epoch's own silence rather than the connection's. A
/// receiver working through an epoch reports each generation as its first
/// symbol lands, so one being received resets this over and over; one that
/// has said nothing for this long holds generations its symbols will never
/// complete, and the reliable path is what carries those.
///
/// Timed rather than counted in passes, because a pass is microseconds on a
/// busy connection and whole milliseconds on an idle one: a budget of 256
/// passes retired epochs whose outcomes were still in flight and took a
/// 256 MB coded fetch from 0.8 to 13 seconds in reliable resends. What the
/// grace has to clear is a round trip and the receiver's decode, so it is
/// set well above both for the paths this serves.
pub(crate) const EPOCH_QUIET_GRACE: std::time::Duration = std::time::Duration::from_millis(500);
/// The most a coded piece covers: one generation per record, and a bundle
/// declares at most `MAX_DATA_RECORDS_PER_BUNDLE` of them.
pub(crate) const FEC_PIECE_BYTES: u64 =
    FEC_GENERATION_BYTES * vot_codec::frames::MAX_DATA_RECORDS_PER_BUNDLE as u64;

fn fec_geometry(repair_symbols: usize) -> vot_fec::Geometry {
    vot_fec::Geometry::new(64, repair_symbols, 1024).expect("the selected profile")
}
