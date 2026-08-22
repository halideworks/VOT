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

    /// Chooses whether negotiated FEC follows measured path loss. Passing
    /// `false` forces coding whenever the peer negotiates the extension.
    pub const fn set_automatic_fec(&mut self, automatic: bool) {
        self.automatic_fec = automatic;
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
        connection.quiet_grace = quiet_grace(path.and_then(|stats| stats.smoothed_rtt_us));
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
            connection.fec_negotiated = session
                .extension_negotiated(vot_codec::extension_id::DATAGRAM_FEC)
                && session.extension_negotiated(vot_codec::extension_id::FEC_COVER_EPOCHS);
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
    /// receiver for the connection's [`quiet_grace`] is repaired reliably and closed,
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
        let grace = connection.quiet_grace;
        let mut spent = Vec::new();
        for (epoch, opened) in &mut connection.fec.epochs {
            if taken < opened.queued_through {
                // Symbols still waiting in this end's own queue, so silence
                // about the epoch says nothing about the receiver yet.
                continue;
            }
            let deadline = *opened.quiet_until.get_or_insert(now + grace);
            if now >= deadline {
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
            // The first quiet deadline is answered with symbols, not round
            // trips (ADR-0042): the reserve repair ESIs the first pass held
            // back, plus the sources the receiver's newest state reported
            // missing. The clock re-arms once; a second silence means the
            // symbols did not land either, and the generations come back as
            // the reliable records they would have been.
            let ladder = connection
                .fec
                .epochs
                .get(&epoch)
                .expect("named by the pass above");
            if !ladder.symbol_repaired {
                // The rung needs both halves: symbols this end held back,
                // and the receiver's word that it holds partial state to
                // top up. A generation no state was ever accepted for may
                // hold nothing at all, and reserve symbols alone cannot
                // decode it; spending the rung there only doubles the
                // retirement latency the grace exists to bound.
                let repairable = ladder.reserve_repairs() > 0
                    && ladder
                        .live
                        .iter()
                        .any(|generation| connection.fec.sender.state_accepted(epoch, *generation));
                if repairable {
                    let opened = ladder.clone();
                    self.repair_epoch_symbols(&opened, connection)?;
                    let renewed = connection
                        .fec
                        .epochs
                        .get_mut(&epoch)
                        .expect("cloned just above");
                    renewed.symbol_repaired = true;
                    renewed.queued_through = connection.outbound.queued_through();
                    renewed.symbols_queued_through = renewed.queued_through;
                    renewed.quiet_until = None;
                    continue;
                }
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

    /// A fresh state naming a generation past its source rounds and short
    /// of `k` gets its holes answered now: the listed missing sources plus
    /// the unsent reserve, within a round trip of the receiver seeing the
    /// repair round, instead of the quiet grace the reliable backstop
    /// costs (ADR-0042 decision 4). Once per generation; the ladder and
    /// the reliable resend still stand behind it.
    ///
    /// Gated on the epoch's symbols all being on the carrier, the
    /// receiver holding at least half the sources, and the missing
    /// sources outnumbering the repair symbols the first pass sent.
    /// `received` already counts repair symbols in hand, so "the
    /// in-flight repair round cannot reach `k`" reduces exactly to that
    /// count comparison, with nothing to subtract. The
    /// restate rides the epoch's first repair symbol, so every
    /// generation's own repair round is still in flight behind it: a
    /// generation whose holes those repairs can fill needs nothing, and
    /// answering it anyway was measured sending a targeted repair for
    /// nearly every generation of a forced 5% transfer while the
    /// over-lost ones bounced off the outbound budget this spends.
    fn answer_short_state(
        &self,
        state: &frames::GenState,
        connection: &mut ServeConnection,
    ) -> Result<(), Fault> {
        // The budget bounds a burst of states the way it bounds the
        // request loop: a whole epoch may re-state at once, and answering
        // every one past the budget would put megabytes behind it in a
        // single dispatch pass.
        if connection.outbound.bytes() >= connection.budget {
            return Ok(());
        }
        let Some(opened) = connection.fec.epochs.get(&state.epoch) else {
            return Ok(());
        };
        let geometry = opened.plan.geometry();
        let sources = geometry.source_count();
        if usize::from(state.received) >= sources
            || usize::from(state.received) < sources / 2
            || state.missing_sources.len() <= opened.transmitted_repairs
            || connection.outbound.taken() < opened.symbols_queued_through
            || opened.repaired.contains(&state.generation)
            || !opened.plan.holds(state.generation)
        {
            return Ok(());
        }
        let opened = opened.clone();
        let served = self
            .objects
            .get(&opened.root)
            .ok_or(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH))?;
        let (offset, length) = opened.plan.generation_span(state.generation);
        let plaintext = served.read_covered(offset, length)?;
        let symbols = vot_fec::encode_generation(&opened.plan, state.generation, &plaintext)
            .map_err(|_| Error::InvalidBundle)?;
        let reserve_from = sources + opened.transmitted_repairs;
        for (esi, symbol) in &symbols {
            let wanted = usize::from(*esi) >= reserve_from || state.missing_sources.contains(esi);
            if !wanted {
                continue;
            }
            let mut datagram =
                Vec::with_capacity(vot_codec::frames::SYMBOL_HEADER_LEN + geometry.symbol_length());
            frames::encode_symbol(
                frames::SymbolHeader {
                    epoch: opened.plan.epoch(),
                    generation: state.generation,
                    esi: *esi,
                },
                geometry,
                symbol,
                &mut datagram,
            )
            .map_err(|_| Error::InvalidBundle)?;
            connection.queue_datagram(Payload::from(datagram));
        }
        let renewed = connection
            .fec
            .epochs
            .get_mut(&state.epoch)
            .expect("held above");
        renewed.repaired.insert(state.generation);
        // The retire mark moves so the quiet clock waits out these bytes
        // too; the symbols mark deliberately does not, or one repair would
        // gate its siblings in the same pass out of theirs.
        renewed.queued_through = connection.outbound.queued_through();
        Ok(())
    }

    /// The epoch's symbol repair: the reserve repair ESIs the first pass
    /// held back, for every live generation, re-encoded from the object
    /// rather than stored, the way [`Self::resend_generation`] re-reads
    /// it. Reserve only: the receiver's one state per generation is the
    /// first symbol's snapshot, so its missing list names nearly every
    /// source and resending them would ship the whole generation again.
    ///
    /// Interleaved ESI-major across the generations, the way the first
    /// pass spreads its symbols, so a dropped segmentation burst costs a
    /// few symbols from each generation rather than one generation's
    /// whole repair.
    fn repair_epoch_symbols(
        &self,
        opened: &OpenedEpoch,
        connection: &mut ServeConnection,
    ) -> Result<(), Fault> {
        let served = self
            .objects
            .get(&opened.root)
            .ok_or(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH))?;
        let geometry = opened.plan.geometry();
        let reserve_from = geometry.source_count() + opened.transmitted_repairs;
        let mut reserves = Vec::new();
        for generation in &opened.live {
            if !opened.plan.holds(*generation) {
                continue;
            }
            let (offset, length) = opened.plan.generation_span(*generation);
            let plaintext = served.read_covered(offset, length)?;
            let mut symbols = vot_fec::encode_generation(&opened.plan, *generation, &plaintext)
                .map_err(|_| Error::InvalidBundle)?;
            symbols.retain(|(esi, _)| usize::from(*esi) >= reserve_from);
            reserves.push((*generation, symbols));
        }
        for slot in 0..geometry.symbol_count().saturating_sub(reserve_from) {
            for (generation, symbols) in &reserves {
                let Some((esi, symbol)) = symbols.get(slot) else {
                    continue;
                };
                let mut datagram = Vec::with_capacity(
                    vot_codec::frames::SYMBOL_HEADER_LEN + geometry.symbol_length(),
                );
                frames::encode_symbol(
                    frames::SymbolHeader {
                        epoch: opened.plan.epoch(),
                        generation: *generation,
                        esi: *esi,
                    },
                    geometry,
                    symbol,
                    &mut datagram,
                )
                .map_err(|_| Error::InvalidBundle)?;
                connection.queue_datagram(Payload::from(datagram));
            }
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
                    opened.quiet_until = None;
                }
                let newer = connection
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
                if newer {
                    self.answer_short_state(&state, connection)?;
                }
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
                if first && verdict == vot_fec::Done::Decoded {
                    // The other half of what the decode policy weighs, off
                    // the same stream of reports as the failures below.
                    connection.fec_policy.note_decoded();
                }
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
                epoch.quiet_until = None;
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
        // Every way a coded generation can fail arrives here: the receiver
        // abandoning it, the epoch refused, and the quiet retirement that
        // covers a generation which never gathered enough symbols to
        // report at all. So this is where the policy learns coding is not
        // working.
        connection.fec_policy.note_repaired();
        let (first, piece_id) = piece_of(&opened.pieces, generation).ok_or(Error::InvalidBundle)?;
        let (offset, length) = opened.plan.generation_span(generation);
        let plaintext = served.read_covered(offset, length)?;
        connection.queue_record(encoded(&TypedFrame::DataRecord(DataRecord {
            bundle_id: piece_id,
            record_index: u64::from(generation - first),
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
        Self::answer_coded(
            served,
            request.request_id,
            bundle_id,
            request.offset,
            request.length,
            connection,
            repair_symbols,
        )
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

    /// The coded answer for one request: one epoch across the whole covered
    /// range (ADR-0042), one proof bundle per piece with one record per
    /// generation, then the epoch open, then each generation's symbols, or
    /// its record when the peer's generation credit is spent.
    ///
    /// Pieces are the object's fixed `FEC_PIECE_BYTES` windows cut to the
    /// request, so a piece's group cover never exceeds the record bound. The
    /// windows are group-aligned, so proving expands only the two ends of
    /// the request and the piece covers abut: their union is the epoch's
    /// range, and every generation lies whole inside one piece.
    fn answer_coded(
        served: &ServedObject,
        request_id: [u8; 16],
        bundle_id: [u8; 16],
        offset: u64,
        length: u64,
        connection: &mut ServeConnection,
        repair_symbols: usize,
    ) -> Result<(), Fault> {
        let request_end = offset.checked_add(length).ok_or(Error::InvalidBundle)?;
        let object = served.object;
        // Bundles go out before the epoch open, so on the ordered control
        // stream no generation can decode ahead of the bundle it joins.
        let mut covers: Vec<(u64, [u8; 16])> = Vec::new();
        let mut covered_end = 0_u64;
        let mut sub_offset = offset;
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
            let (piece_offset, piece_length, proof) = served
                .layer
                .prove(sub_offset, sub_length)
                .map_err(Error::from)?
                .into_parts();
            debug_assert!(
                covers.is_empty() || piece_offset == covered_end,
                "piece covers must abut"
            );
            covered_end = piece_offset
                .checked_add(piece_length)
                .ok_or(Error::InvalidBundle)?;
            connection.queue_control(encoded(&TypedFrame::ProofBundle(ProofBundle {
                request_id,
                bundle_id: piece_id,
                object,
                requested_offset: sub_offset,
                requested_length: sub_length,
                covered_offset: piece_offset,
                covered_length: piece_length,
                data_record_count: piece_length.div_ceil(FEC_GENERATION_BYTES),
                total_plaintext_length: piece_length,
                proof,
            }))?);
            covers.push((piece_offset, piece_id));
            sub_offset = piece_end;
            index = index.checked_add(1).ok_or(Error::InvalidBundle)?;
        }
        let covered_offset = covers.first().ok_or(Error::InvalidBundle)?.0;
        let covered_length = covered_end
            .checked_sub(covered_offset)
            .ok_or(Error::InvalidBundle)?;
        let pieces: Vec<(u32, [u8; 16])> = covers
            .iter()
            .map(|(at, id)| {
                u32::try_from((at - covered_offset) / FEC_GENERATION_BYTES)
                    .map(|first| (first, *id))
                    .map_err(|_| Error::InvalidBundle)
            })
            .collect::<Result<_, _>>()?;
        let epoch = connection
            .fec
            .sender
            .next_epoch()
            .ok_or(Error::InvalidBundle)?;
        // The geometry declares the spec's whole repair count; the policy's
        // size is how many of those ESIs the first pass transmits. The gap
        // is the reserve a symbol repair draws from without reopening
        // (ADR-0042): symbols are sender-chosen, so an ESI never sent is
        // simply sent later.
        let transmitted_repairs = repair_symbols.min(FEC_REPAIR_SYMBOLS);
        let plan = vot_fec::EpochPlan::new(
            epoch,
            covered_offset,
            covered_length,
            fec_geometry(FEC_REPAIR_SYMBOLS),
        )
        .map_err(|_| Error::InvalidBundle)?;
        let generations = plan.generation_count();
        let plaintext = served.read_covered(covered_offset, covered_length)?;
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
                // under its piece's bundle.
                let (first, piece_id) =
                    piece_of(&pieces, generation).ok_or(Error::InvalidBundle)?;
                connection.queue_record(encoded(&TypedFrame::DataRecord(DataRecord {
                    bundle_id: piece_id,
                    record_index: u64::from(generation - first),
                    plaintext_offset: gen_offset,
                    plaintext_length: gen_length,
                    compression: 0,
                    encoded: bytes.to_vec(),
                }))?);
            }
        }
        // Spread each ESI across the cover before sending the next one. A
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
                    if esi >= geometry.source_count() + transmitted_repairs {
                        // The reserve: declared, encoded, held for repair.
                        continue;
                    }
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
                    pieces,
                    transmitted_repairs,
                    symbol_repaired: false,
                    repaired: std::collections::BTreeSet::new(),
                    symbols_queued_through: queued_through,
                    plan,
                    live,
                    queued_through,
                    quiet_until: None,
                },
            );
        }
        Ok(())
    }
}

/// The piece a generation's record rides under: the last piece at or before
/// it, as its first generation and bundle identifier.
fn piece_of(pieces: &[(u32, [u8; 16])], generation: u32) -> Option<(u32, [u8; 16])> {
    pieces
        .iter()
        .rev()
        .find(|(first, _)| *first <= generation)
        .copied()
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
/// 64 KiB integrity group and 64 sources of 1024 bytes. The spec's whole
/// repair ceiling is the startup/fallback profile; a measured path sizes
/// under it at three times its loss (ADR-0042).
pub(crate) const FEC_GENERATION_BYTES: u64 = 65_536;
pub(crate) const FEC_REPAIR_SYMBOLS: usize = vot_fec::MAX_REPAIR_SYMBOLS;

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

/// The longest grace a measured path gets: past this a stalled epoch is
/// holding one of the few slots for whole seconds.
pub(crate) const MAX_QUIET_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// The silence budget for a path: four smoothed round trips, never below
/// [`EPOCH_QUIET_GRACE`] and never above [`MAX_QUIET_GRACE`]. The extension
/// only ever lengthens the budget, because a healthy receiver's silence on a
/// fast path is bounded by its decode and scheduling, not its round trip,
/// and retiring early was measured turning a 0.8 s coded fetch into 13 s of
/// reliable resends. A path reporting no round trip keeps the fixed default.
pub(crate) fn quiet_grace(smoothed_rtt_us: Option<u64>) -> std::time::Duration {
    smoothed_rtt_us.map_or(EPOCH_QUIET_GRACE, |rtt| {
        std::time::Duration::from_micros(rtt.saturating_mul(4))
            .clamp(EPOCH_QUIET_GRACE, MAX_QUIET_GRACE)
    })
}
/// The most a coded piece covers: one generation per record, and a bundle
/// declares at most `MAX_DATA_RECORDS_PER_BUNDLE` of them.
pub(crate) const FEC_PIECE_BYTES: u64 =
    FEC_GENERATION_BYTES * vot_codec::frames::MAX_DATA_RECORDS_PER_BUNDLE as u64;

fn fec_geometry(repair_symbols: usize) -> vot_fec::Geometry {
    vot_fec::Geometry::new(64, repair_symbols, 1024).expect("the selected profile")
}
