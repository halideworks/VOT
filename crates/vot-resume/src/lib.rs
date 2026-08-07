//! Persistent carrier-neutral resume state and RFC 9959 Careful Resume policy.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use vot_transport_api::{PathStats, SubjectId};

pub mod units;
pub use units::UnitRanges;
use vot_transport_tcp::Carrier;

const MAGIC: &[u8; 8] = b"VOTRES02";
const MAX_STORE_BYTES: u64 = 67_108_864;
const MAX_STORE_PAYLOAD_BYTES: u64 = MAX_STORE_BYTES - 20;
const MIN_STORE_BYTES: u64 = 8;
/// Largest unit count a single object can reserve.
///
/// This is derived from the snapshot format, not chosen: it is the largest
/// `total_units` whose worst-case checkpoint encoding — every other unit
/// checkpointed, so the run-length ranges degenerate to one range per pair —
/// still fits a store holding that object alone. At the 64 KiB unit that is
/// just under 1 TiB. `max_units_per_object_is_derived_from_the_snapshot_format`
/// pins both sides of the boundary, so a format change fails the test rather
/// than silently shifting the limit.
const MAX_UNITS_PER_OBJECT: u64 = 16_777_198;
const RECORD_HEADER_BYTES: u64 = 4;
const RECORD_CHECKSUM_BYTES: u64 = 8;
const RESERVE_RECORD: u8 = 1;
const CHECKPOINT_RECORD: u8 = 2;
const SNAPSHOT_RECORD: u8 = 3;
const COMPACTION_THRESHOLD: u64 = MAX_STORE_BYTES * 3 / 4;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Corrupt,
    TooLarge,
    InvalidConfiguration,
    InvalidUnit,
    UnitAlreadyActive,
    UnitNotActive,
    CheckpointRequired,
    IdentityMismatch,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredObject {
    total_units: u64,
    checkpointed: UnitRanges,
}

/// Checksummed append-only state keyed by immutable object identity, never connection ID.
pub struct ResumeStore {
    path: PathBuf,
    objects: BTreeMap<SubjectId, StoredObject>,
    signature: FileSignature,
}

impl ResumeStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let lock = lock_store(&path)?;
        let objects = if path.exists() {
            decode_store(&path)?
        } else {
            BTreeMap::new()
        };
        let signature = file_signature(&path)?;
        drop(lock);
        Ok(Self {
            path,
            objects,
            signature,
        })
    }

    #[must_use]
    pub fn checkpointed(&self, subject: SubjectId) -> Option<&UnitRanges> {
        self.objects
            .get(&subject)
            .map(|object| &object.checkpointed)
    }

    /// Every subject the store holds, in key order.
    pub fn subjects(&self) -> impl Iterator<Item = SubjectId> + '_ {
        self.objects.keys().copied()
    }

    /// Records `units` of `subject` as durable, unioned with what the
    /// store already holds.
    ///
    /// # Errors
    /// Rejects a subject the store never reserved, a unit count that
    /// disagrees with the reservation, or units past it.
    pub fn checkpoint_units(
        &mut self,
        subject: SubjectId,
        total_units: u64,
        units: &UnitRanges,
    ) -> Result<(), Error> {
        self.save_object(subject, total_units, units).map(|_| ())
    }

    /// Opens the store and makes sure it exists on disk, empty if new.
    ///
    /// ADR-0032: the store's presence beside a partial bundle is what
    /// says the bundle may be continued, so it has to exist from the
    /// first moment a crash could leave the bundle behind, not from the
    /// first checkpoint.
    ///
    /// # Errors
    /// Surfaces what [`ResumeStore::open`] or the creating write refuses.
    pub fn create(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let store = Self::open(path)?;
        if !store.path.exists() {
            let lock = lock_store(&store.path)?;
            Self::compact(&store.path, &store.objects)?;
            drop(lock);
        }
        Self::open(store.path)
    }

    /// Removes the store and its lock file, for a bundle that is whole:
    /// a completed bundle looks exactly as one fetched without a store.
    ///
    /// # Errors
    /// Surfaces a file that exists and will not go.
    pub fn remove(self) -> Result<(), Error> {
        let lock = lock_path(&self.path)?;
        for path in [self.path, lock] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(Error::Io(error)),
            }
        }
        Ok(())
    }

    /// Reserves a batch of immutable objects in one compacted transaction.
    ///
    /// # Errors
    /// Rejects identity conflicts, invalid unit counts, or a store that exceeds
    /// the bounded on-disk representation.
    pub fn reserve_many<I>(&mut self, objects: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = (SubjectId, u64)>,
    {
        let lock = lock_store(&self.path)?;
        self.refresh_locked()?;
        let mut candidate = self.objects.clone();
        let mut changed = false;
        for (subject, total_units) in objects {
            validate_total_units(total_units)?;
            if let Some(existing) = candidate.get(&subject) {
                if existing.total_units != total_units {
                    return Err(Error::IdentityMismatch);
                }
            } else {
                candidate.insert(
                    subject,
                    StoredObject {
                        total_units,
                        checkpointed: UnitRanges::new(),
                    },
                );
                changed = true;
            }
        }
        if changed {
            validate_reserved_capacity(&candidate)?;
            Self::compact(&self.path, &candidate)?;
            self.objects = candidate;
            self.signature = file_signature(&self.path)?;
        }
        drop(lock);
        Ok(())
    }

    fn reserve_object(
        &mut self,
        subject: SubjectId,
        total_units: u64,
    ) -> Result<UnitRanges, Error> {
        validate_total_units(total_units)?;
        let lock = lock_store(&self.path)?;
        self.refresh_locked()?;
        let checkpointed = if let Some(object) = self.objects.get(&subject) {
            if object.total_units != total_units {
                return Err(Error::IdentityMismatch);
            }
            object.checkpointed.clone()
        } else {
            let object = StoredObject {
                total_units,
                checkpointed: UnitRanges::new(),
            };
            let current_length = file_len(&self.path)?;
            let mut candidate = self.objects.clone();
            candidate.insert(subject, object.clone());
            validate_reserved_capacity(&candidate)?;
            if reserve_requires_compaction(self.path.exists(), current_length) {
                Self::compact(&self.path, &candidate)?;
            } else {
                append_record(&self.path, &encode_reserve(subject, total_units)?)?;
            }
            self.objects = candidate;
            UnitRanges::new()
        };
        self.signature = file_signature(&self.path)?;
        drop(lock);
        Ok(checkpointed)
    }

    fn save_object(
        &mut self,
        subject: SubjectId,
        total_units: u64,
        checkpointed: &UnitRanges,
    ) -> Result<UnitRanges, Error> {
        validate_total_units(total_units)?;
        if checkpointed
            .max()
            .is_some_and(|highest| highest >= total_units)
        {
            return Err(Error::InvalidUnit);
        }
        let lock = lock_store(&self.path)?;
        self.refresh_locked()?;
        let mut candidate = self.objects.clone();
        let existing = candidate.get(&subject).ok_or(Error::IdentityMismatch)?;
        if existing.total_units != total_units {
            return Err(Error::IdentityMismatch);
        }
        let previous = existing.checkpointed.clone();
        let mut merged = previous.clone();
        merged.union(checkpointed);
        candidate.insert(
            subject,
            StoredObject {
                total_units,
                checkpointed: merged.clone(),
            },
        );
        let delta = difference(&merged, &previous);
        if !delta.is_empty() {
            let record = encode_checkpoint(subject, total_units, &delta)?;
            let projected = file_len(&self.path)?
                .saturating_add(u64::try_from(record.len()).map_err(|_| Error::TooLarge)?);
            if should_compact(projected) {
                Self::compact(&self.path, &candidate)?;
            } else {
                append_record(&self.path, &record)?;
            }
        }
        self.objects = candidate;
        self.signature = file_signature(&self.path)?;
        drop(lock);
        Ok(merged)
    }

    fn compact(path: &Path, objects: &BTreeMap<SubjectId, StoredObject>) -> Result<(), Error> {
        let bytes = encode_snapshot(objects)?;
        let record = encode_record(&bytes)?;
        let record_length = u64::try_from(record.len()).map_err(|_| Error::TooLarge)?;
        if !compact_fits(record_length) {
            return Err(Error::TooLarge);
        }
        let temporary = temporary_path(path)?;
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(MAGIC)?;
        file.write_all(&record)?;
        file.sync_all()?;
        vot_platform_fs::atomic_replace(&temporary, path)?;
        #[cfg(unix)]
        File::open(path.parent().ok_or(Error::InvalidConfiguration)?)?.sync_all()?;
        Ok(())
    }

    fn refresh_locked(&mut self) -> Result<(), Error> {
        let current = file_signature(&self.path)?;
        if current != self.signature {
            self.objects = if self.path.exists() {
                decode_store(&self.path)?
            } else {
                BTreeMap::new()
            };
            self.signature = current;
        }
        Ok(())
    }
}

/// Per-object bounded-waste tracker. Active and post-checkpoint units are volatile by design.
pub struct ResumeTracker {
    subject: SubjectId,
    total_units: u64,
    checkpoint_window: usize,
    checkpointed: UnitRanges,
    completed_since_checkpoint: BTreeSet<u64>,
    active: BTreeSet<u64>,
}

impl ResumeTracker {
    pub fn discover(
        store: &mut ResumeStore,
        subject: SubjectId,
        total_units: u64,
        checkpoint_window: usize,
    ) -> Result<Self, Error> {
        validate_total_units(total_units)?;
        validate_checkpoint_window(total_units, checkpoint_window)?;
        let checkpointed = store.reserve_object(subject, total_units)?;
        Ok(Self {
            subject,
            total_units,
            checkpoint_window,
            checkpointed,
            completed_since_checkpoint: BTreeSet::new(),
            active: BTreeSet::new(),
        })
    }

    pub fn begin_unit(&mut self, unit: u64) -> Result<bool, Error> {
        self.validate_unit(unit)?;
        if self.checkpointed.contains(unit) || self.completed_since_checkpoint.contains(&unit) {
            return Ok(false);
        }
        if !self.active.insert(unit) {
            return Err(Error::UnitAlreadyActive);
        }
        Ok(true)
    }

    /// Returns true when the checkpoint window is full and should be persisted.
    pub fn complete_unit(&mut self, unit: u64) -> Result<bool, Error> {
        self.validate_unit(unit)?;
        if !self.active.contains(&unit) {
            return Err(Error::UnitNotActive);
        }
        if self.completed_since_checkpoint.len() >= self.checkpoint_window {
            return Err(Error::CheckpointRequired);
        }
        self.active.remove(&unit);
        self.completed_since_checkpoint.insert(unit);
        Ok(self.completed_since_checkpoint.len() >= self.checkpoint_window)
    }

    pub fn checkpoint(&mut self, store: &mut ResumeStore) -> Result<(), Error> {
        // Build the pending units as their own runs first, then merge the two
        // lists in one pass. Inserting them one at a time into a set that
        // already holds millions of runs would shift the vector per unit.
        let mut pending = UnitRanges::new();
        pending.extend_units(self.completed_since_checkpoint.iter().copied());
        let mut checkpointed = self.checkpointed.clone();
        checkpointed.union(&pending);
        let checkpointed = store.save_object(self.subject, self.total_units, &checkpointed)?;
        self.checkpointed = checkpointed;
        self.completed_since_checkpoint.clear();
        Ok(())
    }

    #[must_use]
    pub fn retransmission_units_after_crash(&self) -> usize {
        self.completed_since_checkpoint.len() + self.active.len()
    }

    #[must_use]
    pub fn retransmission_bound(&self) -> usize {
        self.checkpoint_window + self.active.len()
    }

    #[must_use]
    pub fn is_checkpointed(&self, unit: u64) -> bool {
        self.checkpointed.contains(unit)
    }

    pub fn missing_units(&self) -> impl Iterator<Item = u64> + '_ {
        self.checkpointed.missing(self.total_units)
    }

    fn validate_unit(&self, unit: u64) -> Result<(), Error> {
        if unit >= self.total_units {
            Err(Error::InvalidUnit)
        } else {
            Ok(())
        }
    }
}

/// Verified and durable state that survives connection and carrier changes.
pub struct CarrierNeutralState {
    carrier: Carrier,
    connection: u64,
    verified: BTreeSet<u64>,
    durable: BTreeSet<u64>,
}

impl CarrierNeutralState {
    #[must_use]
    pub const fn new(carrier: Carrier, connection: u64) -> Self {
        Self {
            carrier,
            connection,
            verified: BTreeSet::new(),
            durable: BTreeSet::new(),
        }
    }

    pub fn verified(&mut self, unit: u64) {
        self.verified.insert(unit);
    }

    pub fn durable(&mut self, unit: u64) -> Result<(), Error> {
        if !self.verified.contains(&unit) {
            return Err(Error::InvalidUnit);
        }
        self.durable.insert(unit);
        Ok(())
    }

    pub fn switch(&mut self, carrier: Carrier, connection: u64) {
        self.carrier = carrier;
        self.connection = connection;
    }

    #[must_use]
    pub fn is_verified(&self, unit: u64) -> bool {
        self.verified.contains(&unit)
    }

    #[must_use]
    pub fn is_durable(&self, unit: u64) -> bool {
        self.durable.contains(&unit)
    }

    #[must_use]
    pub const fn carrier(&self) -> Carrier {
        self.carrier
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RemoteEndpoint {
    pub interface: u64,
    pub destination: [u8; 16],
    pub dscp: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub saved_cwnd: u64,
    pub saved_rtt: u64,
    pub expires_at: u64,
    pub configuration_epoch: u64,
}

impl Observation {
    /// Builds a resumable observation from the backend-neutral path metrics.
    ///
    /// # Errors
    /// Rejects adapters that cannot expose both RTT and congestion window.
    pub fn from_path_stats(
        stats: PathStats,
        expires_at: u64,
        configuration_epoch: u64,
    ) -> Result<Self, PathReject> {
        Ok(Self {
            saved_cwnd: stats
                .congestion_window_bytes
                .ok_or(PathReject::InvalidObservation)?,
            saved_rtt: stats
                .smoothed_rtt_us
                .ok_or(PathReject::InvalidObservation)?,
            expires_at,
            configuration_epoch,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SavedPath {
    observation: Observation,
    owner: Option<u64>,
    discard_on_release: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reconnaissance {
    pub now: u64,
    pub current_min_rtt: u64,
    pub initial_flight_acknowledged: bool,
    pub congestion_detected: bool,
    pub local_path_changed: bool,
    pub configuration_epoch: u64,
    pub max_jump: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumePermit {
    pub jump_cwnd: u64,
    pub paced_rtt: u64,
    owner: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathReject {
    Unknown,
    PathChanged,
    Expired,
    ConfigurationChanged,
    AlreadyInUse,
    InitialFlightUnacknowledged,
    Congestion,
    RttTooSmall,
    RttTooLarge,
    InvalidObservation,
}

/// One saved RFC 9959 CC parameter set per remote endpoint.
#[derive(Default)]
pub struct CarefulResumeCache {
    saved: BTreeMap<RemoteEndpoint, SavedPath>,
    next_owner: u64,
}

impl CarefulResumeCache {
    pub fn observe(
        &mut self,
        endpoint: RemoteEndpoint,
        observation: Observation,
    ) -> Result<(), PathReject> {
        if observation.saved_cwnd == 0 || observation.saved_rtt == 0 || observation.expires_at == 0
        {
            return Err(PathReject::InvalidObservation);
        }
        if self
            .saved
            .get(&endpoint)
            .is_some_and(|saved| saved.owner.is_some())
        {
            return Err(PathReject::AlreadyInUse);
        }
        self.saved.insert(
            endpoint,
            SavedPath {
                observation,
                owner: None,
                discard_on_release: false,
            },
        );
        Ok(())
    }

    pub fn reconnoitre(
        &mut self,
        saved_endpoint: RemoteEndpoint,
        current_endpoint: RemoteEndpoint,
        input: Reconnaissance,
    ) -> Result<ResumePermit, PathReject> {
        if let Some(saved) = self.saved.get_mut(&saved_endpoint) {
            if saved.owner.is_some() {
                saved.discard_on_release |= saved_endpoint != current_endpoint
                    || input.local_path_changed
                    || input.congestion_detected
                    || input.now >= saved.observation.expires_at
                    || input.configuration_epoch != saved.observation.configuration_epoch;
                return Err(PathReject::AlreadyInUse);
            }
        }
        if saved_endpoint != current_endpoint || input.local_path_changed {
            self.saved.remove(&saved_endpoint);
            return Err(PathReject::PathChanged);
        }
        let Some(saved) = self.saved.get_mut(&saved_endpoint) else {
            return Err(PathReject::Unknown);
        };
        if input.congestion_detected {
            self.saved.remove(&saved_endpoint);
            return Err(PathReject::Congestion);
        }
        if input.now >= saved.observation.expires_at {
            self.saved.remove(&saved_endpoint);
            return Err(PathReject::Expired);
        }
        if input.configuration_epoch != saved.observation.configuration_epoch {
            self.saved.remove(&saved_endpoint);
            return Err(PathReject::ConfigurationChanged);
        }
        if !input.initial_flight_acknowledged {
            return Err(PathReject::InitialFlightUnacknowledged);
        }
        if input.current_min_rtt.saturating_mul(2) <= saved.observation.saved_rtt {
            return Err(PathReject::RttTooSmall);
        }
        if input.current_min_rtt > saved.observation.saved_rtt.saturating_mul(10) {
            return Err(PathReject::RttTooLarge);
        }
        let jump_cwnd = input.max_jump.min(saved.observation.saved_cwnd / 2);
        if jump_cwnd == 0 {
            return Err(PathReject::InvalidObservation);
        }
        let owner = self
            .next_owner
            .checked_add(1)
            .ok_or(PathReject::InvalidObservation)?;
        self.next_owner = owner;
        saved.owner = Some(owner);
        Ok(ResumePermit {
            jump_cwnd,
            paced_rtt: input.current_min_rtt,
            owner,
        })
    }

    pub fn release(
        &mut self,
        endpoint: RemoteEndpoint,
        permit: &ResumePermit,
        congestion_detected: bool,
    ) -> bool {
        if self.saved.get(&endpoint).and_then(|saved| saved.owner) != Some(permit.owner) {
            return false;
        }
        let discard_on_release = self
            .saved
            .get(&endpoint)
            .is_some_and(|saved| saved.discard_on_release);
        if congestion_detected || discard_on_release {
            self.saved.remove(&endpoint);
        } else if let Some(saved) = self.saved.get_mut(&endpoint) {
            saved.owner = None;
        }
        true
    }
}

fn validate_total_units(total_units: u64) -> Result<(), Error> {
    if total_units == 0 || total_units > MAX_UNITS_PER_OBJECT {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn validate_checkpoint_window(total_units: u64, checkpoint_window: usize) -> Result<(), Error> {
    let checkpoint_window =
        u64::try_from(checkpoint_window).map_err(|_| Error::InvalidConfiguration)?;
    if checkpoint_window == 0 || checkpoint_window > total_units {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn validate_reserved_capacity(objects: &BTreeMap<SubjectId, StoredObject>) -> Result<(), Error> {
    let payload = encode_snapshot(objects)?;
    let record = encode_record(&payload)?;
    let record_length = u64::try_from(record.len()).map_err(|_| Error::TooLarge)?;
    if !compact_fits(record_length) {
        return Err(Error::TooLarge);
    }
    let worst_payload_length = worst_case_snapshot_payload_length(objects)?;
    let worst_record_length = worst_payload_length
        .checked_add(RECORD_HEADER_BYTES)
        .and_then(|length| length.checked_add(RECORD_CHECKSUM_BYTES))
        .ok_or(Error::TooLarge)?;
    if compact_fits(worst_record_length) {
        Ok(())
    } else {
        Err(Error::TooLarge)
    }
}

fn worst_case_snapshot_payload_length(
    objects: &BTreeMap<SubjectId, StoredObject>,
) -> Result<u64, Error> {
    let mut length = 1_u64
        .checked_add(uvarint_length(
            u64::try_from(objects.len()).map_err(|_| Error::TooLarge)?,
        ))
        .ok_or(Error::TooLarge)?;
    for object in objects.values() {
        validate_total_units(object.total_units)?;
        length = length
            .checked_add(worst_case_object_payload_length(object.total_units)?)
            .ok_or(Error::TooLarge)?;
    }
    Ok(length)
}

/// Worst-case snapshot bytes for one object: identity, total units, and a
/// fully fragmented checkpoint set.
fn worst_case_object_payload_length(total_units: u64) -> Result<u64, Error> {
    42_u64
        .checked_add(uvarint_length(total_units))
        .and_then(|length| length.checked_add(worst_case_ranges_length(total_units)))
        .ok_or(Error::TooLarge)
}

fn worst_case_ranges_length(total_units: u64) -> u64 {
    let range_count = total_units.div_ceil(2);
    uvarint_length(range_count).saturating_add(range_count.saturating_mul(
        uvarint_length(total_units.saturating_sub(1)).saturating_add(uvarint_length(total_units)),
    ))
}

fn uvarint_length(value: u64) -> u64 {
    let significant_bits = (u64::BITS - value.leading_zeros()).max(1);
    u64::from(significant_bits.div_ceil(7))
}

fn store_size_fits(length: u64) -> bool {
    length <= MAX_STORE_BYTES
}

fn reserve_requires_compaction(path_exists: bool, current_length: u64) -> bool {
    !path_exists || should_compact(current_length)
}

fn should_compact(projected: u64) -> bool {
    projected >= COMPACTION_THRESHOLD
}

fn encode_snapshot(objects: &BTreeMap<SubjectId, StoredObject>) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    output.push(SNAPSHOT_RECORD);
    encode_uvarint(
        u64::try_from(objects.len()).map_err(|_| Error::TooLarge)?,
        &mut output,
    );
    for (subject, object) in objects {
        validate_total_units(object.total_units)?;
        encode_subject(subject, &mut output);
        encode_uvarint(object.total_units, &mut output);
        encode_ranges(&object.checkpointed, &mut output);
    }
    validate_payload_length(u64::try_from(output.len()).map_err(|_| Error::TooLarge)?)?;
    Ok(output)
}

fn decode_store(path: &Path) -> Result<BTreeMap<SubjectId, StoredObject>, Error> {
    let bytes = read_bounded_store(path, MAX_STORE_BYTES)?;
    let length = u64::try_from(bytes.len()).map_err(|_| Error::Corrupt)?;
    if !(MIN_STORE_BYTES..=MAX_STORE_BYTES).contains(&length) {
        return Err(Error::Corrupt);
    }
    let mut decoder = Decoder::new(&bytes);
    if decoder.take(MAGIC.len())? != MAGIC {
        return Err(Error::Corrupt);
    }
    // Replay accumulates raw runs and normalises once at the end. Merging into
    // a UnitRanges per record would copy every run replayed so far, and a valid
    // log can hold hundreds of thousands of checkpoint records.
    let mut objects: BTreeMap<SubjectId, ReplayObject> = BTreeMap::new();
    while !decoder.is_empty() {
        let record_start = bytes.len().saturating_sub(decoder.remaining.len());
        if decoder.remaining.len() < RECORD_HEADER_BYTES as usize {
            truncate_torn_tail(path, record_start)?;
            return settle(objects);
        }
        let record_length = usize::try_from(decoder.u32()?).map_err(|_| Error::Corrupt)?;
        if !record_length_valid(record_length) {
            return Err(Error::Corrupt);
        }
        let required = record_length
            .checked_add(RECORD_CHECKSUM_BYTES as usize)
            .ok_or(Error::Corrupt)?;
        if decoder.remaining.len() < required {
            truncate_torn_tail(path, record_start)?;
            return settle(objects);
        }
        let record = decoder.take(record_length)?;
        let checksum = decoder.take(RECORD_CHECKSUM_BYTES as usize)?;
        let digest = blake3::hash(record);
        if checksum != &digest.as_bytes()[..RECORD_CHECKSUM_BYTES as usize] {
            return Err(Error::Corrupt);
        }
        apply_record(record, &mut objects)?;
    }
    settle(objects)
}

/// Runs for one object as replay found them: unordered, possibly overlapping.
struct ReplayObject {
    total_units: u64,
    runs: Vec<(u64, u64)>,
}

/// Normalises every replayed object once the log has been read.
fn settle(
    objects: BTreeMap<SubjectId, ReplayObject>,
) -> Result<BTreeMap<SubjectId, StoredObject>, Error> {
    objects
        .into_iter()
        .map(|(subject, object)| {
            let checkpointed = UnitRanges::from_runs(object.runs).map_err(|_| Error::Corrupt)?;
            Ok((
                subject,
                StoredObject {
                    total_units: object.total_units,
                    checkpointed,
                },
            ))
        })
        .collect()
}

fn truncate_torn_tail(path: &Path, valid_length: usize) -> Result<(), Error> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(u64::try_from(valid_length).map_err(|_| Error::TooLarge)?)?;
    file.sync_all()?;
    #[cfg(unix)]
    File::open(path.parent().ok_or(Error::InvalidConfiguration)?)?.sync_all()?;
    Ok(())
}

fn record_length_valid(record_length: usize) -> bool {
    record_length != 0 && record_length <= MAX_STORE_BYTES as usize
}

fn encode_reserve(subject: SubjectId, total_units: u64) -> Result<Vec<u8>, Error> {
    validate_total_units(total_units)?;
    let mut output = Vec::with_capacity(1 + 42 + 10);
    output.push(RESERVE_RECORD);
    encode_subject(&subject, &mut output);
    encode_uvarint(total_units, &mut output);
    Ok(output)
}

fn encode_checkpoint(
    subject: SubjectId,
    total_units: u64,
    units: &UnitRanges,
) -> Result<Vec<u8>, Error> {
    validate_total_units(total_units)?;
    let mut output = Vec::new();
    output.push(CHECKPOINT_RECORD);
    encode_subject(&subject, &mut output);
    encode_uvarint(total_units, &mut output);
    encode_ranges(units, &mut output);
    Ok(output)
}

fn encode_subject(subject: &SubjectId, output: &mut Vec<u8>) {
    output.extend_from_slice(&subject.suite.to_be_bytes());
    output.extend_from_slice(&subject.root);
    output.extend_from_slice(&subject.length.to_be_bytes());
}

fn encode_ranges(units: &UnitRanges, output: &mut Vec<u8>) {
    // The set is already run-length in memory, so encoding is a copy rather
    // than a scan that rediscovers the runs.
    encode_uvarint(u64::try_from(units.run_count()).unwrap_or(u64::MAX), output);
    for (start, length) in units.runs() {
        encode_uvarint(start, output);
        encode_uvarint(length, output);
    }
}

fn difference(merged: &UnitRanges, previous: &UnitRanges) -> UnitRanges {
    merged.difference(previous)
}

fn encode_uvarint(mut value: u64, output: &mut Vec<u8>) {
    for _ in 0..10 {
        let low = (value as u8) & 0x7f;
        if value < 0x80 {
            output.push(low);
            return;
        }
        output.push(low + 0x80);
        value >>= 7;
    }
    unreachable!("a u64 varint fits in ten bytes");
}

fn encode_record(payload: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u32::try_from(payload.len()).map_err(|_| Error::TooLarge)?;
    let mut output = Vec::with_capacity(
        RECORD_HEADER_BYTES as usize + payload.len() + RECORD_CHECKSUM_BYTES as usize,
    );
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
    output.extend_from_slice(&blake3::hash(payload).as_bytes()[..RECORD_CHECKSUM_BYTES as usize]);
    Ok(output)
}

fn append_record(path: &Path, payload: &[u8]) -> Result<(), Error> {
    let record = encode_record(payload)?;
    let record_length = u64::try_from(record.len()).map_err(|_| Error::TooLarge)?;
    let current_length = file_len(path)?;
    let header_length = append_header_length(current_length);
    if !append_fits(current_length, header_length, record_length) {
        return Err(Error::TooLarge);
    }
    // One test for both effects of creating the file: the magic prefix is
    // written, and the directory entry needs an fsync. Growing an existing file
    // changes no directory entry, so the parent fsync is charged once per store
    // rather than once per checkpoint.
    let created = current_length == 0;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if created {
        file.write_all(MAGIC)?;
    }
    file.write_all(&record)?;
    file.sync_all()?;
    #[cfg(unix)]
    if created {
        File::open(path.parent().ok_or(Error::InvalidConfiguration)?)?.sync_all()?;
    }
    Ok(())
}

fn append_header_length(current_length: u64) -> u64 {
    if current_length == 0 {
        MAGIC.len() as u64
    } else {
        0
    }
}

fn compact_fits(record_length: u64) -> bool {
    record_length
        .checked_add(MAGIC.len() as u64)
        .is_some_and(store_size_fits)
}

fn append_fits(current_length: u64, header_length: u64, record_length: u64) -> bool {
    current_length
        .checked_add(header_length)
        .and_then(|length| length.checked_add(record_length))
        .is_some_and(store_size_fits)
}

fn apply_record(
    record: &[u8],
    objects: &mut BTreeMap<SubjectId, ReplayObject>,
) -> Result<(), Error> {
    let mut decoder = Decoder::new(record);
    let kind = decoder.take(1)?.first().copied().ok_or(Error::Corrupt)?;
    match kind {
        RESERVE_RECORD => {
            let subject = decode_subject(&mut decoder)?;
            let total_units = decoder.uvar()?;
            validate_total_units(total_units)?;
            if !decoder.is_empty() {
                return Err(Error::Corrupt);
            }
            if let Some(existing) = objects.get(&subject) {
                if existing.total_units != total_units {
                    return Err(Error::Corrupt);
                }
            } else {
                objects.insert(
                    subject,
                    ReplayObject {
                        total_units,
                        runs: Vec::new(),
                    },
                );
            }
        }
        CHECKPOINT_RECORD => {
            let subject = decode_subject(&mut decoder)?;
            let total_units = decoder.uvar()?;
            validate_total_units(total_units)?;
            let delta = decode_run_list(&mut decoder, total_units)?;
            if !decoder.is_empty() {
                return Err(Error::Corrupt);
            }
            let Some(object) = objects.get_mut(&subject) else {
                return Err(Error::Corrupt);
            };
            if object.total_units != total_units {
                return Err(Error::Corrupt);
            }
            // Append only. The whole log is normalised once at the end.
            object.runs.extend(delta);
        }
        SNAPSHOT_RECORD => {
            let count = decoder.uvar()?;
            let mut snapshot = BTreeMap::new();
            for _ in 0..count {
                let subject = decode_subject(&mut decoder)?;
                let total_units = decoder.uvar()?;
                validate_total_units(total_units)?;
                let runs = decode_run_list(&mut decoder, total_units)?;
                if snapshot
                    .insert(subject, ReplayObject { total_units, runs })
                    .is_some()
                {
                    return Err(Error::Corrupt);
                }
            }
            if !decoder.is_empty() {
                return Err(Error::Corrupt);
            }
            *objects = snapshot;
        }
        _ => return Err(Error::Corrupt),
    }
    Ok(())
}

fn decode_subject(decoder: &mut Decoder<'_>) -> Result<SubjectId, Error> {
    Ok(SubjectId {
        suite: decoder.u16()?,
        root: decoder.array()?,
        length: decoder.u64()?,
    })
}

#[cfg(test)]
fn decode_ranges(decoder: &mut Decoder<'_>, total_units: u64) -> Result<UnitRanges, Error> {
    UnitRanges::from_runs(decode_run_list(decoder, total_units)?).map_err(|_| Error::Corrupt)
}

fn decode_run_list(decoder: &mut Decoder<'_>, total_units: u64) -> Result<Vec<(u64, u64)>, Error> {
    let count = decoder.uvar()?;
    // Runs are separated by at least one absent unit, so an object of n units
    // holds at most ceil(n / 2) of them. Checking that before allocating means
    // a corrupt record cannot ask for a reservation the object could never
    // justify.
    if count > total_units.div_ceil(2) {
        return Err(Error::Corrupt);
    }
    let mut runs = Vec::with_capacity(usize::try_from(count).map_err(|_| Error::Corrupt)?);
    let mut previous_end = 0_u64;
    for _ in 0..count {
        let start = decoder.uvar()?;
        let length = decoder.uvar()?;
        if length == 0 || start < previous_end {
            return Err(Error::Corrupt);
        }
        let end = start.checked_add(length).ok_or(Error::Corrupt)?;
        if end > total_units {
            return Err(Error::Corrupt);
        }
        // Runs stay run-length all the way in. Expanding them here was one
        // entry per 64 KiB of every object in the store.
        runs.push((start, length));
        previous_end = end;
    }
    Ok(runs)
}

fn read_bounded_store(path: &Path, maximum: u64) -> Result<Vec<u8>, Error> {
    let mut input = File::open(path)?.take(maximum.saturating_add(1));
    let mut output = Vec::with_capacity(4096);
    input.read_to_end(&mut output)?;
    if u64::try_from(output.len()).map_err(|_| Error::TooLarge)? > maximum {
        return Err(Error::TooLarge);
    }
    Ok(output)
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if self.remaining.len() < length {
            return Err(Error::Corrupt);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    fn array(&mut self) -> Result<[u8; 32], Error> {
        self.take(32)?.try_into().map_err(|_| Error::Corrupt)
    }
    fn uvar(&mut self) -> Result<u64, Error> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        loop {
            let byte = self.take(1)?.first().copied().ok_or(Error::Corrupt)?;
            let bits = u64::from(byte & 0x7f);
            if shift >= 64 || (shift == 63 && bits > 1) {
                return Err(Error::Corrupt);
            }
            value |= bits << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift = shift.checked_add(7).ok_or(Error::Corrupt)?;
        }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSignature {
    length: u64,
    tail: [u8; 8],
}

fn file_len(path: &Path) -> Result<u64, Error> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(Error::Io(error)),
    }
}

fn file_signature(path: &Path) -> Result<FileSignature, Error> {
    let length = file_len(path)?;
    if length == 0 {
        return Ok(FileSignature {
            length,
            tail: [0; 8],
        });
    }
    let mut file = File::open(path)?;
    let mut tail = [0; 8];
    let count = usize::try_from(length.min(8)).map_err(|_| Error::TooLarge)?;
    file.seek(SeekFrom::Start(length.saturating_sub(8)))?;
    file.read_exact(&mut tail[..count])?;
    Ok(FileSignature { length, tail })
}

fn temporary_path(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or(Error::InvalidConfiguration)?;
    let mut temporary = name.to_os_string();
    temporary.push(".tmp");
    Ok(path.with_file_name(temporary))
}

fn lock_path(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or(Error::InvalidConfiguration)?;
    let mut lock = name.to_os_string();
    lock.push(".lock");
    Ok(path.with_file_name(lock))
}

fn lock_store(path: &Path) -> Result<File, Error> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path(path)?)?;
    fs4::FileExt::lock(&lock)?;
    Ok(lock)
}

fn validate_payload_length(length: u64) -> Result<(), Error> {
    if length > MAX_STORE_PAYLOAD_BYTES {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(byte: u8) -> SubjectId {
        SubjectId {
            suite: 1,
            root: [byte; 32],
            length: 100,
        }
    }

    /// Builds a checkpoint set from individual units, as the tests think of them.
    fn units(units: impl IntoIterator<Item = u64>) -> UnitRanges {
        let mut set = UnitRanges::new();
        set.extend_units(units);
        set
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vot-resume-{name}-{}-{}",
            std::process::id(),
            subject(name.as_bytes()[0]).root[0]
        ))
    }

    fn write_raw(path: &Path, payload: &[u8]) {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&encode_record(payload).unwrap());
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn checkpoints_accumulate_under_identity_and_subjects_enumerate() {
        // The public write path a fetch checkpoints through: unions
        // accumulate across calls and reopens, identity is held to the
        // reservation, and the subject listing is what lets a caller find
        // what a store continues without knowing it beforehand.
        let path = temp_path("accumulate");
        let _ = fs::remove_file(&path);
        let mut store = ResumeStore::create(&path).unwrap();
        store
            .reserve_many([(subject(0x31), 4), (subject(0x32), 2)])
            .unwrap();
        store
            .checkpoint_units(subject(0x31), 4, &units([0, 2]))
            .unwrap();
        store
            .checkpoint_units(subject(0x31), 4, &units([1]))
            .unwrap();
        drop(store);
        let mut store = ResumeStore::open(&path).unwrap();
        assert_eq!(
            store.checkpointed(subject(0x31)).unwrap(),
            &units([0, 1, 2]),
            "unions accumulate across calls and reopens"
        );
        assert_eq!(
            store.subjects().collect::<Vec<_>>(),
            vec![subject(0x31), subject(0x32)],
            "every reserved subject, in key order"
        );
        assert!(matches!(
            store.checkpoint_units(subject(0x31), 5, &units([3])),
            Err(Error::IdentityMismatch)
        ));
        assert!(matches!(
            store.checkpoint_units(subject(0x33), 4, &units([0])),
            Err(Error::IdentityMismatch)
        ));
        assert!(matches!(
            store.checkpoint_units(subject(0x31), 4, &units([4])),
            Err(Error::InvalidUnit)
        ));
        store.remove().unwrap();
    }

    #[test]
    fn a_created_store_exists_at_once_and_a_removed_one_is_gone_whole() {
        // ADR-0032: presence beside a partial bundle is what says the
        // bundle may be continued, so creation puts the file on disk
        // before any checkpoint could; removal takes the lock file too,
        // so a completed bundle looks exactly as one fetched without a
        // store.
        let path = temp_path("created");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path(&path).unwrap());

        let store = ResumeStore::create(&path).unwrap();
        assert!(path.exists(), "created means on disk, empty or not");
        // Creating over an existing store keeps what it holds.
        drop(store);
        let mut store = ResumeStore::create(&path).unwrap();
        store.reserve_many([(subject(0x21), 4)]).unwrap();
        drop(store);
        let store = ResumeStore::create(&path).unwrap();
        assert!(
            store.checkpointed(subject(0x21)).is_some(),
            "creation over an existing store reopened it"
        );

        store.remove().unwrap();
        assert!(!path.exists(), "the store is gone");
        assert!(
            !lock_path(&path).unwrap().exists(),
            "and its lock went with it"
        );
        // Removing what is already gone is nothing to report.
        ResumeStore::create(&path).unwrap().remove().unwrap();
        ResumeStore::open(&path).unwrap().remove().unwrap();
    }

    #[test]
    fn store_is_keyed_by_subject_and_rejects_corruption() {
        let path = temp_path("store");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(1), 10, 3).unwrap();
        tracker.begin_unit(0).unwrap();
        tracker.complete_unit(0).unwrap();
        tracker.checkpoint(&mut store).unwrap();
        let mut reopened = ResumeStore::open(&path).unwrap();
        assert!(reopened.checkpointed(subject(1)).unwrap().contains(0));
        assert!(reopened.checkpointed(subject(9)).is_none());
        assert!(matches!(
            ResumeTracker::discover(&mut reopened, subject(1), 11, 3),
            Err(Error::IdentityMismatch)
        ));
        let mut rediscovered = ResumeTracker::discover(&mut reopened, subject(1), 10, 3).unwrap();
        assert!(!rediscovered.begin_unit(0).unwrap());
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn torn_final_record_is_truncated_and_valid_prefix_replayed() {
        let path = temp_path("torn-tail");
        let mut store = ResumeStore::open(&path).unwrap();
        store.reserve_many([(subject(11), 3)]).unwrap();
        let valid_length = fs::metadata(&path).unwrap().len();
        let torn_record = encode_record(&encode_reserve(subject(12), 3).unwrap()).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(&torn_record[..torn_record.len() - 1]);
        fs::write(&path, bytes).unwrap();

        let reopened = ResumeStore::open(&path).unwrap();
        assert!(reopened.checkpointed(subject(11)).is_some());
        assert!(reopened.checkpointed(subject(12)).is_none());
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_length);

        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(&[0, 0]);
        fs::write(&path, bytes).unwrap();
        ResumeStore::open(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_length);

        let exact_header_path = temp_path("torn-header-boundary");
        let mut exact_header = MAGIC.to_vec();
        exact_header.extend_from_slice(&vec![0; RECORD_HEADER_BYTES as usize - 1]);
        fs::write(&exact_header_path, exact_header).unwrap();
        let reopened = ResumeStore::open(&exact_header_path).unwrap();
        assert!(reopened.objects.is_empty());
        assert_eq!(
            fs::metadata(&exact_header_path).unwrap().len(),
            MAGIC.len() as u64
        );
        fs::remove_file(&exact_header_path).unwrap();
        fs::remove_file(lock_path(&exact_header_path).unwrap()).unwrap();

        // A tail of exactly one header is enough to read a length from, so it
        // is decoded rather than treated as torn. A zero length is not a record
        // that was cut short, it is a corrupt one.
        let zero_header_path = temp_path("zero-length-header");
        let mut zero_header = MAGIC.to_vec();
        zero_header.extend_from_slice(&vec![0; RECORD_HEADER_BYTES as usize]);
        fs::write(&zero_header_path, zero_header).unwrap();
        assert!(matches!(
            ResumeStore::open(&zero_header_path),
            Err(Error::Corrupt)
        ));
        fs::remove_file(&zero_header_path).unwrap();
        fs::remove_file(lock_path(&zero_header_path).unwrap()).unwrap();

        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn retransmission_is_bounded_by_window_plus_active_units() {
        let path = temp_path("bounded");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(2), 20, 4).unwrap();
        for unit in 0..7 {
            tracker.begin_unit(unit).unwrap();
            let checkpoint_due = tracker.complete_unit(unit).unwrap();
            assert!(!tracker.begin_unit(unit).unwrap());
            if checkpoint_due {
                tracker.checkpoint(&mut store).unwrap();
            }
        }
        tracker.begin_unit(7).unwrap();
        tracker.begin_unit(8).unwrap();
        assert_eq!(tracker.retransmission_units_after_crash(), 5);
        assert_eq!(tracker.retransmission_bound(), 6);
        assert!(tracker.retransmission_units_after_crash() <= tracker.retransmission_bound());

        let mut reopened = ResumeStore::open(&path).unwrap();
        let restarted = ResumeTracker::discover(&mut reopened, subject(2), 20, 4).unwrap();
        for unit in 0..4 {
            assert!(restarted.is_checkpointed(unit));
        }
        assert_eq!(restarted.missing_units().take(21).count(), 16);
        assert_eq!(
            restarted.missing_units().take(21).collect::<Vec<_>>(),
            (4..20).collect::<Vec<_>>()
        );
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn full_window_blocks_completion_until_checkpoint_succeeds() {
        let path = temp_path("full-window");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(7), 4, 2).unwrap();
        for unit in 0..3 {
            tracker.begin_unit(unit).unwrap();
        }
        assert!(!tracker.complete_unit(0).unwrap());
        assert!(tracker.complete_unit(1).unwrap());
        assert!(matches!(
            tracker.complete_unit(2),
            Err(Error::CheckpointRequired)
        ));
        assert_eq!(tracker.retransmission_units_after_crash(), 3);
        assert_eq!(tracker.retransmission_bound(), 3);
        tracker.checkpoint(&mut store).unwrap();
        assert!(!tracker.complete_unit(2).unwrap());
        assert_eq!(tracker.retransmission_units_after_crash(), 1);
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn repeated_checkpoints_append_and_replay() {
        let path = temp_path("repeated-checkpoint");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(8), 3, 1).unwrap();
        tracker.begin_unit(0).unwrap();
        assert!(tracker.complete_unit(0).unwrap());
        tracker.checkpoint(&mut store).unwrap();
        tracker.begin_unit(1).unwrap();
        assert!(tracker.complete_unit(1).unwrap());
        tracker.checkpoint(&mut store).unwrap();
        let reopened = ResumeStore::open(&path).unwrap();
        assert_eq!(reopened.checkpointed(subject(8)).unwrap(), &units([0, 1]));
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn stale_store_writers_reload_and_merge_checkpointed_units() {
        let path = temp_path("merged-checkpoints");
        let mut first_store = ResumeStore::open(&path).unwrap();
        let mut second_store = ResumeStore::open(&path).unwrap();
        let mut first = ResumeTracker::discover(&mut first_store, subject(9), 3, 1).unwrap();
        let mut second = ResumeTracker::discover(&mut second_store, subject(9), 3, 1).unwrap();
        first.begin_unit(0).unwrap();
        first.complete_unit(0).unwrap();
        second.begin_unit(1).unwrap();
        second.complete_unit(1).unwrap();

        first.checkpoint(&mut first_store).unwrap();
        second.checkpoint(&mut second_store).unwrap();

        let reopened = ResumeStore::open(&path).unwrap();
        assert_eq!(reopened.checkpointed(subject(9)).unwrap(), &units([0, 1]));
        assert!(second.is_checkpointed(0));
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn checkpoint_waits_for_the_store_transaction_lock() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        let path = temp_path("checkpoint-lock");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(10), 1, 1).unwrap();
        let held = lock_store(&path).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            tracker.begin_unit(0).unwrap();
            tracker.complete_unit(0).unwrap();
            started_tx.send(()).unwrap();
            finished_tx.send(tracker.checkpoint(&mut store)).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ));
        drop(held);
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        writer.join().unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn open_waits_for_the_store_transaction_lock() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        let path = temp_path("open-lock");
        let mut store = ResumeStore::open(&path).unwrap();
        store.reserve_many([(subject(10), 1)]).unwrap();
        let held = lock_store(&path).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let open_path = path.clone();
        let reader = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx.send(ResumeStore::open(open_path)).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ));
        drop(held);
        let reopened = finished_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert!(reopened.checkpointed(subject(10)).is_some());
        reader.join().unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic() {
        assert_eq!(MAX_STORE_BYTES, 67_108_864);
        assert_eq!(MAX_STORE_PAYLOAD_BYTES, 67_108_844);
        assert_eq!(MIN_STORE_BYTES, 8);
        assert_eq!(MAX_UNITS_PER_OBJECT, 16_777_198);
        assert!(validate_payload_length(MAX_STORE_PAYLOAD_BYTES).is_ok());
        assert!(matches!(
            validate_payload_length(MAX_STORE_PAYLOAD_BYTES + 1),
            Err(Error::TooLarge)
        ));
        let bounded = temp_path("bounded-read");
        fs::write(&bounded, b"12345").unwrap();
        assert_eq!(read_bounded_store(&bounded, 5).unwrap(), b"12345");
        assert!(matches!(
            read_bounded_store(&bounded, 4),
            Err(Error::TooLarge)
        ));
        fs::write(
            &bounded,
            vec![0; usize::try_from(MIN_STORE_BYTES - 1).unwrap()],
        )
        .unwrap();
        assert!(matches!(ResumeStore::open(&bounded), Err(Error::Corrupt)));
        fs::remove_file(bounded).unwrap();

        let missing_root = temp_path("missing-parent");
        fs::create_dir(&missing_root).unwrap();
        let missing_parent = missing_root.join("state");
        let mut store = ResumeStore::open(&missing_parent).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(3), 1, 1).unwrap();
        fs::remove_file(&missing_parent).unwrap();
        fs::remove_file(lock_path(&missing_parent).unwrap()).unwrap();
        fs::remove_dir(&missing_root).unwrap();
        tracker.begin_unit(0).unwrap();
        tracker.complete_unit(0).unwrap();
        assert!(matches!(tracker.checkpoint(&mut store), Err(Error::Io(_))));
        assert_eq!(tracker.retransmission_units_after_crash(), 1);
        assert!(!tracker.is_checkpointed(0));

        let bounds_path = temp_path("bounds");
        let mut store = ResumeStore::open(&bounds_path).unwrap();
        assert!(matches!(
            ResumeTracker::discover(&mut store, subject(4), 0, 1),
            Err(Error::InvalidConfiguration)
        ));
        assert!(ResumeTracker::discover(&mut store, subject(4), MAX_UNITS_PER_OBJECT, 1).is_ok());
        assert!(matches!(
            ResumeTracker::discover(&mut store, subject(4), MAX_UNITS_PER_OBJECT + 1, 1),
            Err(Error::InvalidConfiguration)
        ));
        fs::remove_file(&bounds_path).unwrap();
        fs::remove_file(lock_path(&bounds_path).unwrap()).unwrap();

        let exact_path = temp_path("exact-bounds");
        let mut exact_store = ResumeStore::open(&exact_path).unwrap();
        assert!(matches!(
            ResumeTracker::discover(&mut exact_store, subject(6), 1, usize::MAX),
            Err(Error::InvalidConfiguration)
        ));
        assert!(matches!(
            ResumeTracker::discover(&mut exact_store, subject(6), 1, 2),
            Err(Error::InvalidConfiguration)
        ));
        let mut exact = ResumeTracker::discover(&mut exact_store, subject(6), 1, 1).unwrap();
        assert!(exact.begin_unit(0).unwrap());
        assert!(matches!(exact.begin_unit(1), Err(Error::InvalidUnit)));
        fs::remove_file(&exact_path).unwrap();
        fs::remove_file(lock_path(&exact_path).unwrap()).unwrap();
    }

    #[test]
    fn reservation_capacity_includes_worst_case_checkpoint_ranges() {
        let mut one = BTreeMap::new();
        one.insert(
            subject(17),
            StoredObject {
                total_units: MAX_UNITS_PER_OBJECT,
                checkpointed: UnitRanges::new(),
            },
        );
        assert!(validate_reserved_capacity(&one).is_ok());
        assert_eq!(worst_case_ranges_length(1), 3);
        assert_eq!(
            [
                uvarint_length(0),
                uvarint_length(127),
                uvarint_length(128),
                uvarint_length(16_383),
                uvarint_length(16_384),
                uvarint_length(u64::MAX),
            ],
            [1, 1, 2, 2, 3, 10]
        );

        let mut two = one.clone();
        two.insert(
            subject(18),
            StoredObject {
                total_units: MAX_UNITS_PER_OBJECT,
                checkpointed: UnitRanges::new(),
            },
        );
        assert!(matches!(
            validate_reserved_capacity(&two),
            Err(Error::TooLarge)
        ));
    }

    #[test]
    fn max_units_per_object_is_derived_from_the_snapshot_format() {
        // A snapshot record holding one object: magic, record header, record
        // checksum, the snapshot kind byte, and the object-count varint.
        let ceiling = MAX_STORE_BYTES
            - MAGIC.len() as u64
            - RECORD_HEADER_BYTES
            - RECORD_CHECKSUM_BYTES
            - 1
            - uvarint_length(1);
        assert!(worst_case_object_payload_length(MAX_UNITS_PER_OBJECT).unwrap() <= ceiling);
        assert!(worst_case_object_payload_length(MAX_UNITS_PER_OBJECT + 1).unwrap() > ceiling);
        // The cap is a unit count; at 64 KiB units it admits just under 1 TiB.
        let max_object_bytes = MAX_UNITS_PER_OBJECT * 65_536;
        assert!(max_object_bytes < 1 << 40);
        assert!(max_object_bytes > (1 << 40) - (2 << 20));
    }

    #[test]
    fn resume_store_boundaries_are_explicit() {
        assert_eq!(COMPACTION_THRESHOLD, 50_331_648);
        assert!(store_size_fits(MAX_STORE_BYTES - 1));
        assert!(store_size_fits(MAX_STORE_BYTES));
        assert!(!store_size_fits(MAX_STORE_BYTES + 1));
        assert!(reserve_requires_compaction(false, COMPACTION_THRESHOLD - 1));
        assert!(!reserve_requires_compaction(true, COMPACTION_THRESHOLD - 1));
        assert!(reserve_requires_compaction(true, COMPACTION_THRESHOLD));
        assert!(!should_compact(COMPACTION_THRESHOLD - 1));
        assert!(should_compact(COMPACTION_THRESHOLD));
        assert!(append_fits(
            0,
            MAGIC.len() as u64,
            MAX_STORE_BYTES - MAGIC.len() as u64
        ));
        assert!(!append_fits(
            0,
            MAGIC.len() as u64,
            MAX_STORE_BYTES - MAGIC.len() as u64 + 1
        ));
        assert!(!append_fits(u64::MAX, 0, 1));
        assert_eq!(append_header_length(0), MAGIC.len() as u64);
        assert_eq!(append_header_length(1), 0);
        assert!(!record_length_valid(0));
        assert!(record_length_valid(1));
        assert!(record_length_valid(MAX_STORE_BYTES as usize));
        assert!(!record_length_valid(MAX_STORE_BYTES as usize + 1));
        assert!(compact_fits(MAX_STORE_BYTES - MAGIC.len() as u64));
        assert!(!compact_fits(MAX_STORE_BYTES - MAGIC.len() as u64 + 1));
        assert!(!compact_fits(u64::MAX));
        assert!(validate_checkpoint_window(1, 1).is_ok());
        assert!(matches!(
            validate_checkpoint_window(1, 0),
            Err(Error::InvalidConfiguration)
        ));
        assert!(matches!(
            validate_checkpoint_window(1, 2),
            Err(Error::InvalidConfiguration)
        ));
        let mut invalid_objects = BTreeMap::new();
        invalid_objects.insert(
            subject(15),
            StoredObject {
                total_units: 0,
                checkpointed: UnitRanges::new(),
            },
        );
        assert!(matches!(
            validate_reserved_capacity(&invalid_objects),
            Err(Error::InvalidConfiguration)
        ));
    }

    #[test]
    fn resume_codecs_round_trip() {
        let checkpointed = units([1, 2, 4, 7, 8]);
        let mut encoded_ranges = Vec::new();
        encode_ranges(&checkpointed, &mut encoded_ranges);
        let mut range_decoder = Decoder::new(&encoded_ranges);
        let decoded_ranges = decode_ranges(&mut range_decoder, 9).unwrap();
        assert!(range_decoder.is_empty());
        assert_eq!(decoded_ranges, checkpointed);
        // Three runs, and the encoding says so rather than listing five units.
        assert_eq!(checkpointed.run_count(), 3);
        assert_eq!(encoded_ranges.first().copied(), Some(3));

        let mut encoded_varint = Vec::new();
        encode_uvarint(128, &mut encoded_varint);
        assert_eq!(encoded_varint, [0x80, 0x01]);
        encoded_varint.clear();
        encode_uvarint(255, &mut encoded_varint);
        assert_eq!(encoded_varint, [0xff, 0x01]);
        let mut valid_u64 = vec![0x80; 9];
        valid_u64.push(0x01);
        assert_eq!(Decoder::new(&valid_u64).uvar().unwrap(), 1_u64 << 63);
        let mut invalid_u64 = vec![0x80; 9];
        invalid_u64.push(0x02);
        assert!(matches!(
            Decoder::new(&invalid_u64).uvar(),
            Err(Error::Corrupt)
        ));

        let mut snapshot_objects = BTreeMap::new();
        snapshot_objects.insert(
            subject(11),
            StoredObject {
                total_units: 9,
                checkpointed: checkpointed.clone(),
            },
        );
        let snapshot = encode_snapshot(&snapshot_objects).unwrap();
        assert_eq!(snapshot.first().copied(), Some(SNAPSHOT_RECORD));
        let mut replayed_snapshot = BTreeMap::new();
        apply_record(&snapshot, &mut replayed_snapshot).unwrap();
        assert_eq!(settle(replayed_snapshot).unwrap(), snapshot_objects);

        let reserve = encode_reserve(subject(12), 42).unwrap();
        assert_eq!(reserve.first().copied(), Some(RESERVE_RECORD));
        let mut replayed_reserve = BTreeMap::new();
        apply_record(&reserve, &mut replayed_reserve).unwrap();
        assert_eq!(replayed_reserve[&subject(12)].total_units, 42);
        let conflicting_reserve = encode_reserve(subject(12), 43).unwrap();
        assert!(matches!(
            apply_record(&conflicting_reserve, &mut replayed_reserve),
            Err(Error::Corrupt)
        ));
    }

    #[test]
    fn resume_append_log_replays_and_preserves_errors() {
        let compact_path = temp_path("compact-codecs");
        let mut compact_objects = BTreeMap::new();
        compact_objects.insert(
            subject(14),
            StoredObject {
                total_units: 2,
                checkpointed: units([0]),
            },
        );
        ResumeStore::compact(&compact_path, &compact_objects).unwrap();
        assert!(compact_path.exists());
        assert_eq!(
            ResumeStore::open(&compact_path)
                .unwrap()
                .checkpointed(subject(14))
                .unwrap(),
            &units([0])
        );
        fs::remove_file(&compact_path).unwrap();

        let path = temp_path("append-codecs");
        let reserve = encode_reserve(subject(12), 42).unwrap();
        append_record(&path, &reserve).unwrap();
        let checkpoint = encode_checkpoint(subject(12), 42, &units([3])).unwrap();
        append_record(&path, &checkpoint).unwrap();
        let decoded_store = decode_store(&path).unwrap();
        assert_eq!(decoded_store[&subject(12)].checkpointed, units([3]));
        fs::remove_file(&path).unwrap();

        // The most fragmented an object can be is every other unit, and that
        // exact shape has to decode.
        let alternating = units([0, 2, 4, 6, 8]);
        assert_eq!(alternating.run_count(), 5);
        let mut encoded_alternating = Vec::new();
        encode_ranges(&alternating, &mut encoded_alternating);
        assert_eq!(
            decode_ranges(&mut Decoder::new(&encoded_alternating), 9).unwrap(),
            alternating
        );

        // One more run than the object can hold, and a count no object could
        // ever justify, are both refused before anything is sized from them.
        let mut over_count = Vec::new();
        encode_uvarint(6, &mut over_count);
        assert!(matches!(
            decode_ranges(&mut Decoder::new(&over_count), 9),
            Err(Error::Corrupt)
        ));
        let mut absurd_count = Vec::new();
        encode_uvarint(u64::MAX, &mut absurd_count);
        assert!(matches!(
            decode_ranges(&mut Decoder::new(&absurd_count), 4),
            Err(Error::Corrupt)
        ));

        for malformed in [&[1, 0, 0][..], &[2, 0, 2, 1, 1][..]] {
            let mut malformed_decoder = Decoder::new(malformed);
            assert!(matches!(
                decode_ranges(&mut malformed_decoder, 4),
                Err(Error::Corrupt)
            ));
        }

        let file_path = temp_path("file-len");
        assert_eq!(file_len(&file_path).unwrap(), 0);
        fs::write(&file_path, b"abc").unwrap();
        assert_eq!(file_len(&file_path).unwrap(), 3);
        fs::remove_file(&file_path).unwrap();
        assert!(matches!(
            file_len(Path::new("\0")),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));

        let reserve_many_path = temp_path("reserve-many-identity");
        let mut reserve_many_store = ResumeStore::open(&reserve_many_path).unwrap();
        reserve_many_store.reserve_many([(subject(16), 2)]).unwrap();
        assert!(matches!(
            reserve_many_store.reserve_many([(subject(16), 3)]),
            Err(Error::IdentityMismatch)
        ));
        fs::remove_file(&reserve_many_path).unwrap();
        fs::remove_file(lock_path(&reserve_many_path).unwrap()).unwrap();

        let no_op_path = temp_path("no-op-checkpoint");
        let mut store = ResumeStore::open(&no_op_path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(13), 2, 1).unwrap();
        let before = file_len(&no_op_path).unwrap();
        tracker.checkpoint(&mut store).unwrap();
        assert_eq!(file_len(&no_op_path).unwrap(), before);
        fs::remove_file(&no_op_path).unwrap();
        fs::remove_file(lock_path(&no_op_path).unwrap()).unwrap();
    }

    // The two million-object tests are the whole runtime of this suite: 6.3s of
    // 6.7s. Mutation testing reruns the suite once per mutant, so leaving them
    // in the default set charges that 272 times. They run in their own CI step
    // instead.
    #[test]
    #[ignore = "scale test, run with --ignored"]
    fn replaying_many_checkpoint_records_stays_linear() {
        // Every record adds one isolated run near the front, which is the shape
        // that made replay copy all prior runs per record. Twenty thousand of
        // them has to reopen promptly.
        let path = temp_path("replay-many-checkpoints");
        let object = subject(21);
        let total_units = 100_000;
        append_record(&path, &encode_reserve(object, total_units).unwrap()).unwrap();
        for index in (0..20_000).rev() {
            let record = encode_checkpoint(object, total_units, &units([index * 2])).unwrap();
            append_record(&path, &record).unwrap();
        }

        let reopened = ResumeStore::open(&path).unwrap();
        let held = reopened.checkpointed(object).unwrap();
        assert_eq!(held.count(), 20_000);
        assert_eq!(held.run_count(), 20_000);
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn a_large_contiguous_object_costs_one_run_in_memory() {
        // The point of holding checkpoint state as runs. At the maximum object
        // size a per-unit set would be sixteen million entries; a transfer that
        // has not lost anything is one run, and one gap makes it two.
        let path = temp_path("run-length-memory");
        let subject = SubjectId {
            suite: 1,
            root: [0x5c; 32],
            length: MAX_UNITS_PER_OBJECT * 65_536,
        };
        let mut store = ResumeStore::open(&path).unwrap();
        store
            .reserve_many([(subject, MAX_UNITS_PER_OBJECT)])
            .unwrap();
        store
            .save_object(subject, MAX_UNITS_PER_OBJECT, &units(0..250_000))
            .unwrap();
        let held = store.checkpointed(subject).unwrap();
        assert_eq!(held.count(), 250_000);
        assert_eq!(held.run_count(), 1);

        let mut fragmented = units(0..250_000);
        fragmented.extend_units([250_001]);
        store
            .save_object(subject, MAX_UNITS_PER_OBJECT, &fragmented)
            .unwrap();
        let held = store.checkpointed(subject).unwrap();
        assert_eq!(held.count(), 250_001);
        assert_eq!(held.run_count(), 2);

        // And it survives a reload, still as runs.
        let reopened = ResumeStore::open(&path).unwrap();
        assert_eq!(reopened.checkpointed(subject).unwrap().run_count(), 2);
        assert_eq!(reopened.checkpointed(subject).unwrap(), &fragmented);
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    #[ignore = "scale test, run with --ignored"]
    fn resume_store_handles_million_small_file_workload() {
        let path = temp_path("million-small-files");
        let subject_for = |index: u32| {
            let mut root = [0; 32];
            root[..4].copy_from_slice(&index.to_be_bytes());
            SubjectId {
                suite: 1,
                root,
                length: 1,
            }
        };
        let large_subject = SubjectId {
            suite: 1,
            root: [0xaa; 32],
            length: 100 * 65_536,
        };
        let mut store = ResumeStore::open(&path).unwrap();
        store
            .reserve_many(
                (0_u32..1_000_000)
                    .map(|index| (subject_for(index), 1))
                    .chain(std::iter::once((large_subject, 100))),
            )
            .unwrap();

        let mut tracker = ResumeTracker::discover(&mut store, large_subject, 100, 3).unwrap();
        for unit in 0..3 {
            tracker.begin_unit(unit).unwrap();
            assert_eq!(tracker.complete_unit(unit).unwrap(), unit == 2);
        }
        tracker.checkpoint(&mut store).unwrap();

        let reopened = ResumeStore::open(&path).unwrap();
        assert!(reopened.checkpointed(subject_for(0)).is_some());
        assert!(reopened.checkpointed(subject_for(999_999)).is_some());
        assert_eq!(
            reopened.checkpointed(large_subject).unwrap(),
            &units([0, 1, 2])
        );
        assert!(file_len(&path).unwrap() < MAX_STORE_BYTES);
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    #[ignore = "scale test, run with --ignored"]
    fn fully_checkpointed_million_object_snapshot_fits_the_store() {
        // The reserved-only workload above proves the reservation path. This
        // proves the durable path it grows into: every object checkpointed, so
        // every object also carries a range record.
        let path = temp_path("million-checkpointed");
        let subject_for = |index: u32| {
            let mut root = [0; 32];
            root[..4].copy_from_slice(&index.to_be_bytes());
            SubjectId {
                suite: 1,
                root,
                length: 1,
            }
        };
        let large_subject = SubjectId {
            suite: 1,
            root: [0xaa; 32],
            length: 100 * 65_536,
        };

        let mut objects = BTreeMap::new();
        for index in 0..1_000_000_u32 {
            objects.insert(
                subject_for(index),
                StoredObject {
                    total_units: 1,
                    checkpointed: units([0]),
                },
            );
        }
        objects.insert(
            large_subject,
            StoredObject {
                total_units: 100,
                checkpointed: units(0..100),
            },
        );

        validate_reserved_capacity(&objects).unwrap();
        ResumeStore::compact(&path, &objects).unwrap();

        let reopened = ResumeStore::open(&path).unwrap();
        assert_eq!(reopened.checkpointed(subject_for(0)).unwrap(), &units([0]));
        assert_eq!(
            reopened.checkpointed(subject_for(999_999)).unwrap(),
            &units([0])
        );
        assert_eq!(
            reopened.checkpointed(large_subject).unwrap(),
            &units(0..100)
        );

        let length = file_len(&path).unwrap();
        let headroom = MAX_STORE_BYTES - length;
        assert!(
            headroom >= 16 * 1024 * 1024,
            "fully checkpointed snapshot is {length} bytes, leaving only {headroom} bytes"
        );
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn decoder_rejects_malformed_records_and_accepts_empty_log() {
        let path = temp_path("raw");

        let mut trailing = encode_reserve(subject(1), 1).unwrap();
        trailing.push(0xff);
        write_raw(&path, &trailing);
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));

        let malformed_range = encode_checkpoint(subject(1), 1, &units([1])).unwrap();
        write_raw(&path, &malformed_range);
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));

        let mut bytes = MAGIC.to_vec();
        let mut record = encode_record(&encode_reserve(subject(2), 1).unwrap()).unwrap();
        let last = record.len() - 1;
        record[last] ^= 1;
        bytes.extend_from_slice(&record);
        fs::write(&path, bytes).unwrap();
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));

        fs::write(&path, MAGIC).unwrap();
        assert!(ResumeStore::open(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn compaction_collision_preserves_the_real_error_kind() {
        let path = temp_path("temporary-collision");
        let temporary = temporary_path(&path).unwrap();
        fs::create_dir(&temporary).unwrap();
        let error = ResumeStore::compact(&path, &BTreeMap::new()).unwrap_err();
        let Error::Io(error) = error else {
            panic!("expected I/O error");
        };
        assert_ne!(error.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir(temporary).unwrap();
    }

    #[test]
    fn quic_to_tcp_preserves_verified_and_durable_state() {
        let mut state = CarrierNeutralState::new(Carrier::Quic, 1);
        state.verified(3);
        state.durable(3).unwrap();
        assert!(matches!(state.durable(4), Err(Error::InvalidUnit)));
        state.switch(Carrier::TlsTcp, 2);
        assert_eq!(state.carrier(), Carrier::TlsTcp);
        assert!(state.is_verified(3));
        assert!(state.is_durable(3));
        assert!(!state.is_verified(4));
        assert!(!state.is_durable(4));
    }

    #[test]
    fn stale_path_state_not_reused_unsafely() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [2; 16],
            dscp: 0,
        };
        let observation = Observation {
            saved_cwnd: 1_000_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 7,
        };
        let input = Reconnaissance {
            now: 500,
            current_min_rtt: 100,
            initial_flight_acknowledged: true,
            congestion_detected: false,
            local_path_changed: false,
            configuration_epoch: 7,
            max_jump: 400_000,
        };
        let mut cache = CarefulResumeCache::default();
        cache.observe(endpoint, observation).unwrap();
        let permit = cache.reconnoitre(endpoint, endpoint, input).unwrap();
        assert_eq!(permit.jump_cwnd, 400_000);
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::AlreadyInUse)
        );
        assert!(cache.release(endpoint, &permit, false));
        let permit = cache.reconnoitre(endpoint, endpoint, input).unwrap();
        assert!(cache.release(endpoint, &permit, true));
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::Unknown)
        );
        cache.observe(endpoint, observation).unwrap();

        let changed = RemoteEndpoint {
            interface: 9,
            ..endpoint
        };
        assert_eq!(
            cache.reconnoitre(endpoint, changed, input),
            Err(PathReject::PathChanged)
        );
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, Reconnaissance { ..input }),
            Err(PathReject::Unknown)
        );

        cache.observe(endpoint, observation).unwrap();
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    local_path_changed: true,
                    ..input
                }
            ),
            Err(PathReject::PathChanged)
        );
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::Unknown)
        );
    }

    #[test]
    fn reconnaissance_congestion_discards_saved_state() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [8; 16],
            dscp: 1,
        };
        let observation = Observation {
            saved_cwnd: 1_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 4,
        };
        let mut cache = CarefulResumeCache::default();
        for initial_flight_acknowledged in [false, true] {
            let input = Reconnaissance {
                now: 1,
                current_min_rtt: 100,
                initial_flight_acknowledged,
                congestion_detected: true,
                local_path_changed: false,
                configuration_epoch: 4,
                max_jump: 900,
            };
            cache.observe(endpoint, observation).unwrap();
            assert_eq!(
                cache.reconnoitre(endpoint, endpoint, input),
                Err(PathReject::Congestion)
            );
            assert_eq!(
                cache.reconnoitre(
                    endpoint,
                    endpoint,
                    Reconnaissance {
                        initial_flight_acknowledged: true,
                        congestion_detected: false,
                        ..input
                    }
                ),
                Err(PathReject::Unknown)
            );
        }
    }

    #[test]
    fn active_careful_resume_observation_cannot_be_replaced() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [9; 16],
            dscp: 1,
        };
        let observation = Observation {
            saved_cwnd: 1_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 4,
        };
        let input = Reconnaissance {
            now: 1,
            current_min_rtt: 100,
            initial_flight_acknowledged: true,
            congestion_detected: false,
            local_path_changed: false,
            configuration_epoch: 4,
            max_jump: 900,
        };
        let invalidations = [
            (
                RemoteEndpoint {
                    interface: 2,
                    ..endpoint
                },
                input,
            ),
            (
                endpoint,
                Reconnaissance {
                    local_path_changed: true,
                    ..input
                },
            ),
            (
                endpoint,
                Reconnaissance {
                    congestion_detected: true,
                    ..input
                },
            ),
            (
                endpoint,
                Reconnaissance {
                    now: observation.expires_at,
                    ..input
                },
            ),
            (
                endpoint,
                Reconnaissance {
                    configuration_epoch: observation.configuration_epoch + 1,
                    ..input
                },
            ),
        ];
        for (current_endpoint, invalidation) in invalidations {
            let mut cache = CarefulResumeCache::default();
            cache.observe(endpoint, observation).unwrap();
            let permit = cache.reconnoitre(endpoint, endpoint, input).unwrap();
            assert_eq!(
                cache.observe(
                    endpoint,
                    Observation {
                        saved_cwnd: 2_000,
                        ..observation
                    }
                ),
                Err(PathReject::AlreadyInUse)
            );
            assert_eq!(
                cache.reconnoitre(endpoint, current_endpoint, invalidation),
                Err(PathReject::AlreadyInUse)
            );
            assert!(cache.release(endpoint, &permit, false));
            assert_eq!(
                cache.reconnoitre(endpoint, endpoint, input),
                Err(PathReject::Unknown)
            );
        }
    }

    #[test]
    fn delayed_release_cannot_clear_a_newer_permit_owner() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [10; 16],
            dscp: 1,
        };
        let observation = Observation {
            saved_cwnd: 1_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 4,
        };
        let input = Reconnaissance {
            now: 1,
            current_min_rtt: 100,
            initial_flight_acknowledged: true,
            congestion_detected: false,
            local_path_changed: false,
            configuration_epoch: 4,
            max_jump: 900,
        };
        let mut cache = CarefulResumeCache::default();
        cache.observe(endpoint, observation).unwrap();
        let first = cache.reconnoitre(endpoint, endpoint, input).unwrap();
        assert!(cache.release(endpoint, &first, false));
        let second = cache.reconnoitre(endpoint, endpoint, input).unwrap();
        assert!(!cache.release(endpoint, &first, false));
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::AlreadyInUse)
        );
        assert!(cache.release(endpoint, &second, false));
        assert!(cache.reconnoitre(endpoint, endpoint, input).is_ok());
    }

    #[test]
    fn careful_resume_rejects_each_condition_and_accepts_exact_rtt_edge() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [8; 16],
            dscp: 1,
        };
        let observation = Observation {
            saved_cwnd: 1_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 4,
        };
        let base = Reconnaissance {
            now: 1,
            current_min_rtt: 1_000,
            initial_flight_acknowledged: true,
            congestion_detected: false,
            local_path_changed: false,
            configuration_epoch: 4,
            max_jump: 900,
        };
        for invalid in [
            Observation {
                saved_cwnd: 0,
                ..observation
            },
            Observation {
                saved_rtt: 0,
                ..observation
            },
            Observation {
                expires_at: 0,
                ..observation
            },
        ] {
            assert_eq!(
                CarefulResumeCache::default().observe(endpoint, invalid),
                Err(PathReject::InvalidObservation)
            );
        }

        let mut cache = CarefulResumeCache::default();
        cache.observe(endpoint, observation).unwrap();
        let permit = cache.reconnoitre(endpoint, endpoint, base).unwrap();
        assert_eq!(permit.jump_cwnd, 500);
        assert!(cache.release(endpoint, &permit, false));
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    current_min_rtt: 1_001,
                    ..base
                }
            ),
            Err(PathReject::RttTooLarge)
        );
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    initial_flight_acknowledged: false,
                    current_min_rtt: 100,
                    ..base
                }
            ),
            Err(PathReject::InitialFlightUnacknowledged)
        );
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    congestion_detected: true,
                    current_min_rtt: 100,
                    ..base
                }
            ),
            Err(PathReject::Congestion)
        );
        cache.observe(endpoint, observation).unwrap();
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    configuration_epoch: 5,
                    current_min_rtt: 100,
                    ..base
                }
            ),
            Err(PathReject::ConfigurationChanged)
        );
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, base),
            Err(PathReject::Unknown)
        );
    }
}
