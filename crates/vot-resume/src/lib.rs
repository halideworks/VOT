//! Persistent carrier-neutral resume state and RFC 9959 Careful Resume policy.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use vot_transport_api::SubjectId;
use vot_transport_tcp::Carrier;

const MAGIC: &[u8; 8] = b"VOTRES01";
const MAX_STORE_BYTES: u64 = 67_108_864;
const MAX_STORE_PAYLOAD_BYTES: u64 = MAX_STORE_BYTES - 32;
const MIN_STORE_BYTES: u64 = 44;
const STORE_HEADER_BYTES: u64 = 12;
const OBJECT_HEADER_BYTES: u64 = 54;
const UNIT_BYTES: u64 = 8;
const MAX_UNITS_PER_OBJECT: u64 =
    (MAX_STORE_PAYLOAD_BYTES - STORE_HEADER_BYTES - OBJECT_HEADER_BYTES) / UNIT_BYTES;

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
    checkpointed: BTreeSet<u64>,
}

/// Checksummed state store keyed by immutable object identity, never connection ID.
pub struct ResumeStore {
    path: PathBuf,
    objects: BTreeMap<SubjectId, StoredObject>,
}

impl ResumeStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let objects = if path.exists() {
            decode_store(&path)?
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, objects })
    }

    #[must_use]
    pub fn checkpointed(&self, subject: SubjectId) -> Option<&BTreeSet<u64>> {
        self.objects
            .get(&subject)
            .map(|object| &object.checkpointed)
    }

    fn reserve_object(
        &mut self,
        subject: SubjectId,
        total_units: u64,
    ) -> Result<BTreeSet<u64>, Error> {
        validate_total_units(total_units)?;
        let lock = lock_store(&self.path)?;
        let mut candidate = if self.path.exists() {
            decode_store(&self.path)?
        } else {
            BTreeMap::new()
        };
        if let Some(object) = candidate.get(&subject) {
            if object.total_units != total_units {
                return Err(Error::IdentityMismatch);
            }
        } else {
            candidate.insert(
                subject,
                StoredObject {
                    total_units,
                    checkpointed: BTreeSet::new(),
                },
            );
        }
        validate_reserved_capacity(&candidate)?;
        Self::flush(&self.path, &candidate)?;
        let checkpointed = candidate
            .get(&subject)
            .ok_or(Error::IdentityMismatch)?
            .checkpointed
            .clone();
        self.objects = candidate;
        drop(lock);
        Ok(checkpointed)
    }

    fn save_object(
        &mut self,
        subject: SubjectId,
        total_units: u64,
        checkpointed: BTreeSet<u64>,
    ) -> Result<BTreeSet<u64>, Error> {
        validate_total_units(total_units)?;
        if checkpointed.iter().any(|unit| *unit >= total_units) {
            return Err(Error::InvalidUnit);
        }
        let lock = lock_store(&self.path)?;
        let mut candidate = if self.path.exists() {
            decode_store(&self.path)?
        } else {
            BTreeMap::new()
        };
        if candidate
            .get(&subject)
            .is_some_and(|object| object.total_units != total_units)
        {
            return Err(Error::IdentityMismatch);
        }
        let mut merged = candidate
            .get(&subject)
            .map_or_else(BTreeSet::new, |object| object.checkpointed.clone());
        merged.extend(checkpointed);
        candidate.insert(
            subject,
            StoredObject {
                total_units,
                checkpointed: merged.clone(),
            },
        );
        validate_reserved_capacity(&candidate)?;
        Self::flush(&self.path, &candidate)?;
        self.objects = candidate;
        drop(lock);
        Ok(merged)
    }

    fn flush(path: &Path, objects: &BTreeMap<SubjectId, StoredObject>) -> Result<(), Error> {
        let bytes = encode_store(objects)?;
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
        file.write_all(&bytes)?;
        file.sync_all()?;
        vot_platform_fs::atomic_replace(&temporary, path)?;
        #[cfg(unix)]
        File::open(path.parent().ok_or(Error::InvalidConfiguration)?)?.sync_all()?;
        Ok(())
    }
}

/// Per-object bounded-waste tracker. Active and post-checkpoint units are volatile by design.
pub struct ResumeTracker {
    subject: SubjectId,
    total_units: u64,
    checkpoint_window: usize,
    checkpointed: BTreeSet<u64>,
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
        if self.checkpointed.contains(&unit) || self.completed_since_checkpoint.contains(&unit) {
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
        let mut checkpointed = self.checkpointed.clone();
        checkpointed.extend(&self.completed_since_checkpoint);
        let checkpointed = store.save_object(self.subject, self.total_units, checkpointed)?;
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
        self.checkpointed.contains(&unit)
    }

    pub fn missing_units(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.total_units).filter(|unit| !self.checkpointed.contains(unit))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SavedPath {
    observation: Observation,
    owner: Option<u64>,
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
        if self
            .saved
            .get(&saved_endpoint)
            .is_some_and(|saved| saved.owner.is_some())
        {
            return Err(PathReject::AlreadyInUse);
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
        if congestion_detected {
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
    let object_count = u64::try_from(objects.len()).map_err(|_| Error::InvalidConfiguration)?;
    let units = objects.values().try_fold(0_u64, |total, object| {
        total
            .checked_add(object.total_units)
            .ok_or(Error::InvalidConfiguration)
    })?;
    let length = STORE_HEADER_BYTES
        .checked_add(
            object_count
                .checked_mul(OBJECT_HEADER_BYTES)
                .ok_or(Error::InvalidConfiguration)?,
        )
        .and_then(|length| length.checked_add(units.checked_mul(UNIT_BYTES)?))
        .ok_or(Error::InvalidConfiguration)?;
    if length > MAX_STORE_PAYLOAD_BYTES {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn encode_store(objects: &BTreeMap<SubjectId, StoredObject>) -> Result<Vec<u8>, Error> {
    let count = u32::try_from(objects.len()).map_err(|_| Error::TooLarge)?;
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&count.to_be_bytes());
    for (subject, object) in objects {
        validate_total_units(object.total_units)?;
        let units = u32::try_from(object.checkpointed.len()).map_err(|_| Error::TooLarge)?;
        output.extend_from_slice(&subject.suite.to_be_bytes());
        output.extend_from_slice(&subject.root);
        output.extend_from_slice(&subject.length.to_be_bytes());
        output.extend_from_slice(&object.total_units.to_be_bytes());
        output.extend_from_slice(&units.to_be_bytes());
        for unit in &object.checkpointed {
            output.extend_from_slice(&unit.to_be_bytes());
        }
        validate_payload_length(output.len() as u64)?;
    }
    let digest = blake3::hash(&output);
    output.extend_from_slice(digest.as_bytes());
    Ok(output)
}

fn decode_store(path: &Path) -> Result<BTreeMap<SubjectId, StoredObject>, Error> {
    let bytes = read_bounded_store(path, MAX_STORE_BYTES)?;
    let length = u64::try_from(bytes.len()).map_err(|_| Error::Corrupt)?;
    if !(MIN_STORE_BYTES..=MAX_STORE_BYTES).contains(&length) {
        return Err(Error::Corrupt);
    }
    let (payload, declared_digest) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(payload).as_bytes() != declared_digest {
        return Err(Error::Corrupt);
    }
    let mut decoder = Decoder::new(payload);
    if decoder.take(8)? != MAGIC {
        return Err(Error::Corrupt);
    }
    let count = decoder.u32()?;
    let mut objects = BTreeMap::new();
    for _ in 0..count {
        let suite = decoder.u16()?;
        let root = decoder.array()?;
        let subject_length = decoder.u64()?;
        let total_units = decoder.u64()?;
        validate_total_units(total_units)?;
        let unit_count = decoder.u32()?;
        let mut checkpointed = BTreeSet::new();
        for _ in 0..unit_count {
            let unit = decoder.u64()?;
            if unit >= total_units || !checkpointed.insert(unit) {
                return Err(Error::Corrupt);
            }
        }
        let subject = SubjectId {
            suite,
            root,
            length: subject_length,
        };
        if objects
            .insert(
                subject,
                StoredObject {
                    total_units,
                    checkpointed,
                },
            )
            .is_some()
        {
            return Err(Error::Corrupt);
        }
    }
    if !decoder.is_empty() {
        return Err(Error::Corrupt);
    }
    validate_reserved_capacity(&objects).map_err(|_| Error::Corrupt)?;
    Ok(objects)
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

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
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

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vot-resume-{name}-{}-{}",
            std::process::id(),
            subject(name.as_bytes()[0]).root[0]
        ))
    }

    fn write_raw(path: &Path, payload: &[u8]) {
        let mut bytes = payload.to_vec();
        bytes.extend_from_slice(blake3::hash(payload).as_bytes());
        fs::write(path, bytes).unwrap();
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
        assert!(reopened.checkpointed(subject(1)).unwrap().contains(&0));
        assert!(reopened.checkpointed(subject(9)).is_none());
        assert!(matches!(
            ResumeTracker::discover(&mut reopened, subject(1), 11, 3),
            Err(Error::IdentityMismatch)
        ));
        let mut rediscovered = ResumeTracker::discover(&mut reopened, subject(1), 10, 3).unwrap();
        assert!(!rediscovered.begin_unit(0).unwrap());
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));
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
        assert_eq!(restarted.missing_units().count(), 16);
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
    fn repeated_checkpoints_replace_the_previous_snapshot() {
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
        assert_eq!(
            reopened.checkpointed(subject(8)).unwrap(),
            &BTreeSet::from([0, 1])
        );
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
        assert_eq!(
            reopened.checkpointed(subject(9)).unwrap(),
            &BTreeSet::from([0, 1])
        );
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
    fn store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic() {
        assert_eq!(MAX_STORE_BYTES, 67_108_864);
        assert_eq!(MAX_STORE_PAYLOAD_BYTES, 67_108_832);
        assert_eq!(MIN_STORE_BYTES, 44);
        assert_eq!(MAX_UNITS_PER_OBJECT, 8_388_595);
        let maximum_object_payload =
            STORE_HEADER_BYTES + OBJECT_HEADER_BYTES + MAX_UNITS_PER_OBJECT * UNIT_BYTES;
        assert!(validate_payload_length(maximum_object_payload).is_ok());
        assert!(matches!(
            validate_payload_length(maximum_object_payload + UNIT_BYTES),
            Err(Error::TooLarge)
        ));
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
    fn aggregate_capacity_is_reserved_before_transfer() {
        let path = temp_path("aggregate-capacity");
        let mut store = ResumeStore::open(&path).unwrap();
        let aggregate_units =
            (MAX_STORE_PAYLOAD_BYTES - STORE_HEADER_BYTES - 2 * OBJECT_HEADER_BYTES) / UNIT_BYTES;
        let first_units = aggregate_units / 2;
        let second_units = aggregate_units - first_units;

        assert!(ResumeTracker::discover(&mut store, subject(11), first_units, 1).is_ok());
        assert!(ResumeTracker::discover(&mut store, subject(12), second_units, 1).is_ok());
        assert!(matches!(
            ResumeTracker::discover(&mut store, subject(13), 1, 1),
            Err(Error::InvalidConfiguration)
        ));

        let reopened = ResumeStore::open(&path).unwrap();
        assert!(reopened.checkpointed(subject(11)).is_some());
        assert!(reopened.checkpointed(subject(12)).is_some());
        assert!(reopened.checkpointed(subject(13)).is_none());
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn decoder_rejects_count_overrun_duplicate_and_trailing_data() {
        let path = temp_path("raw");
        let mut payload = Vec::new();
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&1_u32.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&[1; 32]);
        payload.extend_from_slice(&100_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&2_u32.to_be_bytes());
        payload.extend_from_slice(&0_u64.to_be_bytes());
        payload.extend_from_slice(&0_u64.to_be_bytes());
        write_raw(&path, &payload);
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));

        payload.truncate(payload.len() - 8);
        payload[62..66].copy_from_slice(&1_u32.to_be_bytes());
        payload.push(0xff);
        write_raw(&path, &payload);
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));

        let mut empty = Vec::new();
        empty.extend_from_slice(MAGIC);
        empty.extend_from_slice(&0_u32.to_be_bytes());
        write_raw(&path, &empty);
        assert!(ResumeStore::open(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn temporary_store_collision_preserves_the_real_error_kind() {
        let path = temp_path("temporary-collision");
        let temporary = temporary_path(&path).unwrap();
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(5), 1, 1).unwrap();
        fs::create_dir(&temporary).unwrap();
        tracker.begin_unit(0).unwrap();
        tracker.complete_unit(0).unwrap();
        let error = tracker.checkpoint(&mut store).unwrap_err();
        let Error::Io(error) = error else {
            panic!("expected I/O error");
        };
        assert_ne!(error.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir(temporary).unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
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
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::AlreadyInUse)
        );
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                RemoteEndpoint {
                    interface: 2,
                    ..endpoint
                },
                input
            ),
            Err(PathReject::AlreadyInUse)
        );
        for invalidation in [
            Reconnaissance {
                local_path_changed: true,
                ..input
            },
            Reconnaissance {
                congestion_detected: true,
                ..input
            },
            Reconnaissance {
                now: observation.expires_at,
                ..input
            },
            Reconnaissance {
                configuration_epoch: observation.configuration_epoch + 1,
                ..input
            },
        ] {
            assert_eq!(
                cache.reconnoitre(endpoint, endpoint, invalidation),
                Err(PathReject::AlreadyInUse)
            );
        }
        assert!(cache.release(endpoint, &permit, false));
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
