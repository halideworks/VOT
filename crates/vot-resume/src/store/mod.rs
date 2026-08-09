//! The append-only store: replay, install, and compaction policy.

use crate::{BTreeMap, Error, File, OpenOptions, Path, PathBuf, SubjectId, UnitRanges, Write, fs};

pub(crate) mod format;
pub(crate) mod io;
pub(crate) use format::*;
pub use io::remove_files;
pub(crate) use io::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredObject {
    pub(crate) total_units: u64,
    pub(crate) checkpointed: UnitRanges,
}

/// Checksummed append-only state keyed by immutable object identity, never connection ID.
pub struct ResumeStore {
    pub(crate) path: PathBuf,
    pub(crate) objects: BTreeMap<SubjectId, StoredObject>,
    pub(crate) signature: FileSignature,
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

    /// Clears a subject's checkpointed units, keeping its reservation.
    /// Used when the checkpoint file is gone.
    ///
    /// # Errors
    /// Surfaces the snapshot rewrite's failure.
    pub fn reset(&mut self, subject: SubjectId) -> Result<(), Error> {
        let lock = lock_store(&self.path)?;
        self.refresh_locked()?;
        let Some(existing) = self.objects.get(&subject) else {
            drop(lock);
            return Ok(());
        };
        if existing.checkpointed.is_empty() {
            drop(lock);
            return Ok(());
        }
        let mut candidate = self.objects.clone();
        candidate.insert(
            subject,
            StoredObject {
                total_units: existing.total_units,
                checkpointed: UnitRanges::new(),
            },
        );
        Self::compact(&self.path, &candidate)?;
        self.objects = candidate;
        self.signature = file_signature(&self.path)?;
        drop(lock);
        Ok(())
    }

    /// Opens the store, creating it if new. Must exist before any checkpoint.
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

    /// Removes the store and its temporary. A completed bundle looks like
    /// one fetched without a store.
    ///
    /// Removal takes the store lock like every other transaction, so it
    /// cannot run beside a reserve or a checkpoint. The lock file itself
    /// stays. Unlinking a locked name does not release the lock held on the
    /// old inode, so the next process to create that name would take an
    /// independent lock and two writers would believe they were alone. An
    /// empty lock file beside no store is the cost of the name meaning one
    /// thing.
    pub fn remove(self) -> Result<(), Error> {
        remove_files(&self.path, false)
    }

    /// [`Self::remove`], and the lock file with it.
    ///
    /// Only for a caller that owns the containing directory and knows no
    /// other process has this store open, such as a fetch tidying up its own
    /// finished output.
    pub fn remove_unshared(self) -> Result<(), Error> {
        remove_files(&self.path, true)
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

    pub(crate) fn reserve_object(
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

    pub(crate) fn save_object(
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

    pub(crate) fn compact(
        path: &Path,
        objects: &BTreeMap<SubjectId, StoredObject>,
    ) -> Result<(), Error> {
        let bytes = encode_snapshot(objects)?;
        let record = encode_record(&bytes)?;
        let record_length = u64::try_from(record.len()).map_err(|_| Error::TooLarge)?;
        if !compact_fits(record_length) {
            return Err(Error::TooLarge);
        }
        let temporary = temporary_path(path)?;
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
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

pub(crate) fn reserve_requires_compaction(path_exists: bool, current_length: u64) -> bool {
    !path_exists || should_compact(current_length)
}

pub(crate) fn should_compact(projected: u64) -> bool {
    projected >= COMPACTION_THRESHOLD
}

pub(crate) fn decode_store(path: &Path) -> Result<BTreeMap<SubjectId, StoredObject>, Error> {
    let bytes = read_bounded_store(path, MAX_STORE_BYTES)?;
    let length = u64::try_from(bytes.len()).map_err(|_| Error::Corrupt)?;
    if !(MIN_STORE_BYTES..=MAX_STORE_BYTES).contains(&length) {
        return Err(Error::Corrupt);
    }
    let mut decoder = Decoder::new(&bytes);
    if decoder.take(MAGIC.len())? != MAGIC {
        return Err(Error::Corrupt);
    }
    // Replay accumulates raw runs, normalising once at the end.
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
pub(crate) struct ReplayObject {
    pub(crate) total_units: u64,
    pub(crate) runs: Vec<(u64, u64)>,
}

/// Normalises every replayed object once the log has been read.
pub(crate) fn settle(
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

pub(crate) fn difference(merged: &UnitRanges, previous: &UnitRanges) -> UnitRanges {
    merged.difference(previous)
}
