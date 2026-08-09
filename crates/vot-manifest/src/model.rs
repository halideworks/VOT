//! Manifest data: pages, entries, objects, storage, seals, and their validation rules.

use super::{
    BTreeSet, Error, MAX_ENTRIES_PER_PAGE, MAX_PAGE_BYTES, MAX_PAGE_COMMITMENTS, PackagePath,
    PathProfile, canonical_path_key,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectId {
    pub suite: u16,
    pub root: [u8; 32],
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageRef {
    Direct(ObjectId),
    Pack {
        pack: ObjectId,
        offset: u64,
        length: u64,
        logical: ObjectId,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileMetadata {
    pub mode: Option<u16>,
    pub mtime_seconds: Option<i64>,
    pub mtime_nanoseconds: Option<u32>,
    pub media_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestEntry {
    pub path: PackagePath,
    pub kind: EntryKind,
    pub length: Option<u64>,
    pub storage: Option<StorageRef>,
    pub metadata: Option<FileMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestPage {
    pub manifest_id: [u8; 16],
    pub index: u64,
    pub total: Option<u64>,
    pub previous_digest: [u8; 32],
    pub profile: PathProfile,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCommitment {
    pub index: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Seal {
    pub manifest_id: [u8; 16],
    pub final_page_count: u64,
    pub final_page_digest: [u8; 32],
    pub package: ObjectId,
    pub pages: Vec<PageCommitment>,
}

pub fn validate_entries(
    entries: &[ManifestEntry],
    profile: PathProfile,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut keys = Vec::with_capacity(entries.len());
    let mut unique = BTreeSet::new();
    for entry in entries {
        validate_entry(entry)?;
        let key = canonical_path_key(&entry.path, profile)?;
        if !unique.insert(key.clone()) {
            return Err(Error::PathCollision);
        }
        if keys.last().is_some_and(|previous| previous >= &key) {
            return Err(Error::EntriesUnsorted);
        }
        keys.push(key);
    }
    Ok(keys)
}

pub(super) fn validate_seal(seal: &Seal) -> Result<(), Error> {
    if seal.final_page_count == 0 {
        return Err(Error::InvalidSeal);
    }
    if usize::try_from(seal.final_page_count).ok() != Some(seal.pages.len()) {
        return Err(Error::InvalidSeal);
    }
    if seal.pages.len() > MAX_PAGE_COMMITMENTS {
        return Err(Error::InvalidSeal);
    }
    if !valid_object(&seal.package) {
        return Err(Error::InvalidSeal);
    }
    if seal
        .pages
        .iter()
        .enumerate()
        .any(|(index, page)| page.index != index as u64)
    {
        return Err(Error::InvalidSeal);
    }
    if seal.pages.last().map(|page| page.digest) != Some(seal.final_page_digest) {
        return Err(Error::InvalidSeal);
    }
    Ok(())
}

pub(super) fn validate_entry_count(entries: usize) -> Result<(), Error> {
    if entries > MAX_ENTRIES_PER_PAGE {
        Err(Error::PageTooLarge)
    } else {
        Ok(())
    }
}

pub(super) fn validate_page_length(length: usize) -> Result<(), Error> {
    if length > MAX_PAGE_BYTES {
        Err(Error::PageTooLarge)
    } else {
        Ok(())
    }
}

pub(super) fn validate_entry(entry: &ManifestEntry) -> Result<(), Error> {
    match entry.kind {
        EntryKind::File => {
            let length = entry.length.ok_or(Error::InvalidObject)?;
            let storage = entry.storage.as_ref().ok_or(Error::InvalidObject)?;
            // No separate check that the length is representable. Storage is
            // either a whole object, whose own length must be representable and
            // must equal this one, or a record, which is bounded well below that,
            // so a length this side cannot hold has already failed below.
            if !valid_storage(storage, length)
                || entry
                    .metadata
                    .as_ref()
                    .is_some_and(|metadata| !valid_metadata(metadata))
            {
                return Err(Error::InvalidObject);
            }
        }
        EntryKind::Directory => {
            if entry.length.is_some() || entry.storage.is_some() || entry.metadata.is_some() {
                return Err(Error::InvalidObject);
            }
        }
    }
    Ok(())
}

pub(super) fn valid_object(object: &ObjectId) -> bool {
    matches!(object.suite, 1 | 2) && i64::try_from(object.length).is_ok()
}

pub(super) fn valid_metadata(metadata: &FileMetadata) -> bool {
    metadata.mode.is_none_or(|mode| mode <= 511)
        && metadata
            .mtime_nanoseconds
            .is_none_or(|value| value <= 999_999_999)
        && metadata
            .media_type
            .as_ref()
            .is_none_or(|value| !value.is_empty() && value.len() <= 127)
}

pub(super) fn valid_storage(storage: &StorageRef, entry_length: u64) -> bool {
    match storage {
        StorageRef::Direct(object) => valid_object(object) && object.length == entry_length,
        StorageRef::Pack {
            pack,
            offset,
            length,
            logical,
        } => {
            valid_object(pack)
                && valid_object(logical)
                && *length == entry_length
                && *length <= 262_144
                && logical.length == *length
                && offset
                    .checked_add(*length)
                    .is_some_and(|end| end <= pack.length)
                && pack.length <= 134_217_728
        }
    }
}
