#![allow(
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! Deterministic VOT manifest encoding, path validation, and progressive ingest.

use std::collections::HashSet;

use unicode_normalization::UnicodeNormalization;

pub const MAX_PAGE_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathProfile {
    Portable,
    RawPosix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Component {
    Text(String),
    Bytes(Vec<u8>),
}

pub type PackagePath = Vec<Component>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPath,
    PathCollision,
    EntriesUnsorted,
    InvalidObject,
    PageTooLarge,
    WrongManifest,
    WrongPageIndex,
    BrokenPageChain,
    SealedPageInProgressiveStream,
    Poisoned,
    InvalidSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexEntry {
    pub fingerprint: [u8; 16],
    pub page: u32,
    pub entry: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ManifestIndex {
    entries: Vec<IndexEntry>,
}

impl ManifestIndex {
    #[must_use]
    pub fn with_capacity(entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(entries),
        }
    }

    pub fn push(
        &mut self,
        path: &PackagePath,
        profile: PathProfile,
        page: u32,
        entry: u32,
    ) -> Result<(), Error> {
        let key = canonical_path_key(path, profile)?;
        let digest = blake3::hash(&key);
        let mut fingerprint = [0; 16];
        fingerprint.copy_from_slice(&digest.as_bytes()[..16]);
        self.entries.push(IndexEntry {
            fingerprint,
            page,
            entry,
        });
        Ok(())
    }

    pub fn finish(&mut self) {
        self.entries.sort_unstable_by_key(|entry| entry.fingerprint);
    }

    #[must_use]
    pub fn candidates(&self, path: &PackagePath, profile: PathProfile) -> Vec<(u32, u32)> {
        let Ok(key) = canonical_path_key(path, profile) else {
            return Vec::new();
        };
        let digest = blake3::hash(&key);
        let mut fingerprint = [0; 16];
        fingerprint.copy_from_slice(&digest.as_bytes()[..16]);
        let range = self
            .entries
            .partition_point(|entry| entry.fingerprint < fingerprint)
            ..self
                .entries
                .partition_point(|entry| entry.fingerprint <= fingerprint);
        self.entries[range]
            .iter()
            .map(|entry| (entry.page, entry.entry))
            .collect()
    }

    #[must_use]
    pub const fn bytes_per_entry() -> usize {
        std::mem::size_of::<IndexEntry>()
    }
}

#[derive(Clone, Debug)]
pub struct ProgressiveIngest {
    manifest_id: [u8; 16],
    profile: PathProfile,
    digests: Vec<[u8; 32]>,
    last_path: Option<Vec<u8>>,
    poisoned: bool,
}

impl ProgressiveIngest {
    #[must_use]
    pub const fn new(manifest_id: [u8; 16], profile: PathProfile) -> Self {
        Self {
            manifest_id,
            profile,
            digests: Vec::new(),
            last_path: None,
            poisoned: false,
        }
    }

    pub fn accept(&mut self, page: &ManifestPage) -> Result<[u8; 32], Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let result = self.accept_inner(page);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn accept_inner(&mut self, page: &ManifestPage) -> Result<[u8; 32], Error> {
        if page.manifest_id != self.manifest_id || page.profile != self.profile {
            return Err(Error::WrongManifest);
        }
        if page.total.is_some() {
            return Err(Error::SealedPageInProgressiveStream);
        }
        if page.index != self.digests.len() as u64 {
            return Err(Error::WrongPageIndex);
        }
        let expected_previous = self.digests.last().copied().unwrap_or([0; 32]);
        if page.previous_digest != expected_previous {
            return Err(Error::BrokenPageChain);
        }
        let keys = validate_entries(&page.entries, page.profile)?;
        if let (Some(previous), Some(first)) = (&self.last_path, keys.first()) {
            if first <= previous {
                return Err(Error::EntriesUnsorted);
            }
        }
        let encoded = encode_page(page)?;
        let digest = *blake3::hash(&encoded).as_bytes();
        self.last_path = keys.last().cloned().or_else(|| self.last_path.take());
        self.digests.push(digest);
        Ok(digest)
    }

    pub fn verify_seal(&self, seal: &Seal) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let Some(last_digest) = self.digests.last() else {
            return Err(Error::Poisoned);
        };
        if seal.manifest_id != self.manifest_id
            || seal.final_page_count != self.digests.len() as u64
            || seal.final_page_digest != *last_digest
            || seal.pages.len() != self.digests.len()
            || !valid_object(&seal.package)
        {
            return Err(Error::InvalidSeal);
        }
        for (index, (commitment, digest)) in seal.pages.iter().zip(&self.digests).enumerate() {
            if commitment.index != index as u64 || commitment.digest != *digest {
                return Err(Error::InvalidSeal);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

pub fn validate_entries(
    entries: &[ManifestEntry],
    profile: PathProfile,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut keys = Vec::with_capacity(entries.len());
    let mut unique = HashSet::with_capacity(entries.len());
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

pub fn canonical_path_key(path: &PackagePath, profile: PathProfile) -> Result<Vec<u8>, Error> {
    if path.is_empty() {
        return Err(Error::InvalidPath);
    }
    let mut key = Vec::new();
    for component in path {
        if !key.is_empty() {
            key.push(0);
        }
        match (profile, component) {
            (PathProfile::Portable, Component::Text(text)) => {
                validate_portable_component(text)?;
                let folded: String = text.nfc().flat_map(char::to_lowercase).collect();
                key.extend_from_slice(folded.trim_end_matches(['.', ' ']).as_bytes());
            }
            (PathProfile::RawPosix, Component::Bytes(bytes)) if valid_raw_component(bytes) => {
                key.extend_from_slice(bytes);
            }
            _ => return Err(Error::InvalidPath),
        }
    }
    Ok(key)
}

pub fn encode_page(page: &ManifestPage) -> Result<Vec<u8>, Error> {
    validate_entries(&page.entries, page.profile)?;
    let mut out = Vec::new();
    cbor_map(&mut out, 7);
    cbor_uint(&mut out, 0);
    cbor_uint(&mut out, 0);
    cbor_uint(&mut out, 1);
    cbor_bytes(&mut out, &page.manifest_id);
    cbor_uint(&mut out, 2);
    cbor_uint(&mut out, page.index);
    cbor_uint(&mut out, 3);
    if let Some(total) = page.total {
        cbor_uint(&mut out, total);
    } else {
        out.push(0xf6);
    }
    cbor_uint(&mut out, 4);
    cbor_bytes(&mut out, &page.previous_digest);
    cbor_uint(&mut out, 5);
    cbor_uint(&mut out, u64::from(page.profile == PathProfile::RawPosix));
    cbor_uint(&mut out, 6);
    cbor_array(&mut out, page.entries.len() as u64);
    for entry in &page.entries {
        encode_entry(&mut out, entry);
    }
    if out.len() > MAX_PAGE_BYTES {
        Err(Error::PageTooLarge)
    } else {
        Ok(out)
    }
}

fn validate_entry(entry: &ManifestEntry) -> Result<(), Error> {
    match entry.kind {
        EntryKind::File => {
            let length = entry.length.ok_or(Error::InvalidObject)?;
            let storage = entry.storage.as_ref().ok_or(Error::InvalidObject)?;
            if i64::try_from(length).is_err()
                || !valid_storage(storage, length)
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

fn valid_object(object: &ObjectId) -> bool {
    matches!(object.suite, 1 | 2) && i64::try_from(object.length).is_ok()
}

fn valid_metadata(metadata: &FileMetadata) -> bool {
    metadata.mode.is_none_or(|mode| mode <= 511)
        && metadata
            .mtime_nanoseconds
            .is_none_or(|value| value <= 999_999_999)
        && metadata
            .media_type
            .as_ref()
            .is_none_or(|value| !value.is_empty() && value.len() <= 127)
}

fn valid_storage(storage: &StorageRef, entry_length: u64) -> bool {
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

fn validate_portable_component(component: &str) -> Result<(), Error> {
    if component.is_empty()
        || component.len() > 255
        || component == "."
        || component == ".."
        || component.contains(['\0', '/', '\\'])
        || component.ends_with(['.', ' '])
    {
        return Err(Error::InvalidPath);
    }
    let folded: String = component.nfc().flat_map(char::to_lowercase).collect();
    let stem = folded.split('.').next().unwrap_or_default();
    let reserved = matches!(stem, "con" | "prn" | "aux" | "nul")
        || stem.strip_prefix("com").is_some_and(is_device_digit)
        || stem.strip_prefix("lpt").is_some_and(is_device_digit);
    if reserved {
        Err(Error::InvalidPath)
    } else {
        Ok(())
    }
}

fn is_device_digit(value: &str) -> bool {
    value.len() == 1 && matches!(value.as_bytes()[0], b'1'..=b'9')
}

fn valid_raw_component(component: &[u8]) -> bool {
    !component.is_empty()
        && component.len() <= 255
        && !component.contains(&0)
        && !component.contains(&b'/')
}

fn encode_entry(out: &mut Vec<u8>, entry: &ManifestEntry) {
    let fields = 2
        + usize::from(entry.length.is_some())
        + usize::from(entry.storage.is_some())
        + usize::from(entry.metadata.is_some());
    cbor_map(out, fields as u64);
    cbor_uint(out, 0);
    cbor_array(out, entry.path.len() as u64);
    for component in &entry.path {
        match component {
            Component::Text(text) => cbor_text(out, text),
            Component::Bytes(bytes) => cbor_bytes(out, bytes),
        }
    }
    cbor_uint(out, 1);
    cbor_uint(out, u64::from(entry.kind == EntryKind::Directory));
    if let Some(length) = entry.length {
        cbor_uint(out, 2);
        cbor_uint(out, length);
    }
    if let Some(storage) = &entry.storage {
        cbor_uint(out, 3);
        encode_storage(out, storage);
    }
    if let Some(metadata) = &entry.metadata {
        cbor_uint(out, 4);
        encode_metadata(out, metadata);
    }
}

fn encode_object(out: &mut Vec<u8>, object: &ObjectId) {
    cbor_array(out, 3);
    cbor_uint(out, u64::from(object.suite));
    cbor_bytes(out, &object.root);
    cbor_uint(out, object.length);
}

fn encode_storage(out: &mut Vec<u8>, storage: &StorageRef) {
    match storage {
        StorageRef::Direct(object) => {
            cbor_array(out, 2);
            cbor_uint(out, 0);
            encode_object(out, object);
        }
        StorageRef::Pack {
            pack,
            offset,
            length,
            logical,
        } => {
            cbor_array(out, 5);
            cbor_uint(out, 1);
            encode_object(out, pack);
            cbor_uint(out, *offset);
            cbor_uint(out, *length);
            encode_object(out, logical);
        }
    }
}

fn encode_metadata(out: &mut Vec<u8>, metadata: &FileMetadata) {
    let fields = usize::from(metadata.mode.is_some())
        + usize::from(metadata.mtime_seconds.is_some())
        + usize::from(metadata.mtime_nanoseconds.is_some())
        + usize::from(metadata.media_type.is_some());
    cbor_map(out, fields as u64);
    if let Some(mode) = metadata.mode {
        cbor_uint(out, 0);
        cbor_uint(out, u64::from(mode));
    }
    if let Some(seconds) = metadata.mtime_seconds {
        cbor_uint(out, 1);
        cbor_int(out, seconds);
    }
    if let Some(nanoseconds) = metadata.mtime_nanoseconds {
        cbor_uint(out, 2);
        cbor_uint(out, u64::from(nanoseconds));
    }
    if let Some(media_type) = &metadata.media_type {
        cbor_uint(out, 3);
        cbor_text(out, media_type);
    }
}

fn cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => out.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn cbor_uint(out: &mut Vec<u8>, value: u64) {
    cbor_head(out, 0, value);
}
fn cbor_int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        cbor_uint(out, value as u64);
    } else {
        cbor_head(out, 1, (-1_i128 - i128::from(value)) as u64);
    }
}
fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
    cbor_head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}
fn cbor_text(out: &mut Vec<u8>, value: &str) {
    cbor_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn cbor_array(out: &mut Vec<u8>, length: u64) {
    cbor_head(out, 4, length);
}
fn cbor_map(out: &mut Vec<u8>, length: u64) {
    cbor_head(out, 5, length);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> ManifestEntry {
        let object = ObjectId {
            suite: 1,
            root: [7; 32],
            length: 3,
        };
        ManifestEntry {
            path: vec![Component::Text(path.to_owned())],
            kind: EntryKind::File,
            length: Some(3),
            storage: Some(StorageRef::Direct(object)),
            metadata: None,
        }
    }

    fn page(index: u64, previous_digest: [u8; 32], name: &str) -> ManifestPage {
        ManifestPage {
            manifest_id: [9; 16],
            index,
            total: None,
            previous_digest,
            profile: PathProfile::Portable,
            entries: vec![file(name)],
        }
    }

    #[test]
    fn encoding_is_stable_and_uses_integer_keys() {
        let encoded = encode_page(&page(0, [0; 32], "a.txt")).unwrap();
        assert_eq!(encoded[0], 0xa7);
        assert_eq!(encoded, encode_page(&page(0, [0; 32], "a.txt")).unwrap());
        assert!(encoded.len() < MAX_PAGE_BYTES);
    }

    #[test]
    fn portable_collision_and_reserved_corpus() {
        let collisions = vec![file("Readme"), file("README")];
        assert_eq!(
            validate_entries(&collisions, PathProfile::Portable),
            Err(Error::PathCollision)
        );
        for name in ["CON", "aux.txt", "LPT9", "bad/part", "trail.", ".."] {
            assert_eq!(
                canonical_path_key(
                    &vec![Component::Text(name.to_owned())],
                    PathProfile::Portable
                ),
                Err(Error::InvalidPath)
            );
        }
        let composed = vec![Component::Text("\u{e9}".to_owned())];
        let decomposed = vec![Component::Text("e\u{301}".to_owned())];
        assert_eq!(
            canonical_path_key(&composed, PathProfile::Portable),
            canonical_path_key(&decomposed, PathProfile::Portable)
        );
    }

    #[test]
    fn progressive_reorder_mutation_and_truncation_do_not_seal() {
        let mut ingest = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        let first = page(0, [0; 32], "a");
        let first_digest = ingest.accept(&first).unwrap();
        let wrong = page(2, first_digest, "c");
        assert_eq!(ingest.accept(&wrong), Err(Error::WrongPageIndex));
        assert!(ingest.is_poisoned());

        let mut clean = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        let digest = clean.accept(&first).unwrap();
        let truncated = Seal {
            manifest_id: [9; 16],
            final_page_count: 2,
            final_page_digest: digest,
            package: ObjectId {
                suite: 1,
                root: [1; 32],
                length: 1,
            },
            pages: vec![PageCommitment { index: 0, digest }],
        };
        assert_eq!(clean.verify_seal(&truncated), Err(Error::InvalidSeal));

        let mut mutated = first.clone();
        mutated.entries[0] = file("changed");
        assert_eq!(clean.accept(&mutated), Err(Error::WrongPageIndex));
        assert_eq!(clean.verify_seal(&truncated), Err(Error::Poisoned));
    }

    #[test]
    fn million_entry_index_has_fixed_memory_bound() {
        assert!(ManifestIndex::bytes_per_entry() <= 24);
        assert!(ManifestIndex::bytes_per_entry() * 1_000_000 <= 24_000_000);
        let mut index = ManifestIndex::with_capacity(1_000_000);
        for value in 0_u64..1_000_000 {
            let mut fingerprint = [0; 16];
            fingerprint[..8].copy_from_slice(&value.to_be_bytes());
            index.entries.push(IndexEntry {
                fingerprint,
                page: u32::try_from(value / 1_000).unwrap(),
                entry: u32::try_from(value % 1_000).unwrap(),
            });
        }
        index.finish();
        assert_eq!(index.entries.len(), 1_000_000);
        assert!(index.entries.capacity() * ManifestIndex::bytes_per_entry() <= 24_000_000);
    }
}
