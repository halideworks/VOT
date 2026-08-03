#![allow(
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! Deterministic VOT manifest encoding, path validation, and progressive ingest.

use std::collections::BTreeSet;

use unicode_normalization::UnicodeNormalization;

pub const MAX_PAGE_BYTES: usize = 1_048_576;
pub const MAX_ENTRIES_PER_PAGE: usize = 8192;
pub const MAX_PATH_COMPONENTS: usize = 256;
const MAX_SEAL_FIXED_BYTES: usize = 113;
const MAX_ENCODED_PAGE_COMMITMENT_BYTES: usize = 39;
pub const MAX_PAGE_COMMITMENTS: usize =
    (MAX_PAGE_BYTES - MAX_SEAL_FIXED_BYTES) / MAX_ENCODED_PAGE_COMMITMENT_BYTES;

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
pub enum DecodeError {
    PageTooLarge,
    Truncated,
    InvalidCbor,
    NonCanonical,
    WrongType,
    InvalidStructure,
    TooManyEntries,
    TooManyComponents,
    ComponentTooLarge,
    InvalidUtf8,
    Semantic(Error),
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
                let folded = portable_fold(text);
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
    validate_entry_count(page.entries.len())?;
    validate_entries(&page.entries, page.profile)?;
    let mut out = Vec::new();
    vot_cbor::map(&mut out, 7);
    vot_cbor::uint(&mut out, 0);
    vot_cbor::uint(&mut out, 0);
    vot_cbor::uint(&mut out, 1);
    vot_cbor::bytes(&mut out, &page.manifest_id);
    vot_cbor::uint(&mut out, 2);
    vot_cbor::uint(&mut out, page.index);
    vot_cbor::uint(&mut out, 3);
    if let Some(total) = page.total {
        vot_cbor::uint(&mut out, total);
    } else {
        out.push(0xf6);
    }
    vot_cbor::uint(&mut out, 4);
    vot_cbor::bytes(&mut out, &page.previous_digest);
    vot_cbor::uint(&mut out, 5);
    vot_cbor::uint(&mut out, u64::from(page.profile == PathProfile::RawPosix));
    vot_cbor::uint(&mut out, 6);
    vot_cbor::array(&mut out, page.entries.len() as u64);
    for entry in &page.entries {
        encode_entry(&mut out, entry);
    }
    validate_page_length(out.len())?;
    Ok(out)
}

pub fn encode_seal(seal: &Seal) -> Result<Vec<u8>, Error> {
    validate_seal(seal)?;
    let mut out = Vec::new();
    vot_cbor::map(&mut out, 6);
    vot_cbor::uint(&mut out, 0);
    vot_cbor::uint(&mut out, 0);
    vot_cbor::uint(&mut out, 1);
    vot_cbor::bytes(&mut out, &seal.manifest_id);
    vot_cbor::uint(&mut out, 2);
    vot_cbor::uint(&mut out, seal.final_page_count);
    vot_cbor::uint(&mut out, 3);
    vot_cbor::bytes(&mut out, &seal.final_page_digest);
    vot_cbor::uint(&mut out, 4);
    vot_cbor::array(&mut out, 4);
    vot_cbor::uint(&mut out, 1);
    vot_cbor::uint(&mut out, u64::from(seal.package.suite));
    vot_cbor::bytes(&mut out, &seal.package.root);
    vot_cbor::uint(&mut out, seal.package.length);
    vot_cbor::uint(&mut out, 5);
    vot_cbor::array(&mut out, seal.pages.len() as u64);
    for commitment in &seal.pages {
        vot_cbor::array(&mut out, 3);
        vot_cbor::uint(&mut out, commitment.index);
        vot_cbor::bytes(&mut out, &commitment.digest);
        vot_cbor::array(&mut out, 0);
    }
    validate_page_length(out.len())?;
    Ok(out)
}

pub fn decode_seal(input: &[u8]) -> Result<Seal, DecodeError> {
    validate_page_length(input.len()).map_err(|_| DecodeError::PageTooLarge)?;
    let mut decoder = Decoder::new(input);
    if decoder.map_len()? != 6 {
        return Err(DecodeError::InvalidStructure);
    }
    decoder.exact_key(0)?;
    if decoder.uint()? != 0 {
        return Err(DecodeError::InvalidStructure);
    }
    decoder.exact_key(1)?;
    let manifest_id = decoder.fixed_bytes::<16>()?;
    decoder.exact_key(2)?;
    let final_page_count = decoder.uint()?;
    decoder.exact_key(3)?;
    let final_page_digest = decoder.fixed_bytes::<32>()?;
    decoder.exact_key(4)?;
    if decoder.array_len()? != 4 || decoder.uint()? != 1 {
        return Err(DecodeError::InvalidStructure);
    }
    let package = ObjectId {
        suite: u16::try_from(decoder.uint()?).map_err(|_| DecodeError::InvalidStructure)?,
        root: decoder.fixed_bytes::<32>()?,
        length: decoder.uint()?,
    };
    decoder.exact_key(5)?;
    let page_count =
        decoder.bounded_array_len(MAX_PAGE_COMMITMENTS, DecodeError::TooManyEntries)?;
    let mut pages = Vec::with_capacity(page_count);
    for _ in 0..page_count {
        if decoder.array_len()? != 3 {
            return Err(DecodeError::InvalidStructure);
        }
        let index = decoder.uint()?;
        let digest = decoder.fixed_bytes::<32>()?;
        if decoder.array_len()? != 0 {
            return Err(DecodeError::InvalidStructure);
        }
        pages.push(PageCommitment { index, digest });
    }
    decoder.finish()?;
    let seal = Seal {
        manifest_id,
        final_page_count,
        final_page_digest,
        package,
        pages,
    };
    validate_seal(&seal).map_err(DecodeError::Semantic)?;
    if encode_seal(&seal).map_err(DecodeError::Semantic)? != input {
        return Err(DecodeError::NonCanonical);
    }
    Ok(seal)
}

fn validate_seal(seal: &Seal) -> Result<(), Error> {
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

fn validate_entry_count(entries: usize) -> Result<(), Error> {
    if entries > MAX_ENTRIES_PER_PAGE {
        Err(Error::PageTooLarge)
    } else {
        Ok(())
    }
}

fn validate_page_length(length: usize) -> Result<(), Error> {
    if length > MAX_PAGE_BYTES {
        Err(Error::PageTooLarge)
    } else {
        Ok(())
    }
}

/// Decodes one canonical manifest page with allocation bounds enforced before
/// any input-controlled collection is created.
///
/// # Errors
/// Returns a structural, canonical encoding, resource-bound, or semantic error.
pub fn decode_page(input: &[u8]) -> Result<ManifestPage, DecodeError> {
    validate_page_length(input.len()).map_err(|_| DecodeError::PageTooLarge)?;
    let mut decoder = Decoder::new(input);
    if decoder.map_len()? != 7 {
        return Err(DecodeError::InvalidStructure);
    }
    decoder.exact_key(0)?;
    if decoder.uint()? != 0 {
        return Err(DecodeError::InvalidStructure);
    }
    decoder.exact_key(1)?;
    let manifest_id = decoder.fixed_bytes::<16>()?;
    decoder.exact_key(2)?;
    let index = decoder.uint()?;
    decoder.exact_key(3)?;
    // An absent total is `null`, which is the one simple value this encoding
    // has. Reading it as an item rather than as a byte is what keeps another
    // simple value from being taken for it.
    let total = if decoder.peek_null() {
        decoder.null()?;
        None
    } else {
        Some(decoder.uint()?)
    };
    decoder.exact_key(4)?;
    let previous_digest = decoder.fixed_bytes::<32>()?;
    decoder.exact_key(5)?;
    let profile = match decoder.uint()? {
        0 => PathProfile::Portable,
        1 => PathProfile::RawPosix,
        _ => return Err(DecodeError::InvalidStructure),
    };
    decoder.exact_key(6)?;
    let entry_count =
        decoder.bounded_array_len(MAX_ENTRIES_PER_PAGE, DecodeError::TooManyEntries)?;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        entries.push(decode_entry(&mut decoder, profile)?);
    }
    decoder.finish()?;
    let page = ManifestPage {
        manifest_id,
        index,
        total,
        previous_digest,
        profile,
        entries,
    };
    let canonical = encode_page(&page).map_err(DecodeError::Semantic)?;
    if canonical != input {
        return Err(DecodeError::NonCanonical);
    }
    Ok(page)
}

fn decode_entry(
    decoder: &mut Decoder<'_>,
    profile: PathProfile,
) -> Result<ManifestEntry, DecodeError> {
    let fields = decoder.map_len()?;
    if !(2..=5).contains(&fields) {
        return Err(DecodeError::InvalidStructure);
    }
    decoder.exact_key(0)?;
    let component_count =
        decoder.bounded_array_len(MAX_PATH_COMPONENTS, DecodeError::TooManyComponents)?;
    if component_count == 0 {
        return Err(DecodeError::InvalidStructure);
    }
    let mut path = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        path.push(match profile {
            PathProfile::Portable => Component::Text(decoder.text(255)?.to_owned()),
            PathProfile::RawPosix => Component::Bytes(decoder.bytes(255)?.to_vec()),
        });
    }
    decoder.exact_key(1)?;
    let kind = match decoder.uint()? {
        0 => EntryKind::File,
        1 => EntryKind::Directory,
        _ => return Err(DecodeError::InvalidStructure),
    };
    let mut length = None;
    let mut storage = None;
    let mut metadata = None;
    let mut previous_key = 1;
    for _ in 2..fields {
        let key = decoder.uint()?;
        if key <= previous_key {
            return Err(DecodeError::NonCanonical);
        }
        previous_key = key;
        match key {
            2 => length = Some(decoder.uint()?),
            3 => storage = Some(decode_storage(decoder)?),
            4 => metadata = Some(decode_metadata(decoder)?),
            _ => return Err(DecodeError::InvalidStructure),
        }
    }
    Ok(ManifestEntry {
        path,
        kind,
        length,
        storage,
        metadata,
    })
}

fn decode_storage(decoder: &mut Decoder<'_>) -> Result<StorageRef, DecodeError> {
    match decoder.array_len()? {
        2 => {
            if decoder.uint()? != 0 {
                return Err(DecodeError::InvalidStructure);
            }
            Ok(StorageRef::Direct(decode_object(decoder)?))
        }
        5 => {
            if decoder.uint()? != 1 {
                return Err(DecodeError::InvalidStructure);
            }
            Ok(StorageRef::Pack {
                pack: decode_object(decoder)?,
                offset: decoder.uint()?,
                length: decoder.uint()?,
                logical: decode_object(decoder)?,
            })
        }
        _ => Err(DecodeError::InvalidStructure),
    }
}

fn decode_object(decoder: &mut Decoder<'_>) -> Result<ObjectId, DecodeError> {
    if decoder.array_len()? != 3 {
        return Err(DecodeError::InvalidStructure);
    }
    let suite = u16::try_from(decoder.uint()?).map_err(|_| DecodeError::InvalidStructure)?;
    let root = decoder.fixed_bytes::<32>()?;
    let length = decoder.uint()?;
    Ok(ObjectId {
        suite,
        root,
        length,
    })
}

fn decode_metadata(decoder: &mut Decoder<'_>) -> Result<FileMetadata, DecodeError> {
    let fields = decoder.map_len()?;
    if fields > 4 {
        return Err(DecodeError::InvalidStructure);
    }
    let mut metadata = FileMetadata::default();
    let mut previous_key = None;
    for _ in 0..fields {
        let key = decoder.uint()?;
        if previous_key.is_some_and(|previous| key <= previous) {
            return Err(DecodeError::NonCanonical);
        }
        previous_key = Some(key);
        match key {
            0 => {
                metadata.mode = Some(
                    u16::try_from(decoder.uint()?).map_err(|_| DecodeError::InvalidStructure)?,
                );
            }
            1 => metadata.mtime_seconds = Some(decoder.int()?),
            2 => {
                metadata.mtime_nanoseconds = Some(
                    u32::try_from(decoder.uint()?).map_err(|_| DecodeError::InvalidStructure)?,
                );
            }
            3 => metadata.media_type = Some(decoder.text(127)?.to_owned()),
            _ => return Err(DecodeError::InvalidStructure),
        }
    }
    Ok(metadata)
}

/// The manifest's view of a deterministic CBOR reader.
///
/// `vot-cbor` decides what a well-formed canonical item is. This decides what a
/// manifest calls each failure, which is not one mapping but several: a byte
/// string past its bound is a component that is too large, and a collection
/// count past `usize` is an invalid structure.
struct Decoder<'a> {
    reader: vot_cbor::Reader<'a>,
}

/// The failures that mean the bytes are not deterministic CBOR at all, whatever
/// the manifest expected to find.
fn structural(error: vot_cbor::Error) -> DecodeError {
    match error {
        vot_cbor::Error::Truncated => DecodeError::Truncated,
        vot_cbor::Error::NonCanonical => DecodeError::NonCanonical,
        vot_cbor::Error::WrongType => DecodeError::WrongType,
        vot_cbor::Error::NotUtf8 => DecodeError::InvalidUtf8,
        vot_cbor::Error::Malformed | vot_cbor::Error::Trailing => DecodeError::InvalidCbor,
        vot_cbor::Error::TooLarge => DecodeError::InvalidStructure,
    }
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            reader: vot_cbor::Reader::new(input),
        }
    }

    fn uint(&mut self) -> Result<u64, DecodeError> {
        self.reader.uint().map_err(structural)
    }

    fn int(&mut self) -> Result<i64, DecodeError> {
        self.reader.int().map_err(structural)
    }

    fn array_len(&mut self) -> Result<usize, DecodeError> {
        self.collection_len(vot_cbor::major::ARRAY)
    }

    fn map_len(&mut self) -> Result<usize, DecodeError> {
        self.collection_len(vot_cbor::major::MAP)
    }

    fn collection_len(&mut self, expected_major: u8) -> Result<usize, DecodeError> {
        let length = self.reader.typed_head(expected_major).map_err(structural)?;
        usize::try_from(length).map_err(|_| DecodeError::InvalidStructure)
    }

    fn bounded_array_len(
        &mut self,
        limit: usize,
        error: DecodeError,
    ) -> Result<usize, DecodeError> {
        let length = self.array_len()?;
        if length > limit {
            Err(error)
        } else {
            Ok(length)
        }
    }

    fn bytes(&mut self, limit: usize) -> Result<&'a [u8], DecodeError> {
        self.reader.bytes(limit).map_err(|error| match error {
            // The bound is the manifest's, so exceeding it is a component that
            // is too large rather than a structural fault.
            vot_cbor::Error::TooLarge => DecodeError::ComponentTooLarge,
            other => structural(other),
        })
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.reader.fixed_bytes::<N>().map_err(|error| match error {
            // A byte string of another length where a fixed one was expected is
            // the wrong shape rather than an oversized component.
            vot_cbor::Error::TooLarge => DecodeError::InvalidStructure,
            other => structural(other),
        })
    }

    fn text(&mut self, limit: usize) -> Result<&'a str, DecodeError> {
        self.reader.text(limit).map_err(|error| match error {
            vot_cbor::Error::TooLarge => DecodeError::ComponentTooLarge,
            other => structural(other),
        })
    }

    /// Whether the next item is the `null` an absent optional field encodes as.
    fn peek_null(&self) -> bool {
        self.reader.peek_null()
    }

    fn null(&mut self) -> Result<(), DecodeError> {
        self.reader.null().map_err(structural)
    }

    fn exact_key(&mut self, expected: u64) -> Result<(), DecodeError> {
        // A key out of order or absent is what makes a map non-canonical here,
        // rather than merely the wrong type.
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(DecodeError::NonCanonical)
        }
    }

    fn finish(&self) -> Result<(), DecodeError> {
        self.reader
            .finish()
            .map_err(|_| DecodeError::InvalidStructure)
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
        || component.contains(['\0', '/', '\\', '<', '>', ':', '"', '|', '?', '*'])
        || component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character <= '\u{1f}'
                || matches!(
                    character,
                    '\u{200c}'
                        | '\u{200d}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{feff}'
                )
        })
    {
        return Err(Error::InvalidPath);
    }
    let compatibility: String = component.nfkc().collect();
    if matches!(compatibility.as_str(), "." | "..") {
        return Err(Error::InvalidPath);
    }
    let folded = portable_fold(component);
    if matches!(folded.as_str(), "" | "." | "..") {
        return Err(Error::InvalidPath);
    }
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

fn portable_fold(component: &str) -> String {
    let mut folded = String::with_capacity(component.len());
    for character in component.nfc() {
        match character {
            'I' | 'i' | '\u{130}' | '\u{131}' => folded.push('i'),
            _ => folded.extend(character.to_lowercase()),
        }
    }
    folded.nfc().collect()
}

fn is_device_digit(value: &str) -> bool {
    matches!(
        value,
        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "\u{b9}" | "\u{b2}" | "\u{b3}"
    )
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
    vot_cbor::map(out, fields as u64);
    vot_cbor::uint(out, 0);
    vot_cbor::array(out, entry.path.len() as u64);
    for component in &entry.path {
        match component {
            Component::Text(text) => vot_cbor::text(out, text),
            Component::Bytes(bytes) => vot_cbor::bytes(out, bytes),
        }
    }
    vot_cbor::uint(out, 1);
    vot_cbor::uint(out, u64::from(entry.kind == EntryKind::Directory));
    if let Some(length) = entry.length {
        vot_cbor::uint(out, 2);
        vot_cbor::uint(out, length);
    }
    if let Some(storage) = &entry.storage {
        vot_cbor::uint(out, 3);
        encode_storage(out, storage);
    }
    if let Some(metadata) = &entry.metadata {
        vot_cbor::uint(out, 4);
        encode_metadata(out, metadata);
    }
}

fn encode_object(out: &mut Vec<u8>, object: &ObjectId) {
    vot_cbor::array(out, 3);
    vot_cbor::uint(out, u64::from(object.suite));
    vot_cbor::bytes(out, &object.root);
    vot_cbor::uint(out, object.length);
}

fn encode_storage(out: &mut Vec<u8>, storage: &StorageRef) {
    match storage {
        StorageRef::Direct(object) => {
            vot_cbor::array(out, 2);
            vot_cbor::uint(out, 0);
            encode_object(out, object);
        }
        StorageRef::Pack {
            pack,
            offset,
            length,
            logical,
        } => {
            vot_cbor::array(out, 5);
            vot_cbor::uint(out, 1);
            encode_object(out, pack);
            vot_cbor::uint(out, *offset);
            vot_cbor::uint(out, *length);
            encode_object(out, logical);
        }
    }
}

fn encode_metadata(out: &mut Vec<u8>, metadata: &FileMetadata) {
    let fields = usize::from(metadata.mode.is_some())
        + usize::from(metadata.mtime_seconds.is_some())
        + usize::from(metadata.mtime_nanoseconds.is_some())
        + usize::from(metadata.media_type.is_some());
    vot_cbor::map(out, fields as u64);
    if let Some(mode) = metadata.mode {
        vot_cbor::uint(out, 0);
        vot_cbor::uint(out, u64::from(mode));
    }
    if let Some(seconds) = metadata.mtime_seconds {
        vot_cbor::uint(out, 1);
        vot_cbor::int(out, seconds);
    }
    if let Some(nanoseconds) = metadata.mtime_nanoseconds {
        vot_cbor::uint(out, 2);
        vot_cbor::uint(out, u64::from(nanoseconds));
    }
    if let Some(media_type) = &metadata.media_type {
        vot_cbor::uint(out, 3);
        vot_cbor::text(out, media_type);
    }
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
        assert_eq!(decode_page(&encoded).unwrap(), page(0, [0; 32], "a.txt"));
    }

    #[test]
    fn decoder_rejects_noncanonical_truncated_and_unbounded_inputs() {
        let encoded = encode_page(&page(0, [0; 32], "a.txt")).unwrap();
        for length in 0..encoded.len() {
            assert!(decode_page(&encoded[..length]).is_err());
        }

        let mut empty = page(0, [0; 32], "a.txt");
        empty.entries.clear();
        let mut oversized_entries = encode_page(&empty).unwrap();
        assert_eq!(oversized_entries.pop(), Some(0x80));
        oversized_entries.extend_from_slice(&[0x9a, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            decode_page(&oversized_entries),
            Err(DecodeError::TooManyEntries)
        );

        let mut noncanonical = vec![0xb8, 0x07];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert_eq!(decode_page(&noncanonical), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn packed_raw_page_with_metadata_round_trips() {
        let logical = ObjectId {
            suite: 2,
            root: [3; 32],
            length: 3,
        };
        let rich = ManifestPage {
            manifest_id: [4; 16],
            index: 7,
            total: Some(8),
            previous_digest: [5; 32],
            profile: PathProfile::RawPosix,
            entries: vec![ManifestEntry {
                path: vec![Component::Bytes(b"raw-name".to_vec())],
                kind: EntryKind::File,
                length: Some(3),
                storage: Some(StorageRef::Pack {
                    pack: ObjectId {
                        suite: 1,
                        root: [6; 32],
                        length: 4096,
                    },
                    offset: 100,
                    length: 3,
                    logical,
                }),
                metadata: Some(FileMetadata {
                    mode: Some(0o640),
                    mtime_seconds: Some(-1),
                    mtime_nanoseconds: Some(999_999_999),
                    media_type: Some("application/octet-stream".to_owned()),
                }),
            }],
        };
        let encoded = encode_page(&rich).unwrap();
        assert_eq!(decode_page(&encoded).unwrap(), rich);
    }

    #[test]
    fn seal_round_trips_and_rejects_inconsistent_commitments() {
        let seal = Seal {
            manifest_id: [4; 16],
            final_page_count: 2,
            final_page_digest: [8; 32],
            package: ObjectId {
                suite: 1,
                root: [9; 32],
                length: 123,
            },
            pages: vec![
                PageCommitment {
                    index: 0,
                    digest: [7; 32],
                },
                PageCommitment {
                    index: 1,
                    digest: [8; 32],
                },
            ],
        };
        let encoded = encode_seal(&seal).unwrap();
        assert_eq!(decode_seal(&encoded).unwrap(), seal);
        for length in 0..encoded.len() {
            assert!(decode_seal(&encoded[..length]).is_err());
        }
        let mut wrong = seal.clone();
        wrong.pages[1].index = 2;
        assert_eq!(encode_seal(&wrong), Err(Error::InvalidSeal));
        wrong = seal.clone();
        wrong.final_page_digest = [0; 32];
        assert_eq!(encode_seal(&wrong), Err(Error::InvalidSeal));

        wrong = seal.clone();
        wrong.final_page_count = 0;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));
        wrong = seal.clone();
        wrong.final_page_count = 1;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));
        wrong = seal.clone();
        wrong.package.suite = 0;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));
        wrong = seal.clone();
        wrong.package.length = i64::MAX as u64 + 1;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));

        let pages = (0..MAX_PAGE_COMMITMENTS)
            .map(|index| PageCommitment {
                index: index as u64,
                digest: [8; 32],
            })
            .collect::<Vec<_>>();
        wrong = seal.clone();
        wrong.final_page_count = pages.len() as u64;
        wrong.pages = pages;
        wrong.package.suite = 2;
        wrong.package.length = i64::MAX as u64;
        assert_eq!(validate_seal(&wrong), Ok(()));
        let encoded = encode_seal(&wrong).unwrap();
        assert!(encoded.len() <= MAX_PAGE_BYTES);

        wrong.pages.push(PageCommitment {
            index: MAX_PAGE_COMMITMENTS as u64,
            digest: [8; 32],
        });
        wrong.final_page_count = wrong.pages.len() as u64;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));
    }

    #[test]
    fn manifest_collection_and_byte_bounds_are_exact() {
        assert_eq!(MAX_PAGE_COMMITMENTS, 26_883);
        assert!(validate_entry_count(MAX_ENTRIES_PER_PAGE).is_ok());
        assert_eq!(
            validate_entry_count(MAX_ENTRIES_PER_PAGE + 1),
            Err(Error::PageTooLarge)
        );
        assert!(validate_page_length(MAX_PAGE_BYTES).is_ok());
        assert_eq!(
            validate_page_length(MAX_PAGE_BYTES + 1),
            Err(Error::PageTooLarge)
        );
    }

    #[test]
    fn deterministic_mutation_corpus_never_panics() {
        let mut state = 0xbb67_ae85_84ca_a73b_u64;
        for length in 0..4096 {
            let mut input = vec![0; length % 1025];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            if let Ok(page) = decode_page(&input) {
                assert_eq!(encode_page(&page).unwrap(), input);
            }
        }
    }

    #[test]
    fn portable_collision_and_reserved_corpus() {
        for (left, right) in [
            ("Readme", "README"),
            ("\u{e9}", "e\u{301}"),
            ("I", "\u{131}"),
            ("\u{130}", "i"),
        ] {
            let collisions = vec![file(left), file(right)];
            assert_eq!(
                validate_entries(&collisions, PathProfile::Portable),
                Err(Error::PathCollision)
            );
        }
        for name in [
            "CON",
            "aux.txt",
            "NUL.tar.gz",
            "COM1",
            "COM\u{b9}",
            "LPT9",
            "bad/part",
            "bad\\part",
            "bad:name",
            "trail.",
            "trail ",
            ".",
            "..",
            "\u{ff0e}",
            "\u{2024}\u{2024}",
            "join\u{200d}er",
            "rtl\u{202e}name",
        ] {
            assert_eq!(
                canonical_path_key(
                    &vec![Component::Text(name.to_owned())],
                    PathProfile::Portable
                ),
                Err(Error::InvalidPath)
            );
        }
    }

    #[test]
    fn progressive_reorder_replay_missing_and_broken_chain_are_rejected_by_ingest() {
        let first = page(0, [0; 32], "a");
        let first_digest = *blake3::hash(&encode_page(&first).unwrap()).as_bytes();

        let mut reordered = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        assert_eq!(
            reordered.accept(&page(1, first_digest, "b")),
            Err(Error::WrongPageIndex)
        );

        let mut replayed = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        replayed.accept(&first).unwrap();
        assert_eq!(replayed.accept(&first), Err(Error::WrongPageIndex));

        let mut missing = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        missing.accept(&first).unwrap();
        assert_eq!(
            missing.accept(&page(2, first_digest, "c")),
            Err(Error::WrongPageIndex)
        );

        let mut broken_chain = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        broken_chain.accept(&first).unwrap();
        assert_eq!(
            broken_chain.accept(&page(1, [7; 32], "b")),
            Err(Error::BrokenPageChain)
        );
    }

    #[test]
    fn source_mutation_is_rejected_at_seal() {
        let first = page(0, [0; 32], "a");
        let mut ingest = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        let accepted_digest = ingest.accept(&first).unwrap();
        let valid_package = ObjectId {
            suite: 1,
            root: [1; 32],
            length: 1,
        };
        let valid = Seal {
            manifest_id: [9; 16],
            final_page_count: 1,
            final_page_digest: accepted_digest,
            package: valid_package.clone(),
            pages: vec![PageCommitment {
                index: 0,
                digest: accepted_digest,
            }],
        };
        assert_eq!(ingest.verify_seal(&valid), Ok(()));

        let mut mutated = first.clone();
        mutated.entries[0] = file("changed");
        let mutated_digest = *blake3::hash(&encode_page(&mutated).unwrap()).as_bytes();
        let mut wrong_final_digest = valid.clone();
        wrong_final_digest.final_page_digest = mutated_digest;
        assert_eq!(
            ingest.verify_seal(&wrong_final_digest),
            Err(Error::InvalidSeal)
        );
        let mut wrong_page_commitment = valid.clone();
        wrong_page_commitment.pages[0].digest = mutated_digest;
        assert_eq!(
            ingest.verify_seal(&wrong_page_commitment),
            Err(Error::InvalidSeal)
        );
        let mutated_seal = Seal {
            manifest_id: [9; 16],
            final_page_count: 1,
            final_page_digest: mutated_digest,
            package: valid_package,
            pages: vec![PageCommitment {
                index: 0,
                digest: mutated_digest,
            }],
        };
        assert_eq!(ingest.verify_seal(&mutated_seal), Err(Error::InvalidSeal));
        assert!(!ingest.is_poisoned());
    }

    #[test]
    fn index_entry_geometry_is_fixed() {
        assert!(ManifestIndex::bytes_per_entry() <= 24);
        assert!(ManifestIndex::bytes_per_entry() * 1_000_000 <= 24_000_000);
    }
}
