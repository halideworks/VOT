//! Bounded canonical readers.

use super::{
    Component, DecodeError, EntryKind, FileMetadata, MAX_ENTRIES_PER_PAGE, MAX_PAGE_COMMITMENTS,
    MAX_PATH_COMPONENTS, ManifestEntry, ManifestPage, ObjectId, PageCommitment, PathProfile, Seal,
    StorageRef, encode_page, encode_seal, validate_page_length, validate_seal,
};

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

pub(super) fn decode_entry(
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

pub(super) fn decode_storage(decoder: &mut Decoder<'_>) -> Result<StorageRef, DecodeError> {
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

pub(super) fn decode_object(decoder: &mut Decoder<'_>) -> Result<ObjectId, DecodeError> {
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

pub(super) fn decode_metadata(decoder: &mut Decoder<'_>) -> Result<FileMetadata, DecodeError> {
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
pub(super) struct Decoder<'a> {
    reader: vot_cbor::Reader<'a>,
}

/// The failures that mean the bytes are not deterministic CBOR at all, whatever
/// the manifest expected to find.
pub(super) fn structural(error: vot_cbor::Error) -> DecodeError {
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
