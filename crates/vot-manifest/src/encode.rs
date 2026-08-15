//! Canonical writers.

use super::{
    Component, EntryKind, Error, FileMetadata, ManifestEntry, ManifestPage, ObjectId, PathProfile,
    Seal, StorageRef, validate_entries, validate_entry_count, validate_page_length, validate_seal,
};

pub fn page_encoded_len(page: &ManifestPage) -> Result<usize, Error> {
    validate_entry_count(page.entries.len())?;
    validate_entries(&page.entries, page.profile)?;
    let mut total = add(0, vot_cbor::head_len(7))?;
    total = add(total, vot_cbor::head_len(0))?;
    total = add(total, vot_cbor::head_len(0))?;
    total = add(total, vot_cbor::head_len(1))?;
    total = add(total, vot_cbor::payload_len(page.manifest_id.len()))?;
    total = add(total, vot_cbor::head_len(2))?;
    total = add(total, vot_cbor::head_len(page.index))?;
    total = add(total, vot_cbor::head_len(3))?;
    total = add(total, page.total.map_or(1, vot_cbor::head_len))?;
    total = add(total, vot_cbor::head_len(4))?;
    total = add(total, vot_cbor::payload_len(page.previous_digest.len()))?;
    total = add(total, vot_cbor::head_len(5))?;
    total = add(total, vot_cbor::head_len(profile_code(page.profile)))?;
    total = add(total, vot_cbor::head_len(6))?;
    total = add(total, vot_cbor::head_len(page.entries.len() as u64))?;
    for entry in &page.entries {
        total = add(total, entry_encoded_len(entry)?)?;
    }
    validate_page_length(total)?;
    Ok(total)
}

pub fn seal_encoded_len(seal: &Seal) -> Result<usize, Error> {
    validate_seal(seal)?;
    let mut total = add(0, vot_cbor::head_len(6))?;
    total = add(total, vot_cbor::head_len(0))?;
    total = add(total, vot_cbor::head_len(0))?;
    total = add(total, vot_cbor::head_len(1))?;
    total = add(total, vot_cbor::payload_len(seal.manifest_id.len()))?;
    total = add(total, vot_cbor::head_len(2))?;
    total = add(total, vot_cbor::head_len(seal.final_page_count))?;
    total = add(total, vot_cbor::head_len(3))?;
    total = add(total, vot_cbor::payload_len(seal.final_page_digest.len()))?;
    total = add(total, vot_cbor::head_len(4))?;
    total = add(total, vot_cbor::head_len(4))?;
    total = add(total, vot_cbor::head_len(1))?;
    total = add(total, vot_cbor::head_len(u64::from(seal.package.suite)))?;
    total = add(total, vot_cbor::payload_len(seal.package.root.len()))?;
    total = add(total, vot_cbor::head_len(seal.package.length))?;
    total = add(total, vot_cbor::head_len(5))?;
    total = add(total, vot_cbor::head_len(seal.pages.len() as u64))?;
    for commitment in &seal.pages {
        total = add(total, vot_cbor::head_len(3))?;
        total = add(total, vot_cbor::head_len(commitment.index))?;
        total = add(total, vot_cbor::payload_len(commitment.digest.len()))?;
        total = add(total, vot_cbor::head_len(0))?;
    }
    validate_page_length(total)?;
    Ok(total)
}

pub fn encode_page(page: &ManifestPage) -> Result<Vec<u8>, Error> {
    let expected = page_encoded_len(page)?;
    let mut out = Vec::with_capacity(expected);
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
    vot_cbor::uint(&mut out, profile_code(page.profile));
    vot_cbor::uint(&mut out, 6);
    vot_cbor::array(&mut out, page.entries.len() as u64);
    for entry in &page.entries {
        encode_entry(&mut out, entry);
    }
    if out.len() != expected {
        return Err(Error::PageTooLarge);
    }
    Ok(out)
}

pub fn encode_seal(seal: &Seal) -> Result<Vec<u8>, Error> {
    let expected = seal_encoded_len(seal)?;
    let mut out = Vec::with_capacity(expected);
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
    if out.len() != expected {
        return Err(Error::PageTooLarge);
    }
    Ok(out)
}

fn add(total: usize, part: usize) -> Result<usize, Error> {
    total.checked_add(part).ok_or(Error::PageTooLarge)
}

pub(super) fn counted_fields(base: u64, flags: impl IntoIterator<Item = bool>) -> u64 {
    flags.into_iter().fold(base, |n, flag| n + u64::from(flag))
}

pub(super) const fn profile_code(profile: PathProfile) -> u64 {
    match profile {
        PathProfile::Portable => 0,
        PathProfile::RawPosix => 1,
    }
}

pub(super) const fn kind_code(kind: EntryKind) -> u64 {
    match kind {
        EntryKind::File => 0,
        EntryKind::Directory => 1,
    }
}

fn entry_fields(entry: &ManifestEntry) -> u64 {
    counted_fields(
        2,
        [
            entry.length.is_some(),
            entry.storage.is_some(),
            entry.metadata.is_some(),
        ],
    )
}

fn metadata_fields(metadata: &FileMetadata) -> u64 {
    counted_fields(
        0,
        [
            metadata.mode.is_some(),
            metadata.mtime_seconds.is_some(),
            metadata.mtime_nanoseconds.is_some(),
            metadata.media_type.is_some(),
        ],
    )
}

fn entry_encoded_len(entry: &ManifestEntry) -> Result<usize, Error> {
    let mut total = add(0, vot_cbor::head_len(entry_fields(entry)))?;
    total = add(total, vot_cbor::head_len(0))?;
    total = add(total, vot_cbor::head_len(entry.path.len() as u64))?;
    for component in &entry.path {
        total = add(
            total,
            match component {
                Component::Text(text) => vot_cbor::payload_len(text.len()),
                Component::Bytes(bytes) => vot_cbor::payload_len(bytes.len()),
            },
        )?;
    }
    total = add(total, vot_cbor::head_len(1))?;
    total = add(total, vot_cbor::head_len(kind_code(entry.kind)))?;
    if let Some(length) = entry.length {
        total = add(total, vot_cbor::head_len(2))?;
        total = add(total, vot_cbor::head_len(length))?;
    }
    if let Some(storage) = &entry.storage {
        total = add(total, vot_cbor::head_len(3))?;
        total = add(total, storage_encoded_len(storage)?)?;
    }
    if let Some(metadata) = &entry.metadata {
        total = add(total, vot_cbor::head_len(4))?;
        total = add(total, metadata_encoded_len(metadata)?)?;
    }
    Ok(total)
}

fn object_encoded_len(object: &ObjectId) -> Result<usize, Error> {
    let mut total = add(0, vot_cbor::head_len(3))?;
    total = add(total, vot_cbor::head_len(u64::from(object.suite)))?;
    total = add(total, vot_cbor::payload_len(object.root.len()))?;
    add(total, vot_cbor::head_len(object.length))
}

fn storage_encoded_len(storage: &StorageRef) -> Result<usize, Error> {
    match storage {
        StorageRef::Direct(object) => {
            let mut total = add(0, vot_cbor::head_len(2))?;
            total = add(total, vot_cbor::head_len(0))?;
            add(total, object_encoded_len(object)?)
        }
        StorageRef::Pack {
            pack,
            offset,
            length,
            logical,
        } => {
            let mut total = add(0, vot_cbor::head_len(5))?;
            total = add(total, vot_cbor::head_len(1))?;
            total = add(total, object_encoded_len(pack)?)?;
            total = add(total, vot_cbor::head_len(*offset))?;
            total = add(total, vot_cbor::head_len(*length))?;
            add(total, object_encoded_len(logical)?)
        }
    }
}

fn metadata_encoded_len(metadata: &FileMetadata) -> Result<usize, Error> {
    let mut total = add(0, vot_cbor::head_len(metadata_fields(metadata)))?;
    if let Some(mode) = metadata.mode {
        total = add(total, vot_cbor::head_len(0))?;
        total = add(total, vot_cbor::head_len(u64::from(mode)))?;
    }
    if let Some(seconds) = metadata.mtime_seconds {
        total = add(total, vot_cbor::head_len(1))?;
        total = add(total, vot_cbor::int_len(seconds))?;
    }
    if let Some(nanoseconds) = metadata.mtime_nanoseconds {
        total = add(total, vot_cbor::head_len(2))?;
        total = add(total, vot_cbor::head_len(u64::from(nanoseconds)))?;
    }
    if let Some(media_type) = &metadata.media_type {
        total = add(total, vot_cbor::head_len(3))?;
        total = add(total, vot_cbor::payload_len(media_type.len()))?;
    }
    Ok(total)
}

pub(super) fn encode_entry(out: &mut Vec<u8>, entry: &ManifestEntry) {
    vot_cbor::map(out, entry_fields(entry));
    vot_cbor::uint(out, 0);
    vot_cbor::array(out, entry.path.len() as u64);
    for component in &entry.path {
        match component {
            Component::Text(text) => vot_cbor::text(out, text),
            Component::Bytes(bytes) => vot_cbor::bytes(out, bytes),
        }
    }
    vot_cbor::uint(out, 1);
    vot_cbor::uint(out, kind_code(entry.kind));
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

pub(super) fn encode_object(out: &mut Vec<u8>, object: &ObjectId) {
    vot_cbor::array(out, 3);
    vot_cbor::uint(out, u64::from(object.suite));
    vot_cbor::bytes(out, &object.root);
    vot_cbor::uint(out, object.length);
}

pub(super) fn encode_storage(out: &mut Vec<u8>, storage: &StorageRef) {
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

pub(super) fn encode_metadata(out: &mut Vec<u8>, metadata: &FileMetadata) {
    vot_cbor::map(out, metadata_fields(metadata));
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
    use super::{counted_fields, kind_code, profile_code};
    use crate::{EntryKind, PathProfile};

    #[test]
    fn counted_fields_adds_each_present_flag() {
        assert_eq!(counted_fields(2, [false, false, false]), 2);
        assert_eq!(counted_fields(2, [true, false, false]), 3);
        assert_eq!(counted_fields(2, [false, true, false]), 3);
        assert_eq!(counted_fields(2, [true, true, false]), 4);
        assert_eq!(counted_fields(2, [true, true, true]), 5);
        assert_eq!(counted_fields(0, [true, true, true, true]), 4);
        assert_eq!(counted_fields(0, [false, false, false, false]), 0);
        assert_eq!(profile_code(PathProfile::Portable), 0);
        assert_eq!(profile_code(PathProfile::RawPosix), 1);
        assert_eq!(kind_code(EntryKind::File), 0);
        assert_eq!(kind_code(EntryKind::Directory), 1);
    }
}
