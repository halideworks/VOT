//! Canonical writers.

use super::{
    Component, EntryKind, Error, FileMetadata, ManifestEntry, ManifestPage, ObjectId, PathProfile,
    Seal, StorageRef, validate_entries, validate_entry_count, validate_page_length, validate_seal,
};

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

pub(super) fn encode_entry(out: &mut Vec<u8>, entry: &ManifestEntry) {
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
