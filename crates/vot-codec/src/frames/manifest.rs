//! Package descriptor and manifest frame family.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use super::{Error, MAX_OBJECT_LENGTH, ObjectId, Reader, decode_object, encode_object, frame_type};

/// Maximum pages one `MANIFEST_REQUEST` may name.
pub const MAX_MANIFEST_REQUEST_PAGES: u64 = 8_192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDescriptor {
    pub package: ObjectId,
    pub manifest_id: [u8; 16],
    pub page_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestRequest {
    pub request_id: [u8; 16],
    pub manifest_id: [u8; 16],
    pub first_page: u64,
    pub page_count: u64,
}

pub(super) fn encode_package_descriptor(
    value: &PackageDescriptor,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    value.package.validate()?;
    if value.page_count == 0 {
        return Err(Error::InvalidValue);
    }
    vot_cbor::map(output, 3);
    vot_cbor::uint(output, 0);
    encode_object(&value.package, output);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.manifest_id);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.page_count);
    Ok(())
}

pub(super) fn decode_package_descriptor(input: &[u8]) -> Result<PackageDescriptor, Error> {
    let mut reader = Reader::new(input);
    reader.map(3)?;
    reader.key(0)?;
    let package = decode_object(&mut reader)?;
    reader.key(1)?;
    let manifest_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let page_count = reader.uint()?;
    reader.finish()?;
    let value = PackageDescriptor {
        package,
        manifest_id,
        page_count,
    };
    if value.page_count == 0 {
        Err(Error::InvalidValue)
    } else {
        Ok(value)
    }
}

pub(super) fn encode_manifest_request(
    value: &ManifestRequest,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    validate_manifest_request(value)?;
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    vot_cbor::bytes(output, &value.request_id);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.manifest_id);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.first_page);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.page_count);
    Ok(())
}

pub(super) fn decode_manifest_request(input: &[u8]) -> Result<ManifestRequest, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let request_id = reader.fixed::<16>()?;
    reader.key(1)?;
    let manifest_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let first_page = reader.uint()?;
    reader.key(3)?;
    let page_count = reader.uint()?;
    reader.finish()?;
    let value = ManifestRequest {
        request_id,
        manifest_id,
        first_page,
        page_count,
    };
    validate_manifest_request(&value)?;
    Ok(value)
}

pub(super) fn validate_manifest_request(value: &ManifestRequest) -> Result<(), Error> {
    if value.page_count == 0
        || value.page_count > MAX_MANIFEST_REQUEST_PAGES
        || value.first_page > MAX_OBJECT_LENGTH
        || value.first_page.checked_add(value.page_count).is_none()
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

pub(super) fn validate_manifest_page(bytes: &[u8]) -> Result<(), Error> {
    vot_manifest::decode_page(bytes)
        .map(|_| ())
        .map_err(|_| Error::Manifest)
}

pub(super) fn validate_seal(bytes: &[u8]) -> Result<(), Error> {
    if crate::registered_payload_limit(frame_type::SEAL).is_some_and(|limit| bytes.len() > limit) {
        return Err(Error::TooLarge);
    }
    vot_manifest::decode_seal(bytes)
        .map(|_| ())
        .map_err(|_| Error::Seal)
}
