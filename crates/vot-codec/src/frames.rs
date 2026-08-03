//! Typed application payloads for the VOT v0.3 frame envelope.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use super::{DecodeError, DecodeLimits, DecodedFrame, decode_one, encode_frame, frame_type};

const MAX_OBJECT_LENGTH: u64 = i64::MAX as u64;
const GROUP_BYTES: u64 = 65_536;

const MAX_REQUESTED_RANGE: u64 = 4_194_304;
const MAX_COVERED_RANGE: u64 = 4_259_840;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_DATA_BYTES: usize = 256 * 1024;
const MAX_MANIFEST_REQUEST_PAGES: u64 = 8_192;
const MAX_HAVE_RUNS: u64 = 2_097_152;

/// The most records one bundle can declare, from `spec/proof-bundle.cddl`.
pub const MAX_DATA_RECORDS_PER_BUNDLE: usize = 17;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Envelope(DecodeError),
    WrongFrameType(u64),
    Malformed,
    InvalidValue,
    TooLarge,
    Manifest,
    Seal,
    Receipt,
}

impl From<DecodeError> for Error {
    fn from(error: DecodeError) -> Self {
        Self::Envelope(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId {
    pub suite: u16,
    pub root: [u8; 32],
    pub length: u64,
}

impl ObjectId {
    pub fn validate(&self) -> Result<(), Error> {
        if !matches!(self.suite, 1 | 2) || self.length > MAX_OBJECT_LENGTH {
            Err(Error::InvalidValue)
        } else {
            Ok(())
        }
    }
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeRequest {
    pub request_id: [u8; 16],
    pub object: ObjectId,
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofBundle {
    pub request_id: [u8; 16],
    pub bundle_id: [u8; 16],
    pub object: ObjectId,
    pub requested_offset: u64,
    pub requested_length: u64,
    pub covered_offset: u64,
    pub covered_length: u64,
    pub data_record_count: u64,
    pub total_plaintext_length: u64,
    pub proof: Vec<u8>,
}

impl ProofBundle {
    pub fn validate(&self) -> Result<(), Error> {
        validate_proof_bundle(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataRecord {
    pub bundle_id: [u8; 16],
    pub record_index: u64,
    pub plaintext_offset: u64,
    pub plaintext_length: u64,
    pub compression: u8,
    pub encoded: Vec<u8>,
}

impl DataRecord {
    pub fn validate(&self) -> Result<(), Error> {
        validate_data_record(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaveRun {
    pub start_group: u64,
    pub group_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Have {
    pub object: ObjectId,
    pub map_sequence: u64,
    pub runs: Vec<HaveRun>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capacity {
    pub epoch: u64,
    pub available_bytes: u64,
    pub bdp_target_bytes: u64,
    pub max_inflight_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceFrame {
    pub object: ObjectId,
    pub sequence: u64,
    pub unit_start: u64,
    pub unit_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedFrame {
    PackageDescriptor(PackageDescriptor),
    ManifestRequest(ManifestRequest),
    ManifestPage(Vec<u8>),
    Seal(Vec<u8>),
    Have(Have),
    RangeRequest(RangeRequest),
    ProofBundle(ProofBundle),
    DataRecord(DataRecord),
    Capacity(Capacity),
    TransitVerified(AssuranceFrame),
    ChunkDurable(AssuranceFrame),
    ChunkAtRestVerified(AssuranceFrame),
    PublishReceipt(Vec<u8>),
}

impl TypedFrame {
    #[must_use]
    pub const fn frame_type(&self) -> u64 {
        match self {
            Self::PackageDescriptor(_) => frame_type::PACKAGE_DESCRIPTOR,
            Self::ManifestRequest(_) => frame_type::MANIFEST_REQUEST,
            Self::ManifestPage(_) => frame_type::MANIFEST_PAGE,
            Self::Seal(_) => frame_type::SEAL,
            Self::Have(_) => frame_type::HAVE,
            Self::RangeRequest(_) => frame_type::RANGE_REQUEST,
            Self::ProofBundle(_) => frame_type::PROOF_BUNDLE,
            Self::DataRecord(_) => frame_type::DATA_RECORD,
            Self::Capacity(_) => frame_type::CAPACITY,
            Self::TransitVerified(_) => frame_type::TRANSIT_VERIFIED,
            Self::ChunkDurable(_) => frame_type::CHUNK_DURABLE,
            Self::ChunkAtRestVerified(_) => frame_type::CHUNK_AT_REST_VERIFIED,
            Self::PublishReceipt(_) => frame_type::PUBLISH_RECEIPT,
        }
    }
}

/// Encodes one typed frame and its bounded envelope.
pub fn encode(frame: &TypedFrame, output: &mut Vec<u8>) -> Result<(), Error> {
    let mut payload = Vec::new();
    match frame {
        TypedFrame::PackageDescriptor(value) => encode_package_descriptor(value, &mut payload)?,
        TypedFrame::ManifestRequest(value) => encode_manifest_request(value, &mut payload)?,
        TypedFrame::ManifestPage(bytes) => {
            validate_manifest_page(bytes)?;
            payload.extend_from_slice(bytes);
        }
        TypedFrame::Seal(bytes) => {
            validate_seal(bytes)?;
            payload.extend_from_slice(bytes);
        }
        TypedFrame::Have(value) => encode_have(value, &mut payload)?,
        TypedFrame::RangeRequest(value) => encode_range_request(value, &mut payload)?,
        TypedFrame::ProofBundle(value) => encode_proof_bundle(value, &mut payload)?,
        TypedFrame::DataRecord(value) => encode_data_record(value, &mut payload)?,
        TypedFrame::Capacity(value) => encode_capacity(value, &mut payload),
        TypedFrame::TransitVerified(value)
        | TypedFrame::ChunkDurable(value)
        | TypedFrame::ChunkAtRestVerified(value) => encode_assurance(value, &mut payload)?,
        TypedFrame::PublishReceipt(bytes) => {
            validate_receipt(bytes)?;
            payload.extend_from_slice(bytes);
        }
    }
    encode_frame(frame.frame_type(), &payload, output)?;
    Ok(())
}

/// Decodes one typed frame without accepting an unknown application payload.
pub fn decode(input: &[u8], limits: DecodeLimits) -> Result<(TypedFrame, usize), Error> {
    let (decoded, consumed) = decode_one(input, limits)?;
    let frame_kind = decoded.frame_type();
    let payload = match decoded {
        DecodedFrame::Known { payload, .. } => payload,
        DecodedFrame::SkippedOptional { .. } => return Err(Error::WrongFrameType(frame_kind)),
    };
    let frame = match frame_kind {
        frame_type::PACKAGE_DESCRIPTOR => {
            TypedFrame::PackageDescriptor(decode_package_descriptor(payload)?)
        }
        frame_type::MANIFEST_REQUEST => {
            TypedFrame::ManifestRequest(decode_manifest_request(payload)?)
        }
        frame_type::MANIFEST_PAGE => {
            validate_manifest_page(payload)?;
            TypedFrame::ManifestPage(payload.to_vec())
        }
        frame_type::SEAL => {
            validate_seal(payload)?;
            TypedFrame::Seal(payload.to_vec())
        }
        frame_type::HAVE => TypedFrame::Have(decode_have(payload)?),
        frame_type::RANGE_REQUEST => TypedFrame::RangeRequest(decode_range_request(payload)?),
        frame_type::PROOF_BUNDLE => TypedFrame::ProofBundle(decode_proof_bundle(payload)?),
        frame_type::DATA_RECORD => TypedFrame::DataRecord(decode_data_record(payload)?),
        frame_type::CAPACITY => TypedFrame::Capacity(decode_capacity(payload)?),
        frame_type::TRANSIT_VERIFIED => TypedFrame::TransitVerified(decode_assurance(payload)?),
        frame_type::CHUNK_DURABLE => TypedFrame::ChunkDurable(decode_assurance(payload)?),
        frame_type::CHUNK_AT_REST_VERIFIED => {
            TypedFrame::ChunkAtRestVerified(decode_assurance(payload)?)
        }
        frame_type::PUBLISH_RECEIPT => {
            validate_receipt(payload)?;
            TypedFrame::PublishReceipt(payload.to_vec())
        }
        other => return Err(Error::WrongFrameType(other)),
    };
    Ok((frame, consumed))
}

fn encode_package_descriptor(value: &PackageDescriptor, output: &mut Vec<u8>) -> Result<(), Error> {
    value.package.validate()?;
    if value.page_count == 0 {
        return Err(Error::InvalidValue);
    }
    map(3, output);
    uint(0, output);
    encode_object(&value.package, output);
    uint(1, output);
    bytes(&value.manifest_id, output);
    uint(2, output);
    uint(value.page_count, output);
    Ok(())
}

fn decode_package_descriptor(input: &[u8]) -> Result<PackageDescriptor, Error> {
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

fn encode_manifest_request(value: &ManifestRequest, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_manifest_request(value)?;
    map(4, output);
    uint(0, output);
    bytes(&value.request_id, output);
    uint(1, output);
    bytes(&value.manifest_id, output);
    uint(2, output);
    uint(value.first_page, output);
    uint(3, output);
    uint(value.page_count, output);
    Ok(())
}

fn decode_manifest_request(input: &[u8]) -> Result<ManifestRequest, Error> {
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

fn validate_manifest_request(value: &ManifestRequest) -> Result<(), Error> {
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

fn encode_range_request(value: &RangeRequest, output: &mut Vec<u8>) -> Result<(), Error> {
    value.object.validate()?;
    if value.length == 0
        || value.length > MAX_REQUESTED_RANGE
        || value.offset > MAX_OBJECT_LENGTH
        || value
            .offset
            .checked_add(value.length)
            .is_none_or(|end| end > value.object.length)
    {
        return Err(Error::InvalidValue);
    }
    map(4, output);
    uint(0, output);
    bytes(&value.request_id, output);
    uint(1, output);
    encode_object(&value.object, output);
    uint(2, output);
    uint(value.offset, output);
    uint(3, output);
    uint(value.length, output);
    Ok(())
}

fn decode_range_request(input: &[u8]) -> Result<RangeRequest, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let request_id = reader.fixed::<16>()?;
    reader.key(1)?;
    let object = decode_object(&mut reader)?;
    reader.key(2)?;
    let offset = reader.uint()?;
    reader.key(3)?;
    let length = reader.uint()?;
    reader.finish()?;
    let value = RangeRequest {
        request_id,
        object,
        offset,
        length,
    };
    encode_range_request(&value, &mut Vec::new())?;
    Ok(value)
}

fn encode_proof_bundle(value: &ProofBundle, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_proof_bundle(value)?;
    map(11, output);
    uint(0, output);
    uint(0, output);
    uint(1, output);
    bytes(&value.request_id, output);
    uint(2, output);
    bytes(&value.bundle_id, output);
    uint(3, output);
    encode_object(&value.object, output);
    uint(4, output);
    uint(value.requested_offset, output);
    uint(5, output);
    uint(value.requested_length, output);
    uint(6, output);
    uint(value.covered_offset, output);
    uint(7, output);
    uint(value.covered_length, output);
    uint(8, output);
    uint(value.data_record_count, output);
    uint(9, output);
    uint(value.total_plaintext_length, output);
    uint(10, output);
    bytes(&value.proof, output);
    Ok(())
}

fn decode_proof_bundle(input: &[u8]) -> Result<ProofBundle, Error> {
    let mut reader = Reader::new(input);
    reader.map(11)?;
    reader.key(0)?;
    if reader.uint()? != 0 {
        return Err(Error::InvalidValue);
    }
    reader.key(1)?;
    let request_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let bundle_id = reader.fixed::<16>()?;
    reader.key(3)?;
    let object = decode_object(&mut reader)?;
    reader.key(4)?;
    let requested_offset = reader.uint()?;
    reader.key(5)?;
    let requested_length = reader.uint()?;
    reader.key(6)?;
    let covered_offset = reader.uint()?;
    reader.key(7)?;
    let covered_length = reader.uint()?;
    reader.key(8)?;
    let data_record_count = reader.uint()?;
    reader.key(9)?;
    let total_plaintext_length = reader.uint()?;
    reader.key(10)?;
    let proof = reader.bytes(MAX_PROOF_BYTES)?;
    reader.finish()?;
    let mut value = ProofBundle {
        request_id,
        bundle_id,
        object,
        requested_offset,
        requested_length,
        covered_offset,
        covered_length,
        data_record_count,
        total_plaintext_length,
        proof: Vec::new(),
    };
    validate_proof_bundle_with_proof_len(&value, proof.len())?;
    value.proof = proof.to_vec();
    Ok(value)
}

fn validate_proof_bundle(value: &ProofBundle) -> Result<(), Error> {
    validate_proof_bundle_with_proof_len(value, value.proof.len())
}

fn validate_proof_bundle_with_proof_len(
    value: &ProofBundle,
    proof_len: usize,
) -> Result<(), Error> {
    value.object.validate()?;
    if value.object.length == 0
        || value.requested_length == 0
        || value.requested_length > MAX_REQUESTED_RANGE
        || value
            .requested_offset
            .checked_add(value.requested_length)
            .is_none_or(|end| end > value.object.length)
        || value.covered_offset != value.requested_offset / GROUP_BYTES * GROUP_BYTES
        || value.covered_offset % GROUP_BYTES != 0
        || value.covered_offset > value.requested_offset
        || value.covered_length == 0
        || value.covered_length > MAX_COVERED_RANGE
        || value
            .covered_offset
            .checked_add(value.covered_length)
            .is_none_or(|end| end > value.object.length)
        || value.data_record_count == 0
        || value.data_record_count > MAX_DATA_RECORDS_PER_BUNDLE as u64
        || value.total_plaintext_length != value.covered_length
        || proof_len > MAX_PROOF_BYTES
        || crate::registered_payload_limit(frame_type::PROOF_BUNDLE)
            .is_some_and(|limit| proof_bundle_payload_len_with(value, proof_len) > limit)
    {
        return Err(Error::InvalidValue);
    }
    let request_end = value
        .requested_offset
        .checked_add(value.requested_length)
        .ok_or(Error::InvalidValue)?;
    let expected_end = request_end
        .div_ceil(GROUP_BYTES)
        .checked_mul(GROUP_BYTES)
        .ok_or(Error::InvalidValue)?
        .min(value.object.length);
    if value.covered_offset.checked_add(value.covered_length) != Some(expected_end)
        || (expected_end < value.object.length && value.covered_length % GROUP_BYTES != 0)
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn proof_bundle_payload_len(value: &ProofBundle) -> usize {
    proof_bundle_payload_len_with(value, value.proof.len())
}

fn proof_bundle_payload_len_with(value: &ProofBundle, proof_len: usize) -> usize {
    let object_length = cbor_head_len(4)
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_head_len(u64::from(value.object.suite)))
        .saturating_add(cbor_byte_string_len(32))
        .saturating_add(cbor_head_len(value.object.length));
    cbor_head_len(11)
        .saturating_add(cbor_head_len(0))
        .saturating_add(cbor_head_len(0))
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_byte_string_len(16))
        .saturating_add(cbor_head_len(2))
        .saturating_add(cbor_byte_string_len(16))
        .saturating_add(cbor_head_len(3))
        .saturating_add(object_length)
        .saturating_add(cbor_head_len(4))
        .saturating_add(cbor_head_len(value.requested_offset))
        .saturating_add(cbor_head_len(5))
        .saturating_add(cbor_head_len(value.requested_length))
        .saturating_add(cbor_head_len(6))
        .saturating_add(cbor_head_len(value.covered_offset))
        .saturating_add(cbor_head_len(7))
        .saturating_add(cbor_head_len(value.covered_length))
        .saturating_add(cbor_head_len(8))
        .saturating_add(cbor_head_len(value.data_record_count))
        .saturating_add(cbor_head_len(9))
        .saturating_add(cbor_head_len(value.total_plaintext_length))
        .saturating_add(cbor_head_len(10))
        .saturating_add(cbor_byte_string_len(proof_len))
}

fn encode_data_record(value: &DataRecord, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_data_record(value)?;
    map(8, output);
    uint(0, output);
    uint(0, output);
    uint(1, output);
    bytes(&value.bundle_id, output);
    uint(2, output);
    uint(value.record_index, output);
    uint(3, output);
    uint(value.plaintext_offset, output);
    uint(4, output);
    uint(value.plaintext_length, output);
    uint(5, output);
    uint(u64::from(value.compression), output);
    uint(6, output);
    uint(value.encoded.len() as u64, output);
    uint(7, output);
    bytes(&value.encoded, output);
    Ok(())
}

fn decode_data_record(input: &[u8]) -> Result<DataRecord, Error> {
    let mut reader = Reader::new(input);
    reader.map(8)?;
    reader.key(0)?;
    if reader.uint()? != 0 {
        return Err(Error::InvalidValue);
    }
    reader.key(1)?;
    let bundle_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let record_index = reader.uint()?;
    reader.key(3)?;
    let plaintext_offset = reader.uint()?;
    reader.key(4)?;
    let plaintext_length = reader.uint()?;
    reader.key(5)?;
    let compression = u8::try_from(reader.uint()?).map_err(|_| Error::InvalidValue)?;
    reader.key(6)?;
    let encoded_length = reader.uint()?;
    reader.key(7)?;
    let encoded = reader.bytes(MAX_DATA_BYTES)?.to_vec();
    reader.finish()?;
    if encoded_length != encoded.len() as u64 {
        return Err(Error::InvalidValue);
    }
    let value = DataRecord {
        bundle_id,
        record_index,
        plaintext_offset,
        plaintext_length,
        compression,
        encoded,
    };
    validate_data_record(&value)?;
    Ok(value)
}

fn validate_data_record(value: &DataRecord) -> Result<(), Error> {
    let encoded_length = value.encoded.len() as u64;
    if value.record_index > 16
        || value.plaintext_offset > MAX_OBJECT_LENGTH
        || value.plaintext_length == 0
        || value.plaintext_length > MAX_DATA_BYTES as u64
        || encoded_length == 0
        || data_record_payload_len(value) > MAX_DATA_BYTES
        || !matches!(value.compression, 0 | 1)
        || (value.compression == 0 && value.plaintext_length != encoded_length)
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

fn data_record_payload_len(value: &DataRecord) -> usize {
    cbor_head_len(8)
        .saturating_add(cbor_head_len(0))
        .saturating_add(cbor_head_len(0))
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_byte_string_len(16))
        .saturating_add(cbor_head_len(2))
        .saturating_add(cbor_head_len(value.record_index))
        .saturating_add(cbor_head_len(3))
        .saturating_add(cbor_head_len(value.plaintext_offset))
        .saturating_add(cbor_head_len(4))
        .saturating_add(cbor_head_len(value.plaintext_length))
        .saturating_add(cbor_head_len(5))
        .saturating_add(cbor_head_len(u64::from(value.compression)))
        .saturating_add(cbor_head_len(6))
        .saturating_add(cbor_head_len(value.encoded.len() as u64))
        .saturating_add(cbor_head_len(7))
        .saturating_add(cbor_byte_string_len(value.encoded.len()))
}

fn cbor_byte_string_len(length: usize) -> usize {
    cbor_head_len(length as u64).saturating_add(length)
}

fn cbor_head_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn encode_have(value: &Have, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_have(value)?;
    map(3, output);
    uint(0, output);
    encode_object(&value.object, output);
    uint(1, output);
    uint(value.map_sequence, output);
    uint(2, output);
    array(value.runs.len() as u64, output);
    for run in &value.runs {
        array(2, output);
        uint(run.start_group, output);
        uint(run.group_count, output);
    }
    Ok(())
}

fn decode_have(input: &[u8]) -> Result<Have, Error> {
    let mut reader = Reader::new(input);
    reader.map(3)?;
    reader.key(0)?;
    let object = decode_object(&mut reader)?;
    reader.key(1)?;
    let map_sequence = reader.uint()?;
    reader.key(2)?;
    let count = reader.array_len(MAX_HAVE_RUNS)?;
    if count > (reader.remaining_len() / 2) as u64 {
        return Err(Error::Malformed);
    }
    let mut runs = Vec::with_capacity(count.min(8_192) as usize);
    for _ in 0..count {
        if reader.array(2)? != 2 {
            return Err(Error::Malformed);
        }
        runs.push(HaveRun {
            start_group: reader.uint()?,
            group_count: reader.uint()?,
        });
    }
    reader.finish()?;
    let value = Have {
        object,
        map_sequence,
        runs,
    };
    validate_have(&value)?;
    Ok(value)
}

fn validate_have(value: &Have) -> Result<(), Error> {
    value.object.validate()?;
    let payload_limit = crate::registered_payload_limit(frame_type::HAVE);
    if payload_limit.is_some_and(|limit| have_payload_len(value) > limit) {
        return Err(Error::TooLarge);
    }
    let group_count = value.object.length.div_ceil(GROUP_BYTES);
    let mut previous_end = 0_u64;
    for (index, run) in value.runs.iter().enumerate() {
        if run.group_count == 0
            || run.start_group < previous_end
            || (index > 0 && run.start_group == previous_end)
            || run
                .start_group
                .checked_add(run.group_count)
                .is_none_or(|end| end > group_count)
        {
            return Err(Error::InvalidValue);
        }
        previous_end = run.start_group + run.group_count;
    }
    Ok(())
}

fn have_payload_len(value: &Have) -> usize {
    let object_length = cbor_head_len(4)
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_head_len(u64::from(value.object.suite)))
        .saturating_add(cbor_byte_string_len(32))
        .saturating_add(cbor_head_len(value.object.length));
    let mut length = cbor_head_len(3)
        .saturating_add(cbor_head_len(0))
        .saturating_add(object_length)
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_head_len(value.map_sequence))
        .saturating_add(cbor_head_len(2))
        .saturating_add(cbor_head_len(value.runs.len() as u64));
    for run in &value.runs {
        length = length
            .saturating_add(cbor_head_len(2))
            .saturating_add(cbor_head_len(run.start_group))
            .saturating_add(cbor_head_len(run.group_count));
    }
    length
}

fn encode_capacity(value: &Capacity, output: &mut Vec<u8>) {
    map(4, output);
    uint(0, output);
    uint(value.epoch, output);
    uint(1, output);
    uint(value.available_bytes, output);
    uint(2, output);
    uint(value.bdp_target_bytes, output);
    uint(3, output);
    uint(value.max_inflight_bytes, output);
}

fn decode_capacity(input: &[u8]) -> Result<Capacity, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let epoch = reader.uint()?;
    reader.key(1)?;
    let available_bytes = reader.uint()?;
    reader.key(2)?;
    let bdp_target_bytes = reader.uint()?;
    reader.key(3)?;
    let max_inflight_bytes = reader.uint()?;
    reader.finish()?;
    Ok(Capacity {
        epoch,
        available_bytes,
        bdp_target_bytes,
        max_inflight_bytes,
    })
}

fn encode_assurance(value: &AssuranceFrame, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_assurance(value)?;
    map(4, output);
    uint(0, output);
    encode_object(&value.object, output);
    uint(1, output);
    uint(value.sequence, output);
    uint(2, output);
    uint(value.unit_start, output);
    uint(3, output);
    uint(value.unit_count, output);
    Ok(())
}

fn decode_assurance(input: &[u8]) -> Result<AssuranceFrame, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let object = decode_object(&mut reader)?;
    reader.key(1)?;
    let sequence = reader.uint()?;
    reader.key(2)?;
    let unit_start = reader.uint()?;
    reader.key(3)?;
    let unit_count = reader.uint()?;
    reader.finish()?;
    let value = AssuranceFrame {
        object,
        sequence,
        unit_start,
        unit_count,
    };
    validate_assurance(&value)?;
    Ok(value)
}

fn validate_assurance(value: &AssuranceFrame) -> Result<(), Error> {
    value.object.validate()?;
    if value.sequence == 0
        || value.unit_count == 0
        || value
            .unit_start
            .checked_add(value.unit_count)
            .is_none_or(|end| end > value.object.length.div_ceil(GROUP_BYTES))
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

fn validate_manifest_page(bytes: &[u8]) -> Result<(), Error> {
    vot_manifest::decode_page(bytes)
        .map(|_| ())
        .map_err(|_| Error::Manifest)
}

fn validate_seal(bytes: &[u8]) -> Result<(), Error> {
    if crate::registered_payload_limit(frame_type::SEAL).is_some_and(|limit| bytes.len() > limit) {
        return Err(Error::TooLarge);
    }
    vot_manifest::decode_seal(bytes)
        .map(|_| ())
        .map_err(|_| Error::Seal)
}

fn validate_receipt(bytes: &[u8]) -> Result<(), Error> {
    vot_receipt::decode_authenticated(bytes)
        .map(|_| ())
        .map_err(|_| Error::Receipt)
}

fn encode_object(value: &ObjectId, output: &mut Vec<u8>) {
    array(4, output);
    uint(1, output);
    uint(u64::from(value.suite), output);
    bytes(&value.root, output);
    uint(value.length, output);
}

fn decode_object(reader: &mut Reader<'_>) -> Result<ObjectId, Error> {
    if reader.array(4)? != 4 {
        return Err(Error::Malformed);
    }
    if reader.uint()? != 1 {
        return Err(Error::InvalidValue);
    }
    let suite = u16::try_from(reader.uint()?).map_err(|_| Error::InvalidValue)?;
    let root = reader.fixed::<32>()?;
    let length = reader.uint()?;
    let object = ObjectId {
        suite,
        root,
        length,
    };
    object.validate()?;
    Ok(object)
}

fn map(length: u64, output: &mut Vec<u8>) {
    head(5, length, output);
}

fn array(length: u64, output: &mut Vec<u8>) {
    head(4, length, output);
}

fn uint(value: u64, output: &mut Vec<u8>) {
    head(0, value, output);
}

fn bytes(value: &[u8], output: &mut Vec<u8>) {
    head(2, value.len() as u64, output);
    output.extend_from_slice(value);
}

fn head(major: u8, value: u64, output: &mut Vec<u8>) {
    let major = major << 5;
    match value {
        0..=23 => output.push(major | value as u8),
        24..=0xff => {
            output.push(major | 24);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push(major | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(major | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(major | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(length).ok_or(Error::TooLarge)?;
        let bytes = self.input.get(self.offset..end).ok_or(Error::Malformed)?;
        self.offset = end;
        Ok(bytes)
    }

    fn head(&mut self) -> Result<(u8, u64), Error> {
        let first = *self.take(1)?.first().ok_or(Error::Malformed)?;
        let major = first >> 5;
        let additional = first & 0x1f;
        let (value, width) = match additional {
            0..=23 => (u64::from(additional), 0),
            24 => (
                u64::from(*self.take(1)?.first().ok_or(Error::Malformed)?),
                1,
            ),
            25 => (
                u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().map_err(|_| Error::Malformed)?,
                )),
                2,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().map_err(|_| Error::Malformed)?,
                )),
                4,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::Malformed)?),
                8,
            ),
            _ => return Err(Error::Malformed),
        };
        let canonical = match width {
            0 => true,
            1 => value >= 24,
            2 => value > 0xff,
            4 => value > 0xffff,
            8 => value > 0xffff_ffff,
            _ => false,
        };
        if !canonical {
            return Err(Error::Malformed);
        }
        Ok((major, value))
    }

    fn uint(&mut self) -> Result<u64, Error> {
        let (major, value) = self.head()?;
        if major == 0 {
            Ok(value)
        } else {
            Err(Error::Malformed)
        }
    }

    fn key(&mut self, expected: u64) -> Result<(), Error> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    fn map(&mut self, expected: u64) -> Result<(), Error> {
        let (major, value) = self.head()?;
        if major == 5 && value == expected {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    fn array(&mut self, expected: u64) -> Result<u64, Error> {
        let (major, value) = self.head()?;
        if major == 4 && value == expected {
            Ok(value)
        } else {
            Err(Error::Malformed)
        }
    }

    fn array_len(&mut self, maximum: u64) -> Result<u64, Error> {
        let (major, value) = self.head()?;
        if major != 4 || value > maximum {
            Err(Error::TooLarge)
        } else {
            Ok(value)
        }
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let (major, length) = self.head()?;
        if major != 2 {
            return Err(Error::Malformed);
        }
        let length = usize::try_from(length).map_err(|_| Error::TooLarge)?;
        if length > maximum {
            return Err(Error::TooLarge);
        }
        self.take(length)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes(N)?.try_into().map_err(|_| Error::Malformed)
    }

    fn finish(&self) -> Result<(), Error> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    fn remaining_len(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> ObjectId {
        ObjectId {
            suite: 1,
            root: [7; 32],
            length: GROUP_BYTES * 2,
        }
    }

    #[test]
    fn proof_and_data_frames_round_trip() {
        let bundle = TypedFrame::ProofBundle(ProofBundle {
            request_id: [1; 16],
            bundle_id: [2; 16],
            object: object(),
            requested_offset: GROUP_BYTES,
            requested_length: GROUP_BYTES,
            covered_offset: GROUP_BYTES,
            covered_length: GROUP_BYTES,
            data_record_count: 1,
            total_plaintext_length: GROUP_BYTES,
            proof: Vec::new(),
        });
        let data = TypedFrame::DataRecord(DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: GROUP_BYTES,
            plaintext_length: GROUP_BYTES,
            compression: 0,
            encoded: vec![0xaa; GROUP_BYTES as usize],
        });
        let mut encoded = Vec::new();
        encode(&bundle, &mut encoded).unwrap();
        encode(&data, &mut encoded).unwrap();
        let (decoded_bundle, used) = decode(&encoded, DecodeLimits::default()).unwrap();
        let (decoded_data, _) = decode(&encoded[used..], DecodeLimits::default()).unwrap();
        assert_eq!(decoded_bundle, bundle);
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn proof_bundle_metadata_is_checked_before_proof_size() {
        let proof = vec![0xaa; 1024];
        let mut payload = Vec::new();
        map(11, &mut payload);
        uint(0, &mut payload);
        uint(0, &mut payload);
        uint(1, &mut payload);
        bytes(&[1; 16], &mut payload);
        uint(2, &mut payload);
        bytes(&[2; 16], &mut payload);
        uint(3, &mut payload);
        encode_object(&object(), &mut payload);
        uint(4, &mut payload);
        uint(GROUP_BYTES, &mut payload);
        uint(5, &mut payload);
        uint(GROUP_BYTES, &mut payload);
        uint(6, &mut payload);
        uint(GROUP_BYTES, &mut payload);
        uint(7, &mut payload);
        uint(GROUP_BYTES, &mut payload);
        uint(8, &mut payload);
        uint(0, &mut payload);
        uint(9, &mut payload);
        uint(GROUP_BYTES, &mut payload);
        uint(10, &mut payload);
        bytes(&proof, &mut payload);
        let mut encoded = Vec::new();
        encode_frame(frame_type::PROOF_BUNDLE, &payload, &mut encoded).unwrap();
        assert_eq!(
            decode(&encoded, DecodeLimits::default()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn proof_bundle_limit_includes_typed_payload_overhead() {
        let limit = crate::registered_payload_limit(frame_type::PROOF_BUNDLE).unwrap();
        let empty = ProofBundle {
            request_id: [1; 16],
            bundle_id: [2; 16],
            object: object(),
            requested_offset: GROUP_BYTES,
            requested_length: GROUP_BYTES,
            covered_offset: GROUP_BYTES,
            covered_length: GROUP_BYTES,
            data_record_count: 1,
            total_plaintext_length: GROUP_BYTES,
            proof: Vec::new(),
        };
        let metadata = proof_bundle_payload_len(&empty) - cbor_byte_string_len(0);
        let mut maximum_proof_length = MAX_PROOF_BYTES.min(limit.saturating_sub(metadata));
        while metadata.saturating_add(cbor_byte_string_len(maximum_proof_length)) > limit {
            maximum_proof_length -= 1;
        }
        let mut valid = empty.clone();
        valid.proof = vec![0xaa; maximum_proof_length];
        assert!(valid.validate().is_ok());
        assert!(encode(&TypedFrame::ProofBundle(valid), &mut Vec::new()).is_ok());

        let mut invalid = empty;
        invalid.proof = vec![0xaa; maximum_proof_length + 1];
        assert!(proof_bundle_payload_len(&invalid) > limit);
        assert_eq!(invalid.validate(), Err(Error::InvalidValue));
        assert_eq!(
            encode(&TypedFrame::ProofBundle(invalid), &mut Vec::new()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn data_record_limit_includes_typed_payload_overhead() {
        let make_data = |encoded_length: usize| DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: encoded_length as u64,
            compression: 0,
            encoded: vec![0xaa; encoded_length],
        };
        let mut maximum_encoded_length = MAX_DATA_BYTES;
        while data_record_payload_len(&make_data(maximum_encoded_length)) > MAX_DATA_BYTES {
            maximum_encoded_length -= 1;
        }
        let valid = make_data(maximum_encoded_length);
        assert!(valid.validate().is_ok());
        assert!(encode(&TypedFrame::DataRecord(valid), &mut Vec::new()).is_ok());

        let invalid = make_data(maximum_encoded_length + 1);
        assert!(data_record_payload_len(&invalid) > MAX_DATA_BYTES);
        assert_eq!(invalid.validate(), Err(Error::InvalidValue));
        assert_eq!(
            encode(&TypedFrame::DataRecord(invalid), &mut Vec::new()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn data_record_validation_boundaries_are_explicit() {
        let mut data = DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: 1,
            compression: 0,
            encoded: vec![0xaa],
        };
        data.record_index = 16;
        assert!(data.validate().is_ok());
        data.record_index = 17;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.record_index = 0;
        data.plaintext_offset = MAX_OBJECT_LENGTH;
        assert!(data.validate().is_ok());
        data.plaintext_offset += 1;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.plaintext_offset = 0;
        data.plaintext_length = MAX_DATA_BYTES as u64;
        data.compression = 1;
        assert!(data.validate().is_ok());
        data.plaintext_length += 1;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.plaintext_length = 1;
        data.compression = 0;
        data.encoded.clear();
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.encoded.push(0xaa);
        data.compression = 2;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.compression = 0;
        data.plaintext_length = 2;
        assert_eq!(data.validate(), Err(Error::InvalidValue));
        data.compression = 1;
        assert!(data.validate().is_ok());
    }

    #[test]
    fn cbor_head_width_boundaries_are_canonical() {
        assert_eq!(
            [
                cbor_head_len(0),
                cbor_head_len(23),
                cbor_head_len(24),
                cbor_head_len(255),
                cbor_head_len(256),
                cbor_head_len(65_535),
                cbor_head_len(65_536),
                cbor_head_len(u64::from(u32::MAX)),
                cbor_head_len(u64::from(u32::MAX) + 1),
            ],
            [1, 1, 2, 2, 3, 3, 5, 5, 9]
        );
    }

    #[test]
    fn adjacent_have_runs_are_rejected() {
        let error = encode(
            &TypedFrame::Have(Have {
                object: object(),
                map_sequence: 1,
                runs: vec![
                    HaveRun {
                        start_group: 0,
                        group_count: 1,
                    },
                    HaveRun {
                        start_group: 1,
                        group_count: 1,
                    },
                ],
            }),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error, Error::InvalidValue);
    }

    #[test]
    fn have_limit_includes_typed_run_overhead() {
        let run_count = 900_000_u64;
        let value = Have {
            object: ObjectId {
                suite: 1,
                root: [7; 32],
                length: GROUP_BYTES * (run_count * 2 + 1),
            },
            map_sequence: 1,
            runs: (0..run_count)
                .map(|index| HaveRun {
                    start_group: index * 2,
                    group_count: 1,
                })
                .collect(),
        };
        assert!(
            have_payload_len(&value) > crate::registered_payload_limit(frame_type::HAVE).unwrap()
        );
        assert_eq!(validate_have(&value), Err(Error::TooLarge));
        assert_eq!(
            encode(&TypedFrame::Have(value), &mut Vec::new()),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn valid_manifest_seals_are_bounded_by_the_wire_limit() {
        let pages = (0..vot_manifest::MAX_PAGE_COMMITMENTS)
            .map(|index| vot_manifest::PageCommitment {
                index: index as u64,
                digest: [8; 32],
            })
            .collect::<Vec<_>>();
        let seal = vot_manifest::Seal {
            manifest_id: [4; 16],
            final_page_count: pages.len() as u64,
            final_page_digest: [8; 32],
            package: vot_manifest::ObjectId {
                suite: 1,
                root: [9; 32],
                length: 123,
            },
            pages,
        };
        let encoded = vot_manifest::encode_seal(&seal).unwrap();
        assert!(encoded.len() > crate::registered_payload_limit(frame_type::SEAL).unwrap());
        assert_eq!(
            encode(&TypedFrame::Seal(encoded), &mut Vec::new()),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn owner_payloads_are_validated_before_framing() {
        assert_eq!(
            encode(&TypedFrame::ManifestPage(vec![0]), &mut Vec::new()),
            Err(Error::Manifest)
        );
        assert_eq!(
            encode(&TypedFrame::PublishReceipt(vec![0]), &mut Vec::new()),
            Err(Error::Receipt)
        );
    }
}
