//! Range, proof, data, and have frame family.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use super::{
    Error, GROUP_BYTES, MAX_OBJECT_LENGTH, ObjectId, Reader, cbor_byte_string_len, cbor_head_len,
    decode_object, encode_object, frame_type,
};

/// Maximum bytes a `RANGE_REQUEST` may ask for.
pub const MAX_REQUESTED_RANGE: u64 = 4_194_304;

/// Max covered range: one group more than `MAX_REQUESTED_RANGE` for an unaligned request.
#[cfg(test)]
pub(super) const MAX_COVERED_RANGE: u64 = MAX_REQUESTED_RANGE + GROUP_BYTES;
#[cfg(test)]
const _: () = assert!(MAX_COVERED_RANGE == 4_259_840);
pub(super) const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_DATA_BYTES: usize = 256 * 1024;
pub(super) const MAX_HAVE_RUNS: u64 = 2_097_152;

/// The most records one bundle can declare, from `spec/proof-bundle.cddl`.
pub const MAX_DATA_RECORDS_PER_BUNDLE: usize = 17;

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

pub(super) fn encode_range_request(
    value: &RangeRequest,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    value.object.validate()?;
    // No separate offset bound: the end check below catches out-of-range offsets.
    if value.length == 0
        || value.length > MAX_REQUESTED_RANGE
        || value
            .offset
            .checked_add(value.length)
            .is_none_or(|end| end > value.object.length)
    {
        return Err(Error::InvalidValue);
    }
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    vot_cbor::bytes(output, &value.request_id);
    vot_cbor::uint(output, 1);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.offset);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.length);
    Ok(())
}

pub(super) fn decode_range_request(input: &[u8]) -> Result<RangeRequest, Error> {
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

pub(super) fn encode_proof_bundle(value: &ProofBundle, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_proof_bundle(value)?;
    vot_cbor::map(output, 11);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.request_id);
    vot_cbor::uint(output, 2);
    vot_cbor::bytes(output, &value.bundle_id);
    vot_cbor::uint(output, 3);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 4);
    vot_cbor::uint(output, value.requested_offset);
    vot_cbor::uint(output, 5);
    vot_cbor::uint(output, value.requested_length);
    vot_cbor::uint(output, 6);
    vot_cbor::uint(output, value.covered_offset);
    vot_cbor::uint(output, 7);
    vot_cbor::uint(output, value.covered_length);
    vot_cbor::uint(output, 8);
    vot_cbor::uint(output, value.data_record_count);
    vot_cbor::uint(output, 9);
    vot_cbor::uint(output, value.total_plaintext_length);
    vot_cbor::uint(output, 10);
    vot_cbor::bytes(output, &value.proof);
    Ok(())
}

pub(super) fn decode_proof_bundle(input: &[u8]) -> Result<ProofBundle, Error> {
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

pub(super) fn validate_proof_bundle(value: &ProofBundle) -> Result<(), Error> {
    validate_proof_bundle_with_proof_len(value, value.proof.len())
}

pub(super) fn validate_proof_bundle_with_proof_len(
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
        // Covered offset must be the group-aligned start of the request.
        || value.covered_offset != value.requested_offset / GROUP_BYTES * GROUP_BYTES
        || value.data_record_count == 0
        || value.data_record_count > MAX_DATA_RECORDS_PER_BUNDLE as u64
        || value.total_plaintext_length != value.covered_length
        // Proof size is bounded by the payload limit, not separately.
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
    // Covered length need not be group-aligned: the last group may be short.
    if value.covered_offset.checked_add(value.covered_length) == Some(expected_end) {
        Ok(())
    } else {
        Err(Error::InvalidValue)
    }
}

#[cfg(test)]
pub(super) fn proof_bundle_payload_len(value: &ProofBundle) -> usize {
    proof_bundle_payload_len_with(value, value.proof.len())
}

pub(super) fn proof_bundle_payload_len_with(value: &ProofBundle, proof_len: usize) -> usize {
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

pub(super) fn encode_validated_data_record(value: &DataRecord, output: &mut Vec<u8>) {
    vot_cbor::map(output, 8);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.bundle_id);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.record_index);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.plaintext_offset);
    vot_cbor::uint(output, 4);
    vot_cbor::uint(output, value.plaintext_length);
    vot_cbor::uint(output, 5);
    vot_cbor::uint(output, u64::from(value.compression));
    vot_cbor::uint(output, 6);
    vot_cbor::uint(output, value.encoded.len() as u64);
    vot_cbor::uint(output, 7);
    vot_cbor::bytes(output, &value.encoded);
}

pub(super) fn decode_data_record(input: &[u8]) -> Result<DataRecord, Error> {
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

pub(super) fn validate_data_record(value: &DataRecord) -> Result<(), Error> {
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

pub(super) fn data_record_payload_len(value: &DataRecord) -> usize {
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

pub(super) fn encode_have(value: &Have, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_have(value)?;
    vot_cbor::map(output, 3);
    vot_cbor::uint(output, 0);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, value.map_sequence);
    vot_cbor::uint(output, 2);
    vot_cbor::array(output, value.runs.len() as u64);
    for run in &value.runs {
        vot_cbor::array(output, 2);
        vot_cbor::uint(output, run.start_group);
        vot_cbor::uint(output, run.group_count);
    }
    Ok(())
}

pub(super) fn decode_have(input: &[u8]) -> Result<Have, Error> {
    let mut reader = Reader::new(input);
    reader.map(3)?;
    reader.key(0)?;
    let object = decode_object(&mut reader)?;
    reader.key(1)?;
    let map_sequence = reader.uint()?;
    reader.key(2)?;
    let count = reader.array_len(MAX_HAVE_RUNS)?;
    // The count is not compared against the bytes that are left. A run is three
    // bytes at the very least, so the loop below cannot read more runs than the
    // input holds however many the head claims, and what is reserved up front is
    // capped rather than taken from the claim.
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

pub(super) fn validate_have(value: &Have) -> Result<(), Error> {
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

pub(super) fn have_payload_len(value: &Have) -> usize {
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
        length = length.saturating_add(have_run_len(run));
    }
    length
}

/// Wire size of one HAVE run.
pub(super) fn have_run_len(run: &HaveRun) -> usize {
    cbor_head_len(2)
        .saturating_add(cbor_head_len(run.start_group))
        .saturating_add(cbor_head_len(run.group_count))
}
