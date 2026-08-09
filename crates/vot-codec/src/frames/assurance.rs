//! Capacity, assurance, and receipt frame family.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use super::{Error, GROUP_BYTES, ObjectId, Reader, decode_object, encode_object};

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

pub(super) fn encode_capacity(value: &Capacity, output: &mut Vec<u8>) {
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, value.epoch);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, value.available_bytes);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.bdp_target_bytes);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.max_inflight_bytes);
}

pub(super) fn decode_capacity(input: &[u8]) -> Result<Capacity, Error> {
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

pub(super) fn encode_assurance(value: &AssuranceFrame, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_assurance(value)?;
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, value.sequence);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.unit_start);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.unit_count);
    Ok(())
}

pub(super) fn decode_assurance(input: &[u8]) -> Result<AssuranceFrame, Error> {
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

pub(super) fn validate_assurance(value: &AssuranceFrame) -> Result<(), Error> {
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

pub(super) fn validate_receipt(bytes: &[u8]) -> Result<(), Error> {
    vot_receipt::decode_authenticated(bytes)
        .map(|_| ())
        .map_err(|_| Error::Receipt)
}
