//! Record identifiers, sizing, encode, and decode.

use crate::{BTreeMap, Error, ReplayObject, StoredObject, SubjectId, UnitRanges};

pub(crate) const MAGIC: &[u8; 8] = b"VOTRES02";
pub(crate) const MAX_STORE_BYTES: u64 = 67_108_864;
pub(crate) const MAX_STORE_PAYLOAD_BYTES: u64 = MAX_STORE_BYTES - 20;
pub(crate) const MIN_STORE_BYTES: u64 = 8;
/// Largest unit count a single object can reserve. Derived from the snapshot
/// format worst case (~1 TiB at 64 KiB units).
pub(crate) const MAX_UNITS_PER_OBJECT: u64 = 16_777_198;
pub(crate) const RECORD_HEADER_BYTES: u64 = 4;
pub(crate) const RECORD_CHECKSUM_BYTES: u64 = 8;
pub(crate) const RESERVE_RECORD: u8 = 1;
pub(crate) const CHECKPOINT_RECORD: u8 = 2;
pub(crate) const SNAPSHOT_RECORD: u8 = 3;
pub(crate) const COMPACTION_THRESHOLD: u64 = MAX_STORE_BYTES * 3 / 4;

pub(crate) fn validate_total_units(total_units: u64) -> Result<(), Error> {
    if total_units == 0 || total_units > MAX_UNITS_PER_OBJECT {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_reserved_capacity(
    objects: &BTreeMap<SubjectId, StoredObject>,
) -> Result<(), Error> {
    let payload = encode_snapshot(objects)?;
    let record = encode_record(&payload)?;
    let record_length = u64::try_from(record.len()).map_err(|_| Error::TooLarge)?;
    if !compact_fits(record_length) {
        return Err(Error::TooLarge);
    }
    let worst_payload_length = worst_case_snapshot_payload_length(objects)?;
    let worst_record_length = worst_payload_length
        .checked_add(RECORD_HEADER_BYTES)
        .and_then(|length| length.checked_add(RECORD_CHECKSUM_BYTES))
        .ok_or(Error::TooLarge)?;
    if compact_fits(worst_record_length) {
        Ok(())
    } else {
        Err(Error::TooLarge)
    }
}

pub(crate) fn worst_case_snapshot_payload_length(
    objects: &BTreeMap<SubjectId, StoredObject>,
) -> Result<u64, Error> {
    let mut length = 1_u64
        .checked_add(uvarint_length(
            u64::try_from(objects.len()).map_err(|_| Error::TooLarge)?,
        ))
        .ok_or(Error::TooLarge)?;
    for object in objects.values() {
        validate_total_units(object.total_units)?;
        length = length
            .checked_add(worst_case_object_payload_length(object.total_units)?)
            .ok_or(Error::TooLarge)?;
    }
    Ok(length)
}

/// Worst-case snapshot bytes for one object: identity, total units, and a
/// fully fragmented checkpoint set.
pub(crate) fn worst_case_object_payload_length(total_units: u64) -> Result<u64, Error> {
    42_u64
        .checked_add(uvarint_length(total_units))
        .and_then(|length| length.checked_add(worst_case_ranges_length(total_units)))
        .ok_or(Error::TooLarge)
}

pub(crate) fn worst_case_ranges_length(total_units: u64) -> u64 {
    let range_count = total_units.div_ceil(2);
    uvarint_length(range_count).saturating_add(range_count.saturating_mul(
        uvarint_length(total_units.saturating_sub(1)).saturating_add(uvarint_length(total_units)),
    ))
}

pub(crate) fn uvarint_length(value: u64) -> u64 {
    let significant_bits = (u64::BITS - value.leading_zeros()).max(1);
    u64::from(significant_bits.div_ceil(7))
}

pub(crate) fn store_size_fits(length: u64) -> bool {
    length <= MAX_STORE_BYTES
}

pub(crate) fn encode_snapshot(
    objects: &BTreeMap<SubjectId, StoredObject>,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    output.push(SNAPSHOT_RECORD);
    encode_uvarint(
        u64::try_from(objects.len()).map_err(|_| Error::TooLarge)?,
        &mut output,
    );
    for (subject, object) in objects {
        validate_total_units(object.total_units)?;
        encode_subject(subject, &mut output);
        encode_uvarint(object.total_units, &mut output);
        encode_ranges(&object.checkpointed, &mut output);
    }
    validate_payload_length(u64::try_from(output.len()).map_err(|_| Error::TooLarge)?)?;
    Ok(output)
}

pub(crate) fn record_length_valid(record_length: usize) -> bool {
    record_length != 0 && record_length <= MAX_STORE_BYTES as usize
}

pub(crate) fn encode_reserve(subject: SubjectId, total_units: u64) -> Result<Vec<u8>, Error> {
    validate_total_units(total_units)?;
    let mut output = Vec::with_capacity(1 + 42 + 10);
    output.push(RESERVE_RECORD);
    encode_subject(&subject, &mut output);
    encode_uvarint(total_units, &mut output);
    Ok(output)
}

pub(crate) fn encode_checkpoint(
    subject: SubjectId,
    total_units: u64,
    units: &UnitRanges,
) -> Result<Vec<u8>, Error> {
    validate_total_units(total_units)?;
    let mut output = Vec::new();
    output.push(CHECKPOINT_RECORD);
    encode_subject(&subject, &mut output);
    encode_uvarint(total_units, &mut output);
    encode_ranges(units, &mut output);
    Ok(output)
}

pub(crate) fn encode_subject(subject: &SubjectId, output: &mut Vec<u8>) {
    output.extend_from_slice(&subject.suite().to_be_bytes());
    output.extend_from_slice(&subject.root());
    output.extend_from_slice(&subject.length().to_be_bytes());
}

pub(crate) fn encode_ranges(units: &UnitRanges, output: &mut Vec<u8>) {
    encode_uvarint(u64::try_from(units.run_count()).unwrap_or(u64::MAX), output);
    for (start, length) in units.runs() {
        encode_uvarint(start, output);
        encode_uvarint(length, output);
    }
}

pub(crate) fn encode_uvarint(mut value: u64, output: &mut Vec<u8>) {
    for _ in 0..10 {
        let low = (value as u8) & 0x7f;
        if value < 0x80 {
            output.push(low);
            return;
        }
        output.push(low + 0x80);
        value >>= 7;
    }
    unreachable!("a u64 varint fits in ten bytes");
}

pub(crate) fn encode_record(payload: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u32::try_from(payload.len()).map_err(|_| Error::TooLarge)?;
    let mut output = Vec::with_capacity(
        RECORD_HEADER_BYTES as usize + payload.len() + RECORD_CHECKSUM_BYTES as usize,
    );
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
    output.extend_from_slice(&blake3::hash(payload).as_bytes()[..RECORD_CHECKSUM_BYTES as usize]);
    Ok(output)
}

pub(crate) fn append_header_length(current_length: u64) -> u64 {
    if current_length == 0 {
        MAGIC.len() as u64
    } else {
        0
    }
}

pub(crate) fn compact_fits(record_length: u64) -> bool {
    record_length
        .checked_add(MAGIC.len() as u64)
        .is_some_and(store_size_fits)
}

pub(crate) fn append_fits(current_length: u64, header_length: u64, record_length: u64) -> bool {
    current_length
        .checked_add(header_length)
        .and_then(|length| length.checked_add(record_length))
        .is_some_and(store_size_fits)
}

pub(crate) fn apply_record(
    record: &[u8],
    objects: &mut BTreeMap<SubjectId, ReplayObject>,
) -> Result<(), Error> {
    let mut decoder = Decoder::new(record);
    let kind = decoder.take(1)?.first().copied().ok_or(Error::Corrupt)?;
    match kind {
        RESERVE_RECORD => {
            let subject = decode_subject(&mut decoder)?;
            let total_units = decoder.uvar()?;
            validate_total_units(total_units)?;
            if !decoder.is_empty() {
                return Err(Error::Corrupt);
            }
            if let Some(existing) = objects.get(&subject) {
                if existing.total_units != total_units {
                    return Err(Error::Corrupt);
                }
            } else {
                objects.insert(
                    subject,
                    ReplayObject {
                        total_units,
                        runs: Vec::new(),
                    },
                );
            }
        }
        CHECKPOINT_RECORD => {
            let subject = decode_subject(&mut decoder)?;
            let total_units = decoder.uvar()?;
            validate_total_units(total_units)?;
            let delta = decode_run_list(&mut decoder, total_units)?;
            if !decoder.is_empty() {
                return Err(Error::Corrupt);
            }
            let Some(object) = objects.get_mut(&subject) else {
                return Err(Error::Corrupt);
            };
            if object.total_units != total_units {
                return Err(Error::Corrupt);
            }
            object.runs.extend(delta);
        }
        SNAPSHOT_RECORD => {
            let count = decoder.uvar()?;
            let mut snapshot = BTreeMap::new();
            for _ in 0..count {
                let subject = decode_subject(&mut decoder)?;
                let total_units = decoder.uvar()?;
                validate_total_units(total_units)?;
                let runs = decode_run_list(&mut decoder, total_units)?;
                if snapshot
                    .insert(subject, ReplayObject { total_units, runs })
                    .is_some()
                {
                    return Err(Error::Corrupt);
                }
            }
            if !decoder.is_empty() {
                return Err(Error::Corrupt);
            }
            *objects = snapshot;
        }
        _ => return Err(Error::Corrupt),
    }
    Ok(())
}

pub(crate) fn decode_subject(decoder: &mut Decoder<'_>) -> Result<SubjectId, Error> {
    let suite = decoder.u16()?;
    let root = decoder.array()?;
    let length = decoder.u64()?;
    if suite == 0 && length == 0 {
        return Ok(SubjectId::marker(root));
    }
    SubjectId::new(suite, root, length).map_err(|_| Error::Corrupt)
}

#[cfg(test)]
pub(crate) fn decode_ranges(
    decoder: &mut Decoder<'_>,
    total_units: u64,
) -> Result<UnitRanges, Error> {
    UnitRanges::from_runs(decode_run_list(decoder, total_units)?).map_err(|_| Error::Corrupt)
}

pub(crate) fn decode_run_list(
    decoder: &mut Decoder<'_>,
    total_units: u64,
) -> Result<Vec<(u64, u64)>, Error> {
    let count = decoder.uvar()?;
    if count > total_units.div_ceil(2) {
        return Err(Error::Corrupt);
    }
    let mut runs = Vec::with_capacity(usize::try_from(count).map_err(|_| Error::Corrupt)?);
    let mut previous_end = 0_u64;
    for _ in 0..count {
        let start = decoder.uvar()?;
        let length = decoder.uvar()?;
        if length == 0 || start < previous_end {
            return Err(Error::Corrupt);
        }
        let end = start.checked_add(length).ok_or(Error::Corrupt)?;
        if end > total_units {
            return Err(Error::Corrupt);
        }
        runs.push((start, length));
        previous_end = end;
    }
    Ok(runs)
}

pub(crate) struct Decoder<'a> {
    pub(crate) remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if self.remaining.len() < length {
            return Err(Error::Corrupt);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }

    pub(crate) fn array(&mut self) -> Result<[u8; 32], Error> {
        self.take(32)?.try_into().map_err(|_| Error::Corrupt)
    }
    pub(crate) fn uvar(&mut self) -> Result<u64, Error> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        loop {
            let byte = self.take(1)?.first().copied().ok_or(Error::Corrupt)?;
            let bits = u64::from(byte & 0x7f);
            if shift >= 64 || (shift == 63 && bits > 1) {
                return Err(Error::Corrupt);
            }
            value |= bits << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift = shift.checked_add(7).ok_or(Error::Corrupt)?;
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

pub(crate) fn validate_payload_length(length: u64) -> Result<(), Error> {
    if length > MAX_STORE_PAYLOAD_BYTES {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}
