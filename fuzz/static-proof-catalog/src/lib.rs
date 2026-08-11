//! Bounded static proof catalog exercise shared by the standalone driver and
//! the libFuzzer target.

#![forbid(unsafe_code)]

use vot_proof_catalog::{
    Error, HEADER_LENGTH, INDEX_ENTRY_LENGTH, ObjectId, RANGE_LENGTH, decode_header,
    validate_complete,
};

/// Largest catalog candidate accepted by either driver.
pub const MAX_INPUT: usize = 256 * 1024;

/// Allocation ceiling enforced by both drivers.
pub const ALLOCATION_LIMIT: usize = 256 * 1024 * 1024;

fn expected_identity(input: &[u8]) -> Option<ObjectId> {
    let header = input.get(..HEADER_LENGTH)?;
    let suite = u16::from_be_bytes(header.get(16..18)?.try_into().ok()?);
    let root = header.get(24..56)?.try_into().ok()?;
    let length = u64::from_be_bytes(header.get(56..64)?.try_into().ok()?);
    Some(ObjectId {
        suite,
        root,
        length,
    })
}

fn selector(input: &[u8]) -> u64 {
    input
        .iter()
        .rev()
        .take(8)
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

fn available(input: &[u8], offset: u64, requested: u64) -> &[u8] {
    let Ok(start) = usize::try_from(offset) else {
        return &[];
    };
    let Ok(length) = usize::try_from(requested) else {
        return &[];
    };
    if start > input.len() {
        return &[];
    }
    &input[start..start.saturating_add(length).min(input.len())]
}

fn vector_data(offset: u64, length: u64) -> Option<Vec<u8>> {
    if length > RANGE_LENGTH {
        return None;
    }
    let length = usize::try_from(length).ok()?;
    let start = offset % 251;
    Some(
        (0..length)
            .map(|index| ((start + index as u64 % 251) * 17 % 251) as u8)
            .collect(),
    )
}

/// Exercises complete and selected-entry catalog parsing with bounded input and
/// at most one fixed-size profile range of synthesized object data.
pub fn exercise(input: &[u8]) {
    let Some(expected) = expected_identity(input) else {
        return;
    };
    let header_bytes = &input[..HEADER_LENGTH];

    let _ = validate_complete(input, &expected);
    let Ok(header) = decode_header(header_bytes, &expected) else {
        return;
    };

    let mut mismatched = expected.clone();
    mismatched.root[0] ^= 1;
    assert!(matches!(
        decode_header(header_bytes, &mismatched),
        Err(Error::IdentityMismatch)
    ));

    if header.record_count() == 0 {
        return;
    }
    let ordinal = selector(input) % header.record_count();
    let Ok(index_offset) = header.index_entry_offset(ordinal) else {
        return;
    };
    let entry_bytes = available(input, index_offset, INDEX_ENTRY_LENGTH as u64);
    let Ok(entry) = header.decode_entry(ordinal, entry_bytes) else {
        return;
    };

    let proof = available(input, entry.proof_offset(), entry.proof_length());
    let Some(data) = vector_data(entry.data_offset(), entry.data_length()) else {
        return;
    };
    let _ = entry.verify(&data, proof);
}

#[cfg(test)]
mod tests {
    use super::exercise;

    #[test]
    fn degenerate_inputs_do_not_panic() {
        exercise(&[]);
        exercise(&[0xff; 64]);
        exercise(&[0; 128]);
    }

    #[test]
    fn committed_suite_catalogs_do_not_panic() {
        exercise(include_bytes!("../corpus/blake3-65537.bin"));
        exercise(include_bytes!("../corpus/sha256-65537.bin"));
    }
}
