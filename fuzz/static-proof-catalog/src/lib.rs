//! Bounded static proof catalog exercise shared by the standalone driver and
//! the libFuzzer target.

#![forbid(unsafe_code)]

use vot_object::{ObjectBuilder, Suite};
use vot_proof_catalog::{
    CatalogEncoder, Error, HEADER_LENGTH, INDEX_ENTRY_LENGTH, ObjectId, RANGE_LENGTH,
    decode_header, validate_complete,
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

fn exercise_multi_record_encoder(input: &[u8]) {
    const CHUNK_LENGTH: usize = 64 * 1024;

    let selected = selector(input);
    let suite = if selected & 0x100 == 0 {
        Suite::Blake3Bao64
    } else {
        Suite::Sha256Bep52
    };
    let final_record_length = 1 + (selected >> 16) % CHUNK_LENGTH as u64;
    let object_length = RANGE_LENGTH + final_record_length;
    let mut builder = ObjectBuilder::new(suite, Some(object_length)).unwrap();
    let chunk = vec![selected as u8; CHUNK_LENGTH];
    let mut remaining = object_length;
    while remaining != 0 {
        let length = usize::try_from(remaining.min(CHUNK_LENGTH as u64)).unwrap();
        builder.update(&chunk[..length]).unwrap();
        remaining -= length as u64;
    }
    let prepared = builder.finish().unwrap();
    let mut encoder = CatalogEncoder::new(&prepared).unwrap();
    let mut proof_offset = HEADER_LENGTH as u64 + 2 * INDEX_ENTRY_LENGTH as u64;
    for ordinal in 0..2 {
        let record = encoder.next_record().unwrap().unwrap();
        assert_eq!(record.ordinal(), ordinal);
        assert_eq!(
            record.index_offset(),
            HEADER_LENGTH as u64 + ordinal * INDEX_ENTRY_LENGTH as u64
        );
        assert_eq!(record.proof_offset(), proof_offset);
        proof_offset += u64::try_from(record.proof().len()).unwrap();
    }
    assert!(encoder.next_record().unwrap().is_none());
    let finished = encoder.finish().unwrap();
    assert_eq!(finished.record_count(), 2);
    assert_eq!(finished.catalog_length(), proof_offset);
}

/// Exercises complete and selected-entry parsing with bounded input and a
/// sparsely selected synthesized object slightly larger than one profile range.
pub fn exercise(input: &[u8]) {
    if selector(input) & 0xff == 0 {
        exercise_multi_record_encoder(input);
    }

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
    use super::{exercise, exercise_multi_record_encoder};

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

    #[test]
    fn sparse_multi_record_encoder_path_is_bounded() {
        exercise_multi_record_encoder(&[0; 8]);
    }
}
