use vot_object::{ObjectBuilder, PreparedObject, Suite};
use vot_proof_store::MemoryNodeStorage;

use super::*;

macro_rules! vector {
    ($name:literal) => {
        include_bytes!(concat!(
            "../../../test-vectors/static-proof-catalog/",
            $name,
            ".bin"
        ))
        .as_slice()
    };
}

struct Case {
    suite: Suite,
    length: usize,
    fixture: &'static [u8],
}

fn cases() -> [Case; 18] {
    use Suite::{Blake3Bao64 as B, Sha256Bep52 as S};
    [
        Case {
            suite: B,
            length: 0,
            fixture: vector!("blake3-empty"),
        },
        Case {
            suite: B,
            length: 1,
            fixture: vector!("blake3-1"),
        },
        Case {
            suite: B,
            length: 65_535,
            fixture: vector!("blake3-65535"),
        },
        Case {
            suite: B,
            length: 65_536,
            fixture: vector!("blake3-65536"),
        },
        Case {
            suite: B,
            length: 65_537,
            fixture: vector!("blake3-65537"),
        },
        Case {
            suite: B,
            length: 4_194_303,
            fixture: vector!("blake3-4m-minus-1"),
        },
        Case {
            suite: B,
            length: 4_194_304,
            fixture: vector!("blake3-4m"),
        },
        Case {
            suite: B,
            length: 4_194_305,
            fixture: vector!("blake3-4m-plus-1"),
        },
        Case {
            suite: B,
            length: 8_388_625,
            fixture: vector!("blake3-large-final"),
        },
        Case {
            suite: S,
            length: 0,
            fixture: vector!("sha256-empty"),
        },
        Case {
            suite: S,
            length: 1,
            fixture: vector!("sha256-1"),
        },
        Case {
            suite: S,
            length: 65_535,
            fixture: vector!("sha256-65535"),
        },
        Case {
            suite: S,
            length: 65_536,
            fixture: vector!("sha256-65536"),
        },
        Case {
            suite: S,
            length: 65_537,
            fixture: vector!("sha256-65537"),
        },
        Case {
            suite: S,
            length: 4_194_303,
            fixture: vector!("sha256-4m-minus-1"),
        },
        Case {
            suite: S,
            length: 4_194_304,
            fixture: vector!("sha256-4m"),
        },
        Case {
            suite: S,
            length: 4_194_305,
            fixture: vector!("sha256-4m-plus-1"),
        },
        Case {
            suite: S,
            length: 8_388_625,
            fixture: vector!("sha256-large-final"),
        },
    ]
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from((index * 17) % 251).unwrap())
        .collect()
}

fn prepare(suite: Suite, data: &[u8]) -> PreparedObject {
    let mut builder = ObjectBuilder::new(suite, Some(data.len() as u64)).unwrap();
    for chunk in data.chunks(131_071) {
        builder.update(chunk).unwrap();
    }
    builder.finish().unwrap()
}

fn prepare_stored(suite: Suite, data: &[u8]) -> PreparedObject {
    let mut builder = ObjectBuilder::with_proof_storage(
        suite,
        Some(data.len() as u64),
        Box::new(MemoryNodeStorage::new()),
    )
    .unwrap();
    for chunk in data.chunks(131_071) {
        builder.update(chunk).unwrap();
    }
    builder.finish().unwrap()
}

fn identity(fixture: &[u8]) -> ObjectId {
    let mut root = [0; 32];
    root.copy_from_slice(&fixture[24..56]);
    ObjectId {
        suite: read_u16(fixture, 16),
        root,
        length: read_u64(fixture, 56),
    }
}

fn selected<'header>(
    header: &'header CatalogHeader,
    catalog: &[u8],
    ordinal: u64,
) -> SelectedEntry<'header> {
    let start = usize::try_from(header.index_entry_offset(ordinal).unwrap()).unwrap();
    header
        .decode_entry(ordinal, &catalog[start..start + INDEX_ENTRY_LENGTH])
        .unwrap()
}

fn proof<'catalog>(entry: &SelectedEntry<'_>, catalog: &'catalog [u8]) -> &'catalog [u8] {
    let start = usize::try_from(entry.proof_offset()).unwrap();
    let length = usize::try_from(entry.proof_length()).unwrap();
    &catalog[start..start + length]
}

#[test]
fn every_committed_catalog_is_reproduced_and_verifies() {
    for case in cases() {
        let data = pattern(case.length);
        let prepared = prepare(case.suite, &data);
        let catalog = encode(&prepared).unwrap();
        assert_eq!(
            catalog, case.fixture,
            "suite {:?}, length {}",
            case.suite, case.length
        );
        let stored = prepare_stored(case.suite, &data);
        assert_eq!(stored.object_id(), prepared.object_id());
        assert_eq!(encode(&stored).unwrap(), case.fixture);
        let header = validate_complete(&catalog, prepared.object_id()).unwrap();
        for ordinal in 0..header.record_count() {
            let entry = selected(&header, &catalog, ordinal);
            let start = usize::try_from(entry.data_offset()).unwrap();
            let length = usize::try_from(entry.data_length()).unwrap();
            let data_range = &data[start..start + length];
            let proof_bytes = proof(&entry, &catalog);
            let verified = entry.verify(data_range, proof_bytes).unwrap();
            assert_eq!(verified.object().suite, prepared.object_id().suite);
            assert_eq!(verified.object().root, prepared.object_id().root);
            assert_eq!(verified.object().length, prepared.object_id().length);
            assert_eq!(verified.covered_offset(), entry.data_offset());
            assert!(std::ptr::eq(verified.data(), data_range));
            let cold = match case.suite {
                Suite::Blake3Bao64 => {
                    vot_proof_blake3::prove(&data, entry.data_offset(), entry.data_length())
                        .unwrap()
                        .proof
                }
                Suite::Sha256Bep52 => {
                    vot_proof_sha256::prove(&data, entry.data_offset(), entry.data_length())
                        .unwrap()
                        .proof
                }
            };
            assert_eq!(proof_bytes, cold);
        }
    }
}

#[test]
fn identity_is_required_before_addressing() {
    let fixture = vector!("blake3-65537");
    let expected = identity(fixture);
    let mut wrong = expected.clone();
    wrong.root[0] ^= 1;
    assert_eq!(decode_header(fixture, &wrong), Err(Error::IdentityMismatch));
    assert_eq!(
        decode_header(&fixture[..127], &expected),
        Err(Error::CatalogUnavailable)
    );
    let header = decode_header(fixture, &expected).unwrap();
    assert_eq!(header.catalog_length(), 208);
    assert_eq!(header.index_entry_offset(0), Ok(128));
    assert_eq!(header.index_entry_offset(1), Err(Error::RecordOutOfRange));
}

#[test]
fn all_header_classes_have_exact_outcomes() {
    let fixture = vector!("blake3-1");
    let expected = identity(fixture);
    for (offset, value, outcome) in [
        (0, 0, Error::MalformedCatalog),
        (9, 1, Error::UnsupportedCatalog),
        (11, 127, Error::MalformedCatalog),
        (15, 1, Error::MalformedCatalog),
        (17, 3, Error::UnsupportedCatalog),
        (19, 2, Error::UnsupportedCatalog),
        (23, 1, Error::MalformedCatalog),
        (112, 1, Error::MalformedCatalog),
    ] {
        let mut changed = fixture.to_vec();
        changed[offset] = value;
        assert_eq!(
            decode_header(&changed, &expected),
            Err(outcome),
            "offset {offset}"
        );
    }
    for offset in [24, 63] {
        let mut changed = fixture.to_vec();
        changed[offset] ^= 1;
        assert_eq!(
            decode_header(&changed, &expected),
            Err(Error::IdentityMismatch)
        );
    }
    for offset in [71, 79, 87, 95, 103, 111] {
        let mut changed = fixture.to_vec();
        changed[offset] ^= 1;
        assert_eq!(
            decode_header(&changed, &expected),
            Err(Error::MalformedCatalog)
        );
    }
}

#[test]
fn selected_entry_bounds_are_independent_of_neighbors() {
    let fixture = vector!("blake3-65537");
    let expected = identity(fixture);
    let header = decode_header(fixture, &expected).unwrap();
    let start = usize::try_from(header.index_entry_offset(0).unwrap()).unwrap();
    let base = &fixture[start..start + INDEX_ENTRY_LENGTH];
    assert_eq!(
        header.decode_entry(0, &base[..15]),
        Err(Error::CatalogUnavailable)
    );
    let mut oversized = base.to_vec();
    oversized.push(0);
    assert_eq!(
        header.decode_entry(0, &oversized),
        Err(Error::MalformedCatalog)
    );
    for (offset, value) in [(15, 1), (11, 1)] {
        let mut changed = base.to_vec();
        changed[offset] = value;
        assert_eq!(
            header.decode_entry(0, &changed),
            Err(Error::MalformedCatalog)
        );
    }
    let mut overflow = base.to_vec();
    overflow[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        header.decode_entry(0, &overflow),
        Err(Error::MalformedCatalog)
    );

    let large = vector!("blake3-large-final");
    let large_header = decode_header(large, &identity(large)).unwrap();
    let final_entry = selected(&large_header, large, 2);
    assert_eq!(final_entry.ordinal(), 2);
}

#[test]
fn fixed_width_integer_readers_use_every_byte() {
    let bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    assert_eq!(read_u16(&bytes, 1), 0x1122);
    assert_eq!(read_u32(&bytes, 1), 0x1122_3344);
    assert_eq!(read_u64(&bytes, 1), 0x1122_3344_5566_7788);
}

#[test]
fn encoder_guards_have_exact_boundaries() {
    use crate::encode::{
        cover_is_exact, finished_catalog_length, next_proof_blob_length, proof_length_is_valid,
    };

    assert!(cover_is_exact(4, 8, 4, 8));
    assert!(!cover_is_exact(3, 8, 4, 8));
    assert!(!cover_is_exact(4, 7, 4, 8));

    for (length, valid) in [
        (0, true),
        (31, false),
        (32, true),
        (8_192, true),
        (8_193, false),
    ] {
        assert_eq!(
            proof_length_is_valid(length),
            valid,
            "proof length {length}"
        );
    }

    assert_eq!(
        next_proof_blob_length(MAX_PROOF_BLOB_LENGTH - 32, 32),
        Ok(MAX_PROOF_BLOB_LENGTH)
    );
    assert_eq!(
        next_proof_blob_length(MAX_PROOF_BLOB_LENGTH, 1),
        Err(Error::ProofGeneration)
    );
    assert_eq!(
        next_proof_blob_length(u64::MAX, 1),
        Err(Error::ProofGeneration)
    );

    assert_eq!(
        finished_catalog_length(MAX_CATALOG_LENGTH, 0, MAX_CATALOG_LENGTH),
        Ok(MAX_CATALOG_LENGTH)
    );
    assert_eq!(
        finished_catalog_length(MAX_CATALOG_LENGTH, 1, MAX_CATALOG_LENGTH + 1),
        Err(Error::ProofGeneration)
    );
    assert_eq!(
        finished_catalog_length(128, 32, 159),
        Err(Error::ProofGeneration)
    );
    assert_eq!(
        finished_catalog_length(u64::MAX, 1, 0),
        Err(Error::ProofGeneration)
    );
}

#[test]
fn complete_scan_rejects_gaps_overlap_trailing_and_short_catalogs() {
    let fixture = vector!("blake3-4m-plus-1");
    let expected = identity(fixture);
    assert_eq!(
        validate_complete(&fixture[..fixture.len() - 1], &expected),
        Err(Error::CatalogUnavailable)
    );
    let mut trailing = fixture.to_vec();
    trailing.push(0);
    assert_eq!(
        validate_complete(&trailing, &expected),
        Err(Error::MalformedCatalog)
    );
    for (entry, relative) in [(0_usize, 1_u64), (1, 0), (1, 65)] {
        let mut changed = fixture.to_vec();
        write_u64(
            &mut changed,
            HEADER_LENGTH + entry * INDEX_ENTRY_LENGTH,
            relative,
        );
        assert_eq!(
            validate_complete(&changed, &expected),
            Err(Error::MalformedCatalog)
        );
    }
    let mut unindexed = fixture.to_vec();
    let blob_length = read_u64(&unindexed, 96) + 1;
    let catalog_length = read_u64(&unindexed, 104) + 1;
    write_u64(&mut unindexed, 96, blob_length);
    write_u64(&mut unindexed, 104, catalog_length);
    unindexed.push(0);
    assert_eq!(
        validate_complete(&unindexed, &expected),
        Err(Error::MalformedCatalog)
    );
}

fn with_single_proof(base: &[u8], length: usize) -> Vec<u8> {
    let mut changed = base[..HEADER_LENGTH + INDEX_ENTRY_LENGTH].to_vec();
    write_u32(
        &mut changed,
        HEADER_LENGTH + 8,
        u32::try_from(length).unwrap(),
    );
    write_u64(&mut changed, 96, length as u64);
    write_u64(
        &mut changed,
        104,
        (HEADER_LENGTH + INDEX_ENTRY_LENGTH + length) as u64,
    );
    changed.resize(HEADER_LENGTH + INDEX_ENTRY_LENGTH + length, 0);
    changed
}

#[test]
fn proof_limit_is_inclusive_before_proof_verification() {
    let base = vector!("blake3-1");
    let expected = identity(base);
    let exact = with_single_proof(base, 8_192);
    let header = validate_complete(&exact, &expected).unwrap();
    let entry = selected(&header, &exact, 0);
    assert_eq!(
        entry.verify(&[0], proof(&entry, &exact)).unwrap_err(),
        Error::ProofInvalid
    );
    let over = with_single_proof(base, 8_193);
    assert_eq!(
        validate_complete(&over, &expected),
        Err(Error::MalformedCatalog)
    );
}

#[test]
fn corrupt_data_and_proofs_fail_for_both_suites() {
    for fixture in [vector!("blake3-65536"), vector!("sha256-65536")] {
        let expected = identity(fixture);
        let header = validate_complete(fixture, &expected).unwrap();
        let entry = selected(&header, fixture, 0);
        let mut data = pattern(65_536);
        data[0] ^= 1;
        assert_eq!(
            entry.verify(&data, proof(&entry, fixture)).unwrap_err(),
            Error::ProofInvalid
        );
    }
    for fixture in [vector!("blake3-4m-plus-1"), vector!("sha256-4m-plus-1")] {
        let expected = identity(fixture);
        let header = validate_complete(fixture, &expected).unwrap();
        let entry = selected(&header, fixture, 0);
        let mut proof_bytes = proof(&entry, fixture).to_vec();
        proof_bytes[0] ^= 1;
        assert_eq!(
            entry.verify(&pattern(4_194_304), &proof_bytes).unwrap_err(),
            Error::ProofInvalid
        );
        proof_bytes.pop();
        assert_eq!(
            entry.verify(&pattern(4_194_304), &proof_bytes).unwrap_err(),
            Error::CatalogUnavailable
        );
    }
}

#[test]
fn maximum_geometry_decodes_without_catalog_allocation() {
    let mut bytes = vector!("blake3-empty").to_vec();
    let expected = ObjectId {
        suite: 1,
        root: [7; 32],
        length: MAX_OBJECT_LENGTH,
    };
    bytes[24..56].copy_from_slice(&expected.root);
    write_u64(&mut bytes, 56, expected.length);
    write_u64(&mut bytes, 64, MAX_RECORDS);
    write_u64(&mut bytes, 80, MAX_INDEX_LENGTH);
    write_u64(&mut bytes, 88, HEADER_LENGTH as u64 + MAX_INDEX_LENGTH);
    write_u64(&mut bytes, 96, MAX_PROOF_BLOB_LENGTH);
    write_u64(&mut bytes, 104, MAX_CATALOG_LENGTH);
    let header = decode_header(&bytes, &expected).unwrap();
    assert_eq!(header.record_count(), MAX_RECORDS);
    assert_eq!(
        header.index_entry_offset(MAX_RECORDS - 1),
        Ok(HEADER_LENGTH as u64 + (MAX_RECORDS - 1) * INDEX_ENTRY_LENGTH as u64)
    );
}
