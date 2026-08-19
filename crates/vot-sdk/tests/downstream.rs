use vot_sdk::object::{InMemoryObjectBuilder, Suite};
use vot_sdk::{ErrorCode, coverage, package, proof, receipt, resume, verify};

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

#[test]
fn object_and_catalog_flow_uses_only_the_sdk_facade() {
    let data = b"abc";
    let mut builder =
        InMemoryObjectBuilder::new(Suite::Sha256Bep52, Some(3), 3).expect("bounded builder");
    builder.update(data).expect("object bytes");
    let prepared = builder.finish().expect("prepared object");
    let object = prepared.object_id().clone();

    let range = prepared.prove(0, 3).expect("range proof");
    let verified = verify::verify_range(&object, range.covered_offset(), data, range.proof())
        .expect("direct verification");
    assert_eq!(verified.object_id(), object);
    assert_eq!(verified.data(), data);

    let catalog = proof::encode_in_memory(&prepared, 16 * 1024).expect("bounded catalog");
    let header = proof::validate_catalog(&catalog, &object).expect("catalog header");
    let index_offset = usize::try_from(header.index_entry_offset(0).expect("index offset"))
        .expect("platform offset");
    let entry = header
        .decode_entry(
            0,
            &catalog[index_offset..index_offset + proof::INDEX_ENTRY_LENGTH],
        )
        .expect("catalog entry");
    let proof_offset = usize::try_from(entry.proof_offset()).expect("proof offset");
    let proof_length = usize::try_from(entry.proof_length()).expect("proof length");
    let verified = entry
        .verify(data, &catalog[proof_offset..proof_offset + proof_length])
        .expect("catalog verification");
    assert_eq!(verified.data(), data);
}

#[test]
fn coverage_accepts_only_authenticated_ranges_for_one_identity() {
    let data = vec![7; 131_072];
    let mut builder = InMemoryObjectBuilder::new(
        Suite::Sha256Bep52,
        Some(data.len() as u64),
        data.len() as u64,
    )
    .expect("bounded builder");
    builder.update(&data).expect("object bytes");
    let prepared = builder.finish().expect("prepared object");
    let object = prepared.object_id().clone();

    let first_proof = prepared.prove(0, 1).expect("first proof");
    let first = verify::verify_range(
        &object,
        first_proof.covered_offset(),
        &data[..65_536],
        first_proof.proof(),
    )
    .expect("first verified range");
    let second_proof = prepared.prove(65_536, 1).expect("second proof");
    let second = verify::verify_range(
        &object,
        second_proof.covered_offset(),
        &data[65_536..],
        second_proof.proof(),
    )
    .expect("second verified range");
    let whole_proof = prepared.prove(0, data.len() as u64).expect("whole proof");
    let whole =
        verify::verify_range(&object, 0, &data, whole_proof.proof()).expect("whole verified range");

    let mut accepted = coverage::ObjectCoverage::new(&object);
    assert_eq!(accepted.object_id(), &object);
    assert_eq!(accepted.covered_bytes(), 0);
    assert_eq!(accepted.fragment_count(), 0);
    assert!(!accepted.is_complete());
    assert_eq!(
        accepted.accept(&first).expect("first acceptance"),
        coverage::CoverageUpdate::Accepted
    );
    assert_eq!(accepted.covered_bytes(), 65_536);
    assert_eq!(accepted.fragment_count(), 1);
    assert_eq!(
        accepted.accept(&first).expect("authenticated replay"),
        coverage::CoverageUpdate::Replay
    );
    assert_eq!(
        accepted.accept(&whole).unwrap_err().code(),
        ErrorCode::StateConflict
    );

    let other_data = b"other object";
    let mut other_builder = InMemoryObjectBuilder::new(
        Suite::Sha256Bep52,
        Some(other_data.len() as u64),
        other_data.len() as u64,
    )
    .expect("other builder");
    other_builder.update(other_data).expect("other bytes");
    let other = other_builder.finish().expect("other object");
    let other_proof = other.prove(0, 1).expect("other proof");
    let other_verified = verify::verify_range(
        other.object_id(),
        other_proof.covered_offset(),
        other_data,
        other_proof.proof(),
    )
    .expect("other verified range");
    assert_eq!(
        accepted.accept(&other_verified).unwrap_err().code(),
        ErrorCode::IdentityMismatch
    );
    assert_eq!(accepted.covered_bytes(), 65_536);

    assert_eq!(
        accepted.accept(&second).expect("second acceptance"),
        coverage::CoverageUpdate::Accepted
    );
    assert_eq!(accepted.covered_bytes(), data.len() as u64);
    assert_eq!(accepted.fragment_count(), 1);
    assert!(accepted.is_complete());
    assert_eq!(coverage::MAX_FRAGMENTS, 4096);
}

#[test]
fn package_flow_uses_only_the_sdk_facade() {
    let object = vot_sdk::object::ObjectId {
        suite: Suite::Sha256Bep52.identifier(),
        root: [6; 32],
        length: 3,
    };
    let entry = package::PackageEntry::direct(vec!["file.bin".to_owned()], &object).expect("entry");
    assert_eq!(entry.path().collect::<Vec<_>>(), ["file.bin"]);
    assert_eq!(entry.object_id(), object);
    assert_eq!(entry.storage(), package::EntryStorage::Direct);
    let pack = vot_sdk::object::ObjectId {
        suite: object.suite,
        root: [8; 32],
        length: 8,
    };
    let packed = package::PackageEntry::packed(vec!["packed.bin".to_owned()], &object, &pack, 2)
        .expect("packed entry");
    assert_eq!(
        packed.storage(),
        package::EntryStorage::Pack {
            object: pack,
            offset: 2,
        }
    );
    let other_suite = vot_sdk::object::ObjectId {
        suite: Suite::Blake3Bao64.identifier(),
        root: [7; 32],
        length: 8,
    };
    assert_eq!(
        package::PackageEntry::packed(vec!["invalid.bin".to_owned()], &object, &other_suite, 0,)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidInput
    );
    let mut package_builder = package::PackageBuilder::new().expect("package builder");
    assert!(
        package_builder
            .push(&entry)
            .expect("package entry")
            .is_none()
    );
    let (summary, final_page, mut finalizer) = package_builder
        .finish()
        .expect("package assembly")
        .into_parts();
    assert_ne!(summary.root(), [0; 32]);
    assert_ne!(summary.root(), [1; 32]);
    assert_eq!(summary.logical_length(), 3);
    assert_eq!(summary.entries(), 1);
    let draft_bytes = final_page.encode().expect("draft bytes");
    assert_eq!(
        package::PageDraft::decode(&draft_bytes)
            .expect("draft decode")
            .encode()
            .expect("draft re-encode"),
        draft_bytes
    );
    let page = finalizer.push(final_page).expect("final page");
    let seal = finalizer.finish().expect("seal");
    assert_eq!(page.clone().into_bytes(), page.as_bytes());
    assert_eq!(seal.clone().into_bytes(), seal.as_bytes());
    let mut ingest = package::PackageIngest::new_expected(seal.as_bytes(), &summary.object_id())
        .expect("ingest");
    let validated = ingest.push_page(page.as_bytes()).expect("page ingest");
    assert_eq!(validated.entries()[0].object_id(), object);
    assert_eq!(ingest.finish().expect("package identity"), summary);
}

#[test]
fn receipt_vector_verifies_through_the_public_facade() {
    let public_key: [u8; 32] =
        hex("197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61")
            .try_into()
            .expect("public key");
    let envelope = hex(concat!(
        "a400ae000001840101582011111111111111111111111111111111111111111111111111111111",
        "111111111a00100000020503010404050106830004000750222222222222222222222222222222",
        "2208503333333333333333333333333333333309070a74323032362d30382d30325430303a3030",
        "3a30305a0b010c010d000101024f766f742d636f6e666f726d616e63650358409cd793b6ba9d",
        "3b84079328fd69823004653bab15c499283fba99e3759b4378d62e5cbe89736ef41b4e8083b90",
        "b76f4511d0c00b856bc040f8c5081a75cb27f0d"
    ));
    let receipt = receipt::verify_ed25519(&envelope, &public_key).expect("receipt signature");
    assert_eq!(receipt.subject_kind(), receipt::SubjectKind::Package);
    assert_eq!(receipt.assurance(), receipt::AssuranceLevel::Published);
}

#[test]
fn representative_limits_and_failures_have_stable_codes() {
    let Err(error) = InMemoryObjectBuilder::new(Suite::Sha256Bep52, Some(2), 1) else {
        panic!("declared length exceeds the explicit limit");
    };
    assert_eq!(error.code(), ErrorCode::LimitExceeded);

    let mut incremental =
        InMemoryObjectBuilder::new(Suite::Sha256Bep52, None, 4).expect("bounded builder");
    incremental.update(&[1; 3]).expect("below bound");
    assert_eq!(
        incremental.update(&[2; 2]).unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
    incremental.update(&[3]).expect("exact bound");

    let error = resume::UnitRanges::from_runs([(0, 1), (2, 1)], 1).expect_err("input run limit");
    assert_eq!(error.code(), ErrorCode::LimitExceeded);

    let error = receipt::verify_ed25519(&[], &[0; 32]).expect_err("malformed receipt");
    assert_eq!(error.code(), ErrorCode::Malformed);
}

#[test]
fn nonzero_range_geometry_stays_bound_to_verified_bytes() {
    let mut data = vec![3; 131_073];
    data[65_536..131_072].fill(5);
    data[131_072] = 7;
    let mut builder = InMemoryObjectBuilder::new(
        Suite::Sha256Bep52,
        Some(data.len() as u64),
        data.len() as u64,
    )
    .expect("bounded builder");
    builder.update(&data).expect("object bytes");
    let prepared = builder.finish().expect("prepared object");
    let range = prepared.prove(65_537, 1).expect("range proof");
    assert_eq!(range.covered_offset(), 65_536);
    assert_eq!(range.covered_length(), 65_536);
    let covered = &data[65_536..131_072];
    assert!(prepared.holds(65_536, covered));
    assert!(!prepared.holds(0, covered));
    let verified = verify::verify_range(
        prepared.object_id(),
        range.covered_offset(),
        covered,
        range.proof(),
    )
    .expect("range verification");
    assert_eq!(verified.object_id(), *prepared.object_id());
    assert_eq!(verified.covered_offset(), 65_536);
    assert_eq!(verified.data(), covered);
    let proof = range.proof().to_vec();
    let (offset, length, owned_proof) = range.into_parts();
    assert_eq!(offset, 65_536);
    assert_eq!(length, 65_536);
    assert_eq!(owned_proof, proof);
    assert!(!owned_proof.is_empty());
}

#[test]
fn streaming_catalog_positions_two_records_and_checks_exact_limit() {
    let data = vec![7; usize::try_from(proof::RANGE_LENGTH + 1).expect("fixture length")];
    let mut builder = InMemoryObjectBuilder::new(
        Suite::Blake3Bao64,
        Some(data.len() as u64),
        data.len() as u64,
    )
    .expect("bounded builder");
    builder.update(&data).expect("object bytes");
    let prepared = builder.finish().expect("prepared object");
    let object = prepared.object_id().clone();

    let mut encoder = proof::CatalogEncoder::new(&prepared).expect("catalog encoder");
    let first = encoder
        .next_record()
        .expect("first record")
        .expect("present first record");
    let second = encoder
        .next_record()
        .expect("second record")
        .expect("present second record");
    assert!(encoder.next_record().expect("end record").is_none());
    assert_eq!(first.ordinal(), 0);
    assert_eq!(second.ordinal(), 1);
    assert_eq!(first.index_offset(), proof::HEADER_LENGTH as u64);
    assert_eq!(
        second.index_offset(),
        (proof::HEADER_LENGTH + proof::INDEX_ENTRY_LENGTH) as u64
    );
    assert_ne!(first.index_entry(), &[0; proof::INDEX_ENTRY_LENGTH]);
    assert!(first.proof_offset() > 1);
    assert!(!first.proof().is_empty());
    let finished = encoder.finish().expect("finished catalog");
    assert_eq!(finished.record_count(), 2);
    assert!(finished.catalog_length() > finished.header().len() as u64);

    let catalog = proof::encode_in_memory(&prepared, u64::MAX).expect("bounded catalog");
    let exact_limit = catalog.len() as u64;
    assert_eq!(
        proof::encode_in_memory(&prepared, exact_limit).expect("exact catalog limit"),
        catalog
    );
    assert_eq!(
        proof::encode_in_memory(&prepared, exact_limit - 1)
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded
    );
    let header = proof::decode_header(&catalog[..proof::HEADER_LENGTH], &object)
        .expect("partial catalog header");
    assert_eq!(header.object_id(), &object);
    assert_eq!(header.record_count(), 2);
    assert_eq!(header.catalog_length(), exact_limit);
    let header = proof::validate_catalog(&catalog, &object).expect("complete catalog");
    let first_offset =
        usize::try_from(header.index_entry_offset(0).expect("first index")).expect("offset");
    let second_offset =
        usize::try_from(header.index_entry_offset(1).expect("second index")).expect("offset");
    let first_entry = header
        .decode_entry(
            0,
            &catalog[first_offset..first_offset + proof::INDEX_ENTRY_LENGTH],
        )
        .expect("first entry");
    let second_entry = header
        .decode_entry(
            1,
            &catalog[second_offset..second_offset + proof::INDEX_ENTRY_LENGTH],
        )
        .expect("second entry");
    assert_eq!(first_entry.ordinal(), 0);
    assert_eq!(first_entry.data_offset(), 0);
    assert_eq!(first_entry.data_length(), proof::RANGE_LENGTH);
    assert_eq!(second_entry.ordinal(), 1);
    assert_eq!(second_entry.data_offset(), proof::RANGE_LENGTH);
    assert_eq!(second_entry.data_length(), 1);
    assert!(second_entry.proof_offset() > 1);
    assert!(second_entry.proof_length() > 1);
    let proof_offset = usize::try_from(second_entry.proof_offset()).expect("proof offset");
    let proof_length = usize::try_from(second_entry.proof_length()).expect("proof length");
    let verified = second_entry
        .verify(
            &data[usize::try_from(proof::RANGE_LENGTH).expect("data offset")..],
            &catalog[proof_offset..proof_offset + proof_length],
        )
        .expect("second range verification");
    assert_eq!(verified.covered_offset(), proof::RANGE_LENGTH);
}

#[test]
fn resume_ranges_and_waste_counters_are_exact() {
    let ranges = resume::UnitRanges::from_runs([(2, 3), (8, 2)], 2).expect("bounded runs");
    assert!(!ranges.is_empty());
    assert_eq!(ranges.run_count(), 2);
    assert_eq!(ranges.count(), 5);
    assert!(ranges.contains(3));
    assert!(!ranges.contains(0));
    assert_eq!(ranges.runs().collect::<Vec<_>>(), [(2, 3), (8, 2)]);
    assert!(resume::UnitRanges::new().is_empty());

    let object = vot_sdk::object::ObjectId {
        suite: 2,
        root: [4; 32],
        length: 99,
    };
    let mut state = resume::ResumeState::new(
        resume::ResumeIdentity::for_object(&object),
        4,
        2,
        resume::UnitRanges::from_runs([(0, 1)], 1).expect("checkpointed"),
    )
    .expect("resume state");
    assert_eq!(state.total_units(), 4);
    assert!(state.is_checkpointed(0));
    assert!(!state.is_checkpointed(1));
    assert_eq!(state.missing_units().collect::<Vec<_>>(), [1, 2, 3]);
    assert!(state.begin_unit(1).expect("first active"));
    assert!(!state.complete_unit(1).expect("below window"));
    assert!(state.begin_unit(2).expect("second active"));
    assert_eq!(state.retransmission_units_after_crash(), 2);
    assert_eq!(state.retransmission_bound(), 3);

    let plan = state.prepare_checkpoint();
    assert_eq!(plan.checkpointed_runs().collect::<Vec<_>>(), [(0, 2)]);
    assert_eq!(plan.checkpointed_count(), 2);
    let other_object = vot_sdk::object::ObjectId {
        suite: 1,
        root: [5; 32],
        length: 100,
    };
    let mut other = resume::ResumeState::new(
        resume::ResumeIdentity::for_object(&other_object),
        4,
        2,
        resume::UnitRanges::from_runs([(0, 1)], 1).expect("checkpointed"),
    )
    .expect("other state");
    let durable = resume::UnitRanges::from_runs([(0, 2)], 1).expect("durable");
    assert_eq!(
        other.commit_checkpoint(plan, durable).unwrap_err().code(),
        ErrorCode::StateConflict
    );
}
