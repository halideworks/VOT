use vot_wasm::{
    CoverageUpdate, ObjectBuilder, ObjectCoverage, ObjectId, PackageBuilder, PackageEntry,
    PackageIngest, PackagePath, Suite, decode_catalog_header, validate_catalog, verify_range,
};

#[test]
fn native_and_wasm_facades_produce_identical_object_and_catalog_results() {
    let data = b"abc";
    let mut wasm = ObjectBuilder::new(Suite::Sha256Bep52, Some(3), 3).unwrap();
    wasm.update(&data[..1]).unwrap();
    wasm.update(&data[1..]).unwrap();
    let wasm = wasm.finish().unwrap();

    let mut native = vot_sdk::object::InMemoryObjectBuilder::new(
        vot_sdk::object::Suite::Sha256Bep52,
        Some(3),
        3,
    )
    .unwrap();
    native.update(&data[..1]).unwrap();
    native.update(&data[1..]).unwrap();
    let native = native.finish().unwrap();

    assert_eq!(wasm.object_id().root(), native.object_id().root);
    assert_eq!(wasm.object_id().length(), native.object_id().length);
    let wasm_proof = wasm.prove(0, 3).unwrap();
    let native_proof = native.prove(0, 3).unwrap();
    assert_eq!(wasm_proof.covered_offset(), native_proof.covered_offset());
    assert_eq!(wasm_proof.covered_length(), native_proof.covered_length());
    assert_eq!(wasm_proof.bytes(), native_proof.proof());

    let verified = verify_range(&wasm.object_id(), 0, data, &wasm_proof.bytes()).unwrap();
    assert_eq!(verified.object_id().root(), native.object_id().root);
    assert_eq!(verified.bytes(), data);

    let wasm_catalog = wasm.encode_catalog(u64::MAX).unwrap();
    let native_catalog = vot_sdk::proof::encode_in_memory(&native, u64::MAX).unwrap();
    assert_eq!(wasm_catalog, native_catalog);
    let header = decode_catalog_header(
        &wasm_catalog[..vot_sdk::proof::HEADER_LENGTH],
        &wasm.object_id(),
    )
    .unwrap();
    assert_eq!(header.catalog_length(), wasm_catalog.len() as u64);
    let complete = validate_catalog(&wasm_catalog, &wasm.object_id()).unwrap();
    let offset = usize::try_from(complete.index_entry_offset(0).unwrap()).unwrap();
    let entry = complete
        .entry(
            0,
            &wasm_catalog[offset..offset + vot_sdk::proof::INDEX_ENTRY_LENGTH],
        )
        .unwrap();
    let proof_offset = usize::try_from(entry.proof_offset()).unwrap();
    let proof_end = proof_offset + usize::try_from(entry.proof_length()).unwrap();
    assert_eq!(
        entry
            .verify(data, &wasm_catalog[proof_offset..proof_end])
            .unwrap()
            .bytes(),
        data
    );
}

#[test]
fn authenticated_coverage_advances_once_and_returns_only_verified_bytes() {
    let data = b"authenticated range";
    let mut builder = ObjectBuilder::new(
        Suite::Blake3Bao64,
        Some(data.len() as u64),
        data.len() as u64,
    )
    .unwrap();
    builder.update(data).unwrap();
    let prepared = builder.finish().unwrap();
    let proof = prepared.prove(0, data.len() as u64).unwrap();
    let mut coverage = ObjectCoverage::new(&prepared.object_id());
    let accepted = coverage
        .verify_and_accept(proof.covered_offset(), data, &proof.bytes())
        .unwrap();
    assert_eq!(accepted.update(), CoverageUpdate::Accepted);
    assert_eq!(accepted.into_verified_range().bytes(), data);
    assert_eq!(coverage.covered_bytes(), data.len() as u64);
    assert_eq!(coverage.fragment_count(), 1);
    assert!(coverage.is_complete());
    assert_eq!(
        coverage
            .verify_and_accept(proof.covered_offset(), data, &proof.bytes())
            .unwrap()
            .update(),
        CoverageUpdate::Replay
    );
}

#[test]
fn package_outputs_match_the_sdk_and_pages_unlock_only_after_final_authentication() {
    let object = ObjectId::new(Suite::Sha256Bep52, &[6; 32], 3).unwrap();
    let mut path = PackagePath::new();
    path.push("directory".to_owned()).unwrap();
    path.push("file.bin".to_owned()).unwrap();
    assert_eq!(path.length(), 2);
    let entry = PackageEntry::direct(path, &object).unwrap();
    assert_eq!(entry.path_length(), 2);
    assert_eq!(entry.path_component(1).unwrap(), "file.bin");

    let native_entry = vot_sdk::package::PackageEntry::direct(
        vec!["directory".to_owned(), "file.bin".to_owned()],
        &vot_sdk::object::ObjectId {
            suite: 2,
            root: [6; 32],
            length: 3,
        },
    )
    .unwrap();
    let mut wasm_builder = PackageBuilder::new().unwrap();
    assert!(wasm_builder.push(&entry).unwrap().is_none());
    let mut native_builder = vot_sdk::package::PackageBuilder::new().unwrap();
    assert!(native_builder.push(&native_entry).unwrap().is_none());
    let mut wasm = wasm_builder.finish().unwrap();
    let (native_summary, native_page, mut native_finalizer) =
        native_builder.finish().unwrap().into_parts();
    assert_eq!(wasm.summary().root(), native_summary.root());
    let wasm_page = wasm.take_final_page().unwrap();
    let wasm_draft = wasm_page.encode().unwrap();
    assert_eq!(wasm_draft, native_page.encode().unwrap());
    let mut wasm_finalizer = wasm.take_finalizer().unwrap();
    let wasm_page = wasm_finalizer.push(wasm_page).unwrap().bytes();
    let native_page = native_finalizer.push(native_page).unwrap().into_bytes();
    assert_eq!(wasm_page, native_page);
    let wasm_seal = wasm_finalizer.finish().unwrap().bytes();
    let native_seal = native_finalizer.finish().unwrap().into_bytes();
    assert_eq!(wasm_seal, native_seal);

    let mut ingest = PackageIngest::new(&wasm_seal, &wasm.summary().object_id()).unwrap();
    let page = ingest.push(&wasm_page).unwrap();
    assert_eq!(page.entry_count(), 1);
    assert!(page.entry(0).is_err());
    assert_eq!(ingest.finish().unwrap(), wasm.summary());
    assert_eq!(page.entry(0).unwrap(), entry);
}

#[test]
fn an_object_prepared_from_segment_leaves_matches_the_sequential_builder() {
    let leaf = usize::try_from(vot_wasm::proof_leaf_size()).unwrap();
    // Eleven leaves and a short tail, cut at odd leaf counts so no segment is
    // a whole subtree on its own.
    let data: Vec<u8> = (0..(leaf * 11 + 4321))
        .map(|i| u8::try_from(i % 239).unwrap())
        .collect();
    let cuts = [0, leaf * 3, leaf * 8, data.len()];
    for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
        let mut sequential =
            ObjectBuilder::new(suite, Some(data.len() as u64), data.len() as u64).unwrap();
        for piece in data.chunks(leaf * 2 + 100) {
            sequential.update(piece).unwrap();
        }
        let sequential = sequential.finish().unwrap();

        let mut leaves = Vec::new();
        for window in cuts.windows(2) {
            let (start, end) = (window[0], window[1]);
            leaves.extend(
                vot_wasm::proof_leaves_at(
                    suite,
                    start as u64,
                    &data[start..end],
                    data.len() as u64,
                )
                .unwrap(),
            );
        }
        let assembled = vot_wasm::PreparedObject::from_proof_leaves(
            suite,
            data.len() as u64,
            &leaves,
            data.len() as u64,
        )
        .unwrap();
        assert_eq!(assembled.object_id().root(), sequential.object_id().root());
        assert_eq!(
            assembled.object_id().length(),
            sequential.object_id().length()
        );
        for (offset, length) in [
            (0, leaf as u64 * 2 + 7),
            (leaf as u64 * 7, 5000),
            (0, data.len() as u64),
        ] {
            let a = assembled.prove(offset, length).unwrap();
            let b = sequential.prove(offset, length).unwrap();
            assert_eq!(a.covered_offset(), b.covered_offset());
            assert_eq!(a.bytes(), b.bytes());
        }
        assert_eq!(
            assembled.encode_catalog(u64::MAX).unwrap(),
            sequential.encode_catalog(u64::MAX).unwrap()
        );
        // A blake3 segment hashed at the wrong place names a different object;
        // a sha256 piece hash does not depend on its place, so only blake3 is
        // asserted.
        let mut wrong =
            vot_wasm::proof_leaves_at(suite, leaf as u64, &data[..leaf * 3], data.len() as u64)
                .unwrap();
        wrong.extend_from_slice(&leaves[32 * 3..]);
        let other = vot_wasm::PreparedObject::from_proof_leaves(
            suite,
            data.len() as u64,
            &wrong,
            data.len() as u64,
        );
        if suite == Suite::Blake3Bao64 {
            assert_ne!(
                other.unwrap().object_id().root(),
                sequential.object_id().root()
            );
        }
        assert!(vot_wasm::proof_leaves_at(suite, 1, &data[..leaf], data.len() as u64).is_err());
        // A short read that does not end the object is refused.
        assert!(vot_wasm::proof_leaves_at(suite, 0, &data[..leaf - 1], data.len() as u64).is_err());
        assert!(
            vot_wasm::PreparedObject::from_proof_leaves(
                suite,
                data.len() as u64,
                &leaves[..31],
                u64::MAX
            )
            .is_err()
        );
    }
}
