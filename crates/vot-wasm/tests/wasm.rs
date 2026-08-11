#![cfg(target_arch = "wasm32")]

use vot_wasm::{
    CoverageUpdate, ErrorCode, ObjectBuilder, ObjectCoverage, PackageBuilder, PackageEntry,
    PackageIngest, PackagePath, Suite, validate_catalog, verify_range, verify_receipt_ed25519,
};
use wasm_bindgen_test::wasm_bindgen_test;

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

#[wasm_bindgen_test]
fn object_proof_catalog_and_coverage_match_the_native_sdk() {
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
    native.update(data).unwrap();
    let native = native.finish().unwrap();
    assert_eq!(wasm.object_id().root(), native.object_id().root);

    let proof = wasm.prove(0, 3).unwrap();
    assert_eq!(proof.bytes(), native.prove(0, 3).unwrap().proof());
    let verified = verify_range(&wasm.object_id(), 0, data, &proof.bytes()).unwrap();
    assert_eq!(verified.bytes(), data);
    assert_eq!(
        verify_range(&wasm.object_id(), 0, b"abd", &proof.bytes())
            .unwrap_err()
            .code(),
        ErrorCode::VerificationFailed
    );

    let catalog = wasm.encode_catalog(u64::MAX).unwrap();
    assert_eq!(
        catalog,
        vot_sdk::proof::encode_in_memory(&native, u64::MAX).unwrap()
    );
    let header = validate_catalog(&catalog, &wasm.object_id()).unwrap();
    let index = usize::try_from(header.index_entry_offset(0).unwrap()).unwrap();
    let entry = header
        .entry(
            0,
            &catalog[index..index + vot_sdk::proof::INDEX_ENTRY_LENGTH],
        )
        .unwrap();
    let start = usize::try_from(entry.proof_offset()).unwrap();
    let end = start + usize::try_from(entry.proof_length()).unwrap();
    assert_eq!(
        entry.verify(data, &catalog[start..end]).unwrap().bytes(),
        data
    );

    let mut coverage = ObjectCoverage::new(&wasm.object_id());
    let accepted = coverage.verify_and_accept(0, data, &proof.bytes()).unwrap();
    assert_eq!(accepted.update(), CoverageUpdate::Accepted);
    assert_eq!(accepted.into_verified_range().bytes(), data);
    assert!(coverage.is_complete());
}

#[wasm_bindgen_test]
fn package_bytes_match_and_manifest_entries_remain_opaque_until_finish() {
    let object = vot_wasm::ObjectId::new(Suite::Sha256Bep52, &[6; 32], 3).unwrap();
    let mut path = PackagePath::new();
    path.push("file.bin".to_owned()).unwrap();
    let entry = PackageEntry::direct(path, &object).unwrap();
    let mut builder = PackageBuilder::new().unwrap();
    assert!(builder.push(&entry).unwrap().is_none());
    let mut assembly = builder.finish().unwrap();
    let draft = assembly.take_final_page().unwrap();
    let mut finalizer = assembly.take_finalizer().unwrap();
    let page_bytes = finalizer.push(draft).unwrap().bytes();
    let seal_bytes = finalizer.finish().unwrap().bytes();

    let mut ingest = PackageIngest::new(&seal_bytes, &assembly.summary().object_id()).unwrap();
    let page = ingest.push(&page_bytes).unwrap();
    assert_eq!(page.entry(0).unwrap_err().code(), ErrorCode::StateConflict);
    assert_eq!(ingest.finish().unwrap(), assembly.summary());
    assert_eq!(page.entry(0).unwrap().object_id(), object);
}

#[wasm_bindgen_test]
fn committed_receipt_vector_matches_the_native_sdk() {
    let public_key: [u8; 32] =
        hex("197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61")
            .try_into()
            .unwrap();
    let envelope = hex(concat!(
        "a400ae000001840101582011111111111111111111111111111111111111111111111111111111",
        "111111111a00100000020503010404050106830004000750222222222222222222222222222222",
        "2208503333333333333333333333333333333309070a74323032362d30382d30325430303a3030",
        "3a30305a0b010c010d000101024f766f742d636f6e666f726d616e63650358409cd793b6ba9d",
        "3b84079328fd69823004653bab15c499283fba99e3759b4378d62e5cbe89736ef41b4e8083b90",
        "b76f4511d0c00b856bc040f8c5081a75cb27f0d"
    ));
    let wasm = verify_receipt_ed25519(&envelope, &public_key).unwrap();
    let native = vot_sdk::receipt::verify_ed25519(&envelope, &public_key).unwrap();
    assert_eq!(wasm.subject_id().root(), native.subject_id().root);
    assert_eq!(wasm.sequence(), native.sequence());
    assert_eq!(
        wasm.envelope_digest().unwrap(),
        native.envelope_digest().unwrap()
    );
}
