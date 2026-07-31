use vot_proof_sha256::{prove, root, verify};

#[test]
fn short_single_piece_proofs_use_actual_bep52_height() {
    for length in [1_usize, 16_383, 16_384, 16_385, 65_535, 65_536] {
        let data: Vec<_> = (0..length)
            .map(|index| u8::try_from(index * 17 % 251).unwrap())
            .collect();
        let bundle = prove(&data, 0, 1).unwrap();
        verify(
            &root(&data),
            data.len() as u64,
            0,
            &bundle.data,
            &bundle.proof,
        )
        .unwrap();
    }
}
