#![allow(clippy::cast_possible_truncation, clippy::format_collect)]

use vot_proof_sha256::{piece_layer, prove, root};

fn pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (i.wrapping_mul(17) % 251) as u8)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let cases = [
        (1, 0, 1),
        (65_536, 65_535, 1),
        (327_699, 65_540, 8),
        (327_699, 70_000, 140_000),
    ];
    println!(
        "{{\n  \"suite\": \"sha256-bep52-64k\",\n  \"pattern\": \"byte[i]=(i*17)%251\",\n  \"cases\": ["
    );
    for (position, (length, offset, request_length)) in cases.into_iter().enumerate() {
        let data = pattern(length);
        let bundle = prove(&data, offset, request_length).unwrap();
        let pieces: Vec<_> = piece_layer(&data)
            .iter()
            .flat_map(|hash| hash.iter().copied())
            .collect();
        println!(
            "    {{\"object_length\":{length},\"request_offset\":{offset},\"request_length\":{request_length},\"covered_offset\":{},\"covered_length\":{},\"root\":\"{}\",\"proof\":\"{}\",\"piece_layer\":\"{}\"}}{}",
            bundle.covered_offset,
            bundle.data.len(),
            hex(&root(&data)),
            hex(&bundle.proof),
            hex(&pieces),
            if position + 1 == cases.len() { "" } else { "," }
        );
    }
    println!("  ]\n}}");
}
