#![allow(clippy::cast_possible_truncation, clippy::format_collect)]

use vot_proof_blake3::{canonical_outboard, prove, root};

fn pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (i.wrapping_mul(31) % 251) as u8)
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
        "{{\n  \"suite\": \"blake3-bao64\",\n  \"pattern\": \"byte[i]=(i*31)%251\",\n  \"cases\": ["
    );
    for (position, (length, offset, request_length)) in cases.into_iter().enumerate() {
        let data = pattern(length);
        let bundle = prove(&data, offset, request_length).unwrap();
        println!(
            "    {{\"object_length\":{length},\"request_offset\":{offset},\"request_length\":{request_length},\"covered_offset\":{},\"covered_length\":{},\"root\":\"{}\",\"proof\":\"{}\",\"outboard\":\"{}\"}}{}",
            bundle.covered_offset,
            bundle.data.len(),
            hex(&root(&data)),
            hex(&bundle.proof),
            hex(&canonical_outboard(&data)),
            if position + 1 == cases.len() { "" } else { "," }
        );
    }
    println!("  ]\n}}");
}
