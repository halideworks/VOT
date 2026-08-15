//! Writes the canonical conformance vectors for `ed25519-cbor-tls-exporter-v1`.
//!
//! Run with `cargo run -p vot-capability --bin vot-capability-vectors`. The
//! refusal cases in the vector file are hand-written bytes rather than output
//! from here: a refusal this crate cannot produce is exactly the case worth
//! fixing in the file.

use std::fmt::Write as _;

use ed25519_dalek::SigningKey;
use vot_capability::{Capability, Limit, NO_FURTHER_DELEGATION, Range, Scope};

fn main() {
    let holder = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
    let issuer = SigningKey::from_bytes(&[3; 32]);

    let full = Capability {
        issuer: "issuer.example".to_owned(),
        audience: "receiver.example".to_owned(),
        holder_key: holder,
        operations: vec![1, 3],
        scope: Scope {
            suite: 1,
            root: [7; 32],
            length: Some(1 << 20),
            ranges: vec![
                Range::new(0, 65_536).unwrap(),
                Range::new(131_072, 65_536).unwrap(),
            ],
        },
        limits: vec![
            Limit { id: 1, value: 4 },
            Limit {
                id: 2,
                value: 1 << 30,
            },
        ],
        not_before: 1_700_000_000,
        expiry: 1_700_003_600,
        token_id: [0xc1; 16],
        delegation: NO_FURTHER_DELEGATION,
    };

    let minimal = Capability {
        issuer: "i".to_owned(),
        audience: "a".to_owned(),
        holder_key: holder,
        operations: vec![2],
        scope: Scope {
            suite: 2,
            root: [0; 32],
            length: None,
            ranges: Vec::new(),
        },
        limits: Vec::new(),
        not_before: 0,
        expiry: 1,
        token_id: [0; 16],
        delegation: NO_FURTHER_DELEGATION,
    };

    // A non-ASCII identity with a non-breaking space in it. The rule is "no
    // control characters", and an implementation reaching for a printability test
    // instead refuses this one.
    let unicode = Capability {
        issuer: "issüer.example".to_owned(),
        audience: "receiver\u{a0}example".to_owned(),
        ..minimal.clone()
    };

    for (name, capability) in [
        ("full", &full),
        ("minimal", &minimal),
        ("unicode", &unicode),
    ] {
        let bytes = capability.canonical_bytes().unwrap();
        println!("{name} capability {}", hex(&bytes));
        let signed = vot_capability::sign(capability, b"issuer-1", &issuer).unwrap();
        println!(
            "{name} signed {}",
            hex(&vot_capability::encode(&signed).unwrap())
        );
        println!(
            "{name} scope {}",
            hex(&vot_capability::encode_scope(&capability.scope).unwrap())
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}
