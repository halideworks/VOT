//! Line-oriented oracle for the capability encoding and possession vectors.
//!
//! `tools/validate_capability_vectors.py` reimplements `spec/capability.cddl`
//! from the specification text and compares its answer to this one, so agreement
//! is evidence rather than a restatement of the same code.

use std::fmt::Write as _;
use std::io::{self, BufRead};

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use vot_capability::{Capability, Error, Scope, SignedCapability};

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let answer = match fields.as_slice() {
            ["possession", public_key, transcript, signature] => {
                verification_line(public_key, transcript, signature, "possession")
            }
            ["ed25519-sign", seed, transcript] => signing_line(seed, transcript),
            ["ed25519-verify", public_key, transcript, signature] => {
                verification_line(public_key, transcript, signature, "signature")
            }
            [kind @ ("signed" | "capability" | "scope"), hex] => {
                let Some(input) = decode_hex(hex) else {
                    println!("err|INVALID_HEX");
                    continue;
                };
                match *kind {
                    "signed" => signed_line(&input),
                    "capability" => capability_line(&input),
                    "scope" => scope_line(&input),
                    _ => unreachable!(),
                }
            }
            _ => "err|INVALID_REQUEST".to_owned(),
        };
        println!("{answer}");
    }
    Ok(())
}

fn signing_line(seed: &str, transcript: &str) -> String {
    let Some(seed) = decode_hex(seed).and_then(|value| value.try_into().ok()) else {
        return "err|INVALID_REQUEST".to_owned();
    };
    let Some(transcript) = decode_hex(transcript) else {
        return "err|INVALID_HEX".to_owned();
    };
    let key = SigningKey::from_bytes(&seed);
    let signature = key.sign(&transcript).to_bytes();
    format!(
        "ok|signature|{}|{}",
        encode_hex(&key.verifying_key().to_bytes()),
        encode_hex(&signature)
    )
}

fn verification_line(public_key: &str, transcript: &str, signature: &str, kind: &str) -> String {
    let Some(public_key) = decode_hex(public_key).and_then(|value| value.try_into().ok()) else {
        return "err|INVALID_REQUEST".to_owned();
    };
    let Some(transcript) = decode_hex(transcript) else {
        return "err|INVALID_HEX".to_owned();
    };
    let Some(signature) = decode_hex(signature).and_then(|value| value.try_into().ok()) else {
        return "err|INVALID_REQUEST".to_owned();
    };
    let Ok(public_key) = VerifyingKey::from_bytes(&public_key) else {
        return "err|INVALID_REQUEST".to_owned();
    };
    if public_key
        .verify_strict(&transcript, &Signature::from_bytes(&signature))
        .is_ok()
    {
        format!("ok|{kind}")
    } else {
        "err|SIGNATURE".to_owned()
    }
}

/// The envelope, without checking its signature: that needs a key the vectors do
/// not carry, and what a vector fixes is the encoding.
fn signed_line(input: &[u8]) -> String {
    match vot_capability::decode(input) {
        Ok(SignedCapability {
            key_id,
            capability,
            signature,
        }) => format!(
            "ok|signed|{}|{}|{}",
            encode_hex(&key_id),
            capability.len(),
            encode_hex(&signature[..4])
        ),
        Err(error) => format!("err|{}", name(&error)),
    }
}

fn capability_line(input: &[u8]) -> String {
    match Capability::from_canonical_bytes(input) {
        Ok(value) => {
            let mut answer = format!(
                "ok|capability|{}|{}|{}|{}|{}|{}|{}",
                value.issuer,
                value.audience,
                encode_hex(&value.holder_key[..4]),
                value
                    .operations
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join("+"),
                value.not_before,
                value.expiry,
                encode_hex(&value.token_id[..4])
            );
            let _ = write!(answer, "|{}", scope_fields(&value.scope));
            for limit in &value.limits {
                let _ = write!(answer, "|l{}={}", limit.id, limit.value);
            }
            answer
        }
        Err(error) => format!("err|{}", name(&error)),
    }
}

fn scope_line(input: &[u8]) -> String {
    match vot_capability::decode_scope(input) {
        Ok(scope) => format!("ok|scope|{}", scope_fields(&scope)),
        Err(error) => format!("err|{}", name(&error)),
    }
}

fn scope_fields(scope: &Scope) -> String {
    let ranges = scope
        .ranges
        .iter()
        .map(|range| format!("{}:{}", range.offset(), range.length()))
        .collect::<Vec<_>>()
        .join("+");
    format!(
        "{},{},{},{ranges}",
        scope.suite,
        encode_hex(&scope.root[..4]),
        scope
            .length
            .map_or_else(|| "null".to_owned(), |length| length.to_string())
    )
}

/// The name a vector states, so a refusal is compared by its rule and not by a
/// message.
fn name(error: &Error) -> &'static str {
    match error {
        Error::Encoding(vot_cbor::Error::Truncated) => "TRUNCATED",
        Error::Encoding(vot_cbor::Error::NonCanonical) => "NON_CANONICAL",
        Error::Encoding(vot_cbor::Error::Trailing) => "TRAILING",
        Error::Encoding(vot_cbor::Error::NotUtf8) => "NOT_UTF8",
        Error::Encoding(
            vot_cbor::Error::Malformed | vot_cbor::Error::WrongType | vot_cbor::Error::TooLarge,
        ) => "MALFORMED",
        Error::UnsupportedVersion(_) => "UNSUPPORTED_VERSION",
        Error::InvalidIdentity => "INVALID_IDENTITY",
        Error::InvalidKeyId => "INVALID_KEY_ID",
        Error::InvalidOperations => "INVALID_OPERATIONS",
        Error::InvalidLimits => "INVALID_LIMITS",
        Error::InvalidSuite(_) => "INVALID_SUITE",
        Error::InvalidRange => "INVALID_RANGE",
        Error::InvalidValidity => "INVALID_VALIDITY",
        Error::UnsupportedDelegation(_) => "UNSUPPORTED_DELEGATION",
        Error::InvalidLength => "INVALID_LENGTH",
        Error::Signature => "SIGNATURE",
        Error::TooLarge => "TOO_LARGE",
    }
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(input.get(index..index + 2)?, 16).ok())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}
