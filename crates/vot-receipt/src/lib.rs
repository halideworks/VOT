//! Canonical authenticated VOT assurance receipts.

#![allow(clippy::missing_errors_doc)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"VOT receipt v0\0";

mod authenticator;
mod chain;
mod codec;
mod model;
mod time;
mod witness;

pub use authenticator::*;
pub use chain::*;
pub use codec::*;
pub use model::*;
use time::valid_rfc3339;
pub use witness::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidKey,
    InvalidKeyId,
    InvalidTimestamp,
    InvalidFlags,
    InvalidClockSource,
    InvalidSuite,
    InvalidProvider,
    InvalidSubjectLength,
    InvalidSequence,
    Authentication,
    /// The envelope names a scheme other than the one the verifier requires.
    UnexpectedScheme,
    /// A witness signed a different head than the one presented.
    WitnessHeadMismatch,
    /// An entry does not link to its predecessor, or the first one links.
    ChainBroken,
    /// An entry in the chain is about a different subject.
    ChainSubjectMismatch,
    /// An entry was checked by something other than what checked the chain's
    /// first: another key, or another scheme. Two issuers signing in turn is
    /// not one issuer's record, and neither is a signature followed by a MAC
    /// the reader could have minted.
    ChainIssuerMismatch,
    /// An entry names a different provider, session, or incarnation. A chain
    /// is one incarnation's account of one object.
    ChainScopeMismatch,
    /// An entry claims no more assurance than the one before it. A chain is
    /// scoped to one incarnation, and the relation performs each level once
    /// within one, so a repeat is as wrong as a step backwards.
    AssuranceDidNotAdvance,
    /// A publication names a predecessor that is not the one its profile
    /// requires.
    PredecessorTooWeak,
    /// A publication names the right predecessor, but no entry before it in
    /// the chain observed that assurance. The field is the issuer's own word;
    /// the chain is what checks it.
    PredecessorNotObserved,
    /// A chain with no observations proves nothing.
    EmptyChain,
    InvalidEncoding,
    TooLarge,
    NonCanonical,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> Receipt {
        Receipt {
            subject_kind: SubjectKind::Object,
            suite_id: 1,
            subject_digest: [7; 32],
            subject_length: 4096,
            assurance: AssuranceLevel::Published,
            profile: CommitProfile::Strict,
            actual_predecessor: AssuranceLevel::AtRestVerified,
            provider: 1,
            provider_version: [0, 3, 0],
            session_id: [2; 16],
            incarnation_id: [3; 16],
            sequence: 5,
            observed_at: "2026-07-31T16:00:00Z".to_owned(),
            clock_source: 1,
            flags: 0,
            previous: None,
        }
    }

    /// Pulls one hex string out of the conformance vector without a JSON
    /// dependency. The file is flat and machine-generated, so a field lookup is
    /// enough, and `tools/validate_receipt_vectors.py` parses it properly.
    fn vector_field(name: &str) -> Vec<u8> {
        vector_field_after("{", name)
    }

    /// `authenticator_hex` and the key fields appear once per scheme, so a
    /// lookup says which scheme it means rather than relying on file order.
    fn vector_field_after(marker: &str, name: &str) -> Vec<u8> {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/receipt/signing-transcript.json"
        ))
        .expect("conformance vector is missing");
        let from = text
            .find(marker)
            .unwrap_or_else(|| panic!("no marker {marker}"));
        let text = &text[from..];
        let key = format!("\"{name}\": \"");
        let start = text.find(&key).unwrap_or_else(|| panic!("no field {name}")) + key.len();
        let value = &text[start..start + text[start..].find('"').expect("unterminated field")];
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for pair in value.as_bytes().chunks_exact(2) {
            let digit = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("{name} is not hexadecimal"),
            };
            bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
        }
        bytes
    }

    #[test]
    fn the_published_conformance_vector_is_what_this_produces() {
        let key_id = vector_field("key_id_hex");
        let canonical = vector_field("canonical_receipt_hex");
        let seed: [u8; 32] = vector_field("secret_key_seed_hex").try_into().unwrap();
        let signing = SigningKey::from_bytes(&seed);

        let receipt = Receipt {
            subject_kind: SubjectKind::Package,
            suite_id: 1,
            subject_digest: [0x11; 32],
            subject_length: 1_048_576,
            assurance: AssuranceLevel::Published,
            profile: CommitProfile::Fast,
            actual_predecessor: AssuranceLevel::AtRestVerified,
            provider: 1,
            provider_version: [0, 4, 0],
            session_id: [0x22; 16],
            incarnation_id: [0x33; 16],
            sequence: 7,
            observed_at: "2026-08-02T00:00:00Z".to_owned(),
            clock_source: 1,
            flags: 0,
            previous: None,
        };
        assert_eq!(
            receipt.canonical_bytes().unwrap(),
            canonical,
            "the canonical receipt encoding drifted from the published vector"
        );

        let signed = sign_ed25519(receipt.clone(), &key_id, &signing).unwrap();
        assert_eq!(
            signed.authentication,
            vector_field_after("\"name\": \"ED25519\"", "authenticator_hex"),
            "the Ed25519 authenticator drifted from the published vector"
        );
        assert_eq!(
            signing.verifying_key().to_bytes().to_vec(),
            vector_field("public_key_hex")
        );
        verify_ed25519(&signed, &signing.verifying_key()).unwrap();
        assert_eq!(
            encode_authenticated(&signed).unwrap(),
            vector_field("authenticated_envelope_ed25519_hex")
        );

        let mac_key = vector_field_after("\"name\": \"HMAC_SHA256\"", "secret_key_hex");
        let maced = authenticate_hmac_sha256(receipt, &key_id, &mac_key).unwrap();
        assert_eq!(
            maced.authentication,
            vector_field_after("\"name\": \"HMAC_SHA256\"", "authenticator_hex"),
            "the HMAC authenticator drifted from the published vector"
        );
        verify_hmac_sha256(&maced, &mac_key).unwrap();
    }

    #[test]
    fn the_authenticated_bytes_match_the_registry() {
        // Pinned as bytes: this crate defines the format, so rebuilding the
        // input the same way would agree with any encoding.
        let input = signing_input(AuthScheme::Ed25519, b"receiver-1", &receipt()).unwrap();
        let canonical = receipt().canonical_bytes().unwrap();

        assert_eq!(&input[..DOMAIN.len()], b"VOT receipt v0\0");
        let rest = &input[DOMAIN.len()..];
        assert_eq!(&rest[..2], &[0x00, 0x01], "ED25519 is scheme 0x0001");
        assert_eq!(rest[2], 10, "the key identifier is length prefixed");
        assert_eq!(&rest[3..13], b"receiver-1");
        assert_eq!(&rest[13..], canonical.as_slice());
        assert_eq!(input.len(), DOMAIN.len() + 3 + 10 + canonical.len());

        // The MAC scheme differs only in the two scheme bytes.
        let maced = signing_input(AuthScheme::HmacSha256, b"receiver-1", &receipt()).unwrap();
        assert_eq!(&maced[DOMAIN.len()..DOMAIN.len() + 2], &[0x00, 0x02]);
        assert_eq!(&maced[DOMAIN.len() + 2..], &input[DOMAIN.len() + 2..]);

        // A one-byte prefix covers the identifier bounds receipt.cddl sets.
        assert_eq!(
            signing_input(AuthScheme::Ed25519, &[b'k'; 64], &receipt()).unwrap()[DOMAIN.len() + 2],
            64
        );
        assert_eq!(
            signing_input(AuthScheme::Ed25519, &[b'k'; 65], &receipt()),
            Err(Error::InvalidKeyId)
        );
        assert_eq!(
            signing_input(AuthScheme::Ed25519, b"", &receipt()),
            Err(Error::InvalidKeyId)
        );
    }

    #[test]
    fn authentication_binds_every_receipt_field() {
        let key = [9; 32];
        let authenticated = authenticate_hmac_sha256(receipt(), b"receiver-1", &key).unwrap();
        verify_hmac_sha256(&authenticated, &key).unwrap();
        let mut changed = authenticated;
        changed.receipt.sequence += 1;
        assert_eq!(
            verify_hmac_sha256(&changed, &key).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn timestamps_require_rfc3339_syntax_and_ranges() {
        let mut receipt = receipt();
        for valid in [
            "2024-02-29T23:59:60Z",
            "2000-02-29T00:00:00Z",
            "2026-07-31T16:00:00.123456789-04:00",
            "2026-07-31T20:00:00+00:00",
            "2026-07-31t20:00:00z",
            "2026-07-31t20:00:00Z",
            "2026-07-31T20:00:00z",
        ] {
            receipt.observed_at = valid.to_owned();
            assert_eq!(receipt.validate(), Ok(()), "{valid}");
        }
        for invalid in [
            "xxxxxxxxxxxxxxxxxxxx",
            "2026-01-01T00:00:0Z",
            "2026-01-01T00:00:00.1234567890123456Z",
            "2026/07-31T16:00:00Z",
            "2026-07/31T16:00:00Z",
            "2026-07-31 16:00:00Z",
            "2026-07-31T16.00:00Z",
            "2026-07-31T16:00.00Z",
            "2026-00-31T16:00:00Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-07-00T00:00:00Z",
            "2026-07-31T24:00:00Z",
            "2026-07-31T16:60:00Z",
            "2026-07-31T16:00:61Z",
            "2026-07-31T16:00:00.Z",
            "2026-07-31T16:00:00+24:00",
            "2026-07-31T16:00:00+00:60",
        ] {
            receipt.observed_at = invalid.to_owned();
            assert_eq!(
                receipt.validate(),
                Err(Error::InvalidTimestamp),
                "{invalid}"
            );
        }
    }

    #[test]
    fn receipt_numeric_bounds_are_exact() {
        let mut receipt = receipt();
        receipt.subject_length = i64::MAX as u64;
        receipt.clock_source = 2;
        receipt.flags = 15;
        assert_eq!(receipt.validate(), Ok(()));

        receipt.subject_length = i64::MAX as u64 + 1;
        assert_eq!(receipt.validate(), Err(Error::InvalidSubjectLength));
        receipt.subject_length = 0;
        receipt.clock_source = 3;
        assert_eq!(receipt.validate(), Err(Error::InvalidClockSource));
        receipt.clock_source = 0;
        receipt.flags = 16;
        assert_eq!(receipt.validate(), Err(Error::InvalidFlags));
    }

    #[test]
    fn weak_keys_and_unidentified_keys_are_rejected() {
        assert_eq!(
            authenticate_hmac_sha256(receipt(), b"", &[1; 32]),
            Err(Error::InvalidKeyId)
        );
        assert_eq!(
            authenticate_hmac_sha256(receipt(), b"key", &[1; 16]),
            Err(Error::InvalidKey)
        );
    }

    #[test]
    fn authenticated_envelope_is_deterministic_cbor() {
        let authenticated = authenticate_hmac_sha256(receipt(), b"receiver-1", &[9; 32]).unwrap();
        let first = encode_authenticated(&authenticated).unwrap();
        let second = encode_authenticated(&authenticated).unwrap();
        assert_eq!(first, second);
        assert_eq!(decode_authenticated(&first).unwrap(), authenticated);
        assert_eq!(first[0], 0xa4);
        let canonical = authenticated.receipt.canonical_bytes().unwrap();
        assert_eq!(canonical[0], 0xae);
        let mut actual = String::new();
        for byte in canonical {
            use std::fmt::Write as _;
            write!(&mut actual, "{byte:02x}").unwrap();
        }
        assert_eq!(
            actual,
            "ae000001840001582007070707070707070707070707070707070707070707070707070707070707071910000205030304040501068300030007500202020202020202020202020202020208500303030303030303030303030303030309050a74323032362d30372d33315431363a30303a30305a0b010c010d00"
        );
    }

    #[test]
    fn authenticated_round_trip_covers_every_receipt_enum_value() {
        for subject_kind in [SubjectKind::Object, SubjectKind::Package] {
            for assurance in [
                AssuranceLevel::Admitted,
                AssuranceLevel::TransitVerified,
                AssuranceLevel::Durable,
                AssuranceLevel::AtRestVerified,
                AssuranceLevel::Published,
            ] {
                for profile in [
                    CommitProfile::Fast,
                    CommitProfile::Balanced,
                    CommitProfile::Strict,
                ] {
                    let mut value = receipt();
                    value.subject_kind = subject_kind;
                    value.assurance = assurance;
                    value.actual_predecessor = assurance;
                    value.profile = profile;
                    let authenticated =
                        authenticate_hmac_sha256(value, b"receiver-1", &[9; 32]).unwrap();
                    let encoded = encode_authenticated(&authenticated).unwrap();
                    assert_eq!(decode_authenticated(&encoded).unwrap(), authenticated);
                }
            }
        }
    }

    #[test]
    fn deterministic_cbor_integer_widths_and_decoder_edges_are_exact() {
        for value in [
            23,
            24,
            0xff,
            0x100,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
        ] {
            let mut receipt = receipt();
            receipt.subject_length = value;
            let authenticated = authenticate_hmac_sha256(receipt, b"receiver-1", &[9; 32]).unwrap();
            let encoded = encode_authenticated(&authenticated).unwrap();
            assert_eq!(decode_authenticated(&encoded).unwrap(), authenticated);
        }

        for (input, expected) in [
            (&[0x18, 0x17][..], Err(Error::NonCanonical)),
            (&[0x18, 0x18][..], Ok(24)),
            (&[0x19, 0x00, 0xff][..], Err(Error::NonCanonical)),
            (&[0x19, 0x01, 0x00][..], Ok(0x100)),
            (
                &[0x1a, 0x00, 0x00, 0xff, 0xff][..],
                Err(Error::NonCanonical),
            ),
            (&[0x1a, 0x00, 0x01, 0x00, 0x00][..], Ok(0x1_0000)),
            (
                &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff][..],
                Err(Error::NonCanonical),
            ),
            (
                &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00][..],
                Ok(0x1_0000_0000),
            ),
        ] {
            assert_eq!(Decoder::new(input).uint(), expected);
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    /// Builds a signed chain: each observation links to the previous envelope.
    fn chain(key: &SigningKey, levels: &[AssuranceLevel]) -> Vec<AuthenticatedReceipt> {
        let mut chain: Vec<AuthenticatedReceipt> = Vec::new();
        for (index, level) in levels.iter().enumerate() {
            let mut entry = receipt();
            entry.assurance = *level;
            entry.sequence = index as u64 + 1;
            entry.previous = chain.last().map(|last| last.digest().unwrap());
            chain.push(sign_ed25519(entry, b"issuer-1", key).unwrap());
        }
        chain
    }

    /// Verifies every entry, which is the only way to get a chain now.
    fn verified(chain: &[AuthenticatedReceipt], key: &SigningKey) -> Vec<VerifiedReceipt> {
        chain
            .iter()
            .map(|entry| verify_ed25519(entry, &key.verifying_key()).expect("a signature"))
            .collect()
    }

    #[test]
    fn a_chain_links_every_observation_to_its_predecessor() {
        let key = signing_key();
        let signed = chain(
            &key,
            &[
                AssuranceLevel::Admitted,
                AssuranceLevel::TransitVerified,
                AssuranceLevel::Durable,
                AssuranceLevel::AtRestVerified,
                AssuranceLevel::Published,
            ],
        );
        verify_chain(&verified(&signed, &key)).unwrap();
        assert!(signed[0].receipt.previous.is_none());
        assert_eq!(
            signed[4].receipt.previous,
            Some(signed[3].digest().unwrap())
        );
    }

    #[test]
    fn rewriting_one_observation_breaks_every_link_after_it() {
        let key = signing_key();
        let mut signed = chain(
            &key,
            &[
                AssuranceLevel::Admitted,
                AssuranceLevel::TransitVerified,
                AssuranceLevel::Durable,
            ],
        );
        let mut rewritten = signed[1].receipt.clone();
        rewritten.observed_at = "2031-01-01T00:00:00Z".to_owned();
        signed[1] = sign_ed25519(rewritten, b"issuer-1", &key).unwrap();
        // Re-signed and individually valid, but the chain no longer joins.
        verify_ed25519(&signed[1], &key.verifying_key()).unwrap();
        assert_eq!(
            verify_chain(&verified(&signed, &key)),
            Err(Error::ChainBroken)
        );
    }

    #[test]
    fn a_chain_belongs_to_one_issuer_and_one_incarnation() {
        let key = signing_key();
        let signed = chain(&key, &[AssuranceLevel::Admitted, AssuranceLevel::Durable]);

        // A second issuer's signature over the same link. Both entries verify
        // and the digests join, so only the scope check refuses it.
        let other = SigningKey::from_bytes(&[8; 32]);
        let elsewhere = sign_ed25519(signed[1].receipt.clone(), b"issuer-2", &other).unwrap();
        let mixed = vec![
            verify_ed25519(&signed[0], &key.verifying_key()).unwrap(),
            verify_ed25519(&elsewhere, &other.verifying_key()).unwrap(),
        ];
        assert_eq!(verify_chain(&mixed), Err(Error::ChainIssuerMismatch));

        // A provider, a provider version, a session, or an incarnation that
        // changes part way is a different account of the object.
        for divergent in [
            Receipt {
                provider: signed[1].receipt.provider + 1,
                ..signed[1].receipt.clone()
            },
            Receipt {
                provider_version: [9, 9, 9],
                ..signed[1].receipt.clone()
            },
            Receipt {
                session_id: [0xab; 16],
                ..signed[1].receipt.clone()
            },
            Receipt {
                incarnation_id: [0xcd; 16],
                ..signed[1].receipt.clone()
            },
        ] {
            let switched = sign_ed25519(divergent, b"issuer-1", &key).unwrap();
            assert_eq!(
                verify_chain(&verified(&[signed[0].clone(), switched], &key)),
                Err(Error::ChainScopeMismatch)
            );
        }
    }

    #[test]
    fn a_chain_cannot_lose_assurance_or_publish_without_its_predecessor() {
        let key = signing_key();
        // Strict, so the publication's predecessor is the at-rest read, and
        // the chain has to contain one.
        let signed = chain(
            &key,
            &[AssuranceLevel::AtRestVerified, AssuranceLevel::Published],
        );
        verify_chain(&verified(&signed, &key)).unwrap();

        // Going backwards. Every field but the assurance is the one the chain
        // already accepted.
        let mut weaker = signed[1].receipt.clone();
        weaker.assurance = AssuranceLevel::Admitted;
        let weaker = sign_ed25519(weaker, b"issuer-1", &key).unwrap();
        assert_eq!(
            verify_chain(&verified(&[signed[0].clone(), weaker], &key)),
            Err(Error::AssuranceDidNotAdvance)
        );

        // And standing still. Two observations at one level cannot both be
        // this incarnation performing it.
        let mut repeated = signed[1].receipt.clone();
        repeated.assurance = signed[0].receipt.assurance;
        let repeated = sign_ed25519(repeated, b"issuer-1", &key).unwrap();
        assert_eq!(
            verify_chain(&verified(&[signed[0].clone(), repeated], &key)),
            Err(Error::AssuranceDidNotAdvance)
        );

        // Publishing under a profile whose predecessor was never reached. The
        // required assurance per profile is the one `vot_commit_model` holds
        // the machine to, not a second copy of the table.
        for (profile, too_weak) in [
            (CommitProfile::Balanced, AssuranceLevel::TransitVerified),
            (CommitProfile::Strict, AssuranceLevel::Durable),
            (CommitProfile::Fast, AssuranceLevel::Admitted),
            // Not merely weaker: the machine gates on membership, so a
            // publication naming itself is as wrong as one naming too little.
            (CommitProfile::Fast, AssuranceLevel::Published),
        ] {
            let mut published = signed[1].receipt.clone();
            published.profile = profile;
            published.actual_predecessor = too_weak;
            let published = sign_ed25519(published, b"issuer-1", &key).unwrap();
            let mut genesis = signed[0].receipt.clone();
            genesis.profile = profile;
            let genesis = sign_ed25519(genesis, b"issuer-1", &key).unwrap();
            let mut linked = published.receipt.clone();
            linked.previous = Some(genesis.digest().unwrap());
            let linked = sign_ed25519(linked, b"issuer-1", &key).unwrap();
            assert_eq!(
                verify_chain(&verified(&[genesis, linked], &key)),
                Err(Error::PredecessorTooWeak),
                "{profile:?} published on {too_weak:?}"
            );
        }
    }

    #[test]
    fn a_chain_rejects_every_structural_break() {
        let key = signing_key();
        assert_eq!(verify_chain(&[]), Err(Error::EmptyChain));

        // A first entry that claims a predecessor.
        let mut genesis = receipt();
        genesis.previous = Some([9; 32]);
        let orphan = sign_ed25519(genesis, b"issuer-1", &key).unwrap();
        assert_eq!(
            verify_chain(&verified(&[orphan], &key)),
            Err(Error::ChainBroken)
        );

        let signed = chain(&key, &[AssuranceLevel::Admitted, AssuranceLevel::Durable]);
        verify_chain(&verified(&signed, &key)).unwrap();

        // An entry about a different subject. Identity is the suite, the root
        // and the length, so each of them has to break the chain.
        for divergent in [
            Receipt {
                subject_digest: [0xfe; 32],
                ..signed[1].receipt.clone()
            },
            Receipt {
                subject_length: signed[1].receipt.subject_length + 1,
                ..signed[1].receipt.clone()
            },
            Receipt {
                // Same digest bytes under another suite is another object.
                suite_id: 2,
                ..signed[1].receipt.clone()
            },
            Receipt {
                subject_kind: SubjectKind::Package,
                ..signed[1].receipt.clone()
            },
        ] {
            let foreign = sign_ed25519(divergent, b"issuer-1", &key).unwrap();
            assert_eq!(
                verify_chain(&verified(&[signed[0].clone(), foreign], &key)),
                Err(Error::ChainSubjectMismatch)
            );
        }

        // A sequence that does not advance.
        let mut stalled = signed[1].receipt.clone();
        stalled.sequence = signed[0].receipt.sequence;
        let stalled = sign_ed25519(stalled, b"issuer-1", &key).unwrap();
        assert_eq!(
            verify_chain(&verified(&[signed[0].clone(), stalled], &key)),
            Err(Error::InvalidSequence)
        );
    }

    #[test]
    fn witness_bytes_are_pinned_and_cover_every_field() {
        // Signing and verifying with the same function proves nothing about
        // what is signed, so the encoding is pinned directly.
        let statement = WitnessStatement {
            head: [0xab; 32],
            observed_at: "2026-08-02T04:00:00Z".to_owned(),
            key_id: b"witness-a".to_vec(),
        };
        let bytes = statement.canonical_bytes().unwrap();
        assert_eq!(
            hex(&bytes),
            "564f54207769746e65737320763000a3005820abababababababababababababababababababababababababababababababab0174323032362d30382d30325430343a30303a30305a02497769746e6573732d61"
        );

        for changed in [
            WitnessStatement {
                head: [0xac; 32],
                ..statement.clone()
            },
            WitnessStatement {
                observed_at: "2026-08-02T04:00:01Z".to_owned(),
                ..statement.clone()
            },
            WitnessStatement {
                key_id: b"witness-b".to_vec(),
                ..statement.clone()
            },
        ] {
            assert_ne!(changed.canonical_bytes().unwrap(), bytes);
        }
    }

    #[test]
    fn a_witness_anchors_the_head_at_its_own_time() {
        let issuer = signing_key();
        let witness = SigningKey::from_bytes(&[11; 32]);
        let signed = chain(
            &issuer,
            &[AssuranceLevel::Admitted, AssuranceLevel::Durable],
        );
        let head = signed.last().unwrap().digest().unwrap();

        let statement = WitnessStatement {
            head,
            observed_at: "2026-08-02T04:00:00Z".to_owned(),
            key_id: b"witness-a".to_vec(),
        };
        let attested = witness_ed25519(statement, &witness).unwrap();
        verify_witness(&attested, &head, &witness.verifying_key()).unwrap();

        // A witness signature does not carry over to another head.
        let other = signed[0].digest().unwrap();
        assert_eq!(
            verify_witness(&attested, &other, &witness.verifying_key()),
            Err(Error::WitnessHeadMismatch)
        );

        // Nor to another witness key.
        let impostor = SigningKey::from_bytes(&[12; 32]);
        assert_eq!(
            verify_witness(&attested, &head, &impostor.verifying_key()),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn a_witness_statement_is_rejected_when_malformed_or_symmetric() {
        let witness = SigningKey::from_bytes(&[11; 32]);
        let head = [3; 32];
        let good = WitnessStatement {
            head,
            observed_at: "2026-08-02T04:00:00Z".to_owned(),
            key_id: b"witness-a".to_vec(),
        };
        assert!(good.canonical_bytes().is_ok());

        for broken in [
            WitnessStatement {
                key_id: Vec::new(),
                ..good.clone()
            },
            WitnessStatement {
                key_id: vec![1; 65],
                ..good.clone()
            },
            WitnessStatement {
                observed_at: "not a time".to_owned(),
                ..good.clone()
            },
        ] {
            assert!(broken.validate().is_err());
        }

        // A symmetric witness would be checkable only by someone able to forge
        // it, which defeats the point of a witness.
        let mut symmetric = witness_ed25519(good, &witness).unwrap();
        symmetric.scheme = AuthScheme::HmacSha256;
        assert_eq!(
            verify_witness(&symmetric, &head, &witness.verifying_key()),
            Err(Error::UnexpectedScheme)
        );
    }

    #[test]
    fn the_chain_link_survives_the_envelope_round_trip() {
        let key = signing_key();
        let signed = chain(&key, &[AssuranceLevel::Admitted, AssuranceLevel::Durable]);
        for entry in &signed {
            let decoded = decode_authenticated(&encode_authenticated(entry).unwrap()).unwrap();
            assert_eq!(&decoded, entry);
        }
        // The linked form encodes one more map entry than the genesis form.
        let genesis = encode_authenticated(&signed[0]).unwrap();
        let linked = encode_authenticated(&signed[1]).unwrap();
        assert!(linked.len() > genesis.len());
        verify_chain(&verified(
            &[
                decode_authenticated(&genesis).unwrap(),
                decode_authenticated(&linked).unwrap(),
            ],
            &key,
        ))
        .unwrap();
    }

    #[test]
    fn an_ed25519_receipt_verifies_with_only_the_public_key() {
        let key = signing_key();
        let signed = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();
        assert_eq!(signed.scheme, AuthScheme::Ed25519);
        assert_eq!(signed.authentication.len(), 64);
        assert!(signed.scheme.is_third_party_verifiable());
        verify_ed25519(&signed, &key.verifying_key()).unwrap();

        let other = SigningKey::from_bytes(&[8; 32]);
        assert_eq!(
            verify_ed25519(&signed, &other.verifying_key()).unwrap_err(),
            Error::Authentication
        );

        // Relabelling the key identifier breaks the signature, so a receipt
        // cannot be moved between contexts.
        let mut relabelled = signed.clone();
        relabelled.key_id = b"issuer-2".to_vec();
        assert_eq!(
            verify_ed25519(&relabelled, &key.verifying_key()).unwrap_err(),
            Error::Authentication
        );

        // An identifier outside the registry bound is refused before any
        // signature check, on the way in and on the way out.
        let mut unbounded = signed.clone();
        unbounded.key_id = Vec::new();
        assert_eq!(
            verify_ed25519(&unbounded, &key.verifying_key()).unwrap_err(),
            Error::InvalidKeyId
        );
        unbounded.key_id = vec![b'k'; 65];
        assert_eq!(
            verify_ed25519(&unbounded, &key.verifying_key()).unwrap_err(),
            Error::InvalidKeyId
        );
    }

    #[test]
    fn a_changed_receipt_or_signature_fails() {
        let key = signing_key();
        let signed = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();

        let mut altered = signed.clone();
        altered.receipt.sequence += 1;
        assert_eq!(
            verify_ed25519(&altered, &key.verifying_key()).unwrap_err(),
            Error::Authentication
        );

        let mut flipped = signed.clone();
        flipped.authentication[0] ^= 1;
        assert_eq!(
            verify_ed25519(&flipped, &key.verifying_key()).unwrap_err(),
            Error::Authentication
        );

        let mut truncated = signed;
        truncated.authentication.pop();
        assert_eq!(
            verify_ed25519(&truncated, &key.verifying_key()).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn an_authenticator_cannot_be_replayed_under_another_scheme() {
        let key = signing_key();
        let signed = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();
        let maced = authenticate_hmac_sha256(receipt(), b"issuer-1", &[9; 32]).unwrap();

        // A verifier that requires one scheme refuses the other outright,
        // rather than reporting a signature failure it might retry.
        assert_eq!(
            verify_hmac_sha256(&signed, &[9; 32]).unwrap_err(),
            Error::UnexpectedScheme
        );
        assert_eq!(
            verify_ed25519(&maced, &key.verifying_key()).unwrap_err(),
            Error::UnexpectedScheme
        );

        // The scheme is inside the signed bytes, so the two cover different
        // input even for an identical receipt.
        assert_ne!(
            signing_input(AuthScheme::Ed25519, b"issuer-1", &receipt()).unwrap(),
            signing_input(AuthScheme::HmacSha256, b"issuer-1", &receipt()).unwrap()
        );
        // So is the key identifier, so a receipt cannot be relabelled as
        // belonging to another context without breaking its authenticator.
        assert_ne!(
            signing_input(AuthScheme::Ed25519, b"issuer-1", &receipt()).unwrap(),
            signing_input(AuthScheme::Ed25519, b"issuer-2", &receipt()).unwrap()
        );
        // Length prefixed, so a longer identifier cannot absorb the byte that
        // follows it and leave the same input.
        assert_ne!(
            signing_input(AuthScheme::Ed25519, b"ab", &receipt()).unwrap(),
            signing_input(AuthScheme::Ed25519, b"a", &receipt()).unwrap()
        );
        assert!(!AuthScheme::HmacSha256.is_third_party_verifiable());
    }

    #[test]
    fn the_envelope_round_trips_both_schemes() {
        let key = signing_key();
        for authenticated in [
            sign_ed25519(receipt(), b"issuer-1", &key).unwrap(),
            authenticate_hmac_sha256(receipt(), b"issuer-1", &[9; 32]).unwrap(),
        ] {
            let encoded = encode_authenticated(&authenticated).unwrap();
            let decoded = decode_authenticated(&encoded).unwrap();
            assert_eq!(decoded, authenticated);
            assert_eq!(
                decoded.authentication.len(),
                decoded.scheme.authenticator_len()
            );
        }
    }

    #[test]
    fn the_envelope_rejects_a_scheme_length_mismatch() {
        let mut wrong = authenticate_hmac_sha256(receipt(), b"issuer-1", &[9; 32]).unwrap();
        wrong.scheme = AuthScheme::Ed25519;
        assert_eq!(encode_authenticated(&wrong), Err(Error::Authentication));

        let key = signing_key();
        let mut short = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();
        short.authentication.truncate(32);
        assert_eq!(encode_authenticated(&short), Err(Error::Authentication));
    }

    #[test]
    fn an_unregistered_scheme_is_refused_on_decode() {
        assert_eq!(AuthScheme::from_registry(1), Some(AuthScheme::Ed25519));
        assert_eq!(AuthScheme::from_registry(2), Some(AuthScheme::HmacSha256));
        for unknown in [0, 3, 255] {
            assert_eq!(AuthScheme::from_registry(unknown), None);
        }
        let key = signing_key();
        let encoded = encode_authenticated(&sign_ed25519(receipt(), b"i", &key).unwrap()).unwrap();
        // Byte-patch the scheme field to an unregistered value.
        let position = encoded
            .windows(2)
            .position(|pair| pair == [0x01, 0x01])
            .unwrap();
        let mut tampered = encoded;
        tampered[position + 1] = 0x03;
        assert_eq!(decode_authenticated(&tampered), Err(Error::InvalidEncoding));
    }

    #[test]
    fn the_envelope_digest_is_what_a_chain_or_witness_commits_to() {
        let key = signing_key();
        let signed = sign_ed25519(receipt(), b"issuer-1", &key).unwrap();
        let digest = signed.digest().unwrap();
        assert_eq!(digest, signed.digest().unwrap());

        let mut later = signed.clone();
        later.receipt.sequence += 1;
        let later = sign_ed25519(later.receipt, b"issuer-1", &key).unwrap();
        assert_ne!(later.digest().unwrap(), digest);

        // It covers the envelope, so the key identifier is inside it too.
        let other_id = sign_ed25519(receipt(), b"issuer-2", &key).unwrap();
        assert_ne!(other_id.digest().unwrap(), digest);
    }

    #[test]
    fn authenticator_lengths_match_the_registry() {
        assert_eq!(AuthScheme::Ed25519.authenticator_len(), 64);
        assert_eq!(AuthScheme::HmacSha256.authenticator_len(), 32);
    }

    #[test]
    fn authentication_and_envelope_bounds_are_exact() {
        let mut key_id_64 = AuthenticatedReceipt {
            receipt: receipt(),
            scheme: AuthScheme::HmacSha256,
            key_id: vec![1; 64],
            authentication: vec![2; 32],
        };
        assert!(encode_authenticated(&key_id_64).is_ok());
        key_id_64.key_id.push(1);
        assert_eq!(encode_authenticated(&key_id_64), Err(Error::InvalidKeyId));
        key_id_64.key_id.clear();
        assert_eq!(encode_authenticated(&key_id_64), Err(Error::InvalidKeyId));

        assert!(authenticate_hmac_sha256(receipt(), &[1; 64], &[9; 32]).is_ok());
        assert_eq!(
            authenticate_hmac_sha256(receipt(), &[1; 65], &[9; 32]),
            Err(Error::InvalidKeyId)
        );
        let authenticated = authenticate_hmac_sha256(receipt(), b"receiver-1", &[9; 32]).unwrap();
        assert_eq!(
            verify_hmac_sha256(&authenticated, &[9; 31]).unwrap_err(),
            Error::InvalidKey
        );

        assert_eq!(
            decode_authenticated(&vec![0; 65_536]),
            Err(Error::InvalidEncoding)
        );
        let mut max_timestamp = receipt();
        max_timestamp.observed_at = "2026-07-31T16:00:00.123456789+23:59".to_owned();
        assert_eq!(max_timestamp.observed_at.len(), 35);
        let authenticated =
            authenticate_hmac_sha256(max_timestamp, b"receiver-1", &[9; 32]).unwrap();
        let encoded = encode_authenticated(&authenticated).unwrap();
        assert_eq!(decode_authenticated(&encoded).unwrap(), authenticated);
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(decode_authenticated(&trailing), Err(Error::InvalidEncoding));
    }

    #[test]
    fn authenticated_decoder_rejects_truncation_noncanonical_and_bounds() {
        let authenticated = authenticate_hmac_sha256(receipt(), b"receiver-1", &[9; 32]).unwrap();
        let encoded = encode_authenticated(&authenticated).unwrap();
        for length in 0..encoded.len() {
            assert!(decode_authenticated(&encoded[..length]).is_err());
        }
        let mut noncanonical = vec![0xb8, 0x04];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert_eq!(
            decode_authenticated(&noncanonical),
            Err(Error::NonCanonical)
        );
        assert_eq!(decode_authenticated(&vec![0; 65_537]), Err(Error::TooLarge));
        let mut changed = encoded;
        *changed.last_mut().unwrap() ^= 1;
        let decoded = decode_authenticated(&changed).unwrap();
        assert_eq!(
            verify_hmac_sha256(&decoded, &[9; 32]).unwrap_err(),
            Error::Authentication
        );
    }
}
