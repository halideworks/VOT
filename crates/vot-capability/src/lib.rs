//! `ed25519-cbor-tls-exporter-v1` capability format
//! (`spec/registries.md` section 11).
//!
//! Reads, writes, and checks signatures over capabilities. Signature covers the
//! canonical bytes exactly as signed (not a re-encoding). Times are epoch seconds.

#![forbid(unsafe_code)]

pub mod verify;

/// What a capability can authorize, re-exported so a caller need not depend
/// on `vot-codec` to name one.
pub use vot_codec::Operation;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// The format identifier `spec/registries.md` section 11 gives this format.
pub const FORMAT_ID: u16 = 0x0002;

/// What the signature covers, before the key identifier and the capability.
///
/// Distinct from the receipt and witness domains in `vot-receipt`, so a signature
/// over one statement is not valid input for another.
const DOMAIN: &[u8] = b"VOT capability v0\0";

/// The one delegation constraint this format defines. Any other value is refused.
pub const NO_FURTHER_DELEGATION: u64 = 0;

/// Bounds every field the format fixes. `spec/capability.cddl` is normative and
/// these are the same numbers.
pub mod bounds {
    /// A key identifier names a key rather than being one.
    pub const KEY_ID: (usize, usize) = (1, 64);
    /// Issuer and audience are deployment identities.
    pub const IDENTITY: (usize, usize) = (1, 128);
    /// Operations a capability may allow, from `spec/registries.md` section 12.
    pub const OPERATIONS: (usize, usize) = (1, 16);
    /// Resource limits, from `spec/registries.md` section 13.
    pub const LIMITS: usize = 16;
    /// Byte ranges a scope may name. Empty means the whole object.
    pub const RANGES: usize = 64;
    /// A signed capability, which `spec/session.cddl` bounds again at 48 KiB when
    /// it travels in `SESSION_OPEN`.
    pub const SIGNED: usize = 49_152;
    /// A scope, which `spec/session.cddl` bounds again at 4 KiB when it travels
    /// as a requested or granted scope.
    pub const SCOPE: usize = 4_096;
}

mod codec;
mod model;
mod signing;

pub use codec::*;
pub use model::*;
pub use signing::*;

/// Why a capability could not be read, written, or checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Not deterministic CBOR at all.
    Encoding(vot_cbor::Error),
    /// A version this format does not define.
    UnsupportedVersion(u64),
    /// An identity that is empty, too long, or carries a control character.
    InvalidIdentity,
    /// A key identifier outside its length bounds.
    InvalidKeyId,
    /// An operation set that is empty, unordered, repeats, or names the reserved
    /// zero.
    InvalidOperations,
    /// A resource limit map that is unordered, repeats, or names the reserved
    /// zero.
    InvalidLimits,
    /// A verification suite this revision does not define.
    InvalidSuite(u64),
    /// A range that is empty, out of order, overlapping, or past the object.
    InvalidRange,
    /// An expiry that does not follow its not-before.
    InvalidValidity,
    /// A delegation constraint other than [`NO_FURTHER_DELEGATION`].
    UnsupportedDelegation(u64),
    /// A nonce or proof outside the size `spec/session.cddl` fixes for it.
    InvalidLength,
    /// The signature does not verify under the key it names.
    Signature,
    /// A structure too large to encode within the bounds the format fixes.
    TooLarge,
}

impl From<vot_cbor::Error> for Error {
    fn from(error: vot_cbor::Error) -> Self {
        Self::Encoding(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn holder_key() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    fn capability() -> Capability {
        Capability {
            issuer: "issuer.example".to_owned(),
            audience: "receiver.example".to_owned(),
            holder_key: holder_key().verifying_key().to_bytes(),
            operations: vec![1, 3],
            scope: Scope {
                suite: 1,
                root: [7; 32],
                length: Some(1 << 20),
                ranges: vec![
                    Range {
                        offset: 0,
                        length: 65_536,
                    },
                    Range {
                        offset: 131_072,
                        length: 65_536,
                    },
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
        }
    }

    #[test]
    fn a_capability_round_trips_through_its_canonical_bytes() {
        let value = capability();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(Capability::from_canonical_bytes(&bytes), Ok(value.clone()));

        let signed = sign(&value, b"issuer-1", &issuer_key()).unwrap();
        assert_eq!(
            signed.capability, bytes,
            "the signature covers what it sends"
        );
        let encoded = encode(&signed).unwrap();
        assert_eq!(decode(&encoded), Ok(signed.clone()));
        assert_eq!(
            verify_signature(&signed, &issuer_key().verifying_key()),
            Ok(())
        );
    }

    #[test]
    fn the_signature_is_over_the_bytes_that_arrived() {
        let signed = sign(&capability(), b"issuer-1", &issuer_key()).unwrap();
        let decoded = decode(&encode(&signed).unwrap()).unwrap();
        assert_eq!(decoded.capability, signed.capability);
        assert_eq!(
            verify_signature(&decoded, &issuer_key().verifying_key()),
            Ok(())
        );
    }

    #[test]
    fn a_signature_is_bound_to_its_key_identifier_and_its_format() {
        let signed = sign(&capability(), b"issuer-1", &issuer_key()).unwrap();

        let mut relabelled = signed.clone();
        relabelled.key_id = b"issuer-2".to_vec();
        assert_eq!(
            verify_signature(&relabelled, &issuer_key().verifying_key()),
            Err(Error::Signature)
        );

        let mut other_format = signing_input(b"issuer-1", &signed.capability).unwrap();
        let position = DOMAIN.len();
        other_format[position..position + 2].copy_from_slice(&1u16.to_be_bytes());
        assert!(
            issuer_key()
                .verifying_key()
                .verify_strict(&other_format, &Signature::from_bytes(&signed.signature))
                .is_err()
        );

        let other = SigningKey::from_bytes(&[9; 32]);
        assert_eq!(
            verify_signature(&signed, &other.verifying_key()),
            Err(Error::Signature)
        );
    }

    #[test]
    fn one_altered_byte_of_the_capability_fails_the_signature() {
        let signed = sign(&capability(), b"issuer-1", &issuer_key()).unwrap();
        for index in 0..signed.capability.len() {
            let mut altered = signed.clone();
            altered.capability[index] ^= 1;
            assert_eq!(
                verify_signature(&altered, &issuer_key().verifying_key()),
                Err(Error::Signature),
                "byte {index}"
            );
        }
        for index in 0..signed.signature.len() {
            let mut altered = signed.clone();
            altered.signature[index] ^= 1;
            assert_eq!(
                verify_signature(&altered, &issuer_key().verifying_key()),
                Err(Error::Signature),
                "signature byte {index}"
            );
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one row per rule reads as a table")]
    fn every_rule_the_format_fixes_is_refused_on_its_own() {
        let cases: Vec<(&str, Capability, Error)> = vec![
            (
                "an empty issuer",
                Capability {
                    issuer: String::new(),
                    ..capability()
                },
                Error::InvalidIdentity,
            ),
            (
                "a control character in an audience",
                Capability {
                    audience: "receiver\n.example".to_owned(),
                    ..capability()
                },
                Error::InvalidIdentity,
            ),
            (
                "an identity one byte past its bound",
                Capability {
                    issuer: "i".repeat(bounds::IDENTITY.1 + 1),
                    ..capability()
                },
                Error::InvalidIdentity,
            ),
            (
                "no operations at all",
                Capability {
                    operations: Vec::new(),
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "the reserved operation zero",
                Capability {
                    operations: vec![0, 1],
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "operations out of order",
                Capability {
                    operations: vec![3, 1],
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "a repeated operation",
                Capability {
                    operations: vec![1, 1],
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "an operation past the registry's width",
                Capability {
                    operations: vec![0x1_0000],
                    ..capability()
                },
                Error::InvalidOperations,
            ),
            (
                "the reserved limit zero",
                Capability {
                    limits: vec![Limit { id: 0, value: 1 }],
                    ..capability()
                },
                Error::InvalidLimits,
            ),
            (
                "limits out of order",
                Capability {
                    limits: vec![Limit { id: 2, value: 1 }, Limit { id: 1, value: 1 }],
                    ..capability()
                },
                Error::InvalidLimits,
            ),
            (
                "a repeated limit",
                Capability {
                    limits: vec![Limit { id: 1, value: 1 }, Limit { id: 1, value: 2 }],
                    ..capability()
                },
                Error::InvalidLimits,
            ),
            (
                "an unknown suite",
                Capability {
                    scope: Scope {
                        suite: 3,
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidSuite(3),
            ),
            (
                "an empty range",
                Capability {
                    scope: Scope {
                        ranges: vec![Range {
                            offset: 0,
                            length: 0,
                        }],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "ranges out of order",
                Capability {
                    scope: Scope {
                        ranges: vec![
                            Range {
                                offset: 128,
                                length: 8,
                            },
                            Range {
                                offset: 0,
                                length: 8,
                            },
                        ],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "overlapping ranges",
                Capability {
                    scope: Scope {
                        ranges: vec![
                            Range {
                                offset: 0,
                                length: 16,
                            },
                            Range {
                                offset: 8,
                                length: 16,
                            },
                        ],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "a range past a known length",
                Capability {
                    scope: Scope {
                        length: Some(64),
                        ranges: vec![Range {
                            offset: 0,
                            length: 65,
                        }],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "a range that overflows",
                Capability {
                    scope: Scope {
                        length: None,
                        ranges: vec![Range {
                            offset: u64::MAX,
                            length: 2,
                        }],
                        ..capability().scope
                    },
                    ..capability()
                },
                Error::InvalidRange,
            ),
            (
                "an expiry at its not-before",
                Capability {
                    expiry: capability().not_before,
                    ..capability()
                },
                Error::InvalidValidity,
            ),
            (
                "an expiry before its not-before",
                Capability {
                    expiry: capability().not_before - 1,
                    ..capability()
                },
                Error::InvalidValidity,
            ),
            (
                "a delegation this format does not define",
                Capability {
                    delegation: 1,
                    ..capability()
                },
                Error::UnsupportedDelegation(1),
            ),
        ];
        for (name, value, expected) in cases {
            assert_eq!(value.validate(), Err(expected), "{name}");
            assert_eq!(value.canonical_bytes(), Err(expected), "{name} encoded");
        }
    }

    #[test]
    fn a_bound_admits_its_own_maximum() {
        let mut value = capability();
        value.issuer = "i".repeat(bounds::IDENTITY.1);
        value.audience = "a".repeat(bounds::IDENTITY.1);
        value.operations = (1..=bounds::OPERATIONS.1 as u64).collect();
        value.limits = (1..=u16::try_from(bounds::LIMITS).unwrap())
            .map(|id| Limit {
                id,
                value: u64::MAX,
            })
            .collect();
        value.scope.length = None;
        value.scope.ranges = (0..bounds::RANGES as u64)
            .map(|index| Range {
                offset: index * 2,
                length: 1,
            })
            .collect();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(Capability::from_canonical_bytes(&bytes), Ok(value.clone()));

        let signed = sign(&value, &[0xab; 64], &issuer_key()).unwrap();
        assert_eq!(decode(&encode(&signed).unwrap()), Ok(signed));

        let mut wide = capability();
        wide.operations = (1..=bounds::OPERATIONS.1 as u64 + 1).collect();
        assert_eq!(wide.validate(), Err(Error::InvalidOperations));
        let mut many = capability();
        many.limits = (1..=u16::try_from(bounds::LIMITS).unwrap() + 1)
            .map(|id| Limit { id, value: 1 })
            .collect();
        assert_eq!(many.validate(), Err(Error::TooLarge));
        let mut ranged = capability();
        ranged.scope.length = None;
        ranged.scope.ranges = (0..=bounds::RANGES as u64)
            .map(|index| Range {
                offset: index * 2,
                length: 1,
            })
            .collect();
        assert_eq!(ranged.validate(), Err(Error::TooLarge));
    }

    #[test]
    fn a_key_identifier_outside_its_bounds_never_reaches_a_signature() {
        for key_id in [vec![], vec![0; bounds::KEY_ID.1 + 1]] {
            assert_eq!(
                signing_input(&key_id, b"bytes"),
                Err(Error::InvalidKeyId),
                "{} bytes",
                key_id.len()
            );
            assert_eq!(
                sign(&capability(), &key_id, &issuer_key()),
                Err(Error::InvalidKeyId)
            );
            let signed = SignedCapability {
                key_id,
                capability: capability().canonical_bytes().unwrap(),
                signature: [0; 64],
            };
            assert_eq!(encode(&signed), Err(Error::InvalidKeyId));
            assert_eq!(
                verify_signature(&signed, &issuer_key().verifying_key()),
                Err(Error::InvalidKeyId)
            );
        }
    }

    #[test]
    fn an_envelope_that_is_not_one_canonical_item_is_refused() {
        let signed = sign(&capability(), b"issuer-1", &issuer_key()).unwrap();
        let encoded = encode(&signed).unwrap();

        for length in 0..encoded.len() {
            assert!(decode(&encoded[..length]).is_err(), "truncated at {length}");
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode(&trailing),
            Err(Error::Encoding(vot_cbor::Error::Trailing))
        );

        let mut noncanonical = vec![0xb8, 0x04];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert_eq!(
            decode(&noncanonical),
            Err(Error::Encoding(vot_cbor::Error::NonCanonical))
        );

        let mut future = SignedCapability { ..signed };
        future.capability = {
            let mut bytes = capability().canonical_bytes().unwrap();
            bytes[2] = 1;
            bytes
        };
        assert_eq!(
            Capability::from_canonical_bytes(&future.capability),
            Err(Error::UnsupportedVersion(1))
        );
    }

    #[test]
    fn a_scope_decides_what_it_allows() {
        let scope = capability().scope;
        assert!(scope.allows(Range {
            offset: 0,
            length: 65_536
        }));
        assert!(scope.allows(Range {
            offset: 65_535,
            length: 1
        }));
        assert!(scope.allows(Range {
            offset: 131_072,
            length: 1
        }));
        assert!(!scope.allows(Range {
            offset: 0,
            length: 65_537
        }));
        assert!(!scope.allows(Range {
            offset: 65_536,
            length: 1
        }));
        assert!(!scope.allows(Range {
            offset: 0,
            length: 196_608
        }));
        assert!(!scope.allows(Range {
            offset: 0,
            length: 0
        }));
        assert!(!scope.allows(Range {
            offset: u64::MAX,
            length: 1
        }));

        let whole = Scope {
            ranges: Vec::new(),
            length: Some(1024),
            ..scope.clone()
        };
        assert!(whole.allows(Range {
            offset: 0,
            length: 1024
        }));
        assert!(!whole.allows(Range {
            offset: 0,
            length: 1025
        }));

        let unbounded = Scope {
            ranges: Vec::new(),
            length: None,
            ..scope
        };
        assert!(unbounded.allows(Range {
            offset: 0,
            length: u64::MAX
        }));
    }

    #[test]
    fn a_scope_travels_on_its_own_and_round_trips() {
        let scope = capability().scope;
        let encoded = encode_scope(&scope).unwrap();
        assert!(encoded.len() <= bounds::SCOPE);
        assert_eq!(decode_scope(&encoded), Ok(scope));

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_scope(&trailing),
            Err(Error::Encoding(vot_cbor::Error::Trailing))
        );
        assert_eq!(decode_scope(&[0; bounds::SCOPE + 1]), Err(Error::TooLarge));
    }

    #[test]
    fn every_bound_is_tested_at_its_own_edge() {
        let adjacent = Scope {
            ranges: vec![
                Range {
                    offset: 0,
                    length: 8,
                },
                Range {
                    offset: 8,
                    length: 8,
                },
            ],
            ..capability().scope
        };
        assert_eq!(adjacent.validate(), Err(Error::InvalidRange));
        let separated = Scope {
            ranges: vec![
                Range {
                    offset: 0,
                    length: 8,
                },
                Range {
                    offset: 9,
                    length: 8,
                },
            ],
            ..capability().scope
        };
        assert_eq!(separated.validate(), Ok(()));

        let exact = Scope {
            length: Some(64),
            ranges: vec![Range {
                offset: 32,
                length: 32,
            }],
            ..capability().scope
        };
        assert_eq!(exact.validate(), Ok(()));
        let past = Scope {
            length: Some(64),
            ranges: vec![Range {
                offset: 32,
                length: 33,
            }],
            ..capability().scope
        };
        assert_eq!(past.validate(), Err(Error::InvalidRange));

        let mut widest = capability();
        widest.operations = vec![0xffff];
        assert_eq!(widest.validate(), Ok(()));
        widest.operations = vec![0x1_0000];
        assert_eq!(widest.validate(), Err(Error::InvalidOperations));

        assert_eq!(
            decode_scope(&[0; bounds::SCOPE]),
            Err(Error::Encoding(vot_cbor::Error::WrongType))
        );
        assert_eq!(decode_scope(&[0; bounds::SCOPE + 1]), Err(Error::TooLarge));
        assert_eq!(
            decode(&vec![0; bounds::SIGNED]),
            Err(Error::Encoding(vot_cbor::Error::WrongType))
        );
        assert_eq!(decode(&vec![0; bounds::SIGNED + 1]), Err(Error::TooLarge));

        let mut value = capability();
        value.scope.length = None;
        value.scope.ranges = Vec::new();
        let signed = sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let envelope = encode(&signed).unwrap();
        assert!(envelope.len() < bounds::SIGNED);
        assert_eq!(decode(&envelope), Ok(signed));
    }

    #[test]
    fn the_validity_window_is_inclusive_then_exclusive() {
        let value = capability();
        assert!(!value.is_current(value.not_before - 1));
        assert!(value.is_current(value.not_before));
        assert!(value.is_current(value.expiry - 1));
        assert!(!value.is_current(value.expiry));
    }

    #[test]
    fn what_a_capability_allows_and_limits_is_read_by_identifier() {
        let value = capability();
        assert!(value.allows(vot_codec::Operation::Publish));
        assert!(value.allows(vot_codec::Operation::ReadRanges));
        assert!(
            !value.allows(vot_codec::Operation::ReadManifest),
            "an operation it does not name"
        );
        // The raw view answers about the set, not about a grant, so it sees
        // what a later revision issued and `allows` cannot be asked.
        assert!(value.carries(1));
        assert!(!value.carries(0x0004));
        assert_eq!(value.limit(1), Some(4));
        assert_eq!(value.limit(2), Some(1 << 30));
        assert_eq!(value.limit(3), None, "a limit it does not state");
    }

    #[test]
    fn the_widest_capability_fits_the_field_that_carries_it() {
        let mut value = capability();
        value.issuer = "i".repeat(bounds::IDENTITY.1);
        value.audience = "a".repeat(bounds::IDENTITY.1);
        value.operations = (1..=bounds::OPERATIONS.1 as u64).collect();
        value.limits = (1..=u16::try_from(bounds::LIMITS).unwrap())
            .map(|id| Limit {
                id,
                value: u64::MAX,
            })
            .collect();
        value.scope.length = None;
        value.scope.ranges = (0..bounds::RANGES as u64)
            .map(|index| Range {
                offset: index * (1 << 49),
                length: 1 << 48,
            })
            .collect();

        let scope = encode_scope(&value.scope).unwrap();
        assert_eq!(scope.len(), 1_251, "the widest scope");
        assert!(scope.len() <= bounds::SCOPE, "and it fits its field");

        let signed = sign(&value, &[0xab; 64], &issuer_key()).unwrap();
        let envelope = encode(&signed).unwrap();
        assert_eq!(envelope.len(), 1_905, "the widest signed capability");
        assert!(envelope.len() <= bounds::SIGNED, "and it fits its field");
        assert_eq!(decode(&envelope), Ok(signed));

        assert_eq!(decode(&vec![0; bounds::SIGNED + 1]), Err(Error::TooLarge));
    }
}
