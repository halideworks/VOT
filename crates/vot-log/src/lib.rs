//! Append-only transparency log for receipt chain heads.
//!
//! RFC 6962 merkle tree. Entries are append-only; consistency proofs show
//! nothing earlier was changed. Checkpoints are compatible with Go's signed-note
//! format and Sigstore.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// RFC 6962 prefixes keep a leaf hash from ever colliding with an interior one.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Largest log this implementation will build, so a caller cannot ask for an
/// allocation it has not sized.
pub const MAX_ENTRIES: usize = 1 << 32;

pub type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An index or size falls outside the tree.
    OutOfRange,
    /// A proof did not reconstruct the head it claims.
    ProofInvalid,
    /// A checkpoint could not be parsed.
    Malformed,
    /// A signature did not verify, or there were too few witnesses.
    Unwitnessed,
    /// The log is at its size limit.
    Full,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::OutOfRange => "index or size outside the tree",
            Self::ProofInvalid => "proof does not reconstruct the head",
            Self::Malformed => "checkpoint is malformed",
            Self::Unwitnessed => "signature failed or too few witnesses",
            Self::Full => "log is at its size limit",
        })
    }
}

mod checkpoint;
mod merkle;
mod note;
mod proof;
mod witness;

pub use checkpoint::*;
pub use merkle::*;
pub use note::*;
pub use proof::*;
pub use witness::*;

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{
        Checkpoint, Error, Hash, MAX_ENTRIES, MerkleLog, NoteSignature, SignedCheckpoint,
        WitnessKey, base64, decompose, leaf_hash, node_hash, note_key_hash, sign_checkpoint, split,
        unbase64, verify_checkpoint, verify_consistency, verify_inclusion,
    };
    use ed25519_dalek::SigningKey;

    fn log_of(entries: usize) -> MerkleLog {
        let mut log = MerkleLog::new();
        for index in 0..entries {
            log.append(&index.to_be_bytes()).unwrap();
        }
        log
    }

    fn hex(bytes: &Hash) -> String {
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    #[test]
    fn hashing_matches_rfc_6962() {
        assert_eq!(
            hex(&MerkleLog::new().root().unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&leaf_hash(b"")),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        let one = log_of(1);
        assert_eq!(one.root().unwrap(), leaf_hash(&0_usize.to_be_bytes()));
        let two = log_of(2);
        assert_eq!(
            two.root().unwrap(),
            node_hash(
                &leaf_hash(&0_usize.to_be_bytes()),
                &leaf_hash(&1_usize.to_be_bytes())
            )
        );
    }

    #[test]
    fn every_inclusion_proof_verifies_for_every_size() {
        for size in 1..=64_usize {
            let log = log_of(size);
            let root = log.root().unwrap();
            for index in 0..size {
                let proof = log.inclusion_proof(index, size).unwrap();
                let leaf = leaf_hash(&index.to_be_bytes());
                verify_inclusion(&leaf, index, size, &proof, &root)
                    .unwrap_or_else(|error| panic!("size {size} index {index}: {error}"));
            }
        }
    }

    #[test]
    fn an_inclusion_proof_fails_for_anything_it_does_not_prove() {
        let size = 13;
        let log = log_of(size);
        let root = log.root().unwrap();
        let proof = log.inclusion_proof(6, size).unwrap();
        let leaf = leaf_hash(&6_usize.to_be_bytes());
        verify_inclusion(&leaf, 6, size, &proof, &root).unwrap();

        let other = leaf_hash(&7_usize.to_be_bytes());
        assert_eq!(
            verify_inclusion(&other, 6, size, &proof, &root),
            Err(Error::ProofInvalid)
        );
        assert!(verify_inclusion(&leaf, 5, size, &proof, &root).is_err());
        assert_eq!(
            verify_inclusion(&leaf, 6, size, &proof, &[9; 32]),
            Err(Error::ProofInvalid)
        );
        let mut tampered = proof.clone();
        tampered[0][0] ^= 1;
        assert_eq!(
            verify_inclusion(&leaf, 6, size, &tampered, &root),
            Err(Error::ProofInvalid)
        );

        let mut padded = proof.clone();
        padded.push([0; 32]);
        assert_eq!(
            verify_inclusion(&leaf, 6, size, &padded, &root),
            Err(Error::ProofInvalid)
        );
        let mut short = proof;
        short.pop();
        assert_eq!(
            verify_inclusion(&leaf, 6, size, &short, &root),
            Err(Error::ProofInvalid)
        );

        assert_eq!(
            verify_inclusion(&leaf, 0, 0, &[], &root),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            verify_inclusion(&leaf, 13, size, &[], &root),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn every_consistency_proof_verifies_for_every_pair_of_sizes() {
        for new_size in 1..=48_usize {
            let log = log_of(new_size);
            let new_root = log.root().unwrap();
            for old_size in 1..=new_size {
                let old_root = log.root_at(old_size).unwrap();
                let proof = log.consistency_proof(old_size, new_size).unwrap();
                verify_consistency(old_size, &old_root, new_size, &new_root, &proof)
                    .unwrap_or_else(|error| panic!("{old_size} -> {new_size}: {error}"));
            }
        }
    }

    #[test]
    fn a_log_that_rewrote_history_cannot_produce_a_consistency_proof() {
        let honest = log_of(20);
        let mut forged = MerkleLog::new();
        for index in 0..20_usize {
            let entry = if index == 3 {
                b"rewritten".to_vec()
            } else {
                index.to_be_bytes().to_vec()
            };
            forged.append(&entry).unwrap();
        }
        let published = honest.root_at(10).unwrap();
        let forged_head = forged.root().unwrap();
        assert_ne!(forged.root_at(10).unwrap(), published);

        let proof = forged.consistency_proof(10, 20).unwrap();
        assert_eq!(
            verify_consistency(10, &published, 20, &forged_head, &proof),
            Err(Error::ProofInvalid)
        );
    }

    #[test]
    fn a_consistency_proof_fails_when_padded_truncated_or_tampered() {
        let log = log_of(21);
        let old_root = log.root_at(9).unwrap();
        let new_root = log.root().unwrap();
        let proof = log.consistency_proof(9, 21).unwrap();
        verify_consistency(9, &old_root, 21, &new_root, &proof).unwrap();

        let mut padded = proof.clone();
        padded.push([0; 32]);
        assert_eq!(
            verify_consistency(9, &old_root, 21, &new_root, &padded),
            Err(Error::ProofInvalid)
        );
        let mut short = proof.clone();
        short.pop();
        assert!(verify_consistency(9, &old_root, 21, &new_root, &short).is_err());
        let mut tampered = proof;
        tampered[0][0] ^= 1;
        assert_eq!(
            verify_consistency(9, &old_root, 21, &new_root, &tampered),
            Err(Error::ProofInvalid)
        );
    }

    #[test]
    fn an_unchanged_log_needs_an_empty_proof_and_matching_heads() {
        let log = log_of(7);
        let root = log.root().unwrap();
        verify_consistency(7, &root, 7, &root, &[]).unwrap();
        assert_eq!(
            verify_consistency(7, &root, 7, &root, &[[0; 32]]),
            Err(Error::ProofInvalid)
        );
        assert_eq!(
            verify_consistency(7, &root, 7, &[1; 32], &[]),
            Err(Error::ProofInvalid)
        );
    }

    #[test]
    fn ranges_outside_the_log_are_refused() {
        let log = log_of(5);
        assert_eq!(log.root_at(6), Err(Error::OutOfRange));
        assert_eq!(log.inclusion_proof(5, 5), Err(Error::OutOfRange));
        assert_eq!(log.inclusion_proof(0, 6), Err(Error::OutOfRange));
        assert_eq!(log.consistency_proof(0, 5), Err(Error::OutOfRange));
        assert_eq!(log.consistency_proof(4, 3), Err(Error::OutOfRange));
        assert_eq!(log.consistency_proof(1, 6), Err(Error::OutOfRange));
        assert_eq!(
            verify_consistency(0, &[0; 32], 1, &[0; 32], &[]),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            verify_consistency(2, &[0; 32], 1, &[0; 32], &[]),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn appending_grows_the_log_and_reports_the_index() {
        let mut log = MerkleLog::new();
        assert!(log.is_empty());
        assert_eq!(log.append(b"a").unwrap(), 0);
        assert_eq!(log.append(b"b").unwrap(), 1);
        assert_eq!(log.len(), 2);
        assert!(!log.is_empty());
        assert_eq!(log.root_at(1).unwrap(), leaf_hash(b"a"));
        assert_eq!(MAX_ENTRIES, 1 << 32);
    }

    #[test]
    fn the_split_point_is_the_largest_power_of_two_below_the_size() {
        for (size, expected) in [(2, 1), (3, 2), (4, 2), (5, 4), (8, 4), (9, 8), (16, 8)] {
            assert_eq!(split(size), expected, "size {size}");
        }
    }

    #[test]
    fn proof_lengths_are_derived_not_assumed() {
        assert_eq!(decompose(0, 1), (0, 0));
        assert_eq!(decompose(0, 2), (1, 0));
        assert_eq!(decompose(2, 3), (0, 1));
        for size in 1..=32_usize {
            let log = log_of(size);
            for index in 0..size {
                let (inner, border) = decompose(index, size);
                assert_eq!(
                    log.inclusion_proof(index, size).unwrap().len(),
                    (inner + border) as usize,
                    "size {size} index {index}"
                );
            }
        }
    }

    fn checkpoint_of(log: &MerkleLog) -> SignedCheckpoint {
        SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: "vot.example/log".to_owned(),
                size: log.len(),
                root: log.root().unwrap(),
            },
            signatures: Vec::new(),
        }
    }

    #[test]
    fn base64_round_trips_and_rejects_malformed_input() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            if bytes.is_empty() {
                continue;
            }
            assert_eq!(unbase64(&base64(bytes)).unwrap(), bytes);
        }
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        for bad in ["A", "AAAAA", "A===", "Zg=A", "!!!!"] {
            assert_eq!(unbase64(bad), Err(Error::Malformed), "accepted {bad}");
        }
        assert_eq!(unbase64("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_checkpoint_note_round_trips() {
        let log = log_of(11);
        let mut signed = checkpoint_of(&log);
        let operator = SigningKey::from_bytes(&[21; 32]);
        let witness = SigningKey::from_bytes(&[22; 32]);
        sign_checkpoint(&mut signed, "vot.example", &operator).unwrap();
        sign_checkpoint(&mut signed, "witness.example", &witness).unwrap();

        let note = signed.to_note().unwrap();
        assert!(note.starts_with("vot.example/log\n11\n"));
        assert_eq!(SignedCheckpoint::parse_note(&note).unwrap(), signed);
    }

    #[test]
    fn a_note_that_the_encoder_would_not_produce_is_refused() {
        let log = log_of(4);
        let mut signed = checkpoint_of(&log);
        sign_checkpoint(
            &mut signed,
            "vot.example",
            &SigningKey::from_bytes(&[21; 32]),
        )
        .unwrap();
        let note = signed.to_note().unwrap();

        for broken in [
            note.replace("\n\n", "\n"),
            note.replace("vot.example/log", ""),
            note.replace("4\n", "four\n"),
            format!("{note}trailing"),
            note.replacen('\u{2014}', "-", 1),
        ] {
            assert_eq!(
                SignedCheckpoint::parse_note(&broken),
                Err(Error::Malformed),
                "accepted {broken:?}"
            );
        }

        let mut sneaky = checkpoint_of(&log);
        sneaky.checkpoint.origin = "a\nb".to_owned();
        assert_eq!(sneaky.to_note(), Err(Error::Malformed));
        sneaky.checkpoint.origin = String::new();
        assert_eq!(sneaky.to_note(), Err(Error::Malformed));
    }

    #[test]
    fn a_head_counts_only_with_enough_distinct_witnesses() {
        let log = log_of(9);
        let mut signed = checkpoint_of(&log);
        let alpha = SigningKey::from_bytes(&[31; 32]);
        let beta = SigningKey::from_bytes(&[32; 32]);
        let witnesses = vec![
            WitnessKey {
                name: "alpha".to_owned(),
                key: alpha.verifying_key(),
            },
            WitnessKey {
                name: "beta".to_owned(),
                key: beta.verifying_key(),
            },
        ];

        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 1),
            Err(Error::Unwitnessed)
        );
        sign_checkpoint(&mut signed, "alpha", &alpha).unwrap();
        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 1).unwrap(),
            ["alpha"]
        );
        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 2),
            Err(Error::Unwitnessed)
        );
        sign_checkpoint(&mut signed, "beta", &beta).unwrap();
        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 2).unwrap(),
            ["alpha", "beta"]
        );

        sign_checkpoint(&mut signed, "alpha", &alpha).unwrap();
        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 3),
            Err(Error::Unwitnessed)
        );

        let aliased = vec![
            WitnessKey {
                name: "alpha".to_owned(),
                key: alpha.verifying_key(),
            },
            WitnessKey {
                name: "alpha-backup".to_owned(),
                key: alpha.verifying_key(),
            },
        ];
        let mut doubled = checkpoint_of(&log_of(9));
        sign_checkpoint(&mut doubled, "alpha", &alpha).unwrap();
        sign_checkpoint(&mut doubled, "alpha-backup", &alpha).unwrap();
        assert_eq!(verify_checkpoint(&doubled, &aliased, 1).unwrap().len(), 1);
        assert_eq!(
            verify_checkpoint(&doubled, &aliased, 2),
            Err(Error::Unwitnessed)
        );

        let rotating = SigningKey::from_bytes(&[33; 32]);
        let two_keys_one_name = vec![
            WitnessKey {
                name: "alpha".to_owned(),
                key: alpha.verifying_key(),
            },
            WitnessKey {
                name: "alpha".to_owned(),
                key: rotating.verifying_key(),
            },
        ];
        let mut rotated = checkpoint_of(&log_of(9));
        sign_checkpoint(&mut rotated, "alpha", &alpha).unwrap();
        sign_checkpoint(&mut rotated, "alpha", &rotating).unwrap();
        let names = verify_checkpoint(&rotated, &two_keys_one_name, 1).unwrap();
        assert_eq!(names, ["alpha"]);
        assert_eq!(
            verify_checkpoint(&rotated, &two_keys_one_name, 2),
            Err(Error::Unwitnessed)
        );
    }

    #[test]
    fn a_signature_does_not_carry_to_another_head_name_or_key() {
        let alpha = SigningKey::from_bytes(&[31; 32]);
        let witnesses = vec![WitnessKey {
            name: "alpha".to_owned(),
            key: alpha.verifying_key(),
        }];
        let mut signed = checkpoint_of(&log_of(9));
        sign_checkpoint(&mut signed, "alpha", &alpha).unwrap();
        verify_checkpoint(&signed, &witnesses, 1).unwrap();

        for mutated in [
            Checkpoint {
                size: 10,
                ..signed.checkpoint.clone()
            },
            Checkpoint {
                root: [7; 32],
                ..signed.checkpoint.clone()
            },
            Checkpoint {
                origin: "other.example/log".to_owned(),
                ..signed.checkpoint.clone()
            },
        ] {
            let moved = SignedCheckpoint {
                checkpoint: mutated,
                signatures: signed.signatures.clone(),
            };
            assert_eq!(
                verify_checkpoint(&moved, &witnesses, 1),
                Err(Error::Unwitnessed)
            );
        }

        let mut relabelled = signed.clone();
        relabelled.signatures[0].name = "beta".to_owned();
        let beta_listed = vec![WitnessKey {
            name: "beta".to_owned(),
            key: alpha.verifying_key(),
        }];
        assert_eq!(
            verify_checkpoint(&relabelled, &beta_listed, 1),
            Err(Error::Unwitnessed)
        );

        let mut extra = signed;
        extra.signatures.push(NoteSignature {
            name: "stranger".to_owned(),
            key_hash: [0; 4],
            signature: vec![0; 64],
        });
        assert_eq!(verify_checkpoint(&extra, &witnesses, 1).unwrap(), ["alpha"]);
    }

    /// Builds a valid note of exactly `target` bytes by padding signer names.
    ///
    fn note_of_length(target: usize) -> String {
        const LINE_OVERHEAD: usize = 14;
        let mut signed = checkpoint_of(&log_of(3));
        let base = signed.to_note().unwrap().len();
        let mut remaining = target - base;
        let line = |name_len: usize, signed: &mut SignedCheckpoint| {
            signed.signatures.push(NoteSignature {
                name: "n".repeat(name_len),
                key_hash: [1, 2, 3, 4],
                signature: Vec::new(),
            });
        };
        while remaining > 256 + LINE_OVERHEAD {
            line(100, &mut signed);
            remaining -= 100 + LINE_OVERHEAD;
        }
        line(remaining - LINE_OVERHEAD, &mut signed);
        signed.to_note().unwrap()
    }

    #[test]
    fn an_absurd_tree_size_is_refused_rather_than_crashing() {
        let root = [0; 32];
        assert_eq!(
            verify_inclusion(&root, 0, usize::MAX, &[], &root),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            verify_inclusion(&root, 0, MAX_ENTRIES + 1, &[], &root),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            verify_consistency(1, &root, usize::MAX, &root, &[]),
            Err(Error::OutOfRange)
        );

        assert_eq!(
            verify_inclusion(&root, 0, MAX_ENTRIES, &[], &root),
            Err(Error::ProofInvalid)
        );
        assert_eq!(
            verify_consistency(1, &root, MAX_ENTRIES, &root, &[]),
            Err(Error::ProofInvalid)
        );
        let mut signed = checkpoint_of(&log_of(2));
        signed.checkpoint.size = usize::MAX;
        let note = signed.to_note().unwrap();
        let parsed = SignedCheckpoint::parse_note(&note).unwrap();
        assert_eq!(
            verify_inclusion(&root, 0, parsed.checkpoint.size, &[], &root),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn signer_names_follow_the_signed_note_rules() {
        let mut signed = checkpoint_of(&log_of(3));
        let key = SigningKey::from_bytes(&[81; 32]);
        for bad in [
            "",
            "has space",
            "has\nnewline",
            "has\ttab",
            "has\rreturn",
            "has+plus",
            "has\u{00a0}nbsp",
            "has\u{2003}emspace",
        ] {
            assert_eq!(
                sign_checkpoint(&mut signed, bad, &key),
                Err(Error::Malformed),
                "accepted {bad:?}"
            );
        }
        for good in ["vot.example", "witness-1", "a.b/c", "\u{00e9}quipe"] {
            assert!(sign_checkpoint(&mut signed, good, &key).is_ok(), "{good}");
        }
        signed.signatures[0].name = "bad+name".to_owned();
        assert_eq!(signed.to_note(), Err(Error::Malformed));
    }

    #[test]
    fn every_error_says_what_went_wrong() {
        for (error, expected) in [
            (Error::OutOfRange, "index or size outside the tree"),
            (Error::ProofInvalid, "proof does not reconstruct the head"),
            (Error::Malformed, "checkpoint is malformed"),
            (Error::Unwitnessed, "signature failed or too few witnesses"),
            (Error::Full, "log is at its size limit"),
        ] {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn note_and_name_limits_are_checked_at_their_exact_edges() {
        let log = log_of(2);
        let mut signed = checkpoint_of(&log);

        signed.checkpoint.origin = "o".repeat(256);
        assert!(signed.checkpoint.body().is_ok());
        signed.checkpoint.origin = "o".repeat(257);
        assert_eq!(signed.checkpoint.body(), Err(Error::Malformed));
        signed.checkpoint.origin = "vot.example/log".to_owned();

        let key = SigningKey::from_bytes(&[61; 32]);
        sign_checkpoint(&mut signed, "ok", &key).unwrap();
        signed.signatures[0].name = "n".repeat(256);
        assert!(signed.to_note().is_ok());
        signed.signatures[0].name = "n".repeat(257);
        assert_eq!(signed.to_note(), Err(Error::Malformed));
        signed.signatures[0].name = String::new();
        assert_eq!(signed.to_note(), Err(Error::Malformed));

        assert_eq!(
            note_of_length(super::MAX_NOTE_BYTES).len(),
            super::MAX_NOTE_BYTES
        );
        SignedCheckpoint::parse_note(&note_of_length(super::MAX_NOTE_BYTES)).unwrap();
        assert_eq!(
            SignedCheckpoint::parse_note(&note_of_length(super::MAX_NOTE_BYTES + 1)),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn a_signature_blob_shorter_than_its_key_hash_is_refused() {
        let log = log_of(2);
        let mut signed = checkpoint_of(&log);
        sign_checkpoint(&mut signed, "alpha", &SigningKey::from_bytes(&[71; 32])).unwrap();
        let note = signed.to_note().unwrap();
        let line = note.lines().last().unwrap();
        let blob = line.rsplit(' ').next().unwrap();

        let four = note.replace(blob, &base64(&[1, 2, 3, 4]));
        let parsed = SignedCheckpoint::parse_note(&four).unwrap();
        assert!(parsed.signatures[0].signature.is_empty());

        let three = note.replace(blob, &base64(&[1, 2, 3]));
        assert_eq!(SignedCheckpoint::parse_note(&three), Err(Error::Malformed));
    }

    #[test]
    fn a_key_hash_binds_the_name_to_the_key() {
        let key = SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes();
        let other = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
        assert_ne!(note_key_hash("a", &key), note_key_hash("b", &key));
        assert_ne!(note_key_hash("a", &key), note_key_hash("a", &other));
        assert_eq!(note_key_hash("a", &key), note_key_hash("a", &key));
    }

    #[test]
    fn a_signer_name_cannot_break_the_note_shape() {
        let mut signed = checkpoint_of(&log_of(3));
        let key = SigningKey::from_bytes(&[51; 32]);
        for bad in ["", "has space", "has\nnewline"] {
            assert_eq!(
                sign_checkpoint(&mut signed, bad, &key),
                Err(Error::Malformed)
            );
        }
        assert!(sign_checkpoint(&mut signed, &"n".repeat(256), &key).is_ok());
        assert_eq!(
            sign_checkpoint(&mut signed, &"n".repeat(257), &key),
            Err(Error::Malformed)
        );
    }
}
