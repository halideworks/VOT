#![allow(
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! Deterministic VOT manifest encoding, path validation, and progressive ingest.

use std::collections::BTreeSet;

use unicode_normalization::UnicodeNormalization;

pub const MAX_PAGE_BYTES: usize = 1_048_576;
pub const MAX_ENTRIES_PER_PAGE: usize = 8192;
pub const MAX_PATH_COMPONENTS: usize = 256;
const MAX_SEAL_FIXED_BYTES: usize = 113;
const MAX_ENCODED_PAGE_COMMITMENT_BYTES: usize = 39;
pub const MAX_PAGE_COMMITMENTS: usize =
    (MAX_PAGE_BYTES - MAX_SEAL_FIXED_BYTES) / MAX_ENCODED_PAGE_COMMITMENT_BYTES;

mod decode;
mod encode;
mod index;
mod model;
mod path;
mod progressive;

pub use decode::*;
pub use encode::*;
pub use index::*;
pub use model::*;
pub use path::*;
pub use progressive::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPath,
    PathCollision,
    EntriesUnsorted,
    InvalidObject,
    PageTooLarge,
    WrongManifest,
    WrongPageIndex,
    BrokenPageChain,
    SealedPageInProgressiveStream,
    Poisoned,
    InvalidSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    PageTooLarge,
    Truncated,
    InvalidCbor,
    NonCanonical,
    WrongType,
    InvalidStructure,
    TooManyEntries,
    TooManyComponents,
    ComponentTooLarge,
    InvalidUtf8,
    Semantic(Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> ManifestEntry {
        nested_file(&[path])
    }

    fn nested_file(parts: &[&str]) -> ManifestEntry {
        let object = ObjectId {
            suite: 1,
            root: [7; 32],
            length: 3,
        };
        ManifestEntry {
            path: PackagePath::portable(parts.iter().copied()).unwrap(),
            kind: EntryKind::File,
            length: Some(3),
            storage: Some(StorageRef::Direct(object)),
            metadata: None,
        }
    }

    fn directory(parts: &[&str]) -> ManifestEntry {
        ManifestEntry {
            path: PackagePath::portable(parts.iter().copied()).unwrap(),
            kind: EntryKind::Directory,
            length: None,
            storage: None,
            metadata: None,
        }
    }

    fn page(index: u64, previous_digest: [u8; 32], name: &str) -> ManifestPage {
        ManifestPage {
            manifest_id: [9; 16],
            index,
            total: None,
            previous_digest,
            profile: PathProfile::Portable,
            entries: vec![file(name)],
        }
    }

    #[test]
    fn encoding_is_stable_and_uses_integer_keys() {
        let encoded = encode_page(&page(0, [0; 32], "a.txt")).unwrap();
        assert_eq!(encoded[0], 0xa7);
        assert_eq!(encoded, encode_page(&page(0, [0; 32], "a.txt")).unwrap());
        assert!(encoded.len() < MAX_PAGE_BYTES);
        assert_eq!(decode_page(&encoded).unwrap(), page(0, [0; 32], "a.txt"));
    }

    #[test]
    fn decoder_rejects_noncanonical_truncated_and_unbounded_inputs() {
        let encoded = encode_page(&page(0, [0; 32], "a.txt")).unwrap();
        for length in 0..encoded.len() {
            assert!(decode_page(&encoded[..length]).is_err());
        }

        let mut empty = page(0, [0; 32], "a.txt");
        empty.entries.clear();
        let mut oversized_entries = encode_page(&empty).unwrap();
        assert_eq!(oversized_entries.pop(), Some(0x80));
        oversized_entries.extend_from_slice(&[0x9a, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            decode_page(&oversized_entries),
            Err(DecodeError::TooManyEntries)
        );

        let mut noncanonical = vec![0xb8, 0x07];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert_eq!(decode_page(&noncanonical), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn packed_raw_page_with_metadata_round_trips() {
        let logical = ObjectId {
            suite: 2,
            root: [3; 32],
            length: 3,
        };
        let rich = ManifestPage {
            manifest_id: [4; 16],
            index: 7,
            total: Some(8),
            previous_digest: [5; 32],
            profile: PathProfile::RawPosix,
            entries: vec![ManifestEntry {
                path: PackagePath::raw([b"raw-name"]).unwrap(),
                kind: EntryKind::File,
                length: Some(3),
                storage: Some(StorageRef::Pack {
                    pack: ObjectId {
                        suite: 1,
                        root: [6; 32],
                        length: 4096,
                    },
                    offset: 100,
                    length: 3,
                    logical,
                }),
                metadata: Some(FileMetadata {
                    mode: Some(0o640),
                    mtime_seconds: Some(-1),
                    mtime_nanoseconds: Some(999_999_999),
                    media_type: Some("application/octet-stream".to_owned()),
                }),
            }],
        };
        let encoded = encode_page(&rich).unwrap();
        assert_eq!(decode_page(&encoded).unwrap(), rich);
    }

    #[test]
    fn seal_round_trips_and_rejects_inconsistent_commitments() {
        let seal = Seal {
            manifest_id: [4; 16],
            final_page_count: 2,
            final_page_digest: [8; 32],
            package: ObjectId {
                suite: 1,
                root: [9; 32],
                length: 123,
            },
            pages: vec![
                PageCommitment {
                    index: 0,
                    digest: [7; 32],
                },
                PageCommitment {
                    index: 1,
                    digest: [8; 32],
                },
            ],
        };
        let encoded = encode_seal(&seal).unwrap();
        assert_eq!(decode_seal(&encoded).unwrap(), seal);
        for length in 0..encoded.len() {
            assert!(decode_seal(&encoded[..length]).is_err());
        }
        let mut wrong = seal.clone();
        wrong.pages[1].index = 2;
        assert_eq!(encode_seal(&wrong), Err(Error::InvalidSeal));
        wrong = seal.clone();
        wrong.final_page_digest = [0; 32];
        assert_eq!(encode_seal(&wrong), Err(Error::InvalidSeal));

        wrong = seal.clone();
        wrong.final_page_count = 0;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));
        wrong = seal.clone();
        wrong.final_page_count = 1;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));
        wrong = seal.clone();
        wrong.package.suite = 0;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));
        wrong = seal.clone();
        wrong.package.length = i64::MAX as u64 + 1;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));

        let pages = (0..MAX_PAGE_COMMITMENTS)
            .map(|index| PageCommitment {
                index: index as u64,
                digest: [8; 32],
            })
            .collect::<Vec<_>>();
        wrong = seal.clone();
        wrong.final_page_count = pages.len() as u64;
        wrong.pages = pages;
        wrong.package.suite = 2;
        wrong.package.length = i64::MAX as u64;
        assert_eq!(validate_seal(&wrong), Ok(()));
        let encoded = encode_seal(&wrong).unwrap();
        assert!(encoded.len() <= MAX_PAGE_BYTES);

        wrong.pages.push(PageCommitment {
            index: MAX_PAGE_COMMITMENTS as u64,
            digest: [8; 32],
        });
        wrong.final_page_count = wrong.pages.len() as u64;
        assert_eq!(validate_seal(&wrong), Err(Error::InvalidSeal));
    }

    #[test]
    fn manifest_collection_and_byte_bounds_are_exact() {
        assert_eq!(MAX_PAGE_COMMITMENTS, 26_883);
        assert!(validate_entry_count(MAX_ENTRIES_PER_PAGE).is_ok());
        assert_eq!(
            validate_entry_count(MAX_ENTRIES_PER_PAGE + 1),
            Err(Error::PageTooLarge)
        );
        assert!(validate_page_length(MAX_PAGE_BYTES).is_ok());
        assert_eq!(
            validate_page_length(MAX_PAGE_BYTES + 1),
            Err(Error::PageTooLarge)
        );
    }

    #[test]
    fn deterministic_mutation_corpus_never_panics() {
        let mut state = 0xbb67_ae85_84ca_a73b_u64;
        for length in 0..4096 {
            let mut input = vec![0; length % 1025];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            if let Ok(page) = decode_page(&input) {
                assert_eq!(encode_page(&page).unwrap(), input);
            }
        }
    }

    #[test]
    fn portable_collision_and_reserved_corpus() {
        for (left, right) in [
            ("Readme", "README"),
            ("\u{e9}", "e\u{301}"),
            ("I", "\u{131}"),
            ("\u{130}", "i"),
        ] {
            let collisions = vec![file(left), file(right)];
            assert_eq!(
                validate_entries(&collisions, PathProfile::Portable),
                Err(Error::PathCollision)
            );
        }
        for name in [
            "CON",
            "aux.txt",
            "NUL.tar.gz",
            "COM1",
            "COM\u{b9}",
            "LPT9",
            "bad/part",
            "bad\\part",
            "bad:name",
            "trail.",
            "trail ",
            ".",
            "..",
            "\u{ff0e}",
            "\u{2024}\u{2024}",
            "join\u{200d}er",
            "rtl\u{202e}name",
        ] {
            assert_eq!(PackagePath::portable([name]), Err(Error::InvalidPath));
        }
    }

    #[test]
    fn progressive_reorder_replay_missing_and_broken_chain_are_rejected_by_ingest() {
        let first = page(0, [0; 32], "a");
        let first_digest = *blake3::hash(&encode_page(&first).unwrap()).as_bytes();

        let mut reordered = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        assert_eq!(
            reordered.accept(&page(1, first_digest, "b")),
            Err(Error::WrongPageIndex)
        );

        let mut replayed = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        replayed.accept(&first).unwrap();
        assert_eq!(replayed.accept(&first), Err(Error::WrongPageIndex));

        let mut missing = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        missing.accept(&first).unwrap();
        assert_eq!(
            missing.accept(&page(2, first_digest, "c")),
            Err(Error::WrongPageIndex)
        );

        let mut broken_chain = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        broken_chain.accept(&first).unwrap();
        assert_eq!(
            broken_chain.accept(&page(1, [7; 32], "b")),
            Err(Error::BrokenPageChain)
        );
    }

    #[test]
    fn source_mutation_is_rejected_at_seal() {
        let first = page(0, [0; 32], "a");
        let mut ingest = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        let accepted_digest = ingest.accept(&first).unwrap();
        let valid_package = ObjectId {
            suite: 1,
            root: [1; 32],
            length: 1,
        };
        let valid = Seal {
            manifest_id: [9; 16],
            final_page_count: 1,
            final_page_digest: accepted_digest,
            package: valid_package.clone(),
            pages: vec![PageCommitment {
                index: 0,
                digest: accepted_digest,
            }],
        };
        assert_eq!(ingest.verify_seal(&valid), Ok(()));

        let mut mutated = first.clone();
        mutated.entries[0] = file("changed");
        let mutated_digest = *blake3::hash(&encode_page(&mutated).unwrap()).as_bytes();
        let mut wrong_final_digest = valid.clone();
        wrong_final_digest.final_page_digest = mutated_digest;
        assert_eq!(
            ingest.verify_seal(&wrong_final_digest),
            Err(Error::InvalidSeal)
        );
        let mut wrong_page_commitment = valid.clone();
        wrong_page_commitment.pages[0].digest = mutated_digest;
        assert_eq!(
            ingest.verify_seal(&wrong_page_commitment),
            Err(Error::InvalidSeal)
        );
        let mutated_seal = Seal {
            manifest_id: [9; 16],
            final_page_count: 1,
            final_page_digest: mutated_digest,
            package: valid_package,
            pages: vec![PageCommitment {
                index: 0,
                digest: mutated_digest,
            }],
        };
        assert_eq!(ingest.verify_seal(&mutated_seal), Err(Error::InvalidSeal));
        assert!(!ingest.is_poisoned());
    }

    #[test]
    fn index_entry_geometry_is_fixed() {
        // The exact size rather than a bound on it. A budget written with room to
        // spare is a budget that an entry growing by a field still fits.
        assert_eq!(ManifestIndex::bytes_per_entry(), 24);
        assert_eq!(ManifestIndex::bytes_per_entry() * 1_000_000, 24_000_000);
    }

    /// A file entry whose storage is a pack record rather than a whole object.
    fn packed(entry_length: u64) -> StorageRef {
        StorageRef::Pack {
            // A pack that holds the record and no less, so a row that breaks the
            // record's own bound does not break the pack's as well.
            pack: ObjectId {
                suite: 1,
                root: [1; 32],
                length: (entry_length + 10).max(1_000),
            },
            offset: 10,
            length: entry_length,
            logical: ObjectId {
                suite: 1,
                root: [2; 32],
                length: entry_length,
            },
        }
    }

    fn direct(length: u64) -> ObjectId {
        ObjectId {
            suite: 1,
            root: [7; 32],
            length,
        }
    }

    #[test]
    fn every_rule_on_a_storage_reference_is_refused_on_its_own() {
        // A reference is a chain of conjuncts, and a chain is where a rule hides:
        // break one at a time, and a row no other rule also refuses is what says
        // this one is asked.
        assert!(valid_storage(&StorageRef::Direct(direct(3)), 3));
        assert!(valid_storage(&packed(3), 3));

        let object_of = |suite: u16, length: u64| ObjectId {
            suite,
            root: [1; 32],
            length,
        };
        let pack_of =
            |pack: ObjectId, offset: u64, length: u64, logical: ObjectId| StorageRef::Pack {
                pack,
                offset,
                length,
                logical,
            };
        let unrepresentable = i64::MAX as u64 + 1;

        for (name, storage, entry_length) in [
            (
                "a direct object of an unregistered suite",
                StorageRef::Direct(object_of(3, 3)),
                3,
            ),
            (
                "a direct object longer than a signed length holds",
                StorageRef::Direct(object_of(1, unrepresentable)),
                unrepresentable,
            ),
            (
                "a direct object that is not the length of the entry",
                StorageRef::Direct(direct(4)),
                3,
            ),
            (
                "a pack of an unregistered suite",
                pack_of(object_of(0, 1_000), 10, 3, direct(3)),
                3,
            ),
            (
                "a logical object of an unregistered suite",
                pack_of(object_of(1, 1_000), 10, 3, object_of(0, 3)),
                3,
            ),
            ("a record that is not the length of the entry", packed(4), 3),
            (
                "a record longer than a record may be",
                packed(262_145),
                262_145,
            ),
            (
                "a logical length that is not the record's",
                pack_of(object_of(1, 1_000), 10, 3, object_of(1, 2)),
                3,
            ),
            (
                "a record that ends past the pack",
                pack_of(object_of(1, 1_000), 998, 3, direct(3)),
                3,
            ),
            (
                "an offset that overflows rather than ending anywhere",
                pack_of(object_of(1, 1_000), u64::MAX, 3, direct(3)),
                3,
            ),
            (
                "a pack longer than a pack may be",
                pack_of(object_of(1, 134_217_729), 10, 3, direct(3)),
                3,
            ),
        ] {
            assert!(!valid_storage(&storage, entry_length), "{name}");
        }

        // Each bound at the value it allows, which is what says it is a bound
        // rather than a refusal.
        assert!(valid_storage(&packed(262_144), 262_144));
        assert!(valid_storage(
            &pack_of(object_of(2, 134_217_728), 134_217_725, 3, direct(3)),
            3
        ));
    }

    #[test]
    fn every_rule_on_file_metadata_is_refused_on_its_own() {
        assert!(valid_metadata(&FileMetadata::default()));
        assert!(valid_metadata(&FileMetadata {
            mode: Some(511),
            mtime_seconds: Some(i64::MIN),
            mtime_nanoseconds: Some(999_999_999),
            media_type: Some("a".repeat(127)),
        }));

        for (name, metadata) in [
            (
                "a mode outside the permission bits",
                FileMetadata {
                    mode: Some(512),
                    ..FileMetadata::default()
                },
            ),
            (
                "a nanosecond that is a whole second",
                FileMetadata {
                    mtime_nanoseconds: Some(1_000_000_000),
                    ..FileMetadata::default()
                },
            ),
            (
                "a media type of no length",
                FileMetadata {
                    media_type: Some(String::new()),
                    ..FileMetadata::default()
                },
            ),
            (
                "a media type past its bound",
                FileMetadata {
                    media_type: Some("a".repeat(128)),
                    ..FileMetadata::default()
                },
            ),
        ] {
            assert!(!valid_metadata(&metadata), "{name}");
        }
    }

    #[test]
    fn every_rule_on_an_entry_is_refused_on_its_own() {
        assert_eq!(validate_entry(&file("a.txt")), Ok(()));
        let directory = ManifestEntry {
            path: PackagePath::portable(["d"]).unwrap(),
            kind: EntryKind::Directory,
            length: None,
            storage: None,
            metadata: None,
        };
        assert_eq!(validate_entry(&directory), Ok(()));

        for (name, entry) in [
            (
                "a file without a length",
                ManifestEntry {
                    length: None,
                    ..file("a.txt")
                },
            ),
            (
                "a file without storage",
                ManifestEntry {
                    storage: None,
                    ..file("a.txt")
                },
            ),
            (
                "a file whose storage is not the length it claims",
                ManifestEntry {
                    storage: Some(StorageRef::Direct(direct(4))),
                    ..file("a.txt")
                },
            ),
            (
                "a file whose metadata is not valid",
                ManifestEntry {
                    metadata: Some(FileMetadata {
                        mode: Some(512),
                        ..FileMetadata::default()
                    }),
                    ..file("a.txt")
                },
            ),
            (
                "a directory with a length",
                ManifestEntry {
                    length: Some(0),
                    ..directory.clone()
                },
            ),
            (
                "a directory with storage",
                ManifestEntry {
                    storage: Some(StorageRef::Direct(direct(3))),
                    ..directory.clone()
                },
            ),
            (
                "a directory with metadata",
                ManifestEntry {
                    metadata: Some(FileMetadata::default()),
                    ..directory.clone()
                },
            ),
        ] {
            assert_eq!(validate_entry(&entry), Err(Error::InvalidObject), "{name}");
        }

        // A file that carries valid metadata is accepted with it, which is what
        // says the metadata rule is asked rather than assumed.
        assert_eq!(
            validate_entry(&ManifestEntry {
                metadata: Some(FileMetadata {
                    mode: Some(420),
                    ..FileMetadata::default()
                }),
                ..file("a.txt")
            }),
            Ok(())
        );
    }

    #[test]
    fn every_rule_on_a_portable_component_is_refused_on_its_own() {
        assert_eq!(validate_portable_component("a.txt"), Ok(()));
        // The longest component allowed, and the shortest refused.
        assert_eq!(validate_portable_component(&"a".repeat(255)), Ok(()));

        let mut refused = vec![
            ("no component at all".to_owned(), String::new()),
            ("one byte past the bound".to_owned(), "a".repeat(256)),
            ("this directory".to_owned(), ".".to_owned()),
            ("the one above".to_owned(), "..".to_owned()),
            ("a name that ends in a dot".to_owned(), "a.".to_owned()),
            ("a name that ends in a space".to_owned(), "a ".to_owned()),
            (
                "a compatibility form of the one above".to_owned(),
                "\u{2024}\u{2024}".to_owned(),
            ),
        ];
        for character in ['\0', '/', '\\', '<', '>', ':', '"', '|', '?', '*'] {
            refused.push((
                format!("a name holding {character:?}"),
                format!("a{character}b"),
            ));
        }
        for character in [
            '\u{1}', '\u{1f}', '\u{200c}', '\u{200d}', '\u{202a}', '\u{202e}', '\u{2066}',
            '\u{2069}', '\u{feff}',
        ] {
            refused.push((
                format!("a name holding {character:?}"),
                format!("a{character}b"),
            ));
        }
        for name in [
            "con",
            "prn",
            "aux",
            "nul",
            "com1",
            "com9",
            "lpt1",
            "lpt9",
            "CON",
            "con.txt",
            "com\u{b9}",
            "com\u{b2}",
            "com\u{b3}",
        ] {
            refused.push((format!("the device name {name}"), name.to_owned()));
        }
        for (name, component) in refused {
            assert_eq!(
                validate_portable_component(&component),
                Err(Error::InvalidPath),
                "{name}"
            );
        }

        // Names that only look like device names. The digit after the prefix is
        // what makes one, so a name without one is a name.
        for allowed in ["com", "com0", "comx", "com10", "lpt", "connect", "nulls"] {
            assert_eq!(validate_portable_component(allowed), Ok(()), "{allowed}");
        }
    }

    #[test]
    fn every_rule_on_a_raw_component_is_refused_on_its_own() {
        assert!(valid_raw_component(b"a"));
        assert!(valid_raw_component(&[b'a'; 255]));

        for (name, component) in [
            ("no component at all", Vec::new()),
            ("one byte past the bound", vec![b'a'; 256]),
            ("a name holding a zero byte", b"a\0b".to_vec()),
            ("a name holding a separator", b"a/b".to_vec()),
            ("a name holding the other separator", b"a\\b".to_vec()),
            ("a name that is only the other separator", b"\\".to_vec()),
            ("this directory", b".".to_vec()),
            ("the one above", b"..".to_vec()),
        ] {
            assert!(!valid_raw_component(&component), "{name}");
        }

        // Only those two exactly. A name that merely starts with a dot is a
        // name.
        assert!(valid_raw_component(b"..."));
        assert!(valid_raw_component(b".hidden"));
        assert!(valid_raw_component(b"..a"));
    }

    /// The hex strings in one array of the published path corpus.
    ///
    /// Scanned rather than parsed, for the reason
    /// `crates/vot-receipt` scans its own vector: the file is flat and
    /// machine-written, and `tools/verify_manifest_pack_vectors.py` parses it
    /// properly. That tool is the second implementation of the rule below;
    /// this test is what makes the corpus bind the first one too.
    fn corpus_array(name: &str) -> Vec<Vec<u8>> {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/manifest/path-collisions.json"
        ))
        .expect("the path corpus is missing");
        let key = format!("\"{name}\": [");
        let from = text.find(&key).unwrap_or_else(|| panic!("no array {name}")) + key.len();
        let body = &text[from..from + text[from..].find(']').expect("unterminated array")];
        body.split('"')
            .skip(1)
            .step_by(2)
            .map(|value| {
                assert!(value.len() % 2 == 0, "{name} holds an odd hex string");
                value
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        let digit = |byte: u8| match byte {
                            b'0'..=b'9' => byte - b'0',
                            b'a'..=b'f' => byte - b'a' + 10,
                            _ => panic!("{name} is not hexadecimal"),
                        };
                        digit(pair[0]) * 16 + digit(pair[1])
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn the_published_corpus_is_the_raw_rule_this_enforces() {
        let invalid = corpus_array("raw_posix_invalid_hex");
        let valid = corpus_array("raw_posix_valid_hex");
        // A scan that found nothing would agree with anything.
        assert!(invalid.len() >= 8, "{} invalid cases", invalid.len());
        assert!(valid.len() >= 7, "{} valid cases", valid.len());
        for component in &invalid {
            assert!(
                !valid_raw_component(component),
                "the corpus calls {component:?} invalid and this accepts it"
            );
        }
        for component in &valid {
            assert!(
                valid_raw_component(component),
                "the corpus calls {component:?} valid and this refuses it"
            );
        }
    }

    #[test]
    fn a_raw_path_cannot_leave_its_destination() {
        let escape = vec![
            Component::Bytes(b"..".to_vec()),
            Component::Bytes(b"etc".to_vec()),
        ];
        assert!(matches!(
            PackagePath::new(escape, PathProfile::RawPosix),
            Err(Error::InvalidPath)
        ));
    }

    #[test]
    fn an_encoder_refuses_a_path_the_decoder_would_not_read() {
        let widest = PackagePath::portable((0..MAX_PATH_COMPONENTS).map(|_| "a")).unwrap();
        assert!(canonical_path_key(&widest, PathProfile::Portable).is_ok());

        let mut wider: Vec<Component> = (0..MAX_PATH_COMPONENTS)
            .map(|_| Component::Text("a".to_owned()))
            .collect();
        wider.push(Component::Text("a".to_owned()));
        assert!(matches!(
            PackagePath::new(wider, PathProfile::Portable),
            Err(Error::InvalidPath)
        ));
    }

    #[test]
    fn a_path_key_joins_components_and_prefixes_nothing() {
        // The separator goes between components, not before the first: a key that
        // began with one would sort a path under the empty component.
        assert_eq!(
            canonical_path_key(
                &PackagePath::portable(["a", "b"]).unwrap(),
                PathProfile::Portable
            ),
            Ok(b"a\0b".to_vec())
        );
        assert_eq!(
            canonical_path_key(&PackagePath::raw([b"a"]).unwrap(), PathProfile::RawPosix),
            Ok(b"a".to_vec())
        );

        // A path of no components names nothing.
        assert_eq!(
            PackagePath::new(Vec::new(), PathProfile::Portable),
            Err(Error::InvalidPath)
        );

        // Each profile takes one kind of component and refuses the other, and the
        // raw profile asks whether the bytes are a component at all rather than
        // taking them.
        for (name, components, profile) in [
            (
                "bytes under the portable profile",
                vec![Component::Bytes(b"a".to_vec())],
                PathProfile::Portable,
            ),
            (
                "text under the raw profile",
                vec![Component::Text("a".to_owned())],
                PathProfile::RawPosix,
            ),
            (
                "raw bytes holding a separator",
                vec![Component::Bytes(b"a/b".to_vec())],
                PathProfile::RawPosix,
            ),
            (
                "raw bytes holding a zero",
                vec![Component::Bytes(b"a\0b".to_vec())],
                PathProfile::RawPosix,
            ),
            (
                "no raw bytes at all",
                vec![Component::Bytes(Vec::new())],
                PathProfile::RawPosix,
            ),
        ] {
            assert_eq!(
                PackagePath::new(components, profile),
                Err(Error::InvalidPath),
                "{name}"
            );
        }

        // Portable keys are folded and stripped of what a case-insensitive
        // filesystem would drop, so two spellings of one name share a key.
        assert_eq!(
            canonical_path_key(
                &PackagePath::portable(["A.TXT"]).unwrap(),
                PathProfile::Portable
            ),
            canonical_path_key(
                &PackagePath::portable(["a.txt"]).unwrap(),
                PathProfile::Portable
            )
        );
    }

    #[test]
    fn a_page_of_sorted_entries_is_accepted_and_one_out_of_order_is_not() {
        let sorted = vec![file("a.txt"), file("b.txt"), file("c.txt")];
        assert_eq!(
            validate_entries(&sorted, PathProfile::Portable).map(|keys| keys.len()),
            Ok(3)
        );

        let unsorted = vec![file("b.txt"), file("a.txt")];
        assert_eq!(
            validate_entries(&unsorted, PathProfile::Portable),
            Err(Error::EntriesUnsorted)
        );

        // The same path twice is a collision rather than a sort fault, which is
        // the answer a reader can act on.
        let repeated = vec![file("a.txt"), file("a.txt")];
        assert_eq!(
            validate_entries(&repeated, PathProfile::Portable),
            Err(Error::PathCollision)
        );
    }

    #[test]
    fn a_file_cannot_be_the_ancestor_of_another_entry() {
        assert!(
            is_path_prefix(b"a", b"a\0b"),
            "a component boundary is an ancestor"
        );
        assert!(
            !is_path_prefix(b"foo", b"foobar"),
            "a shared spelling is not an ancestor"
        );
        assert!(!is_path_prefix(b"a", b"a"), "a path is not above itself");
        assert!(!is_path_prefix(b"b", b"a\0b"));

        assert_eq!(
            validate_entries(
                &[file("a"), nested_file(&["a", "b"])],
                PathProfile::Portable
            ),
            Err(Error::PathCollision)
        );
        assert_eq!(
            validate_entries(
                &[directory(&["a"]), nested_file(&["a", "b"])],
                PathProfile::Portable
            )
            .map(|keys| keys.len()),
            Ok(2)
        );
        assert_eq!(
            validate_entries(&[file("foo"), file("foobar")], PathProfile::Portable)
                .map(|keys| keys.len()),
            Ok(2)
        );
        assert_eq!(
            validate_entries(
                &[
                    directory(&["a"]),
                    nested_file(&["a", "b"]),
                    nested_file(&["a", "c"])
                ],
                PathProfile::Portable
            )
            .map(|keys| keys.len()),
            Ok(3)
        );

        let first = ManifestPage {
            entries: vec![file("a")],
            ..page(0, [0; 32], "unused")
        };
        let digest = *blake3::hash(&encode_page(&first).unwrap()).as_bytes();
        let child = ManifestPage {
            entries: vec![nested_file(&["a", "b"])],
            ..page(1, digest, "unused")
        };
        let mut files = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        files.accept(&first).unwrap();
        assert_eq!(files.accept(&child), Err(Error::PathCollision));

        let dir_page = ManifestPage {
            entries: vec![directory(&["a"])],
            ..page(0, [0; 32], "unused")
        };
        let dir_digest = *blake3::hash(&encode_page(&dir_page).unwrap()).as_bytes();
        let under_dir = ManifestPage {
            entries: vec![nested_file(&["a", "b"])],
            ..page(1, dir_digest, "unused")
        };
        let mut dirs = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        dirs.accept(&dir_page).unwrap();
        assert!(dirs.accept(&under_dir).is_ok());
    }

    #[test]
    fn a_progressive_stream_answers_each_page_rule_on_its_own() {
        let first = page(0, [0; 32], "a.txt");
        let mut ingest = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        let digest = ingest.accept(&first).expect("the first page");

        // Each of the two halves of the identity check, one at a time. A stream
        // that took either for the other would accept a page of another manifest.
        for (name, wrong) in [
            (
                "another manifest, this profile",
                ManifestPage {
                    manifest_id: [8; 16],
                    ..page(1, digest, "b.txt")
                },
            ),
            (
                "this manifest, another profile",
                ManifestPage {
                    profile: PathProfile::RawPosix,
                    entries: vec![ManifestEntry {
                        path: PackagePath::raw([b"b.txt"]).unwrap(),
                        ..file("b.txt")
                    }],
                    ..page(1, digest, "b.txt")
                },
            ),
        ] {
            let mut stream = ProgressiveIngest::new([9; 16], PathProfile::Portable);
            stream.accept(&first).expect("the first page");
            assert_eq!(stream.accept(&wrong), Err(Error::WrongManifest), "{name}");
            assert!(stream.is_poisoned(), "{name} poisons the stream");
        }

        // A page whose first path is the one the last page ended on. The pages
        // are each sorted, so only the seam says the stream is not.
        let mut seam = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        let two = ManifestPage {
            entries: vec![file("a.txt"), file("b.txt")],
            ..page(0, [0; 32], "a.txt")
        };
        let seam_digest = seam.accept(&two).expect("a page of two entries");
        assert_eq!(
            seam.accept(&page(1, seam_digest, "b.txt")),
            Err(Error::EntriesUnsorted),
            "the path the last page ended on"
        );

        // And the path after it, which is the same seam one step along.
        let mut continued = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        let continued_digest = continued.accept(&two).expect("a page of two entries");
        assert!(
            continued
                .accept(&page(1, continued_digest, "c.txt"))
                .is_ok(),
            "the path after the one the last page ended on"
        );
        assert!(!continued.is_poisoned());
    }

    #[test]
    fn every_rule_on_a_seal_is_refused_on_its_own_by_the_ingest() {
        let mut ingest = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        let digest = ingest.accept(&page(0, [0; 32], "a.txt")).expect("a page");
        let valid = Seal {
            manifest_id: [9; 16],
            final_page_count: 1,
            final_page_digest: digest,
            package: ObjectId {
                suite: 1,
                root: [5; 32],
                length: 3,
            },
            pages: vec![PageCommitment { index: 0, digest }],
        };
        assert_eq!(ingest.verify_seal(&valid), Ok(()));

        for (name, seal) in [
            (
                "another manifest",
                Seal {
                    manifest_id: [8; 16],
                    ..valid.clone()
                },
            ),
            (
                "a page count that is not what arrived",
                Seal {
                    final_page_count: 2,
                    ..valid.clone()
                },
            ),
            (
                "a final digest that is not the last page",
                Seal {
                    final_page_digest: [4; 32],
                    ..valid.clone()
                },
            ),
            (
                "one commitment more than there are pages",
                Seal {
                    pages: vec![
                        PageCommitment { index: 0, digest },
                        PageCommitment { index: 1, digest },
                    ],
                    ..valid.clone()
                },
            ),
            (
                "a package of an unregistered suite",
                Seal {
                    package: ObjectId {
                        suite: 0,
                        root: [5; 32],
                        length: 3,
                    },
                    ..valid.clone()
                },
            ),
            (
                "a commitment at the wrong index",
                Seal {
                    pages: vec![PageCommitment { index: 1, digest }],
                    ..valid.clone()
                },
            ),
            (
                "a commitment to another digest",
                Seal {
                    pages: vec![PageCommitment {
                        index: 0,
                        digest: [1; 32],
                    }],
                    ..valid.clone()
                },
            ),
        ] {
            assert_eq!(ingest.verify_seal(&seal), Err(Error::InvalidSeal), "{name}");
        }

        // Verification does not poison: a seal that does not match is the sender's
        // to correct, and the pages that arrived are still good.
        assert!(!ingest.is_poisoned());
        assert_eq!(ingest.verify_seal(&valid), Ok(()));

        // A stream that has taken no page has nothing to seal.
        let empty = ProgressiveIngest::new([9; 16], PathProfile::Portable);
        assert_eq!(empty.verify_seal(&valid), Err(Error::Poisoned));
    }

    #[test]
    fn an_index_finds_every_path_it_holds_and_nothing_it_does_not() {
        // Sixteen paths, so the lookup depends on the order the index puts them in
        // rather than on where one of them happens to land.
        let paths: Vec<PackagePath> = (0..16)
            .map(|index| {
                PackagePath::portable([format!("dir{index}"), format!("file{index}.txt")]).unwrap()
            })
            .collect();

        let mut index = ManifestIndex::with_capacity(paths.len());
        // The capacity asked for is taken up front. A million entries growing an
        // entry at a time is the cost this constructor exists to avoid.
        assert!(index.entries.capacity() >= paths.len());

        for (position, path) in paths.iter().enumerate() {
            index
                .push(path, PathProfile::Portable, 3, position as u32)
                .expect("a valid path");
        }
        index.finish();

        for (position, path) in paths.iter().enumerate() {
            assert_eq!(
                index.candidates(path, PathProfile::Portable),
                vec![(3, position as u32)],
                "{path:?}"
            );
        }

        // A path nothing pushed, and a path this profile did not accept.
        assert!(
            index
                .candidates(
                    &PackagePath::portable(["absent"]).unwrap(),
                    PathProfile::Portable
                )
                .is_empty()
        );
        assert!(
            index
                .candidates(&PackagePath::raw([b"a"]).unwrap(), PathProfile::Portable)
                .is_empty()
        );

        // The same path under two entries answers with both, in the order they
        // were pushed.
        let mut twice = ManifestIndex::with_capacity(2);
        twice
            .push(&paths[0], PathProfile::Portable, 0, 0)
            .expect("a valid path");
        twice
            .push(&paths[0], PathProfile::Portable, 1, 1)
            .expect("a valid path");
        twice.finish();
        assert_eq!(
            twice.candidates(&paths[0], PathProfile::Portable),
            vec![(0, 0), (1, 1)]
        );

        // A path the profile refuses is not indexed, and the refusal is the
        // profile's rather than swallowed.
        assert_eq!(
            twice.push(
                &PackagePath::raw([b"a"]).unwrap(),
                PathProfile::Portable,
                0,
                0
            ),
            Err(Error::InvalidPath)
        );
    }

    #[test]
    fn a_page_at_its_decoding_edges_round_trips() {
        // A path of exactly as many components as one may have. The bound is the
        // count itself, so the page at it has to be readable.
        let deep = ManifestEntry {
            path: PackagePath::portable((0..MAX_PATH_COMPONENTS).map(|index| format!("c{index}")))
                .unwrap(),
            ..file("unused.txt")
        };
        let deep_page = ManifestPage {
            entries: vec![deep],
            ..page(0, [0; 32], "unused.txt")
        };
        let encoded = encode_page(&deep_page).expect("a page at the component bound");
        assert_eq!(decode_page(&encoded), Ok(deep_page));

        // A directory entry, which is the other kind a page may hold.
        let directory_page = ManifestPage {
            entries: vec![ManifestEntry {
                path: PackagePath::portable(["d"]).unwrap(),
                kind: EntryKind::Directory,
                length: None,
                storage: None,
                metadata: None,
            }],
            ..page(0, [0; 32], "d")
        };
        let encoded = encode_page(&directory_page).expect("a directory entry");
        assert_eq!(decode_page(&encoded), Ok(directory_page));

        // Metadata that states nothing. An empty map is as canonical as a full
        // one, and a decoder that read the field count as a lower bound would
        // refuse it.
        let bare_metadata = ManifestPage {
            entries: vec![ManifestEntry {
                metadata: Some(FileMetadata::default()),
                ..file("a.txt")
            }],
            ..page(0, [0; 32], "a.txt")
        };
        let encoded = encode_page(&bare_metadata).expect("metadata of no fields");
        assert_eq!(decode_page(&encoded), Ok(bare_metadata));

        // Metadata of every field it may carry, which is the other edge of the
        // same count.
        let full_metadata = ManifestPage {
            entries: vec![ManifestEntry {
                metadata: Some(FileMetadata {
                    mode: Some(420),
                    mtime_seconds: Some(-1),
                    mtime_nanoseconds: Some(999_999_999),
                    media_type: Some("text/plain".to_owned()),
                }),
                ..file("a.txt")
            }],
            ..page(0, [0; 32], "a.txt")
        };
        let encoded = encode_page(&full_metadata).expect("metadata of every field");
        assert_eq!(decode_page(&encoded), Ok(full_metadata));

        // And a byte after the page, which is not part of it.
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_page(&trailing), Err(DecodeError::InvalidStructure));
    }
}
