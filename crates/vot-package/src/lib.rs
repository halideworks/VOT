//! Filesystem-independent VOT package identity construction.

#![forbid(unsafe_code)]

use vot_manifest::{
    Component, EntryKind, Error as ManifestError, ManifestEntry, ObjectId, PackagePath,
    PathProfile, StorageRef, canonical_path_key, validate_entries,
};
use vot_verifier::{StreamVerifier, Suite, VerifyError};

const PACKAGE_DOMAIN: &[u8] = b"VOT package v0\0";

/// A package identity or logical-entry validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An entry path is not valid under the portable package profile.
    InvalidPath,
    /// An entry, storage reference, ordering relation, or counter is invalid.
    InvalidBundle,
    /// The package transcript verifier rejected an update or finalization.
    Verifier(VerifyError),
}

impl From<VerifyError> for Error {
    fn from(error: VerifyError) -> Self {
        Self::Verifier(error)
    }
}

/// The stored representation that supplies a logical package entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Storage {
    /// The logical object is stored directly.
    Direct,
    /// The logical object occupies a range within a pack object.
    Pack {
        /// The pack object's verification root.
        root: [u8; 32],
        /// The complete pack object's byte length.
        length: u64,
        /// The logical entry's byte offset within the pack.
        offset: u64,
    },
}

/// One file's logical identity and its storage representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryRecord {
    /// The portable package path.
    pub path: PackagePath,
    /// The logical object's verification suite.
    pub suite: Suite,
    /// The logical object's verification root.
    pub logical_root: [u8; 32],
    /// The logical object's byte length.
    pub logical_length: u64,
    /// The representation that supplies the logical bytes.
    pub storage: Storage,
}

impl EntryRecord {
    /// Constructs and validates the canonical manifest entry for this record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPath`] for a non-portable path and
    /// [`Error::InvalidBundle`] for an invalid object or packed range.
    pub fn manifest_entry(&self) -> Result<ManifestEntry, Error> {
        let logical = ObjectId {
            suite: suite_id(self.suite),
            root: self.logical_root,
            length: self.logical_length,
        };
        let storage = match self.storage {
            Storage::Direct => StorageRef::Direct(logical.clone()),
            Storage::Pack {
                root,
                length,
                offset,
            } => StorageRef::Pack {
                pack: ObjectId {
                    suite: suite_id(self.suite),
                    root,
                    length,
                },
                offset,
                length: self.logical_length,
                logical,
            },
        };
        let entry = ManifestEntry {
            path: self.path.clone(),
            kind: EntryKind::File,
            length: Some(self.logical_length),
            storage: Some(storage),
            metadata: None,
        };
        validate_manifest_entry(&entry)?;
        Ok(entry)
    }

    /// Converts a validated portable file manifest entry into package state.
    ///
    /// # Errors
    ///
    /// Rejects malformed paths, non-file or metadata-bearing entries, unknown
    /// suites, invalid object bounds, and inconsistent packed references.
    pub fn from_manifest(entry: ManifestEntry) -> Result<Self, Error> {
        validate_manifest_entry(&entry)?;
        if entry.kind != EntryKind::File {
            return Err(Error::InvalidBundle);
        }
        if entry.metadata.is_some() {
            return Err(Error::InvalidBundle);
        }
        let logical_length = entry.length.ok_or(Error::InvalidBundle)?;
        let storage = entry.storage.ok_or(Error::InvalidBundle)?;
        let (logical_root, suite, storage) = match storage {
            StorageRef::Direct(object) => {
                let suite = suite_from_id(object.suite)?;
                (object.root, suite, Storage::Direct)
            }
            StorageRef::Pack {
                pack,
                offset,
                length: _,
                logical,
            } => {
                let pack_suite = suite_from_id(pack.suite)?;
                let logical_suite = suite_from_id(logical.suite)?;
                if pack_suite != logical_suite {
                    return Err(Error::InvalidBundle);
                }
                (
                    logical.root,
                    logical_suite,
                    Storage::Pack {
                        root: pack.root,
                        length: pack.length,
                        offset,
                    },
                )
            }
        };
        Ok(Self {
            path: entry.path,
            suite,
            logical_root,
            logical_length,
            storage,
        })
    }
}

/// Incrementally constructs the canonical package identity transcript.
pub struct PackageRootBuilder {
    verifier: StreamVerifier,
    last_key: Option<Vec<u8>>,
    logical_length: u64,
    entries: u64,
    verifier_failure: Option<VerifyError>,
    #[cfg(test)]
    updates_before_failure: Option<usize>,
    #[cfg(test)]
    updates_applied: usize,
}

impl PackageRootBuilder {
    /// Starts a package transcript under the frozen package domain.
    ///
    /// # Errors
    ///
    /// Propagates a verifier initialization update failure.
    pub fn new() -> Result<Self, Error> {
        let mut verifier = StreamVerifier::new(Suite::Blake3Bao64);
        verifier.update(PACKAGE_DOMAIN)?;
        Ok(Self {
            verifier,
            last_key: None,
            logical_length: 0,
            entries: 0,
            verifier_failure: None,
            #[cfg(test)]
            updates_before_failure: None,
            #[cfg(test)]
            updates_applied: 0,
        })
    }

    /// Adds one logical entry in strictly increasing portable path order.
    ///
    /// # Errors
    ///
    /// Rejects invalid or out-of-order paths, counter overflow, and verifier
    /// update failures. Path, ordering, and counter rejection leave the
    /// builder unchanged. A verifier failure permanently poisons the builder.
    pub fn push(&mut self, record: &EntryRecord) -> Result<(), Error> {
        if let Some(error) = self.verifier_failure {
            return Err(Error::Verifier(error));
        }
        let encoded_path = encode_path(&record.path)?;
        let key = canonical_path_key(&record.path, PathProfile::Portable)
            .map_err(|_| Error::InvalidPath)?;
        if self
            .last_key
            .as_ref()
            .is_some_and(|last| key.as_slice() <= last.as_slice())
        {
            return Err(Error::InvalidBundle);
        }
        let logical_length = self
            .logical_length
            .checked_add(record.logical_length)
            .ok_or(Error::InvalidBundle)?;
        let entries = self.entries.checked_add(1).ok_or(Error::InvalidBundle)?;
        let verifier_result = (|| {
            self.update_verifier(&u32_len(encoded_path.len())?.to_be_bytes())?;
            self.update_verifier(&encoded_path)?;
            self.update_verifier(&suite_id(record.suite).to_be_bytes())?;
            self.update_verifier(&record.logical_length.to_be_bytes())?;
            self.update_verifier(&record.logical_root)?;
            Ok::<(), Error>(())
        })();
        if let Err(Error::Verifier(error)) = verifier_result {
            self.verifier_failure = Some(error);
            return Err(Error::Verifier(error));
        }
        verifier_result?;
        self.last_key = Some(key);
        self.logical_length = logical_length;
        self.entries = entries;
        Ok(())
    }

    /// Finalizes the package root and accumulated logical counters.
    ///
    /// # Errors
    ///
    /// Propagates a prior update failure or a verifier finalization failure.
    pub fn finish(self) -> Result<PackageSummary, Error> {
        if let Some(error) = self.verifier_failure {
            return Err(Error::Verifier(error));
        }
        Ok(PackageSummary {
            root: self.verifier.finish()?,
            logical_length: self.logical_length,
            entries: self.entries,
        })
    }

    fn update_verifier(&mut self, bytes: &[u8]) -> Result<(), Error> {
        #[cfg(test)]
        if self.updates_before_failure == Some(0) {
            self.updates_before_failure = None;
            return Err(Error::Verifier(VerifyError::LengthOverflow));
        }
        #[cfg(test)]
        if let Some(remaining) = &mut self.updates_before_failure {
            *remaining -= 1;
        }
        self.verifier.update(bytes)?;
        #[cfg(test)]
        {
            self.updates_applied += 1;
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_after_updates(mut self, updates: usize) -> Self {
        self.updates_before_failure = Some(updates);
        self
    }
}

/// The package identity and its logical aggregate sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageSummary {
    /// The canonical package transcript root.
    pub root: [u8; 32],
    /// The sum of all logical entry lengths.
    pub logical_length: u64,
    /// The number of logical entries.
    pub entries: u64,
}

const fn suite_id(suite: Suite) -> u16 {
    suite.identifier()
}

fn suite_from_id(identifier: u16) -> Result<Suite, Error> {
    Suite::try_from(identifier).map_err(|_| Error::InvalidBundle)
}

fn validate_manifest_entry(entry: &ManifestEntry) -> Result<(), Error> {
    validate_entries(std::slice::from_ref(entry), PathProfile::Portable).map_err(|error| {
        if error == ManifestError::InvalidPath {
            Error::InvalidPath
        } else {
            Error::InvalidBundle
        }
    })?;
    Ok(())
}

fn encode_path(path: &PackagePath) -> Result<Vec<u8>, Error> {
    let count = u16::try_from(path.len()).map_err(|_| Error::InvalidPath)?;
    let mut output = Vec::new();
    output.extend_from_slice(&count.to_be_bytes());
    for component in path {
        let Component::Text(text) = component else {
            return Err(Error::InvalidPath);
        };
        let length = u16::try_from(text.len()).map_err(|_| Error::InvalidPath)?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(text.as_bytes());
    }
    Ok(output)
}

fn u32_len(length: usize) -> Result<u32, Error> {
    u32::try_from(length).map_err(|_| Error::InvalidBundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_path(parts: &[&str]) -> PackagePath {
        parts
            .iter()
            .map(|part| Component::Text((*part).to_owned()))
            .collect()
    }

    fn direct(path: &[&str], suite: Suite, root: [u8; 32], length: u64) -> EntryRecord {
        EntryRecord {
            path: text_path(path),
            suite,
            logical_root: root,
            logical_length: length,
            storage: Storage::Direct,
        }
    }

    fn summary(record: &EntryRecord) -> PackageSummary {
        let mut builder = PackageRootBuilder::new().unwrap();
        builder.push(record).unwrap();
        builder.finish().unwrap()
    }

    fn hex(root: [u8; 32]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(64);
        for byte in root {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    fn root(value: &str) -> [u8; 32] {
        let mut decoded = [0; 32];
        for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *output = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        decoded
    }

    #[test]
    fn literal_package_roots_pin_the_transcript() {
        let empty = PackageRootBuilder::new().unwrap().finish().unwrap();
        assert_eq!(
            hex(empty.root),
            "66a92ee0faa1061fd8ff634e004efe9c3c0fcc6c59fb515e1c6873bcf5786fae"
        );
        assert_eq!(empty.logical_length, 0);
        assert_eq!(empty.entries, 0);

        let package = summary(&direct(&["a"], Suite::Sha256Bep52, [5; 32], 3));
        assert_eq!(
            hex(package.root),
            "7f3cd1557d0ff787da2cb3a7aa4f87d1db0befd9917dff09c938800766c505b9"
        );
        assert_eq!(package.logical_length, 3);
        assert_eq!(package.entries, 1);
    }

    #[test]
    fn wave4_logical_entries_reproduce_the_committed_package() {
        let cases = [
            (
                &["frames", "0001.txt"][..],
                "cf8ef05087b7a6113e6e6a3a9ce969052dd7f3a7ae08ef5a8f23755db78ef59d",
                10,
                0,
            ),
            (
                &["frames", "0002.txt"][..],
                "efae92ce8ccedb8a01f1bde1bf91956fb2e31cf6d7e6a998e1c3da74a545329e",
                10,
                16,
            ),
            (
                &["notes.txt"][..],
                "4707342f840357bb2cb4a27a9efd425220ae112513a4dab0053ed44908ba08c7",
                26,
                32,
            ),
        ];
        let pack_root = root("39a14efa9b17ab701742d940edf62fc16a4ad800a581d99e283d68e6c7fec76d");
        let mut builder = PackageRootBuilder::new().unwrap();
        for (path, logical_root, length, offset) in cases {
            builder
                .push(&EntryRecord {
                    path: text_path(path),
                    suite: Suite::Sha256Bep52,
                    logical_root: root(logical_root),
                    logical_length: length,
                    storage: Storage::Pack {
                        root: pack_root,
                        length: 58,
                        offset,
                    },
                })
                .unwrap();
        }
        let package = builder.finish().unwrap();
        assert_eq!(
            hex(package.root),
            "4ff7f2527a6a80d7d6fc3ba8cb74ca3638f0d6f4ef1af6ff37ee7401eec89105"
        );
        assert_eq!(package.logical_length, 46);
        assert_eq!(package.entries, 3);
    }

    #[test]
    fn identity_uses_every_logical_field_but_not_storage() {
        let base = direct(&["a"], Suite::Sha256Bep52, [5; 32], 3);
        let expected = summary(&base);
        assert_ne!(
            expected.root,
            summary(&direct(&["b"], base.suite, [5; 32], 3)).root
        );
        assert_ne!(
            expected.root,
            summary(&direct(&["a"], Suite::Blake3Bao64, [5; 32], 3)).root
        );
        assert_ne!(
            expected.root,
            summary(&direct(&["a"], base.suite, [6; 32], 3)).root
        );
        assert_ne!(
            expected.root,
            summary(&direct(&["a"], base.suite, [5; 32], 4)).root
        );

        let packed = EntryRecord {
            storage: Storage::Pack {
                root: [9; 32],
                length: 20,
                offset: 7,
            },
            ..base
        };
        assert_eq!(expected, summary(&packed));
    }

    #[test]
    fn paths_must_be_valid_and_strictly_canonically_ordered() {
        let mut reversed = PackageRootBuilder::new().unwrap();
        reversed
            .push(&direct(&["b"], Suite::Sha256Bep52, [1; 32], 1))
            .unwrap();
        assert_eq!(
            reversed.push(&direct(&["a"], Suite::Sha256Bep52, [2; 32], 1)),
            Err(Error::InvalidBundle)
        );

        let mut collision = PackageRootBuilder::new().unwrap();
        collision
            .push(&direct(&["A"], Suite::Sha256Bep52, [1; 32], 1))
            .unwrap();
        assert_eq!(
            collision.push(&direct(&["a"], Suite::Sha256Bep52, [2; 32], 1)),
            Err(Error::InvalidBundle)
        );

        let mut invalid = PackageRootBuilder::new().unwrap();
        let mut empty = direct(&["a"], Suite::Sha256Bep52, [1; 32], 1);
        empty.path.clear();
        assert_eq!(invalid.push(&empty), Err(Error::InvalidPath));
        let raw = EntryRecord {
            path: vec![Component::Bytes(b"raw".to_vec())],
            ..direct(&["a"], Suite::Sha256Bep52, [1; 32], 1)
        };
        assert_eq!(invalid.push(&raw), Err(Error::InvalidPath));
    }

    #[test]
    fn package_counters_reject_overflow() {
        let record = direct(&["a"], Suite::Sha256Bep52, [1; 32], 1);
        let mut length = PackageRootBuilder::new().unwrap();
        length.logical_length = u64::MAX;
        assert_eq!(length.push(&record), Err(Error::InvalidBundle));

        let mut entries = PackageRootBuilder::new().unwrap();
        entries.entries = u64::MAX;
        assert_eq!(entries.push(&record), Err(Error::InvalidBundle));
    }

    #[test]
    fn manifest_conversion_preserves_direct_and_packed_storage() {
        let direct_record = direct(&["file"], Suite::Sha256Bep52, [3; 32], 3);
        let restored = EntryRecord::from_manifest(direct_record.manifest_entry().unwrap()).unwrap();
        assert_eq!(restored.path, direct_record.path);
        assert_eq!(restored.suite, direct_record.suite);
        assert_eq!(restored.logical_root, direct_record.logical_root);
        assert_eq!(restored.logical_length, direct_record.logical_length);
        assert!(matches!(restored.storage, Storage::Direct));

        let packed_record = EntryRecord {
            storage: Storage::Pack {
                root: [4; 32],
                length: 8,
                offset: 2,
            },
            ..direct(&["file"], Suite::Sha256Bep52, [3; 32], 3)
        };
        let restored = EntryRecord::from_manifest(packed_record.manifest_entry().unwrap()).unwrap();
        match restored.storage {
            Storage::Pack {
                root,
                length,
                offset,
            } => {
                assert_eq!(root, [4; 32]);
                assert_eq!(length, 8);
                assert_eq!(offset, 2);
            }
            Storage::Direct => panic!("packed storage became direct"),
        }
    }

    #[test]
    fn manifest_conversion_rejects_invalid_direct_entries() {
        let logical = ObjectId {
            suite: 2,
            root: [3; 32],
            length: 3,
        };
        let direct = ManifestEntry {
            path: text_path(&["file"]),
            kind: EntryKind::File,
            length: Some(3),
            storage: Some(StorageRef::Direct(logical.clone())),
            metadata: None,
        };
        let mut wrong = direct.clone();
        wrong.kind = EntryKind::Directory;
        assert_eq!(
            EntryRecord::from_manifest(wrong).err(),
            Some(Error::InvalidBundle)
        );
        let mut wrong = direct.clone();
        wrong.metadata = Some(vot_manifest::FileMetadata::default());
        assert_eq!(
            EntryRecord::from_manifest(wrong).err(),
            Some(Error::InvalidBundle)
        );
        let mut wrong = direct.clone();
        wrong.length = None;
        assert_eq!(
            EntryRecord::from_manifest(wrong).err(),
            Some(Error::InvalidBundle)
        );
        let mut wrong = direct.clone();
        wrong.storage = None;
        assert_eq!(
            EntryRecord::from_manifest(wrong).err(),
            Some(Error::InvalidBundle)
        );
        let mut wrong = direct.clone();
        wrong.storage = Some(StorageRef::Direct(ObjectId {
            suite: 99,
            ..logical.clone()
        }));
        assert_eq!(
            EntryRecord::from_manifest(wrong).err(),
            Some(Error::InvalidBundle)
        );
        let mut wrong = direct.clone();
        wrong.storage = Some(StorageRef::Direct(ObjectId {
            length: 2,
            ..logical.clone()
        }));
        assert_eq!(
            EntryRecord::from_manifest(wrong).err(),
            Some(Error::InvalidBundle)
        );
    }

    #[test]
    fn manifest_conversion_rejects_invalid_packed_entries() {
        let logical = ObjectId {
            suite: 2,
            root: [3; 32],
            length: 3,
        };
        let direct = ManifestEntry {
            path: text_path(&["file"]),
            kind: EntryKind::File,
            length: Some(3),
            storage: Some(StorageRef::Direct(logical.clone())),
            metadata: None,
        };
        let pack = ObjectId {
            suite: 2,
            root: [4; 32],
            length: 8,
        };
        let packed = |pack: ObjectId, length: u64, logical: ObjectId| ManifestEntry {
            storage: Some(StorageRef::Pack {
                pack,
                offset: 0,
                length,
                logical,
            }),
            ..direct.clone()
        };
        assert!(EntryRecord::from_manifest(packed(pack.clone(), 3, logical.clone())).is_ok());
        assert!(
            EntryRecord::from_manifest(packed(
                ObjectId {
                    suite: 1,
                    ..pack.clone()
                },
                3,
                logical.clone(),
            ))
            .is_err()
        );
        assert!(
            EntryRecord::from_manifest(packed(
                pack.clone(),
                3,
                ObjectId {
                    suite: 1,
                    ..logical.clone()
                },
            ))
            .is_err()
        );
        assert!(EntryRecord::from_manifest(packed(pack.clone(), 2, logical.clone())).is_err());
        assert!(
            EntryRecord::from_manifest(packed(
                pack,
                3,
                ObjectId {
                    length: 2,
                    ..logical
                },
            ))
            .is_err()
        );
    }

    #[test]
    fn rejected_counter_overflow_does_not_enter_the_transcript() {
        let first = direct(&["a"], Suite::Sha256Bep52, [1; 32], 1);
        let rejected = direct(&["b"], Suite::Sha256Bep52, [2; 32], 1);

        let mut expected = PackageRootBuilder::new().unwrap();
        expected.push(&first).unwrap();
        let expected = expected.finish().unwrap();

        let mut length_overflow = PackageRootBuilder::new().unwrap();
        length_overflow.push(&first).unwrap();
        length_overflow.logical_length = u64::MAX;
        assert_eq!(length_overflow.push(&rejected), Err(Error::InvalidBundle));
        length_overflow.logical_length = first.logical_length;
        assert_eq!(length_overflow.finish().unwrap(), expected);

        let mut entry_overflow = PackageRootBuilder::new().unwrap();
        entry_overflow.push(&first).unwrap();
        entry_overflow.entries = u64::MAX;
        assert_eq!(entry_overflow.push(&rejected), Err(Error::InvalidBundle));
        entry_overflow.entries = 1;
        assert_eq!(entry_overflow.finish().unwrap(), expected);
    }

    #[test]
    fn verifier_failure_permanently_poisoned_a_partial_record() {
        let first = direct(&["a"], Suite::Sha256Bep52, [1; 32], 1);
        let second = direct(&["b"], Suite::Sha256Bep52, [2; 32], 1);
        let mut builder = PackageRootBuilder::new().unwrap().fail_after_updates(2);

        let expected = Error::Verifier(VerifyError::LengthOverflow);
        assert_eq!(builder.push(&first), Err(expected));
        assert_eq!(builder.updates_applied, 2);
        assert_eq!(builder.push(&second), Err(expected));
        assert_eq!(builder.finish(), Err(expected));
    }

    #[test]
    fn manifest_conversion_enforces_packed_boundaries_and_path_validity() {
        const MAX_LOGICAL: u64 = 262_144;
        const MAX_PACK: u64 = 134_217_728;

        let boundary = EntryRecord {
            path: text_path(&["file"]),
            suite: Suite::Sha256Bep52,
            logical_root: [3; 32],
            logical_length: MAX_LOGICAL,
            storage: Storage::Pack {
                root: [4; 32],
                length: MAX_PACK,
                offset: MAX_PACK - MAX_LOGICAL,
            },
        };
        assert!(boundary.manifest_entry().is_ok());

        let logical_too_large = EntryRecord {
            logical_length: MAX_LOGICAL + 1,
            ..boundary.clone()
        };
        assert_eq!(
            logical_too_large.manifest_entry().err(),
            Some(Error::InvalidBundle)
        );
        let pack_too_large = EntryRecord {
            storage: Storage::Pack {
                root: [4; 32],
                length: MAX_PACK + 1,
                offset: MAX_PACK - MAX_LOGICAL,
            },
            ..boundary.clone()
        };
        assert_eq!(
            pack_too_large.manifest_entry().err(),
            Some(Error::InvalidBundle)
        );
        let range_past_pack = EntryRecord {
            storage: Storage::Pack {
                root: [4; 32],
                length: MAX_PACK,
                offset: MAX_PACK - MAX_LOGICAL + 1,
            },
            ..boundary.clone()
        };
        assert_eq!(
            range_past_pack.manifest_entry().err(),
            Some(Error::InvalidBundle)
        );
        let range_overflow = EntryRecord {
            storage: Storage::Pack {
                root: [4; 32],
                length: MAX_PACK,
                offset: u64::MAX,
            },
            ..boundary.clone()
        };
        assert_eq!(
            range_overflow.manifest_entry().err(),
            Some(Error::InvalidBundle)
        );

        let mut malformed_path = boundary.clone();
        malformed_path.path.clear();
        assert_eq!(
            malformed_path.manifest_entry().err(),
            Some(Error::InvalidPath)
        );

        let mut hostile = boundary.manifest_entry().unwrap();
        hostile.storage = Some(StorageRef::Pack {
            pack: ObjectId {
                suite: 2,
                root: [4; 32],
                length: MAX_PACK,
            },
            offset: u64::MAX,
            length: MAX_LOGICAL,
            logical: ObjectId {
                suite: 2,
                root: [3; 32],
                length: MAX_LOGICAL,
            },
        });
        assert_eq!(
            EntryRecord::from_manifest(hostile).err(),
            Some(Error::InvalidBundle)
        );
    }
}
