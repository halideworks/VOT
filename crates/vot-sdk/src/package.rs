//! Portable package construction and sealed manifest ingest.

use crate::error;
use crate::object::{ObjectId, Suite};
use crate::{Error, ErrorCode};
use vot_manifest::Component;

/// Stored representation of one logical package entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryStorage {
    Direct,
    Pack { object: ObjectId, offset: u64 },
}

/// Validated portable file entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEntry {
    inner: vot_package::EntryRecord,
}

impl PackageEntry {
    pub fn direct(path: Vec<String>, object: &ObjectId) -> Result<Self, Error> {
        Self::new(path, object, None)
    }

    pub fn packed(
        path: Vec<String>,
        logical: &ObjectId,
        pack: &ObjectId,
        offset: u64,
    ) -> Result<Self, Error> {
        if logical.suite != pack.suite {
            return Err(Error::new(ErrorCode::InvalidInput));
        }
        Self::new(path, logical, Some((pack, offset)))
    }

    fn new(
        path: Vec<String>,
        logical: &ObjectId,
        pack: Option<(&ObjectId, u64)>,
    ) -> Result<Self, Error> {
        let suite =
            Suite::try_from(logical.suite).map_err(|_| Error::new(ErrorCode::Unsupported))?;
        let storage = match pack {
            None => vot_package::Storage::Direct,
            Some((pack, offset)) => vot_package::Storage::Pack {
                root: pack.root,
                length: pack.length,
                offset,
            },
        };
        let inner = vot_package::EntryRecord {
            path: path.into_iter().map(Component::Text).collect(),
            suite,
            logical_root: logical.root,
            logical_length: logical.length,
            storage,
        };
        inner.manifest_entry().map_err(error::package)?;
        Ok(Self { inner })
    }

    #[must_use]
    pub fn path(&self) -> impl ExactSizeIterator<Item = &str> {
        self.inner.path.iter().map(|component| match component {
            Component::Text(text) => text.as_str(),
            Component::Bytes(_) => unreachable!("validated portable package path"),
        })
    }

    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        ObjectId {
            suite: self.inner.suite.identifier(),
            root: self.inner.logical_root,
            length: self.inner.logical_length,
        }
    }

    #[must_use]
    pub fn storage(&self) -> EntryStorage {
        match self.inner.storage {
            vot_package::Storage::Direct => EntryStorage::Direct,
            vot_package::Storage::Pack {
                root,
                length,
                offset,
            } => EntryStorage::Pack {
                object: ObjectId {
                    suite: self.inner.suite.identifier(),
                    root,
                    length,
                },
                offset,
            },
        }
    }

    fn from_inner(inner: vot_package::EntryRecord) -> Self {
        Self { inner }
    }
}

/// Canonical package identity and aggregate logical sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageSummary {
    root: [u8; 32],
    logical_length: u64,
    entries: u64,
}

impl PackageSummary {
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    #[must_use]
    pub const fn logical_length(&self) -> u64 {
        self.logical_length
    }

    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }

    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        ObjectId {
            suite: Suite::Blake3Bao64.identifier(),
            root: self.root,
            length: self.logical_length,
        }
    }

    const fn from_inner(summary: vot_package::PackageSummary) -> Self {
        Self {
            root: summary.root,
            logical_length: summary.logical_length,
            entries: summary.entries,
        }
    }
}

/// Incremental package and bounded page-draft builder.
pub struct PackageBuilder {
    inner: vot_package::PackageBuilder,
}

impl PackageBuilder {
    pub fn new() -> Result<Self, Error> {
        vot_package::PackageBuilder::new()
            .map(|inner| Self { inner })
            .map_err(error::package)
    }

    pub fn push(&mut self, entry: &PackageEntry) -> Result<Option<PageDraft>, Error> {
        self.inner
            .push(&entry.inner)
            .map(|draft| draft.map(|inner| PageDraft { inner }))
            .map_err(error::package)
    }

    pub fn finish(self) -> Result<PackageAssembly, Error> {
        let assembly = self.inner.finish().map_err(error::package)?;
        Ok(PackageAssembly {
            summary: PackageSummary::from_inner(assembly.summary),
            final_page: PageDraft {
                inner: assembly.final_page,
            },
            finalizer: ManifestFinalizer {
                inner: assembly.finalizer,
            },
        })
    }
}

/// Host-spoolable page awaiting final package identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageDraft {
    inner: vot_package::PageDraft,
}

impl PageDraft {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.inner.encode().map_err(error::package)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        vot_package::PageDraft::decode(bytes)
            .map(|inner| Self { inner })
            .map_err(error::package)
    }
}

/// Completed identity, final draft, and manifest finalizer.
pub struct PackageAssembly {
    summary: PackageSummary,
    final_page: PageDraft,
    finalizer: ManifestFinalizer,
}

impl PackageAssembly {
    #[must_use]
    pub fn into_parts(self) -> (PackageSummary, PageDraft, ManifestFinalizer) {
        (self.summary, self.final_page, self.finalizer)
    }
}

/// Converts ordered page drafts into canonical pages and a seal.
pub struct ManifestFinalizer {
    inner: vot_package::ManifestFinalizer,
}

impl ManifestFinalizer {
    pub fn push(&mut self, draft: PageDraft) -> Result<EncodedManifestPage, Error> {
        self.inner
            .push(draft.inner)
            .map(|encoded| EncodedManifestPage {
                bytes: encoded.bytes,
            })
            .map_err(error::package)
    }

    pub fn finish(self) -> Result<EncodedSeal, Error> {
        self.inner
            .finish()
            .map(|encoded| EncodedSeal {
                bytes: encoded.bytes,
            })
            .map_err(error::package)
    }
}

/// Canonical manifest page bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedManifestPage {
    bytes: Vec<u8>,
}

impl EncodedManifestPage {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Canonical manifest seal bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedSeal {
    bytes: Vec<u8>,
}

impl EncodedSeal {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Incremental verification of a sealed package manifest.
pub struct PackageIngest {
    inner: vot_package::PackageIngest,
}

impl PackageIngest {
    /// Starts ingest only when the seal authenticates the expected identity.
    pub fn new_expected(encoded_seal: &[u8], expected: &ObjectId) -> Result<Self, Error> {
        vot_package::PackageIngest::new_expected(encoded_seal, expected)
            .map(|inner| Self { inner })
            .map_err(error::package)
    }

    #[must_use]
    pub fn page_count(&self) -> u64 {
        self.inner.page_count()
    }

    pub fn push_page(&mut self, encoded_page: &[u8]) -> Result<ValidatedManifestPage, Error> {
        self.inner
            .push_page(encoded_page)
            .map(|page| ValidatedManifestPage {
                entries: page
                    .into_entries()
                    .into_iter()
                    .map(PackageEntry::from_inner)
                    .collect(),
            })
            .map_err(error::package)
    }

    pub fn finish(self) -> Result<PackageSummary, Error> {
        self.inner
            .finish()
            .map(PackageSummary::from_inner)
            .map_err(error::package)
    }
}

/// Entries from a structurally validated page.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "page entries are not authenticated until PackageIngest::finish succeeds"]
pub struct ValidatedManifestPage {
    entries: Vec<PackageEntry>,
}

impl ValidatedManifestPage {
    #[must_use]
    pub fn entries(&self) -> &[PackageEntry] {
        &self.entries
    }

    #[must_use]
    pub fn into_entries(self) -> Vec<PackageEntry> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_manifest::{ManifestPage, PageCommitment, PathProfile, Seal, encode_page, encode_seal};

    fn record(name: &str, root: u8) -> vot_package::EntryRecord {
        vot_package::EntryRecord {
            path: vec![Component::Text(name.to_owned())],
            suite: Suite::Sha256Bep52,
            logical_root: [root; 32],
            logical_length: u64::from(root),
            storage: vot_package::Storage::Direct,
        }
    }

    #[test]
    fn ingest_reports_and_validates_two_committed_pages() {
        let first = record("a", 2);
        let second = record("b", 3);
        let mut root = vot_package::PackageRootBuilder::new().unwrap();
        root.push(&first).unwrap();
        root.push(&second).unwrap();
        let summary = root.finish().unwrap();
        let manifest_id = [7; 16];
        let first_page = ManifestPage {
            manifest_id,
            index: 0,
            total: Some(2),
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: vec![first.manifest_entry().unwrap()],
        };
        let first_bytes = encode_page(&first_page).unwrap();
        let first_digest = *blake3::hash(&first_bytes).as_bytes();
        let second_page = ManifestPage {
            manifest_id,
            index: 1,
            total: Some(2),
            previous_digest: first_digest,
            profile: PathProfile::Portable,
            entries: vec![second.manifest_entry().unwrap()],
        };
        let second_bytes = encode_page(&second_page).unwrap();
        let second_digest = *blake3::hash(&second_bytes).as_bytes();
        let seal = Seal {
            manifest_id,
            final_page_count: 2,
            final_page_digest: second_digest,
            package: ObjectId {
                suite: Suite::Blake3Bao64.identifier(),
                root: summary.root,
                length: summary.logical_length,
            },
            pages: vec![
                PageCommitment {
                    index: 0,
                    digest: first_digest,
                },
                PageCommitment {
                    index: 1,
                    digest: second_digest,
                },
            ],
        };
        let seal_bytes = encode_seal(&seal).unwrap();
        let expected = PackageSummary::from_inner(summary);
        let mut ingest = PackageIngest::new_expected(&seal_bytes, &expected.object_id()).unwrap();
        assert_eq!(ingest.page_count(), 2);
        assert_eq!(ingest.push_page(&first_bytes).unwrap().entries().len(), 1);
        let entries = ingest.push_page(&second_bytes).unwrap().into_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].object_id().root, [3; 32]);
        assert_eq!(expected.entries(), 2);
        assert_eq!(ingest.finish().unwrap(), expected);
    }
}
