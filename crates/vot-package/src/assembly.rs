//! Bounded package and manifest assembly.

use std::mem;

use vot_manifest::{
    MAX_ENTRIES_PER_PAGE, MAX_PAGE_BYTES, MAX_PAGE_COMMITMENTS, ManifestEntry, ManifestPage,
    ObjectId, PageCommitment, PathProfile, Seal, decode_page, encode_page, encode_seal,
};
use vot_verifier::Suite;

use crate::{EntryRecord, Error, PackageRootBuilder, PackageSummary};

const MAX_PAGE_INDEX_ENCODING_GROWTH: usize = 8;

/// A value and its canonical encoded bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Encoded<T> {
    /// The structured value.
    pub value: T,
    /// The canonical encoding of `value`.
    pub bytes: Vec<u8>,
}

/// One bounded manifest page awaiting the completed package root.
///
/// Draft bytes are temporary construction state, not a persistent VOT format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageDraft {
    index: u64,
    entries: Vec<ManifestEntry>,
}

impl PageDraft {
    /// Returns this draft's final page index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the ordered entries held by this draft.
    #[must_use]
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Encodes the draft for temporary host-owned spooling.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBundle`] if the draft violates manifest bounds.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        encode_page(&self.placeholder()).map_err(|_| Error::InvalidBundle)
    }

    /// Decodes a canonical temporary draft produced by [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, finalized, empty, or out-of-range pages.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let page = decode_page(input).map_err(|_| Error::InvalidBundle)?;
        let index = usize::try_from(page.index).map_err(|_| Error::InvalidBundle)?;
        if page.manifest_id != [0; 16] {
            return Err(Error::InvalidBundle);
        }
        if page.total.is_some() {
            return Err(Error::InvalidBundle);
        }
        if page.previous_digest != [0; 32] {
            return Err(Error::InvalidBundle);
        }
        if page.profile != PathProfile::Portable {
            return Err(Error::InvalidBundle);
        }
        if page.entries.is_empty() {
            return Err(Error::InvalidBundle);
        }
        if index >= MAX_PAGE_COMMITMENTS {
            return Err(Error::InvalidBundle);
        }
        Ok(Self {
            index: page.index,
            entries: page.entries,
        })
    }

    fn placeholder(&self) -> ManifestPage {
        ManifestPage {
            manifest_id: [0; 16],
            index: self.index,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: self.entries.clone(),
        }
    }

    fn digest(&self) -> Result<[u8; 32], Error> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}

/// Incrementally builds package identity and bounded manifest page drafts.
pub struct PackageBuilder {
    identity: PackageRootBuilder,
    entries: Vec<ManifestEntry>,
    estimated_bytes: usize,
    emitted_pages: usize,
    draft_digests: Vec<[u8; 32]>,
    failure: Option<Error>,
}

impl PackageBuilder {
    /// Starts an empty package construction.
    ///
    /// # Errors
    ///
    /// Propagates package identity initialization failure.
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            identity: PackageRootBuilder::new()?,
            entries: Vec::new(),
            estimated_bytes: 0,
            emitted_pages: 0,
            draft_digests: Vec::new(),
            failure: None,
        })
    }

    /// Adds one ordered logical entry and emits a completed bounded draft when needed.
    ///
    /// # Errors
    ///
    /// Rejects invalid entries, identity failures, ordering errors, arithmetic
    /// overflow, and manifests that cannot fit in one bounded seal.
    pub fn push(&mut self, record: &EntryRecord) -> Result<Option<PageDraft>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        match self.push_inner(record) {
            Err(error @ Error::Verifier(_)) => {
                self.failure = Some(error);
                Err(error)
            }
            result => result,
        }
    }

    fn push_inner(&mut self, record: &EntryRecord) -> Result<Option<PageDraft>, Error> {
        let entry = record.manifest_entry()?;
        let entry_bytes = encoded_entry_bytes(&entry)?;
        let flush = page_needs_flush(self.entries.len(), self.estimated_bytes, entry_bytes)?;
        let current_index = u64::try_from(self.emitted_pages).map_err(|_| Error::InvalidBundle)?;
        let candidate_estimated_bytes = self
            .estimated_bytes
            .checked_add(entry_bytes)
            .ok_or(Error::InvalidBundle)?;
        if should_check_actual_page(flush, current_index, candidate_estimated_bytes) {
            PageDraft {
                index: current_index,
                entries: self
                    .entries
                    .iter()
                    .cloned()
                    .chain([entry.clone()])
                    .collect(),
            }
            .encode()?;
        }
        let next_estimated_bytes = if flush {
            entry_bytes
        } else {
            candidate_estimated_bytes
        };
        let next_emitted_pages = self
            .emitted_pages
            .checked_add(usize::from(flush))
            .ok_or(Error::InvalidBundle)?;
        if next_emitted_pages >= MAX_PAGE_COMMITMENTS {
            return Err(Error::InvalidBundle);
        }
        let prepared_draft = if flush {
            let draft = PageDraft {
                index: current_index,
                entries: self.entries.clone(),
            };
            let digest = draft.digest()?;
            let next_index = u64::try_from(next_emitted_pages).map_err(|_| Error::InvalidBundle)?;
            PageDraft {
                index: next_index,
                entries: vec![entry.clone()],
            }
            .encode()?;
            Some((draft, digest))
        } else {
            None
        };

        self.identity.push(record)?;
        let draft = prepared_draft.map(|(draft, digest)| {
            self.draft_digests.push(digest);
            mem::take(&mut self.entries);
            draft
        });
        self.entries.push(entry);
        self.estimated_bytes = next_estimated_bytes;
        self.emitted_pages = next_emitted_pages;
        Ok(draft)
    }

    /// Finishes package identity and returns the final draft and its finalizer.
    ///
    /// # Errors
    ///
    /// Rejects an empty package, an oversized page catalog, or an identity
    /// finalization failure.
    pub fn finish(mut self) -> Result<PackageAssembly, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.entries.is_empty() {
            return Err(Error::InvalidBundle);
        }
        let final_index = u64::try_from(self.emitted_pages).map_err(|_| Error::InvalidBundle)?;
        let final_page = PageDraft {
            index: final_index,
            entries: self.entries,
        };
        self.draft_digests.push(final_page.digest()?);
        let summary = self.identity.finish()?;
        let finalizer = ManifestFinalizer::new(summary, self.draft_digests)?;
        Ok(PackageAssembly {
            summary,
            final_page,
            finalizer,
        })
    }
}

/// The outputs needed to finalize host-spooled page drafts.
pub struct PackageAssembly {
    /// The completed canonical package identity.
    pub summary: PackageSummary,
    /// The final nonempty page draft.
    pub final_page: PageDraft,
    /// The state that chains every draft and emits the seal.
    pub finalizer: ManifestFinalizer,
}

/// Converts ordered page drafts into chained final pages and a seal.
pub struct ManifestFinalizer {
    summary: PackageSummary,
    manifest_id: [u8; 16],
    expected_drafts: Vec<[u8; 32]>,
    next_page: usize,
    previous_digest: [u8; 32],
    commitments: Vec<PageCommitment>,
    identity: PackageRootBuilder,
    poisoned: bool,
}

impl ManifestFinalizer {
    fn new(summary: PackageSummary, expected_drafts: Vec<[u8; 32]>) -> Result<Self, Error> {
        let expected_pages = expected_drafts.len();
        let mut manifest_id = [0; 16];
        manifest_id.copy_from_slice(&summary.root[..16]);
        Ok(Self {
            summary,
            manifest_id,
            expected_drafts,
            next_page: 0,
            previous_digest: [0; 32],
            commitments: Vec::with_capacity(expected_pages),
            identity: PackageRootBuilder::new()?,
            poisoned: false,
        })
    }

    /// Finalizes the next draft in strict index and identity order.
    ///
    /// # Errors
    ///
    /// Rejects a missing, duplicate, reordered, malformed, or identity-invalid
    /// draft. Any rejection permanently poisons the finalizer.
    pub fn push(&mut self, draft: PageDraft) -> Result<Encoded<ManifestPage>, Error> {
        if self.poisoned {
            return Err(Error::InvalidBundle);
        }
        let result = self.push_inner(draft);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn push_inner(&mut self, draft: PageDraft) -> Result<Encoded<ManifestPage>, Error> {
        if self.next_page == self.expected_drafts.len() {
            return Err(Error::InvalidBundle);
        }
        if draft.digest()? != self.expected_drafts[self.next_page] {
            return Err(Error::InvalidBundle);
        }
        let page = ManifestPage {
            manifest_id: self.manifest_id,
            index: draft.index,
            total: None,
            previous_digest: self.previous_digest,
            profile: PathProfile::Portable,
            entries: draft.entries,
        };
        let bytes = encode_page(&page).map_err(|_| Error::InvalidBundle)?;
        let digest = *blake3::hash(&bytes).as_bytes();
        for entry in page.entries.iter().cloned() {
            self.identity.push(&EntryRecord::from_manifest(entry)?)?;
        }

        self.commitments.push(PageCommitment {
            index: page.index,
            digest,
        });
        self.previous_digest = digest;
        self.next_page += 1;
        Ok(Encoded { value: page, bytes })
    }

    /// Emits the canonical seal after every expected page was finalized.
    ///
    /// # Errors
    ///
    /// Rejects poisoned or incomplete state and any manifest whose entries do
    /// not reconstruct the package identity supplied at construction.
    pub fn finish(self) -> Result<Encoded<Seal>, Error> {
        if self.poisoned {
            return Err(Error::InvalidBundle);
        }
        if self.next_page != self.expected_drafts.len() {
            return Err(Error::InvalidBundle);
        }
        if self.identity.finish()? != self.summary {
            return Err(Error::InvalidBundle);
        }
        let seal = Seal {
            manifest_id: self.manifest_id,
            final_page_count: u64::try_from(self.expected_drafts.len())
                .map_err(|_| Error::InvalidBundle)?,
            final_page_digest: self.previous_digest,
            package: ObjectId {
                suite: Suite::Blake3Bao64.identifier(),
                root: self.summary.root,
                length: self.summary.logical_length,
            },
            pages: self.commitments,
        };
        let bytes = encode_seal(&seal).map_err(|_| Error::InvalidBundle)?;
        Ok(Encoded { value: seal, bytes })
    }
}

fn encoded_entry_bytes(entry: &ManifestEntry) -> Result<usize, Error> {
    encode_page(&ManifestPage {
        manifest_id: [0; 16],
        index: 0,
        total: None,
        previous_digest: [0; 32],
        profile: PathProfile::Portable,
        entries: vec![entry.clone()],
    })
    .map(|encoded| encoded.len())
    .map_err(|_| Error::InvalidBundle)
}

fn page_needs_flush(
    entries: usize,
    estimated_bytes: usize,
    next_entry_bytes: usize,
) -> Result<bool, Error> {
    let estimated = estimated_bytes
        .checked_add(next_entry_bytes)
        .ok_or(Error::InvalidBundle)?;
    Ok(entries == MAX_ENTRIES_PER_PAGE || (entries != 0 && estimated > MAX_PAGE_BYTES))
}

fn page_index_may_cross_bound(index: u64, estimated_bytes: usize) -> bool {
    index != 0 && estimated_bytes > MAX_PAGE_BYTES.saturating_sub(MAX_PAGE_INDEX_ENCODING_GROWTH)
}

fn should_check_actual_page(flush: bool, index: u64, estimated_bytes: usize) -> bool {
    !flush && page_index_may_cross_bound(index, estimated_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_manifest::{Component, StorageRef};

    fn record(name: &str, root: u8) -> EntryRecord {
        EntryRecord {
            path: vec![Component::Text(name.to_owned())],
            suite: Suite::Sha256Bep52,
            logical_root: [root; 32],
            logical_length: 3,
            storage: crate::Storage::Direct,
        }
    }

    fn packed_record(name: &str, root: u8) -> EntryRecord {
        EntryRecord {
            storage: crate::Storage::Pack {
                root: [9; 32],
                length: 8,
                offset: 2,
            },
            ..record(name, root)
        }
    }

    #[test]
    fn one_page_build_emits_the_existing_envelope_and_seal() {
        let first = record("a", 1);
        let second = record("b", 2);
        let mut builder = PackageBuilder::new().unwrap();
        assert!(builder.push(&first).unwrap().is_none());
        assert!(builder.push(&second).unwrap().is_none());
        let PackageAssembly {
            summary,
            final_page,
            mut finalizer,
        } = builder.finish().unwrap();

        assert_eq!(final_page.index(), 0);
        assert_eq!(
            PageDraft::decode(&final_page.encode().unwrap()).unwrap(),
            final_page
        );
        let completed = finalizer.push(final_page).unwrap();
        assert_eq!(completed.value.manifest_id, summary.root[..16]);
        assert_eq!(completed.value.index, 0);
        assert_eq!(completed.value.previous_digest, [0; 32]);
        assert_eq!(encode_page(&completed.value).unwrap(), completed.bytes);

        let sealed = finalizer.finish().unwrap();
        assert_eq!(sealed.value.manifest_id, summary.root[..16]);
        assert_eq!(sealed.value.final_page_count, 1);
        assert_eq!(
            sealed.value.final_page_digest,
            *blake3::hash(&completed.bytes).as_bytes()
        );
        assert_eq!(sealed.value.package.root, summary.root);
        assert_eq!(sealed.value.package.length, summary.logical_length);
        assert_eq!(encode_seal(&sealed.value).unwrap(), sealed.bytes);
    }

    #[test]
    fn page_drafts_chain_without_retaining_previous_entries() {
        let mut builder = PackageBuilder::new().unwrap();
        builder.push(&record("a", 1)).unwrap();
        builder.estimated_bytes = MAX_PAGE_BYTES;
        let first = builder.push(&record("b", 2)).unwrap().unwrap();
        let PackageAssembly {
            final_page,
            mut finalizer,
            ..
        } = builder.finish().unwrap();
        assert_eq!(first.index(), 0);
        assert_eq!(final_page.index(), 1);

        let first = finalizer.push(first).unwrap();
        let second = finalizer.push(final_page).unwrap();
        let first_digest = *blake3::hash(&first.bytes).as_bytes();
        let second_digest = *blake3::hash(&second.bytes).as_bytes();
        assert_eq!(second.value.previous_digest, first_digest);
        let sealed = finalizer.finish().unwrap();
        assert_eq!(sealed.value.final_page_count, 2);
        assert_eq!(sealed.value.final_page_digest, second_digest);
        assert_eq!(sealed.value.pages[0].digest, first_digest);
        assert_eq!(sealed.value.pages[1].digest, second_digest);
    }

    #[test]
    fn draft_decoder_rejects_non_drafts_and_truncation() {
        let mut builder = PackageBuilder::new().unwrap();
        builder.push(&record("a", 1)).unwrap();
        let PackageAssembly {
            final_page,
            mut finalizer,
            ..
        } = builder.finish().unwrap();
        let draft_bytes = final_page.encode().unwrap();
        for length in 0..draft_bytes.len() {
            assert!(PageDraft::decode(&draft_bytes[..length]).is_err());
        }
        let completed = finalizer.push(final_page).unwrap();
        assert!(PageDraft::decode(&completed.bytes).is_err());
    }

    #[test]
    fn draft_decoder_rejects_each_non_draft_field_independently() {
        let entry = record("a", 1).manifest_entry().unwrap();
        let draft = PageDraft {
            index: 0,
            entries: vec![entry],
        };
        let base = draft.placeholder();
        let rejects = |page: ManifestPage| {
            let encoded = encode_page(&page).unwrap();
            assert_eq!(PageDraft::decode(&encoded), Err(Error::InvalidBundle));
        };

        let mut page = base.clone();
        page.manifest_id[0] = 1;
        rejects(page);
        let mut page = base.clone();
        page.total = Some(1);
        rejects(page);
        let mut page = base.clone();
        page.previous_digest[0] = 1;
        rejects(page);
        let mut page = base.clone();
        page.profile = PathProfile::RawPosix;
        page.entries[0].path = vec![Component::Bytes(b"a".to_vec())];
        rejects(page);
        let mut page = base.clone();
        page.entries.clear();
        rejects(page);
        let mut page = base;
        page.index = u64::try_from(MAX_PAGE_COMMITMENTS).unwrap();
        rejects(page);
    }

    #[test]
    fn finalizer_rejects_reordering_and_stays_poisoned() {
        let mut builder = PackageBuilder::new().unwrap();
        builder.push(&record("a", 1)).unwrap();
        let PackageAssembly {
            mut final_page,
            mut finalizer,
            ..
        } = builder.finish().unwrap();
        final_page.index = 1;
        assert_eq!(
            finalizer.push(final_page.clone()),
            Err(Error::InvalidBundle)
        );
        final_page.index = 0;
        assert_eq!(finalizer.push(final_page), Err(Error::InvalidBundle));
        assert_eq!(finalizer.finish(), Err(Error::InvalidBundle));
    }

    #[test]
    fn finalizer_rejects_extra_and_missing_pages() {
        let mut builder = PackageBuilder::new().unwrap();
        builder.push(&record("a", 1)).unwrap();
        let PackageAssembly {
            final_page,
            mut finalizer,
            ..
        } = builder.finish().unwrap();
        finalizer.push(final_page.clone()).unwrap();
        assert_eq!(finalizer.push(final_page), Err(Error::InvalidBundle));

        let mut builder = PackageBuilder::new().unwrap();
        builder.push(&record("a", 1)).unwrap();
        builder.estimated_bytes = MAX_PAGE_BYTES;
        let first = builder.push(&record("b", 2)).unwrap().unwrap();
        let PackageAssembly { mut finalizer, .. } = builder.finish().unwrap();
        finalizer.push(first).unwrap();
        assert_eq!(finalizer.finish(), Err(Error::InvalidBundle));
    }

    #[test]
    fn finalizer_authenticates_exact_draft_storage() {
        let mut builder = PackageBuilder::new().unwrap();
        builder.push(&packed_record("a", 1)).unwrap();
        let PackageAssembly {
            mut final_page,
            mut finalizer,
            ..
        } = builder.finish().unwrap();
        let Some(StorageRef::Pack { pack, .. }) = &mut final_page.entries[0].storage else {
            panic!("packed record became direct");
        };
        pack.root[0] ^= 1;
        assert_eq!(finalizer.push(final_page), Err(Error::InvalidBundle));
        assert_eq!(finalizer.finish(), Err(Error::InvalidBundle));
    }

    #[test]
    fn finalizer_authenticates_page_boundaries() {
        let mut builder = PackageBuilder::new().unwrap();
        builder.push(&record("a", 1)).unwrap();
        builder.push(&record("b", 2)).unwrap();
        builder.estimated_bytes = MAX_PAGE_BYTES;
        let mut first = builder.push(&record("c", 3)).unwrap().unwrap();
        let PackageAssembly {
            mut final_page,
            mut finalizer,
            ..
        } = builder.finish().unwrap();
        let moved = first.entries.pop().unwrap();
        final_page.entries.insert(0, moved);
        assert_eq!(finalizer.push(first), Err(Error::InvalidBundle));
        assert_eq!(finalizer.push(final_page), Err(Error::InvalidBundle));
    }

    #[test]
    fn verifier_poison_dominates_later_wrapper_validation() {
        let mut builder = PackageBuilder::new().unwrap();
        builder.identity = builder.identity.fail_after_updates(2);
        let error = builder.push(&record("a", 1)).unwrap_err();
        assert!(matches!(error, Error::Verifier(_)));
        let mut malformed = record("b", 2);
        malformed.path.clear();
        assert_eq!(builder.push(&malformed), Err(error));
        assert!(matches!(builder.finish(), Err(failure) if failure == error));
    }

    #[test]
    fn empty_and_overlong_manifests_are_rejected_before_identity_changes() {
        assert!(matches!(
            PackageBuilder::new().unwrap().finish(),
            Err(Error::InvalidBundle)
        ));

        let mut builder = PackageBuilder::new().unwrap();
        builder.push(&record("a", 1)).unwrap();
        builder.emitted_pages = MAX_PAGE_COMMITMENTS - 1;
        builder.estimated_bytes = MAX_PAGE_BYTES;
        assert_eq!(builder.push(&record("b", 2)), Err(Error::InvalidBundle));
        builder.emitted_pages = 0;
        let first = builder.push(&record("b", 2)).unwrap().unwrap();
        assert_eq!(first.entries().len(), 1);
        assert_eq!(builder.finish().unwrap().summary.entries, 2);
    }

    #[test]
    fn page_flush_bounds_are_exact() {
        assert!(!page_needs_flush(0, MAX_PAGE_BYTES, 1).unwrap());
        assert!(page_needs_flush(MAX_ENTRIES_PER_PAGE, 0, 1).unwrap());
        assert!(!page_needs_flush(1, MAX_PAGE_BYTES - 1, 1).unwrap());
        assert!(page_needs_flush(1, MAX_PAGE_BYTES, 1).unwrap());
        assert!(page_needs_flush(1, usize::MAX, 1).is_err());
        assert!(!page_index_may_cross_bound(0, MAX_PAGE_BYTES));
        assert!(!page_index_may_cross_bound(
            1,
            MAX_PAGE_BYTES - MAX_PAGE_INDEX_ENCODING_GROWTH
        ));
        assert!(page_index_may_cross_bound(
            1,
            MAX_PAGE_BYTES - MAX_PAGE_INDEX_ENCODING_GROWTH + 1
        ));
        assert!(!should_check_actual_page(true, 1, MAX_PAGE_BYTES));
        assert!(!should_check_actual_page(false, 0, MAX_PAGE_BYTES));
        assert!(should_check_actual_page(false, 1, MAX_PAGE_BYTES));

        let entry = record("a", 1).manifest_entry().unwrap();
        let expected = encode_page(&ManifestPage {
            manifest_id: [0; 16],
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: vec![entry.clone()],
        })
        .unwrap()
        .len();
        assert_eq!(encoded_entry_bytes(&entry).unwrap(), expected);
        assert_ne!(expected, 1);
    }
}
