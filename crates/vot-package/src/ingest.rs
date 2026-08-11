//! Bounded package ingest from a canonical manifest seal and page stream.

use vot_manifest::{ObjectId, Seal, decode_page, decode_seal};
use vot_verifier::Suite;

use crate::{EntryRecord, Error, PackageRootBuilder, PackageSummary};

/// Logical entries from one page validated into a running package transcript.
///
/// A value proves canonical decoding, seal commitment, chain and envelope
/// validation, portable logical-entry validation, and successful incorporation
/// into the running transcript. It does not authenticate entries against the
/// expected package identity; callers must wait for [`PackageIngest::finish`]
/// to succeed before treating them as authenticated by that identity.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "validated entries must be consumed or explicitly discarded"]
pub struct ValidatedManifestPage {
    entries: Vec<EntryRecord>,
}

impl ValidatedManifestPage {
    /// Borrows the validated logical entries in canonical page order.
    #[must_use]
    pub fn entries(&self) -> &[EntryRecord] {
        &self.entries
    }

    /// Consumes the validated page and returns its logical entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<EntryRecord> {
        self.entries
    }
}

/// Incrementally verifies a sealed manifest and reconstructs its package identity.
pub struct PackageIngest {
    seal: Seal,
    next_page: u64,
    previous_digest: [u8; 32],
    package: PackageRootBuilder,
    failure: Option<Error>,
}

impl PackageIngest {
    /// Starts ingest from canonical, bounded seal bytes.
    ///
    /// This verifies internal consistency with the seal. Use [`Self::new_expected`]
    /// when the caller also has an authenticated package identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed seals and package suites other than BLAKE3 Bao64.
    pub fn new(encoded_seal: &[u8]) -> Result<Self, Error> {
        let seal = decode_seal(encoded_seal).map_err(|_| Error::InvalidBundle)?;
        if seal.package.suite != Suite::Blake3Bao64.identifier() {
            return Err(Error::InvalidBundle);
        }
        Ok(Self {
            seal,
            next_page: 0,
            previous_digest: [0; 32],
            package: PackageRootBuilder::new()?,
            failure: None,
        })
    }

    /// Starts ingest and binds the seal to an authenticated package identity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RootMismatch`] unless the seal names the exact expected
    /// suite, root, and logical length.
    pub fn new_expected(encoded_seal: &[u8], expected: &ObjectId) -> Result<Self, Error> {
        let ingest = Self::new(encoded_seal)?;
        if &ingest.seal.package != expected {
            return Err(Error::RootMismatch);
        }
        Ok(ingest)
    }

    /// Returns the exact number of pages committed by the seal.
    #[must_use]
    pub fn page_count(&self) -> u64 {
        self.seal.final_page_count
    }

    /// Verifies and applies the next canonical, bounded manifest page.
    ///
    /// A rejected page permanently poisons the ingest. Pages may omit `total`
    /// or carry the exact sealed page count, matching sealed-bundle semantics.
    ///
    /// # Errors
    ///
    /// Rejects malformed, reordered, replayed, uncommitted, or identity-invalid
    /// pages and propagates package transcript failures.
    pub fn push_page(&mut self, encoded_page: &[u8]) -> Result<ValidatedManifestPage, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.push_page_inner(encoded_page);
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }

    fn push_page_inner(&mut self, encoded_page: &[u8]) -> Result<ValidatedManifestPage, Error> {
        if self.next_page >= self.seal.final_page_count {
            return Err(Error::InvalidBundle);
        }
        let page = decode_page(encoded_page).map_err(|_| Error::InvalidBundle)?;
        let digest = *blake3::hash(encoded_page).as_bytes();
        let commitment = self
            .seal
            .pages
            .get(usize::try_from(self.next_page).map_err(|_| Error::InvalidBundle)?)
            .ok_or(Error::InvalidBundle)?;
        if page.manifest_id != self.seal.manifest_id {
            return Err(Error::InvalidBundle);
        }
        if page.index != self.next_page {
            return Err(Error::InvalidBundle);
        }
        if page
            .total
            .is_some_and(|total| total != self.seal.final_page_count)
        {
            return Err(Error::InvalidBundle);
        }
        if page.previous_digest != self.previous_digest {
            return Err(Error::InvalidBundle);
        }
        if commitment.digest != digest {
            return Err(Error::InvalidBundle);
        }
        let mut entries = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let record = EntryRecord::from_manifest(entry)?;
            self.package.push(&record)?;
            entries.push(record);
        }
        self.previous_digest = digest;
        self.next_page += 1;
        Ok(ValidatedManifestPage { entries })
    }

    /// Finishes the stream and returns the reconstructed package summary.
    ///
    /// # Errors
    ///
    /// Rejects poisoned or incomplete streams, empty packages, and seals whose
    /// root or logical length differs from the reconstructed transcript.
    pub fn finish(self) -> Result<PackageSummary, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.next_page != self.seal.final_page_count
            || self.previous_digest != self.seal.final_page_digest
        {
            return Err(Error::InvalidBundle);
        }
        let actual = self.package.finish()?;
        if actual.entries == 0 {
            return Err(Error::InvalidBundle);
        }
        if actual.root != self.seal.package.root
            || actual.logical_length != self.seal.package.length
        {
            return Err(Error::RootMismatch);
        }
        Ok(actual)
    }
}

#[cfg(test)]
mod tests {
    use vot_manifest::{
        Component, EntryKind, ManifestPage, ObjectId, PageCommitment, PathProfile, Seal,
        StorageRef, encode_page, encode_seal,
    };
    use vot_verifier::Suite;

    use super::*;
    use crate::{EntryRecord, Storage};

    const VECTOR_PAGE: &[u8] =
        include_bytes!("../../../test-vectors/xfer/bundle/manifest/0000000000000000.cbor");
    const VECTOR_SEAL: &[u8] =
        include_bytes!("../../../test-vectors/xfer/bundle/manifest/seal.cbor");

    struct Fixture {
        seal: Seal,
        pages: Vec<ManifestPage>,
        summary: PackageSummary,
    }

    fn record(name: &str, root: u8, length: u64) -> EntryRecord {
        EntryRecord {
            path: vec![Component::Text(name.to_owned())],
            suite: Suite::Sha256Bep52,
            logical_root: [root; 32],
            logical_length: length,
            storage: Storage::Direct,
        }
    }

    fn fixture(names: &[&[&str]]) -> Fixture {
        let mut package = PackageRootBuilder::new().unwrap();
        let mut pages = Vec::new();
        let mut root = 1_u8;
        for names in names {
            let mut entries = Vec::new();
            for name in *names {
                let record = record(name, root, u64::from(root));
                root += 1;
                package.push(&record).unwrap();
                entries.push(record.manifest_entry().unwrap());
            }
            pages.push(ManifestPage {
                manifest_id: [9; 16],
                index: 0,
                total: None,
                previous_digest: [0; 32],
                profile: PathProfile::Portable,
                entries,
            });
        }
        let summary = package.finish().unwrap();
        let package = ObjectId {
            suite: Suite::Blake3Bao64.identifier(),
            root: summary.root,
            length: summary.logical_length,
        };
        let seal = rechain(&mut pages, package);
        Fixture {
            seal,
            pages,
            summary,
        }
    }

    fn rechain(pages: &mut [ManifestPage], package: ObjectId) -> Seal {
        let mut previous = [0; 32];
        let mut commitments = Vec::new();
        for (index, page) in pages.iter_mut().enumerate() {
            page.index = index as u64;
            page.previous_digest = previous;
            let encoded = encode_page(page).unwrap();
            previous = *blake3::hash(&encoded).as_bytes();
            commitments.push(PageCommitment {
                index: index as u64,
                digest: previous,
            });
        }
        Seal {
            manifest_id: [9; 16],
            final_page_count: pages.len() as u64,
            final_page_digest: previous,
            package,
            pages: commitments,
        }
    }

    fn recommit(fixture: &mut Fixture) {
        for (commitment, page) in fixture.seal.pages.iter_mut().zip(&fixture.pages) {
            commitment.digest = *blake3::hash(&encode_page(page).unwrap()).as_bytes();
        }
        fixture.seal.final_page_digest = fixture.seal.pages.last().unwrap().digest;
    }

    fn open_ingest(fixture: &Fixture) -> PackageIngest {
        PackageIngest::new(&encode_seal(&fixture.seal).unwrap()).unwrap()
    }

    fn hex(root: [u8; 32]) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(64);
        for byte in root {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn committed_bundle_reconstructs_the_exact_package_transcript() {
        let mut ingest = PackageIngest::new(VECTOR_SEAL).unwrap();
        assert_eq!(ingest.page_count(), 1);
        drop(ingest.push_page(VECTOR_PAGE).unwrap());
        let summary = ingest.finish().unwrap();
        assert_eq!(
            hex(summary.root),
            "4ff7f2527a6a80d7d6fc3ba8cb74ca3638f0d6f4ef1af6ff37ee7401eec89105"
        );
        assert_eq!(summary.logical_length, 46);
        assert_eq!(summary.entries, 3);
    }

    #[test]
    fn page_count_reports_the_sealed_total() {
        let fixture = fixture(&[&["a"], &["b"]]);
        let mut ingest = open_ingest(&fixture);

        assert_eq!(ingest.page_count(), 2);
        drop(
            ingest
                .push_page(&encode_page(&fixture.pages[0]).unwrap())
                .unwrap(),
        );
        assert_eq!(ingest.page_count(), 2);
    }

    #[test]
    fn sealed_pages_accept_absent_or_exact_totals() {
        let absent = fixture(&[&["a"]]);
        let mut ingest = open_ingest(&absent);
        drop(
            ingest
                .push_page(&encode_page(&absent.pages[0]).unwrap())
                .unwrap(),
        );
        assert_eq!(ingest.finish().unwrap(), absent.summary);

        let mut exact = fixture(&[&["a"]]);
        exact.pages[0].total = Some(1);
        recommit(&mut exact);
        let mut ingest = open_ingest(&exact);
        drop(
            ingest
                .push_page(&encode_page(&exact.pages[0]).unwrap())
                .unwrap(),
        );
        assert_eq!(ingest.finish().unwrap(), exact.summary);
    }

    #[test]
    fn validated_page_borrows_and_owns_logical_entries() {
        let fixture = fixture(&[&["a", "b"]]);
        let expected: Vec<_> = fixture.pages[0]
            .entries
            .iter()
            .cloned()
            .map(|entry| EntryRecord::from_manifest(entry).unwrap())
            .collect();
        let mut ingest = open_ingest(&fixture);
        let validated = ingest
            .push_page(&encode_page(&fixture.pages[0]).unwrap())
            .unwrap();
        assert_eq!(validated.entries(), expected.as_slice());
        assert_eq!(validated.into_entries(), expected);
        assert_eq!(ingest.finish().unwrap(), fixture.summary);
    }

    #[test]
    fn partial_entry_failure_returns_no_validated_page_and_poisons_ingest() {
        let mut fixture = fixture(&[&["a", "b"]]);
        let invalid = &mut fixture.pages[0].entries[1];
        invalid.kind = EntryKind::Directory;
        invalid.length = None;
        invalid.storage = None;
        recommit(&mut fixture);
        let page = encode_page(&fixture.pages[0]).unwrap();
        let mut ingest = open_ingest(&fixture);
        assert!(matches!(ingest.push_page(&page), Err(Error::InvalidBundle)));
        assert!(matches!(ingest.push_page(&page), Err(Error::InvalidBundle)));
        assert_eq!(ingest.finish(), Err(Error::InvalidBundle));
    }

    #[test]
    fn each_page_envelope_field_is_checked_before_state_advances() {
        for mutation in 0..4 {
            let mut fixture = fixture(&[&["a"]]);
            match mutation {
                0 => fixture.pages[0].manifest_id[0] ^= 1,
                1 => fixture.pages[0].index = 1,
                2 => fixture.pages[0].total = Some(2),
                3 => fixture.pages[0].previous_digest[0] = 1,
                _ => unreachable!(),
            }
            recommit(&mut fixture);
            let page = encode_page(&fixture.pages[0]).unwrap();
            let mut ingest = open_ingest(&fixture);
            assert_eq!(ingest.push_page(&page), Err(Error::InvalidBundle));
            assert_eq!(ingest.push_page(&page), Err(Error::InvalidBundle));
            assert_eq!(ingest.finish(), Err(Error::InvalidBundle));
        }
    }

    #[test]
    fn every_committed_page_digest_is_checked() {
        let mut fixture = fixture(&[&["a"], &["b"]]);
        fixture.seal.pages[0].digest[0] ^= 1;
        let mut ingest = open_ingest(&fixture);
        assert_eq!(
            ingest.push_page(&encode_page(&fixture.pages[0]).unwrap()),
            Err(Error::InvalidBundle)
        );
    }

    #[test]
    fn final_page_digest_is_checked_after_every_page_arrives() {
        let fixture = fixture(&[&["a"]]);
        let mut ingest = open_ingest(&fixture);
        ingest.seal.final_page_digest[0] ^= 1;
        drop(
            ingest
                .push_page(&encode_page(&fixture.pages[0]).unwrap())
                .unwrap(),
        );

        assert_eq!(ingest.finish(), Err(Error::InvalidBundle));
    }

    #[test]
    fn missing_extra_empty_and_oversized_inputs_fail_closed() {
        let valid = fixture(&[&["a"]]);
        assert_eq!(open_ingest(&valid).finish(), Err(Error::InvalidBundle));

        let mut extra = open_ingest(&valid);
        let page = encode_page(&valid.pages[0]).unwrap();
        drop(extra.push_page(&page).unwrap());
        assert_eq!(extra.push_page(&page), Err(Error::InvalidBundle));
        assert_eq!(extra.finish(), Err(Error::InvalidBundle));

        let empty = fixture(&[&[]]);
        let mut empty_ingest = open_ingest(&empty);
        drop(
            empty_ingest
                .push_page(&encode_page(&empty.pages[0]).unwrap())
                .unwrap(),
        );
        assert_eq!(empty_ingest.finish(), Err(Error::InvalidBundle));

        assert!(matches!(
            PackageIngest::new(&vec![0; vot_manifest::MAX_PAGE_BYTES + 1]),
            Err(Error::InvalidBundle)
        ));
        let mut oversized = open_ingest(&valid);
        assert_eq!(
            oversized.push_page(&vec![0; vot_manifest::MAX_PAGE_BYTES + 1]),
            Err(Error::InvalidBundle)
        );
        assert_eq!(oversized.push_page(&page), Err(Error::InvalidBundle));
    }

    #[test]
    fn seal_and_authenticated_identity_mismatches_are_exact() {
        let fixture = fixture(&[&["a"]]);
        let encoded = encode_seal(&fixture.seal).unwrap();
        assert!(PackageIngest::new_expected(&encoded, &fixture.seal.package).is_ok());
        for mutation in 0..3 {
            let mut expected = fixture.seal.package.clone();
            match mutation {
                0 => expected.suite = 2,
                1 => expected.root[0] ^= 1,
                2 => expected.length += 1,
                _ => unreachable!(),
            }
            assert!(matches!(
                PackageIngest::new_expected(&encoded, &expected),
                Err(Error::RootMismatch)
            ));
        }

        let mut unsupported = fixture.seal.clone();
        unsupported.package.suite = 2;
        assert!(matches!(
            PackageIngest::new(&encode_seal(&unsupported).unwrap()),
            Err(Error::InvalidBundle)
        ));

        for mutation in 0..2 {
            let mut wrong = fixture.seal.clone();
            if mutation == 0 {
                wrong.package.root[0] ^= 1;
            } else {
                wrong.package.length += 1;
            }
            let mut ingest = PackageIngest::new(&encode_seal(&wrong).unwrap()).unwrap();
            drop(
                ingest
                    .push_page(&encode_page(&fixture.pages[0]).unwrap())
                    .unwrap(),
            );
            assert_eq!(ingest.finish(), Err(Error::RootMismatch));
        }
    }

    #[test]
    fn expected_identity_does_not_authenticate_a_provisional_page() {
        let mut fixture = fixture(&[&["a"]]);
        let expected = fixture.seal.package.clone();
        let StorageRef::Direct(object) = fixture.pages[0].entries[0].storage.as_mut().unwrap()
        else {
            unreachable!();
        };
        object.root[0] ^= 1;
        recommit(&mut fixture);

        let mut ingest =
            PackageIngest::new_expected(&encode_seal(&fixture.seal).unwrap(), &expected).unwrap();
        let provisional = ingest
            .push_page(&encode_page(&fixture.pages[0]).unwrap())
            .unwrap();
        assert_eq!(provisional.entries().len(), 1);
        assert_eq!(ingest.finish(), Err(Error::RootMismatch));
    }

    #[test]
    fn transcript_order_overflow_and_entry_errors_poison_ingest() {
        let mut reversed = fixture(&[&["a"], &["b"]]);
        reversed.pages.swap(0, 1);
        let package = reversed.seal.package.clone();
        reversed.seal = rechain(&mut reversed.pages, package);
        let mut ingest = open_ingest(&reversed);
        drop(
            ingest
                .push_page(&encode_page(&reversed.pages[0]).unwrap())
                .unwrap(),
        );
        let second = encode_page(&reversed.pages[1]).unwrap();
        assert_eq!(ingest.push_page(&second), Err(Error::InvalidBundle));
        assert_eq!(ingest.push_page(&second), Err(Error::InvalidBundle));

        let lengths = [i64::MAX as u64; 3];
        let entries: Vec<_> = lengths
            .iter()
            .enumerate()
            .map(|(index, length)| {
                record(
                    &format!("f{index}"),
                    u8::try_from(index).unwrap() + 1,
                    *length,
                )
            })
            .map(|record| record.manifest_entry().unwrap())
            .collect();
        let mut pages = vec![ManifestPage {
            manifest_id: [9; 16],
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries,
        }];
        let seal = rechain(
            &mut pages,
            ObjectId {
                suite: 1,
                root: [1; 32],
                length: 0,
            },
        );
        let mut overflow = PackageIngest::new(&encode_seal(&seal).unwrap()).unwrap();
        let page = encode_page(&pages[0]).unwrap();
        assert_eq!(overflow.push_page(&page), Err(Error::InvalidBundle));
        assert_eq!(overflow.push_page(&page), Err(Error::InvalidBundle));
    }

    #[test]
    fn raw_profile_behavior_matches_the_existing_bundle_reader() {
        let portable = fixture(&[&["a"]]);
        let mut raw_file = fixture(&[&["a"]]);
        raw_file.pages[0].profile = PathProfile::RawPosix;
        raw_file.pages[0].entries[0].path = vec![Component::Bytes(b"a".to_vec())];
        recommit(&mut raw_file);
        let mut ingest = open_ingest(&raw_file);
        assert_eq!(
            ingest.push_page(&encode_page(&raw_file.pages[0]).unwrap()),
            Err(Error::InvalidPath)
        );

        let mut empty_then_portable = fixture(&[&[] as &[&str], &["a"]]);
        empty_then_portable.pages[0].profile = PathProfile::RawPosix;
        let package = empty_then_portable.seal.package.clone();
        empty_then_portable.seal = rechain(&mut empty_then_portable.pages, package);
        let mut ingest = open_ingest(&empty_then_portable);
        for page in &empty_then_portable.pages {
            drop(ingest.push_page(&encode_page(page).unwrap()).unwrap());
        }
        assert_eq!(ingest.finish().unwrap(), portable.summary);
    }
}
