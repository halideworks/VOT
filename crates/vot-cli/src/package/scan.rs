//! Reading a built bundle back: manifests, seals, and summaries.

use crate::{
    EntryRecord, Error, MANIFEST_DIRECTORY, MANIFEST_SEAL, ManifestEntry, ManifestPage,
    PackageRootBuilder, PackageSummary, PageCommitment, Path, PathBuf, Seal, decode_page,
    decode_seal, manifest_page_path, read_bounded_file,
};

/// The seal's page digests by index, refusing a commitment list that does
/// not name exactly the sealed pages in order. Shared by the serve side,
/// which answers from these digests, and the fetch side, which holds every
/// received page to them.
pub(crate) fn seal_page_digests(seal: &Seal) -> Result<Vec<[u8; 32]>, Error> {
    if seal.pages.len() as u64 != seal.final_page_count {
        return Err(Error::InvalidBundle);
    }
    let mut digests = Vec::with_capacity(seal.pages.len());
    for (index, commitment) in seal.pages.iter().enumerate() {
        if commitment.index != index as u64 {
            return Err(Error::InvalidBundle);
        }
        digests.push(commitment.digest);
    }
    Ok(digests)
}

pub(crate) struct ManifestReader {
    pub(crate) directory: PathBuf,
    pub(crate) seal: Seal,
    pub(crate) next_page: u64,
    pub(crate) previous_digest: [u8; 32],
    pub(crate) entries: std::vec::IntoIter<ManifestEntry>,
    pub(crate) finished: bool,
}

impl ManifestReader {
    pub(crate) fn open(bundle: &Path) -> Result<Self, Error> {
        let directory = bundle.join(MANIFEST_DIRECTORY);
        let encoded =
            read_bounded_file(&directory.join(MANIFEST_SEAL), vot_manifest::MAX_PAGE_BYTES)?;
        let seal = decode_seal(&encoded).map_err(|_| Error::InvalidBundle)?;
        if seal.package.suite != 1 {
            return Err(Error::InvalidBundle);
        }
        Ok(Self {
            directory,
            seal,
            next_page: 0,
            previous_digest: [0; 32],
            entries: Vec::new().into_iter(),
            finished: false,
        })
    }

    pub(crate) fn next_record(&mut self) -> Result<Option<EntryRecord>, Error> {
        loop {
            if let Some(entry) = self.entries.next() {
                return EntryRecord::from_manifest(entry).map(Some);
            }
            if self.next_page == self.seal.final_page_count {
                if self.previous_digest != self.seal.final_page_digest {
                    return Err(Error::InvalidBundle);
                }
                self.finished = true;
                return Ok(None);
            }
            let encoded = read_bounded_file(
                &manifest_page_path(&self.directory, self.next_page),
                vot_manifest::MAX_PAGE_BYTES,
            )?;
            let digest = *blake3::hash(&encoded).as_bytes();
            let page = decode_page(&encoded).map_err(|_| Error::InvalidBundle)?;
            let commitment = self
                .seal
                .pages
                .get(usize::try_from(self.next_page).map_err(|_| Error::InvalidBundle)?)
                .ok_or(Error::InvalidBundle)?;
            validate_page_envelope(
                &page,
                &self.seal,
                commitment,
                self.next_page,
                self.previous_digest,
                digest,
            )?;
            self.previous_digest = digest;
            self.next_page = self.next_page.checked_add(1).ok_or(Error::InvalidBundle)?;
            self.entries = page.entries.into_iter();
        }
    }

    pub(crate) fn expected_package(&self) -> PackageSummary {
        PackageSummary {
            root: self.seal.package.root,
            logical_length: self.seal.package.length,
            entries: 0,
        }
    }
}

pub(crate) fn validate_page_envelope(
    page: &ManifestPage,
    seal: &Seal,
    commitment: &PageCommitment,
    index: u64,
    previous_digest: [u8; 32],
    digest: [u8; 32],
) -> Result<(), Error> {
    if page.manifest_id != seal.manifest_id {
        return Err(Error::InvalidBundle);
    }
    if page.index != index {
        return Err(Error::InvalidBundle);
    }
    if page
        .total
        .is_some_and(|total| total != seal.final_page_count)
    {
        return Err(Error::InvalidBundle);
    }
    if page.previous_digest != previous_digest {
        return Err(Error::InvalidBundle);
    }
    if commitment.index != index {
        return Err(Error::InvalidBundle);
    }
    if commitment.digest != digest {
        return Err(Error::InvalidBundle);
    }
    Ok(())
}

pub(crate) fn scan_manifest(bundle: &Path) -> Result<PackageSummary, Error> {
    let mut reader = ManifestReader::open(bundle)?;
    let expected = reader.expected_package();
    let mut package = PackageRootBuilder::new()?;
    while let Some(record) = reader.next_record()? {
        package.push(&record)?;
    }
    if !reader.finished {
        return Err(Error::InvalidBundle);
    }
    let actual = package.finish()?;
    if actual.entries == 0 {
        return Err(Error::InvalidBundle);
    }
    if actual.root != expected.root {
        return Err(Error::RootMismatch);
    }
    if actual.logical_length != expected.logical_length {
        return Err(Error::RootMismatch);
    }
    Ok(actual)
}
