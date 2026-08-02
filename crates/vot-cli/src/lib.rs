//! Bounded package construction, reliable verification, and durable publication.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use vot_manifest::{
    Component, EntryKind, ManifestEntry, ManifestPage, ObjectId, PackagePath, PageCommitment,
    PathProfile, Seal, StorageRef, canonical_path_key, decode_page, decode_seal, encode_page,
    encode_seal,
};
use vot_pack::{CANDIDATE_MAX, LogicalFile, Pack, StreamingPacker};
use vot_receipt::{
    AssuranceLevel, CommitProfile, Receipt, SubjectKind, authenticate_hmac_sha256,
    decode_authenticated, encode_authenticated, verify_hmac_sha256,
};
use vot_scheduler::ReliableReceiver;
use vot_transport_api::{MAX_DATA_RECORD_BYTES, SubjectId};
use vot_verifier::{StreamVerifier, Suite};

const PACKAGE_DOMAIN: &[u8] = b"VOT package v0\0";
const MANIFEST_DIRECTORY: &str = "manifest";
const MANIFEST_SEAL: &str = "seal.cbor";
const DEFAULT_LOGICAL_SUITE: Suite = Suite::Sha256Bep52;

const fn suite_id(suite: Suite) -> u16 {
    match suite {
        Suite::Blake3Bao64 => 1,
        Suite::Sha256Bep52 => 2,
    }
}

fn suite_from_id(id: u16) -> Result<Suite, Error> {
    match id {
        1 => Ok(Suite::Blake3Bao64),
        2 => Ok(Suite::Sha256Bep52),
        _ => Err(Error::InvalidBundle),
    }
}

pub fn parse_suite(value: &str) -> Result<Suite, Error> {
    match value {
        "blake3" | "blake3-bao64" | "1" => Ok(Suite::Blake3Bao64),
        "sha256" | "sha256-bep52" | "2" => Ok(Suite::Sha256Bep52),
        _ => Err(Error::InvalidArguments),
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidArguments,
    InvalidPath,
    InvalidBundle,
    DestinationExists,
    SourceMutation,
    RootMismatch,
    Randomness,
    Pack(vot_pack::Error),
    Scheduler(vot_scheduler::Error),
    Verifier(vot_verifier::VerifyError),
    Receipt(vot_receipt::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<vot_pack::Error> for Error {
    fn from(error: vot_pack::Error) -> Self {
        Self::Pack(error)
    }
}

impl From<vot_scheduler::Error> for Error {
    fn from(error: vot_scheduler::Error) -> Self {
        Self::Scheduler(error)
    }
}

impl From<vot_verifier::VerifyError> for Error {
    fn from(error: vot_verifier::VerifyError) -> Self {
        Self::Verifier(error)
    }
}

impl From<vot_receipt::Error> for Error {
    fn from(error: vot_receipt::Error) -> Self {
        Self::Receipt(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageSummary {
    pub root: [u8; 32],
    pub logical_length: u64,
    pub entries: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveReport {
    pub package: PackageSummary,
    pub peak_staging: u64,
}

struct SourceFile {
    path: PackagePath,
    key: Vec<u8>,
    source: PathBuf,
    length: u64,
}

#[derive(Clone)]
enum Storage {
    Direct,
    Pack {
        root: [u8; 32],
        length: u64,
        offset: u64,
    },
}

struct EntryRecord {
    path: PackagePath,
    suite: Suite,
    logical_root: [u8; 32],
    logical_length: u64,
    storage: Storage,
}

impl EntryRecord {
    fn manifest_entry(&self) -> ManifestEntry {
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
        ManifestEntry {
            path: self.path.clone(),
            kind: EntryKind::File,
            length: Some(self.logical_length),
            storage: Some(storage),
            metadata: None,
        }
    }

    fn from_manifest(entry: ManifestEntry) -> Result<Self, Error> {
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
                if object.length != logical_length {
                    return Err(Error::InvalidBundle);
                }
                (object.root, suite, Storage::Direct)
            }
            StorageRef::Pack {
                pack,
                offset,
                length,
                logical,
            } => {
                let pack_suite = suite_from_id(pack.suite)?;
                let logical_suite = suite_from_id(logical.suite)?;
                if pack_suite != logical_suite
                    || length != logical_length
                    || logical.length != logical_length
                {
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

struct PackageRootBuilder {
    verifier: StreamVerifier,
    last_key: Option<Vec<u8>>,
    logical_length: u64,
    entries: u64,
}

impl PackageRootBuilder {
    fn new() -> Result<Self, Error> {
        let mut verifier = StreamVerifier::new(Suite::Blake3Bao64);
        verifier.update(PACKAGE_DOMAIN)?;
        Ok(Self {
            verifier,
            last_key: None,
            logical_length: 0,
            entries: 0,
        })
    }

    fn push(&mut self, record: &EntryRecord) -> Result<(), Error> {
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
        self.last_key = Some(key);
        self.verifier
            .update(&u32_len(encoded_path.len())?.to_be_bytes())?;
        self.verifier.update(&encoded_path)?;
        self.verifier
            .update(&suite_id(record.suite).to_be_bytes())?;
        self.verifier.update(&record.logical_length.to_be_bytes())?;
        self.verifier.update(&record.logical_root)?;
        self.logical_length = self
            .logical_length
            .checked_add(record.logical_length)
            .ok_or(Error::InvalidBundle)?;
        self.entries = self.entries.checked_add(1).ok_or(Error::InvalidBundle)?;
        Ok(())
    }

    fn finish(self) -> Result<PackageSummary, Error> {
        Ok(PackageSummary {
            root: self.verifier.finish()?,
            logical_length: self.logical_length,
            entries: self.entries,
        })
    }
}

struct ManifestSpool {
    directory: PathBuf,
    entries: Vec<ManifestEntry>,
    estimated_bytes: usize,
    page_count: u64,
}

impl ManifestSpool {
    fn new(bundle: &Path) -> Result<Self, Error> {
        let directory = bundle.join(MANIFEST_DIRECTORY);
        fs::create_dir(&directory)?;
        Ok(Self {
            directory,
            entries: Vec::new(),
            estimated_bytes: 0,
            page_count: 0,
        })
    }

    fn push(&mut self, entry: ManifestEntry) -> Result<(), Error> {
        let encoded_entry = encode_page(&ManifestPage {
            manifest_id: [0; 16],
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: vec![entry.clone()],
        })
        .map_err(|_| Error::InvalidBundle)?
        .len();
        if page_needs_flush(self.entries.len(), self.estimated_bytes, encoded_entry)? {
            self.flush_placeholder()?;
        }
        self.entries.push(entry);
        self.estimated_bytes = self
            .estimated_bytes
            .checked_add(encoded_entry)
            .ok_or(Error::InvalidBundle)?;
        Ok(())
    }

    fn finish(mut self, package: PackageSummary) -> Result<(), Error> {
        self.flush_placeholder()?;
        if self.page_count == 0 {
            return Err(Error::InvalidBundle);
        }
        let mut manifest_id = [0; 16];
        manifest_id.copy_from_slice(&package.root[..16]);
        let mut previous_digest = [0; 32];
        let mut pages =
            Vec::with_capacity(usize::try_from(self.page_count).map_err(|_| Error::InvalidBundle)?);
        for index in 0..self.page_count {
            let spool = manifest_spool_path(&self.directory, index);
            let encoded = read_bounded_file(&spool, vot_manifest::MAX_PAGE_BYTES)?;
            let mut page = decode_page(&encoded).map_err(|_| Error::InvalidBundle)?;
            page.manifest_id = manifest_id;
            page.index = index;
            page.total = None;
            page.previous_digest = previous_digest;
            let encoded = encode_page(&page).map_err(|_| Error::InvalidBundle)?;
            let digest = *blake3::hash(&encoded).as_bytes();
            write_new_synced(&manifest_page_path(&self.directory, index), &encoded)?;
            fs::remove_file(spool)?;
            pages.push(PageCommitment { index, digest });
            previous_digest = digest;
        }
        let seal = Seal {
            manifest_id,
            final_page_count: self.page_count,
            final_page_digest: previous_digest,
            package: ObjectId {
                suite: 1,
                root: package.root,
                length: package.logical_length,
            },
            pages,
        };
        let encoded = encode_seal(&seal).map_err(|_| Error::InvalidBundle)?;
        write_new_synced(&self.directory.join(MANIFEST_SEAL), &encoded)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn flush_placeholder(&mut self) -> Result<(), Error> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let page = self.placeholder_page();
        let encoded = encode_page(&page).map_err(|_| Error::InvalidBundle)?;
        write_new_synced(
            &manifest_spool_path(&self.directory, self.page_count),
            &encoded,
        )?;
        self.entries.clear();
        self.estimated_bytes = 0;
        self.page_count = self.page_count.checked_add(1).ok_or(Error::InvalidBundle)?;
        Ok(())
    }

    fn placeholder_page(&self) -> ManifestPage {
        ManifestPage {
            manifest_id: [0; 16],
            index: self.page_count,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: self.entries.clone(),
        }
    }
}

fn page_needs_flush(
    entries: usize,
    estimated_bytes: usize,
    next_entry_bytes: usize,
) -> Result<bool, Error> {
    let estimated = estimated_bytes
        .checked_add(next_entry_bytes)
        .ok_or(Error::InvalidBundle)?;
    Ok(entries == vot_manifest::MAX_ENTRIES_PER_PAGE
        || (entries != 0 && estimated > vot_manifest::MAX_PAGE_BYTES))
}

struct ManifestReader {
    directory: PathBuf,
    seal: Seal,
    next_page: u64,
    previous_digest: [u8; 32],
    entries: std::vec::IntoIter<ManifestEntry>,
    finished: bool,
}

impl ManifestReader {
    fn open(bundle: &Path) -> Result<Self, Error> {
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

    fn next_record(&mut self) -> Result<Option<EntryRecord>, Error> {
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

    fn expected_package(&self) -> PackageSummary {
        PackageSummary {
            root: self.seal.package.root,
            logical_length: self.seal.package.length,
            entries: 0,
        }
    }
}

fn validate_page_envelope(
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

fn scan_manifest(bundle: &Path) -> Result<PackageSummary, Error> {
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

fn validate_published_destination(
    bundle: &Path,
    destination: &Path,
    expected: &PackageSummary,
) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(destination)?;
    if !metadata.file_type().is_dir() {
        return Err(Error::InvalidBundle);
    }
    let mut file_count = 0_u64;
    count_published_files(destination, 0, &mut file_count)?;
    if file_count != expected.entries {
        return Err(Error::InvalidBundle);
    }

    let mut reader = ManifestReader::open(bundle)?;
    let mut package = PackageRootBuilder::new()?;
    while let Some(record) = reader.next_record()? {
        package.push(&record)?;
        let output = output_path(destination, &record.path)?;
        let metadata = fs::symlink_metadata(&output)?;
        if !metadata.file_type().is_file() {
            return Err(Error::InvalidBundle);
        }
        let root = match stream_root(&output, record.logical_length, record.suite) {
            Ok(root) => root,
            Err(Error::SourceMutation) => return Err(Error::RootMismatch),
            Err(error) => return Err(error),
        };
        if root != record.logical_root {
            return Err(Error::RootMismatch);
        }
    }
    let actual = package.finish()?;
    if actual != *expected {
        return Err(Error::RootMismatch);
    }
    Ok(())
}

fn count_published_files(directory: &Path, depth: usize, count: &mut u64) -> Result<(), Error> {
    if depth > vot_manifest::MAX_PATH_COMPONENTS {
        return Err(Error::InvalidBundle);
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            *count = count.checked_add(1).ok_or(Error::InvalidBundle)?;
        } else if file_type.is_dir() {
            count_published_files(&entry.path(), depth + 1, count)?;
        } else {
            return Err(Error::InvalidBundle);
        }
    }
    Ok(())
}

fn manifest_page_path(directory: &Path, index: u64) -> PathBuf {
    directory.join(format!("{index:016}.cbor"))
}

fn manifest_spool_path(directory: &Path, index: u64) -> PathBuf {
    directory.join(format!(".spool-{index:016}.cbor"))
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, Error> {
    let limit = u64::try_from(maximum)
        .map_err(|_| Error::InvalidBundle)?
        .saturating_add(1);
    let mut input = File::open(path)?.take(limit);
    let mut output = Vec::with_capacity(maximum.min(4096));
    input.read_to_end(&mut output)?;
    if output.len() > maximum {
        return Err(Error::InvalidBundle);
    }
    Ok(output)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn build_bundle(source: &Path, bundle: &Path) -> Result<PackageSummary, Error> {
    build_bundle_with_suite(source, bundle, DEFAULT_LOGICAL_SUITE)
}

pub fn build_bundle_with_suite(
    source: &Path,
    bundle: &Path,
    suite: Suite,
) -> Result<PackageSummary, Error> {
    if !source.is_dir() || bundle.exists() {
        return Err(Error::InvalidArguments);
    }
    let sources = collect_sources(source)?;
    if sources.is_empty() {
        return Err(Error::InvalidArguments);
    }
    fs::create_dir(bundle)?;
    let objects = bundle.join("objects");
    fs::create_dir(&objects)?;
    let mut manifest = ManifestSpool::new(bundle)?;
    let mut package = PackageRootBuilder::new()?;
    let mut packer = StreamingPacker::new_with_suite(PathProfile::Portable, suite);
    for source_file in sources {
        if source_file.length <= CANDIDATE_MAX as u64 {
            let mut bytes = Vec::with_capacity(
                usize::try_from(source_file.length).map_err(|_| Error::InvalidBundle)?,
            );
            File::open(&source_file.source)?.read_to_end(&mut bytes)?;
            if bytes.len() as u64 != source_file.length {
                return Err(Error::SourceMutation);
            }
            if let Some(pack) = packer.push(LogicalFile {
                path: source_file.path,
                bytes,
            })? {
                emit_pack(&objects, &mut manifest, &mut package, &pack)?;
            }
        } else {
            if let Some(pack) = packer.flush() {
                emit_pack(&objects, &mut manifest, &mut package, &pack)?;
            }
            emit_direct(&objects, &mut manifest, &mut package, &source_file, suite)?;
        }
    }
    if let Some(pack) = packer.finish() {
        emit_pack(&objects, &mut manifest, &mut package, &pack)?;
    }

    let summary = package.finish()?;
    manifest.finish(summary)?;
    File::open(&objects)?.sync_all()?;
    File::open(bundle)?.sync_all()?;
    Ok(summary)
}

pub fn receive_bundle(
    bundle: &Path,
    destination: &Path,
    receipt_path: &Path,
    key: &[u8],
    observed_at: &str,
) -> Result<ReceiveReport, Error> {
    let receipt_summary_path = receipt_path.with_extension("json");
    if receipt_path == receipt_summary_path {
        return Err(Error::InvalidArguments);
    }
    let expected = scan_manifest(bundle)?;
    if destination.exists() {
        let (prepared_receipt, prepared_summary) =
            prepared_receipt_paths(receipt_path, &receipt_summary_path, &expected)?;
        if !receipt_path.exists()
            && !receipt_summary_path.exists()
            && !prepared_receipt.exists()
            && !prepared_summary.exists()
        {
            return Err(Error::DestinationExists);
        }
        validate_published_destination(bundle, destination, &expected)?;
        if recover_prepared_receipts(receipt_path, &receipt_summary_path, &expected, key)? {
            return Ok(ReceiveReport {
                package: expected,
                peak_staging: 0,
            });
        }
        return Err(Error::DestinationExists);
    }
    if receipt_path.exists() {
        return Err(Error::DestinationExists);
    }
    if receipt_summary_path.exists() {
        return Err(Error::DestinationExists);
    }
    let existing_preparation =
        existing_prepared_receipts(receipt_path, &receipt_summary_path, &expected, key)?;
    let mut manifest = ManifestReader::open(bundle)?;
    let staging = staging_path(destination)?;
    fs::create_dir(&staging)?;
    let mut package = PackageRootBuilder::new()?;
    let staging_limit = (MAX_DATA_RECORD_BYTES as u64)
        .checked_add(vot_verifier::GROUP_SIZE as u64)
        .ok_or(Error::InvalidBundle)?;
    let mut receiver = ReliableReceiver::new(
        staging_limit,
        MAX_DATA_RECORD_BYTES as u64,
        MAX_DATA_RECORD_BYTES as u64,
    )?;
    let mut cached_pack: Option<(Suite, [u8; 32], u64, Vec<u8>)> = None;

    while let Some(record) = manifest.next_record()? {
        package.push(&record)?;
        let output = output_path(&staging, &record.path)?;
        match record.storage {
            Storage::Direct => {
                receive_direct(
                    &bundle
                        .join("objects")
                        .join(object_name(&record.logical_root)),
                    &output,
                    record.logical_root,
                    record.logical_length,
                    record.suite,
                    &mut receiver,
                )?;
            }
            Storage::Pack {
                root,
                length,
                offset,
            } => {
                let needs_load = pack_needs_load(cached_pack.as_ref(), record.suite, root, length);
                if needs_load {
                    let bytes = receive_object(
                        &bundle.join("objects").join(object_name(&root)),
                        root,
                        length,
                        record.suite,
                        &mut receiver,
                    )?;
                    cached_pack = Some((record.suite, root, length, bytes));
                }
                let (_, _, _, bytes) = cached_pack.as_ref().ok_or(Error::InvalidBundle)?;
                let start = usize::try_from(offset).map_err(|_| Error::InvalidBundle)?;
                let logical =
                    usize::try_from(record.logical_length).map_err(|_| Error::InvalidBundle)?;
                let end = start.checked_add(logical).ok_or(Error::InvalidBundle)?;
                let extracted = bytes.get(start..end).ok_or(Error::InvalidBundle)?;
                if vot_verifier::root(record.suite, extracted)? != record.logical_root {
                    return Err(Error::RootMismatch);
                }
                write_published_file(&output, extracted)?;
            }
        }
    }
    let actual = package.finish()?;
    if actual != expected {
        return Err(Error::RootMismatch);
    }
    let mut owned_receipt = None;
    let mut owned_summary = None;
    let (prepared_receipt_path, prepared_summary_path) = if let Some(paths) = existing_preparation {
        paths
    } else {
        let freshness = fresh_receipt_identifiers()?;
        let receipt = publication_receipt(&actual, observed_at, freshness);
        let authenticated = authenticate_hmac_sha256(receipt, b"vot-cli", key)?;
        let encoded = encode_authenticated(&authenticated)?;
        let summary = receipt_summary_bytes(&actual);
        let suffix = object_name(&actual.root);
        let suffix = suffix.strip_suffix(".obj").ok_or(Error::InvalidBundle)?;
        let receipt = PreparedFile::new(receipt_path, &encoded, suffix, "receipt")?;
        let summary =
            PreparedFile::new(&receipt_summary_path, summary.as_bytes(), suffix, "summary")?;
        let paths = (receipt.path()?, summary.path()?);
        owned_receipt = Some(receipt);
        owned_summary = Some(summary);
        paths
    };
    if sync_directories(&staging)? == 0 {
        return Err(Error::InvalidBundle);
    }
    publish_staging_with(
        &staging,
        destination,
        &mut owned_receipt,
        &mut owned_summary,
        |parent| {
            File::open(parent)?.sync_all()?;
            Ok(())
        },
    )?;
    finalize_prepared_receipts(
        receipt_path,
        &receipt_summary_path,
        &prepared_receipt_path,
        &prepared_summary_path,
    )?;
    Ok(ReceiveReport {
        package: actual,
        peak_staging: receiver.peak_staging(),
    })
}

fn publish_staging_with(
    staging: &Path,
    destination: &Path,
    owned_receipt: &mut Option<PreparedFile>,
    owned_summary: &mut Option<PreparedFile>,
    sync_parent: impl FnOnce(&Path) -> Result<(), Error>,
) -> Result<(), Error> {
    atomic_rename_noreplace(staging, destination)?;
    if let Some(prepared) = owned_receipt {
        prepared.preserve_for_recovery();
    }
    if let Some(prepared) = owned_summary {
        prepared.preserve_for_recovery();
    }
    sync_parent(parent_directory(destination))
}

fn publication_receipt(
    package: &PackageSummary,
    observed_at: &str,
    freshness: [u8; 32],
) -> Receipt {
    let mut session_id = [0; 16];
    session_id.copy_from_slice(&freshness[..16]);
    let mut incarnation_id = [0; 16];
    incarnation_id.copy_from_slice(&freshness[16..]);
    Receipt {
        subject_kind: SubjectKind::Package,
        suite_id: 1,
        subject_digest: package.root,
        subject_length: package.logical_length,
        assurance: AssuranceLevel::Published,
        profile: CommitProfile::Fast,
        actual_predecessor: AssuranceLevel::TransitVerified,
        provider: 1,
        provider_version: [0, 3, 0],
        session_id,
        incarnation_id,
        sequence: 1,
        observed_at: observed_at.to_owned(),
        clock_source: 1,
        flags: 0,
    }
}

fn collect_sources(root: &Path) -> Result<Vec<SourceFile>, Error> {
    fn visit(
        root: &Path,
        directory: &Path,
        components: &mut PackagePath,
        output: &mut Vec<SourceFile>,
    ) -> Result<(), Error> {
        let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_unstable_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::InvalidPath)?;
            components.push(Component::Text(name));
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(Error::InvalidPath);
            }
            if metadata.is_dir() {
                visit(root, &path, components, output)?;
            } else if metadata.is_file() {
                let package_path = components.clone();
                let key = canonical_path_key(&package_path, PathProfile::Portable)
                    .map_err(|_| Error::InvalidPath)?;
                output.push(SourceFile {
                    path: package_path,
                    key,
                    source: path,
                    length: metadata.len(),
                });
            } else {
                return Err(Error::InvalidPath);
            }
            components.pop();
        }
        let _ = root;
        Ok(())
    }

    let mut output = Vec::new();
    visit(root, root, &mut Vec::new(), &mut output)?;
    output.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    if output.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err(Error::InvalidPath);
    }
    Ok(output)
}

fn emit_pack(
    objects: &Path,
    manifest: &mut ManifestSpool,
    package: &mut PackageRootBuilder,
    pack: &Pack,
) -> Result<(), Error> {
    write_object(objects, &pack.root, &pack.bytes)?;
    for entry in &pack.entries {
        let record = EntryRecord {
            path: entry.path.clone(),
            suite: pack.suite,
            logical_root: entry.logical_root,
            logical_length: entry.length,
            storage: Storage::Pack {
                root: pack.root,
                length: pack.bytes.len() as u64,
                offset: entry.offset,
            },
        };
        package.push(&record)?;
        manifest.push(record.manifest_entry())?;
    }
    Ok(())
}

fn emit_direct(
    objects: &Path,
    manifest: &mut ManifestSpool,
    package: &mut PackageRootBuilder,
    source: &SourceFile,
    suite: Suite,
) -> Result<(), Error> {
    let root = stream_root(&source.source, source.length, suite)?;
    let object = objects.join(object_name(&root));
    if object.exists() {
        if stream_root(&object, source.length, suite)? != root {
            return Err(Error::RootMismatch);
        }
    } else {
        copy_and_verify(&source.source, &object, source.length, root, suite)?;
    }
    let record = EntryRecord {
        path: source.path.clone(),
        suite,
        logical_root: root,
        logical_length: source.length,
        storage: Storage::Direct,
    };
    package.push(&record)?;
    manifest.push(record.manifest_entry())?;
    Ok(())
}

fn copy_and_verify(
    source: &Path,
    destination: &Path,
    expected_length: u64,
    expected_root: [u8; 32],
    suite: Suite,
) -> Result<(), Error> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let mut verifier = StreamVerifier::new(suite);
    let mut length = 0_u64;
    let mut buffer = vec![0; MAX_DATA_RECORD_BYTES];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        verifier.update(&buffer[..read])?;
        length = length
            .checked_add(read as u64)
            .ok_or(Error::InvalidBundle)?;
    }
    output.sync_all()?;
    if length != expected_length || verifier.finish()? != expected_root {
        return Err(Error::SourceMutation);
    }
    Ok(())
}

fn stream_root(path: &Path, expected_length: u64, suite: Suite) -> Result<[u8; 32], Error> {
    let mut input = File::open(path)?;
    let mut verifier = StreamVerifier::new(suite);
    let mut length = 0_u64;
    let mut buffer = vec![0; MAX_DATA_RECORD_BYTES];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        verifier.update(&buffer[..read])?;
        length = length
            .checked_add(read as u64)
            .ok_or(Error::InvalidBundle)?;
    }
    if length != expected_length {
        return Err(Error::SourceMutation);
    }
    Ok(verifier.finish()?)
}

fn write_object(objects: &Path, root: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
    let path = objects.join(object_name(root));
    if path.exists() {
        if file_matches_bytes(&path, bytes)? {
            return Ok(());
        }
        return Err(Error::RootMismatch);
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn file_matches_bytes(path: &Path, expected: &[u8]) -> Result<bool, Error> {
    match read_bounded_file(path, expected.len()) {
        Ok(actual) => Ok(actual == expected),
        Err(Error::InvalidBundle) => Ok(false),
        Err(error) => Err(error),
    }
}

fn receive_direct(
    object: &Path,
    output: &Path,
    root: [u8; 32],
    length: u64,
    suite: Suite,
    receiver: &mut ReliableReceiver,
) -> Result<(), Error> {
    create_parent(output)?;
    let mut source = File::open(object)?;
    if source.metadata()?.len() != length {
        return Err(Error::InvalidBundle);
    }
    let subject = SubjectId {
        suite: suite_id(suite),
        root,
        length,
    };
    let mut destination = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)?;
    let already_verified = receiver.is_verified(subject);
    if !already_verified {
        receiver.begin(subject)?;
    }
    let mut verifier = already_verified.then(|| StreamVerifier::new(suite));
    let mut buffer = vec![0; MAX_DATA_RECORD_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if let Some(verifier) = verifier.as_mut() {
            verifier.update(&buffer[..read])?;
        } else {
            receiver.receive(subject, &buffer[..read])?;
        }
        destination.write_all(&buffer[..read])?;
    }
    if let Some(verifier) = verifier {
        if verifier.finish()? != root {
            return Err(Error::RootMismatch);
        }
    } else {
        receiver.finish(subject)?;
    }
    destination.sync_all()?;
    Ok(())
}

fn receive_object(
    object: &Path,
    root: [u8; 32],
    length: u64,
    suite: Suite,
    receiver: &mut ReliableReceiver,
) -> Result<Vec<u8>, Error> {
    let capacity = usize::try_from(length).map_err(|_| Error::InvalidBundle)?;
    if capacity > vot_pack::HARD_MAX {
        return Err(Error::InvalidBundle);
    }
    let mut source = File::open(object)?;
    if source.metadata()?.len() != length {
        return Err(Error::InvalidBundle);
    }
    let subject = SubjectId {
        suite: suite_id(suite),
        root,
        length,
    };
    let already_verified = receiver.is_verified(subject);
    if !already_verified {
        receiver.begin(subject)?;
    }
    let mut verifier = already_verified.then(|| StreamVerifier::new(suite));
    let mut bytes = Vec::with_capacity(capacity);
    let mut buffer = vec![0; MAX_DATA_RECORD_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if let Some(verifier) = verifier.as_mut() {
            verifier.update(&buffer[..read])?;
        } else {
            receiver.receive(subject, &buffer[..read])?;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    if let Some(verifier) = verifier {
        if verifier.finish()? != root {
            return Err(Error::RootMismatch);
        }
    } else {
        receiver.finish(subject)?;
    }
    Ok(bytes)
}

fn write_published_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    create_parent(path)?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_parent(path: &Path) -> Result<(), Error> {
    let parent = path.parent().ok_or(Error::InvalidPath)?;
    fs::create_dir_all(parent)?;
    Ok(())
}

fn sync_directories(root: &Path) -> Result<usize, Error> {
    let mut pending = vec![root.to_owned()];
    let mut directories = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            }
        }
        directories.push(directory);
    }
    let count = directories.len();
    for directory in directories.into_iter().rev() {
        File::open(directory)?.sync_all()?;
    }
    Ok(count)
}

fn pack_needs_load(
    cached: Option<&(Suite, [u8; 32], u64, Vec<u8>)>,
    suite: Suite,
    root: [u8; 32],
    length: u64,
) -> bool {
    cached.is_none_or(|(cached_suite, cached_root, cached_length, _)| {
        *cached_suite != suite || *cached_root != root || *cached_length != length
    })
}

fn output_path(root: &Path, path: &PackagePath) -> Result<PathBuf, Error> {
    canonical_path_key(path, PathProfile::Portable).map_err(|_| Error::InvalidPath)?;
    let mut output = root.to_owned();
    for component in path {
        let Component::Text(component) = component else {
            return Err(Error::InvalidPath);
        };
        output.push(component);
    }
    Ok(output)
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

fn object_name(root: &[u8; 32]) -> String {
    let mut output = String::with_capacity(68);
    for byte in root {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output.push_str(".obj");
    output
}

fn receipt_summary_bytes(package: &PackageSummary) -> String {
    let root = object_name(&package.root);
    let root = root.strip_suffix(".obj").expect("known suffix");
    format!(
        "{{\"assurance\":\"PUBLISHED\",\"suite\":1,\"root\":\"{root}\",\"length\":{},\"entries\":{}}}\n",
        package.logical_length, package.entries
    )
}

fn fresh_receipt_identifiers() -> Result<[u8; 32], Error> {
    let mut identifiers = [0; 32];
    getrandom::fill(&mut identifiers).map_err(|_| Error::Randomness)?;
    Ok(identifiers)
}

struct PreparedFile {
    temporary: Option<PathBuf>,
    cleanup: bool,
}

impl PreparedFile {
    fn new(destination: &Path, bytes: &[u8], suffix: &str, kind: &str) -> Result<Self, Error> {
        let parent = parent_directory(destination);
        if !fs::metadata(parent)?.is_dir() {
            return Err(Error::InvalidPath);
        }
        if destination.exists() {
            return Err(Error::DestinationExists);
        }
        let temporary = prepared_output_path(destination, suffix, kind)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(Self {
            temporary: Some(temporary),
            cleanup: true,
        })
    }

    fn preserve_for_recovery(&mut self) {
        self.cleanup = false;
    }

    fn path(&self) -> Result<PathBuf, Error> {
        self.temporary.clone().ok_or(Error::InvalidBundle)
    }
}

impl Drop for PreparedFile {
    fn drop(&mut self) {
        if self.cleanup {
            if let Some(temporary) = &self.temporary {
                let _ = fs::remove_file(temporary);
            }
        }
    }
}

fn prepared_output_path(destination: &Path, suffix: &str, kind: &str) -> Result<PathBuf, Error> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::InvalidPath)?;
    Ok(destination.with_file_name(format!(".{name}.vot-{kind}-{suffix}")))
}

fn prepared_receipt_paths(
    receipt: &Path,
    summary: &Path,
    package: &PackageSummary,
) -> Result<(PathBuf, PathBuf), Error> {
    let suffix = object_name(&package.root);
    let suffix = suffix.strip_suffix(".obj").ok_or(Error::InvalidBundle)?;
    Ok((
        prepared_output_path(receipt, suffix, "receipt")?,
        prepared_output_path(summary, suffix, "summary")?,
    ))
}

fn existing_prepared_receipts(
    receipt: &Path,
    summary: &Path,
    package: &PackageSummary,
    key: &[u8],
) -> Result<Option<(PathBuf, PathBuf)>, Error> {
    let (prepared_receipt, prepared_summary) = prepared_receipt_paths(receipt, summary, package)?;
    match (prepared_receipt.exists(), prepared_summary.exists()) {
        (false, false) => Ok(None),
        (true, true) => {
            validate_receipt_files(&prepared_receipt, &prepared_summary, package, key)?;
            Ok(Some((prepared_receipt, prepared_summary)))
        }
        _ => Err(Error::InvalidBundle),
    }
}

fn recover_prepared_receipts(
    receipt: &Path,
    summary: &Path,
    package: &PackageSummary,
    key: &[u8],
) -> Result<bool, Error> {
    let (prepared_receipt, prepared_summary) = prepared_receipt_paths(receipt, summary, package)?;
    let receipt_prepared = prepared_receipt.exists();
    let summary_prepared = prepared_summary.exists();
    if receipt.exists() && summary.exists() {
        if receipt_prepared && !bounded_files_equal(&prepared_receipt, receipt, 65_536)? {
            return Err(Error::DestinationExists);
        }
        if summary_prepared && !bounded_files_equal(&prepared_summary, summary, 4096)? {
            return Err(Error::DestinationExists);
        }
        validate_receipt_files(receipt, summary, package, key)?;
        if receipt_prepared {
            remove_preparation(&prepared_receipt)?;
        }
        if summary_prepared {
            remove_preparation(&prepared_summary)?;
        }
        File::open(parent_directory(receipt))?.sync_all()?;
        return Ok(true);
    }
    match (
        receipt_prepared,
        summary_prepared,
        receipt.exists(),
        summary.exists(),
    ) {
        (false, false, false, false) => return Ok(false),
        (true, true, _, _) => {}
        _ => return Err(Error::InvalidBundle),
    }
    validate_receipt_files(&prepared_receipt, &prepared_summary, package, key)?;
    finalize_prepared_receipts(receipt, summary, &prepared_receipt, &prepared_summary)?;
    Ok(true)
}

fn remove_preparation(prepared: &Path) -> Result<(), Error> {
    match fs::remove_file(prepared) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

fn validate_receipt_files(
    receipt_path: &Path,
    summary_path: &Path,
    package: &PackageSummary,
    key: &[u8],
) -> Result<(), Error> {
    let encoded = read_bounded_file(receipt_path, 65_536)?;
    let authenticated = decode_authenticated(&encoded).map_err(|_| Error::InvalidBundle)?;
    verify_hmac_sha256(&authenticated, key).map_err(|_| Error::InvalidBundle)?;
    let receipt = &authenticated.receipt;
    if authenticated.key_id != b"vot-cli"
        || receipt.subject_kind != SubjectKind::Package
        || receipt.suite_id != 1
        || receipt.subject_digest != package.root
        || receipt.subject_length != package.logical_length
        || receipt.assurance != AssuranceLevel::Published
        || receipt.profile != CommitProfile::Fast
        || receipt.actual_predecessor != AssuranceLevel::TransitVerified
        || receipt.provider != 1
    {
        return Err(Error::InvalidBundle);
    }
    let summary = read_bounded_file(summary_path, 4096)?;
    if summary != receipt_summary_bytes(package).as_bytes() {
        return Err(Error::InvalidBundle);
    }
    Ok(())
}

fn finalize_prepared_receipts(
    receipt: &Path,
    summary: &Path,
    prepared_receipt: &Path,
    prepared_summary: &Path,
) -> Result<(), Error> {
    link_or_match(prepared_receipt, receipt, 65_536)?;
    link_or_match(prepared_summary, summary, 4096)?;
    File::open(parent_directory(receipt))?.sync_all()?;
    fs::remove_file(prepared_receipt)?;
    fs::remove_file(prepared_summary)?;
    File::open(parent_directory(receipt))?.sync_all()?;
    Ok(())
}

fn link_or_match(prepared: &Path, destination: &Path, maximum: usize) -> Result<(), Error> {
    match fs::hard_link(prepared, destination) {
        Ok(()) => Ok(()),
        Err(error) => resolve_link_error(error, prepared, destination, maximum),
    }
}

fn bounded_files_equal(left: &Path, right: &Path, maximum: usize) -> Result<bool, Error> {
    let left = match read_bounded_file(left, maximum) {
        Ok(bytes) => bytes,
        Err(Error::InvalidBundle) => return Ok(false),
        Err(error) => return Err(error),
    };
    let right = match read_bounded_file(right, maximum) {
        Ok(bytes) => bytes,
        Err(Error::InvalidBundle) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(left == right)
}

fn resolve_link_error(
    error: io::Error,
    prepared: &Path,
    destination: &Path,
    maximum: usize,
) -> Result<(), Error> {
    if error.kind() != io::ErrorKind::AlreadyExists {
        return Err(Error::Io(error));
    }
    if bounded_files_equal(prepared, destination, maximum)? {
        Ok(())
    } else {
        Err(Error::DestinationExists)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn atomic_rename_noreplace(source: &Path, destination: &Path) -> Result<(), Error> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| Error::Io(error.into()))
}

#[cfg(target_os = "windows")]
fn windows_rename_noreplace(source: &Path, destination: &Path) -> Result<(), Error> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn unsupported_rename_noreplace(_source: &Path, _destination: &Path) -> Result<(), Error> {
    Err(Error::InvalidArguments)
}

#[cfg(target_os = "windows")]
use windows_rename_noreplace as atomic_rename_noreplace;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use unsupported_rename_noreplace as atomic_rename_noreplace;

fn staging_path(destination: &Path) -> Result<PathBuf, Error> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::InvalidPath)?;
    Ok(destination.with_file_name(format!(".{name}.vot-staging-{}", std::process::id())))
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

const MIN_HMAC_KEY_BYTES: usize = 32;
const MAX_HMAC_KEY_BYTES: usize = 64;
const HEX_KEY_PREFIX: &str = "hex:";
const RAW_KEY_PREFIX: &str = "raw:";
const MAX_KEY_SOURCE_BYTES: usize = HEX_KEY_PREFIX.len() + 2 * MAX_HMAC_KEY_BYTES + 1;

pub fn decode_key(value: &str) -> Result<Vec<u8>, Error> {
    if value.len() % 2 != 0 || value.len() > 2 * MAX_HMAC_KEY_BYTES {
        return Err(Error::InvalidArguments);
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex(pair[0]).ok_or(Error::InvalidArguments)?;
        let low = hex(pair[1]).ok_or(Error::InvalidArguments)?;
        output.push(high * 16 + low);
    }
    if !(MIN_HMAC_KEY_BYTES..=MAX_HMAC_KEY_BYTES).contains(&output.len()) {
        return Err(Error::InvalidArguments);
    }
    Ok(output)
}

const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Loads an HMAC key without putting the key bytes in the process argument list.
///
/// The source is one of:
/// - `env:NAME` for an environment variable;
/// - `-` for stdin; or
/// - a filesystem path.
///
/// Both raw keys and hexadecimal text files are accepted. Raw input is
/// preserved byte-for-byte; hexadecimal text must use the explicit hex:
/// prefix, and textual raw keys may use raw:. Keys must contain 32..=64
/// bytes. Source reads are bounded to `MAX_KEY_SOURCE_BYTES` bytes.
pub fn load_key_spec(spec: &str) -> Result<Vec<u8>, Error> {
    let bytes = if let Some(name) = spec.strip_prefix("env:") {
        if name.is_empty() {
            return Err(Error::InvalidArguments);
        }
        let value = std::env::var(name).map_err(|_| Error::InvalidArguments)?;
        validate_key_source_length(value.len())?;
        value.into_bytes()
    } else if spec == "-" {
        read_key_source(io::stdin().lock())?
    } else {
        read_key_source(File::open(spec)?)?
    };
    parse_loaded_key(bytes)
}

fn validate_key_source_length(length: usize) -> Result<(), Error> {
    if length > MAX_KEY_SOURCE_BYTES {
        Err(Error::InvalidArguments)
    } else {
        Ok(())
    }
}

fn read_key_source(reader: impl Read) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_KEY_SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    validate_key_source_length(bytes.len())?;
    Ok(bytes)
}

fn parse_loaded_key(bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Some(encoded) = text.strip_prefix(HEX_KEY_PREFIX) {
            return decode_key(encoded.trim());
        }
        if let Some(raw) = text.strip_prefix(RAW_KEY_PREFIX) {
            return validate_loaded_key(raw.as_bytes().to_vec());
        }
    }
    validate_loaded_key(bytes)
}

fn validate_loaded_key(bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    if !(MIN_HMAC_KEY_BYTES..=MAX_HMAC_KEY_BYTES).contains(&bytes.len()) {
        return Err(Error::InvalidArguments);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temporary(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vot-cli-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn canonical_manifest_bundle_publishes_with_matching_receipt() {
        let source = temporary("source");
        let bundle = temporary("bundle");
        let destination = temporary("destination");
        let receipt = temporary("receipt.cbor");
        fs::create_dir_all(source.join("frames")).unwrap();
        fs::write(source.join("frames/0001.exr"), b"frame-one").unwrap();
        fs::write(source.join("frames/0002.exr"), b"frame-two").unwrap();
        fs::write(source.join("large.mov"), vec![0x5a; CANDIDATE_MAX + 1]).unwrap();
        fs::write(source.join("large-copy.mov"), vec![0x5a; CANDIDATE_MAX + 1]).unwrap();

        let sent = build_bundle(&source, &bundle).unwrap();
        let manifest_directory = bundle.join(MANIFEST_DIRECTORY);
        let seal = decode_seal(&fs::read(manifest_directory.join(MANIFEST_SEAL)).unwrap()).unwrap();
        assert_eq!(seal.package.root, sent.root);
        assert_eq!(seal.package.length, sent.logical_length);
        let mut previous = [0; 32];
        for commitment in &seal.pages {
            let encoded =
                fs::read(manifest_page_path(&manifest_directory, commitment.index)).unwrap();
            let page = decode_page(&encoded).unwrap();
            assert_eq!(page.manifest_id, seal.manifest_id);
            assert_eq!(page.previous_digest, previous);
            assert_eq!(page.total, None);
            previous = *blake3::hash(&encoded).as_bytes();
            assert_eq!(commitment.digest, previous);
        }
        assert_eq!(scan_manifest(&bundle).unwrap(), sent);
        let seal_path = manifest_directory.join(MANIFEST_SEAL);
        let canonical_seal = encode_seal(&seal).unwrap();
        let mut wrong_root = seal.clone();
        wrong_root.package.root[0] ^= 1;
        fs::write(&seal_path, encode_seal(&wrong_root).unwrap()).unwrap();
        assert!(matches!(scan_manifest(&bundle), Err(Error::RootMismatch)));
        let mut wrong_length = seal.clone();
        wrong_length.package.length += 1;
        fs::write(&seal_path, encode_seal(&wrong_length).unwrap()).unwrap();
        assert!(matches!(scan_manifest(&bundle), Err(Error::RootMismatch)));
        fs::write(&seal_path, canonical_seal).unwrap();
        let received = receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &[7; 32],
            "2026-07-31T23:59:59Z",
        )
        .unwrap();
        assert_eq!(sent, received.package);
        assert!(received.peak_staging <= (MAX_DATA_RECORD_BYTES + vot_verifier::GROUP_SIZE) as u64);
        assert_eq!(
            fs::read(destination.join("frames/0001.exr")).unwrap(),
            b"frame-one"
        );
        assert_eq!(
            fs::read(destination.join("frames/0002.exr")).unwrap(),
            b"frame-two"
        );
        assert_eq!(
            fs::read(destination.join("large.mov")).unwrap().len(),
            CANDIDATE_MAX + 1
        );
        assert_eq!(
            fs::read(destination.join("large-copy.mov")).unwrap().len(),
            CANDIDATE_MAX + 1
        );
        assert!(!fs::read(&receipt).unwrap().is_empty());
        let summary = fs::read_to_string(receipt.with_extension("json")).unwrap();
        assert!(summary.contains("\"assurance\":\"PUBLISHED\""));
        assert!(summary.contains(&object_name(&sent.root)[..64]));

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(receipt.with_extension("json")).unwrap();
        fs::remove_file(receipt).unwrap();
    }

    #[test]
    fn corruption_cannot_publish_or_emit_a_receipt() {
        let source = temporary("bad-source");
        let bundle = temporary("bad-bundle");
        let destination = temporary("bad-destination");
        let receipt = temporary("bad-receipt.cbor");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"contents").unwrap();
        build_bundle(&source, &bundle).unwrap();
        let object = fs::read_dir(bundle.join("objects"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut bytes = fs::read(&object).unwrap();
        bytes[0] ^= 1;
        fs::write(object, bytes).unwrap();
        assert!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &[7; 32],
                "2026-07-31T23:59:59Z"
            )
            .is_err()
        );
        assert!(!destination.exists());
        assert!(!receipt.exists());

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        let staging = staging_path(&destination).unwrap();
        if staging.exists() {
            fs::remove_dir_all(staging).unwrap();
        }
    }

    #[test]
    fn invalid_receipt_metadata_cannot_publish_destination() {
        let source = temporary("timestamp-source");
        let bundle = temporary("timestamp-bundle");
        let destination = temporary("timestamp-destination");
        let receipt = temporary("timestamp-receipt.cbor");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"contents").unwrap();
        build_bundle(&source, &bundle).unwrap();
        assert!(matches!(
            receive_bundle(&bundle, &destination, &receipt, &[7; 32], "not-rfc3339"),
            Err(Error::Receipt(vot_receipt::Error::InvalidTimestamp))
        ));
        assert!(!destination.exists());
        assert!(!receipt.exists());

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        let staging = staging_path(&destination).unwrap();
        if staging.exists() {
            fs::remove_dir_all(staging).unwrap();
        }
    }

    #[test]
    fn receipt_outputs_are_prepared_before_destination_publication() {
        let source = temporary("receipt-output-source");
        let bundle = temporary("receipt-output-bundle");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"contents").unwrap();
        build_bundle(&source, &bundle).unwrap();

        let destination = temporary("missing-receipt-parent-destination");
        let receipt = temporary("missing-receipt-parent").join("receipt.cbor");
        assert!(matches!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &[7; 32],
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::Io(_))
        ));
        assert!(!destination.exists());
        assert!(!receipt.exists());
        let staging = staging_path(&destination).unwrap();
        if staging.exists() {
            fs::remove_dir_all(staging).unwrap();
        }

        let collision_destination = temporary("summary-collision-destination");
        let collision_receipt = temporary("receipt.json");
        assert!(matches!(
            receive_bundle(
                &bundle,
                &collision_destination,
                &collision_receipt,
                &[7; 32],
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::InvalidArguments)
        ));
        assert!(!collision_destination.exists());
        assert!(!collision_receipt.exists());

        let existing_summary_destination = temporary("existing-summary-destination");
        let existing_summary_receipt = temporary("existing-summary.cbor");
        let existing_summary = existing_summary_receipt.with_extension("json");
        fs::write(&existing_summary, b"existing").unwrap();
        assert!(matches!(
            receive_bundle(
                &bundle,
                &existing_summary_destination,
                &existing_summary_receipt,
                &[7; 32],
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::DestinationExists)
        ));
        assert!(!existing_summary_destination.exists());
        assert!(!existing_summary_receipt.exists());
        fs::remove_file(existing_summary).unwrap();

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn destination_publication_is_atomic_and_no_replace() {
        let source = temporary("atomic-source");
        let destination = temporary("atomic-destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"verified").unwrap();
        fs::create_dir(&destination).unwrap();
        assert!(matches!(
            atomic_rename_noreplace(&source, &destination),
            Err(Error::Io(_))
        ));
        assert_eq!(fs::read(source.join("file")).unwrap(), b"verified");
        assert!(fs::read_dir(&destination).unwrap().next().is_none());
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir(destination).unwrap();
    }

    #[test]
    fn receipt_identifiers_are_fresh_for_each_publication() {
        let first = fresh_receipt_identifiers().unwrap();
        let second = fresh_receipt_identifiers().unwrap();
        assert_ne!(first, [0; 32]);
        assert_ne!(second, [0; 32]);
        assert_ne!(first, second);
        assert_ne!(&first[..16], &first[16..]);
        let package = PackageSummary {
            root: [3; 32],
            logical_length: 9,
            entries: 1,
        };
        let receipt = publication_receipt(&package, "2026-07-31T23:59:59Z", first);
        assert_eq!(receipt.session_id, first[..16]);
        assert_eq!(receipt.incarnation_id, first[16..]);
    }

    #[test]
    fn publication_receipt_claims_only_performed_assurance() {
        let package = PackageSummary {
            root: [3; 32],
            logical_length: 9,
            entries: 1,
        };
        let receipt = publication_receipt(&package, "2026-07-31T23:59:59Z", [7; 32]);
        assert_eq!(receipt.profile, CommitProfile::Fast);
        assert_eq!(receipt.actual_predecessor, AssuranceLevel::TransitVerified);
    }

    #[test]
    fn abandoned_prepared_receipt_is_removed() {
        let destination = temporary("prepared-final");
        let prepared = PreparedFile::new(&destination, b"receipt", "unique", "receipt").unwrap();
        let temporary = prepared.temporary.clone().unwrap();
        assert!(temporary.exists());
        drop(prepared);
        assert!(!temporary.exists());
        assert!(!destination.exists());
    }

    fn prepared_evidence(
        receipt: &Path,
        summary: &Path,
        package: &PackageSummary,
        key: &[u8],
    ) -> (PreparedFile, PreparedFile) {
        let authenticated = authenticate_hmac_sha256(
            publication_receipt(package, "2026-07-31T23:59:59Z", [5; 32]),
            b"vot-cli",
            key,
        )
        .unwrap();
        let encoded = encode_authenticated(&authenticated).unwrap();
        let suffix = object_name(&package.root);
        let suffix = suffix.strip_suffix(".obj").unwrap();
        (
            PreparedFile::new(receipt, &encoded, suffix, "receipt").unwrap(),
            PreparedFile::new(
                summary,
                receipt_summary_bytes(package).as_bytes(),
                suffix,
                "summary",
            )
            .unwrap(),
        )
    }

    #[test]
    fn receipt_publication_recovers_after_destination_publish() {
        let receipt = temporary("recover-receipt.cbor");
        let summary = receipt.with_extension("json");
        let package = PackageSummary {
            root: [4; 32],
            logical_length: 7,
            entries: 1,
        };
        let key = [9; 32];
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        let expected_receipt = fs::read(&prepared_receipt_path).unwrap();
        let expected_summary = fs::read(&prepared_summary_path).unwrap();
        drop(prepared_receipt);
        drop(prepared_summary);
        assert!(prepared_receipt_path.exists());
        assert!(prepared_summary_path.exists());
        fs::hard_link(&prepared_receipt_path, &receipt).unwrap();

        assert!(recover_prepared_receipts(&receipt, &summary, &package, &key).unwrap());
        assert_eq!(fs::read(&receipt).unwrap(), expected_receipt);
        assert_eq!(fs::read(&summary).unwrap(), expected_summary);
        assert!(!prepared_receipt_path.exists());
        assert!(!prepared_summary_path.exists());
        assert!(recover_prepared_receipts(&receipt, &summary, &package, &key).unwrap());
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn destination_sync_failure_preserves_receipt_recovery_evidence() {
        let staging = temporary("sync-failure-staging");
        let destination = temporary("sync-failure-destination");
        let receipt = temporary("sync-failure-receipt.cbor");
        let summary = receipt.with_extension("json");
        let package = PackageSummary {
            root: [14; 32],
            logical_length: 7,
            entries: 1,
        };
        let key = [9; 32];
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("file"), b"published").unwrap();
        let (prepared_receipt, prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        let mut owned_receipt = Some(prepared_receipt);
        let mut owned_summary = Some(prepared_summary);

        assert!(matches!(
            publish_staging_with(
                &staging,
                &destination,
                &mut owned_receipt,
                &mut owned_summary,
                |_| Err(Error::Io(io::Error::other(
                    "injected directory sync failure"
                ))),
            ),
            Err(Error::Io(_))
        ));
        drop((owned_receipt, owned_summary));
        assert!(destination.exists());
        assert!(prepared_receipt_path.exists());
        assert!(prepared_summary_path.exists());
        assert!(recover_prepared_receipts(&receipt, &summary, &package, &key).unwrap());

        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn receipt_recovery_reports_absent_evidence() {
        let receipt = temporary("absent-recovery-receipt.cbor");
        let summary = receipt.with_extension("json");
        let package = PackageSummary {
            root: [4; 32],
            logical_length: 7,
            entries: 1,
        };
        assert!(!recover_prepared_receipts(&receipt, &summary, &package, &[9; 32]).unwrap());
    }

    #[test]
    fn receipt_recovery_completes_after_one_preparation_was_cleaned() {
        let package = PackageSummary {
            root: [5; 32],
            logical_length: 7,
            entries: 1,
        };
        let key = [9; 32];
        for remove_receipt_preparation in [false, true] {
            let receipt = temporary(&format!(
                "partial-cleanup-{remove_receipt_preparation}.cbor"
            ));
            let summary = receipt.with_extension("json");
            let (mut prepared_receipt, mut prepared_summary) =
                prepared_evidence(&receipt, &summary, &package, &key);
            prepared_receipt.preserve_for_recovery();
            prepared_summary.preserve_for_recovery();
            let prepared_receipt = prepared_receipt.path().unwrap();
            let prepared_summary = prepared_summary.path().unwrap();
            fs::hard_link(&prepared_receipt, &receipt).unwrap();
            fs::hard_link(&prepared_summary, &summary).unwrap();
            if remove_receipt_preparation {
                fs::remove_file(&prepared_receipt).unwrap();
            } else {
                fs::remove_file(&prepared_summary).unwrap();
            }

            assert!(recover_prepared_receipts(&receipt, &summary, &package, &key).unwrap());
            assert!(!prepared_receipt.exists());
            assert!(!prepared_summary.exists());
            validate_receipt_files(&receipt, &summary, &package, &key).unwrap();
            fs::remove_file(receipt).unwrap();
            fs::remove_file(summary).unwrap();
        }
    }

    #[test]
    fn receipt_recovery_rejects_partial_and_conflicting_preparations() {
        let package = PackageSummary {
            root: [6; 32],
            logical_length: 7,
            entries: 1,
        };
        let suffix = object_name(&package.root);
        let suffix = suffix.strip_suffix(".obj").unwrap();
        let key = [9; 32];

        let receipt = temporary("only-receipt.cbor");
        let summary = receipt.with_extension("json");
        let prepared_receipt = prepared_output_path(&receipt, suffix, "receipt").unwrap();
        fs::write(&prepared_receipt, b"receipt").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &key),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(prepared_receipt).unwrap();

        let receipt = temporary("only-summary.cbor");
        let summary = receipt.with_extension("json");
        let prepared_summary = prepared_output_path(&summary, suffix, "summary").unwrap();
        fs::write(&prepared_summary, b"summary").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &key),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(prepared_summary).unwrap();

        let receipt = temporary("conflicting-receipt.cbor");
        let summary = receipt.with_extension("json");
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt = prepared_receipt.path().unwrap();
        let prepared_summary = prepared_summary.path().unwrap();
        drop((prepared_receipt, prepared_summary));
        let prepared_receipt = prepared_output_path(&receipt, suffix, "receipt").unwrap();
        let prepared_summary = prepared_output_path(&summary, suffix, "summary").unwrap();
        fs::write(&receipt, b"conflict").unwrap();
        fs::write(&summary, receipt_summary_bytes(&package)).unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &key),
            Err(Error::DestinationExists)
        ));
        fs::remove_file(prepared_receipt).unwrap();
        fs::remove_file(prepared_summary).unwrap();
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();

        let receipt = temporary("conflicting-summary.cbor");
        let summary = receipt.with_extension("json");
        let (mut prepared_receipt_owner, mut prepared_summary_owner) =
            prepared_evidence(&receipt, &summary, &package, &key);
        prepared_receipt_owner.preserve_for_recovery();
        prepared_summary_owner.preserve_for_recovery();
        let prepared_receipt = prepared_receipt_owner.path().unwrap();
        let prepared_summary = prepared_summary_owner.path().unwrap();
        drop((prepared_receipt_owner, prepared_summary_owner));
        fs::copy(&prepared_receipt, &receipt).unwrap();
        fs::write(&summary, b"conflict").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &key),
            Err(Error::DestinationExists)
        ));
        fs::remove_file(prepared_receipt).unwrap();
        fs::remove_file(prepared_summary).unwrap();
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn receipt_recovery_authenticates_prepared_evidence() {
        let package = PackageSummary {
            root: [8; 32],
            logical_length: 7,
            entries: 1,
        };
        let receipt = temporary("wrong-key-receipt.cbor");
        let summary = receipt.with_extension("json");
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &[8; 32]);
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        drop((prepared_receipt, prepared_summary));
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &[9; 32]),
            Err(Error::InvalidBundle)
        ));
        assert!(!receipt.exists());
        assert!(!summary.exists());
        assert!(prepared_receipt_path.exists());
        assert!(prepared_summary_path.exists());

        fs::remove_file(&prepared_receipt_path).unwrap();
        fs::remove_file(&prepared_summary_path).unwrap();
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &[9; 32]);
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        drop((prepared_receipt, prepared_summary));
        fs::write(&prepared_summary_path, b"{\"root\":\"wrong\"}\n").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &[9; 32]),
            Err(Error::InvalidBundle)
        ));
        assert!(!receipt.exists());
        assert!(!summary.exists());
        fs::remove_file(prepared_receipt_path).unwrap();
        fs::remove_file(prepared_summary_path).unwrap();
    }

    #[test]
    fn recovered_receipt_requires_every_publication_field() {
        let package = PackageSummary {
            root: [10; 32],
            logical_length: 7,
            entries: 1,
        };
        let key = [9; 32];
        let base = publication_receipt(&package, "2026-07-31T23:59:59Z", [5; 32]);
        let mut cases = Vec::new();

        let mut wrong = base.clone();
        wrong.subject_kind = SubjectKind::Object;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.suite_id = 2;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.subject_digest[0] ^= 1;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.subject_length += 1;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.assurance = AssuranceLevel::Durable;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.profile = CommitProfile::Balanced;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.actual_predecessor = AssuranceLevel::Durable;
        cases.push(wrong);
        let mut wrong = base;
        wrong.provider = 2;
        cases.push(wrong);

        for (index, wrong) in cases.into_iter().enumerate() {
            let receipt = temporary(&format!("wrong-field-{index}.cbor"));
            let summary = receipt.with_extension("json");
            let authenticated = authenticate_hmac_sha256(wrong, b"vot-cli", &key).unwrap();
            fs::write(&receipt, encode_authenticated(&authenticated).unwrap()).unwrap();
            fs::write(&summary, receipt_summary_bytes(&package)).unwrap();
            assert!(matches!(
                validate_receipt_files(&receipt, &summary, &package, &key),
                Err(Error::InvalidBundle)
            ));
            fs::remove_file(receipt).unwrap();
            fs::remove_file(summary).unwrap();
        }

        let receipt = temporary("wrong-key-id.cbor");
        let summary = receipt.with_extension("json");
        let authenticated = authenticate_hmac_sha256(
            publication_receipt(&package, "2026-07-31T23:59:59Z", [5; 32]),
            b"another-key",
            &key,
        )
        .unwrap();
        fs::write(&receipt, encode_authenticated(&authenticated).unwrap()).unwrap();
        fs::write(&summary, receipt_summary_bytes(&package)).unwrap();
        assert!(matches!(
            validate_receipt_files(&receipt, &summary, &package, &key),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn live_receipt_preparation_is_not_removed_by_a_contender() {
        let package = PackageSummary {
            root: [7; 32],
            logical_length: 1,
            entries: 1,
        };
        let receipt = temporary("live-receipt.cbor");
        let summary = receipt.with_extension("json");
        let key = [9; 32];
        let (prepared_receipt, prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        let paths = existing_prepared_receipts(&receipt, &summary, &package, &key)
            .unwrap()
            .unwrap();
        assert!(paths.0.exists());
        assert!(paths.1.exists());
        assert!(matches!(
            existing_prepared_receipts(&receipt, &summary, &package, &[8; 32]),
            Err(Error::InvalidBundle)
        ));
        assert!(paths.0.exists());
        assert!(paths.1.exists());
        drop((prepared_receipt, prepared_summary));
        assert!(!paths.0.exists());
        assert!(!paths.1.exists());
    }

    #[test]
    fn receipt_file_bounds_are_exact() {
        let left = temporary("bounded-left");
        let right = temporary("bounded-right");
        fs::write(&left, b"same").unwrap();
        fs::write(&right, b"same").unwrap();
        assert!(bounded_files_equal(&left, &right, 4).unwrap());
        assert!(!bounded_files_equal(&left, &right, 3).unwrap());
        fs::write(&right, b"diff").unwrap();
        assert!(!bounded_files_equal(&left, &right, 4).unwrap());
        fs::write(&right, b"short").unwrap();
        assert!(!bounded_files_equal(&left, &right, 5).unwrap());
        fs::write(&left, b"longer").unwrap();
        assert!(!bounded_files_equal(&left, &right, 5).unwrap());

        fs::write(&left, b"same").unwrap();
        fs::write(&right, b"same").unwrap();
        assert!(
            resolve_link_error(
                io::Error::from(io::ErrorKind::AlreadyExists),
                &left,
                &right,
                4
            )
            .is_ok()
        );
        assert!(matches!(
            resolve_link_error(
                io::Error::from(io::ErrorKind::PermissionDenied),
                &left,
                &right,
                4
            ),
            Err(Error::Io(_))
        ));
        fs::write(&right, b"nope").unwrap();
        assert!(matches!(
            resolve_link_error(
                io::Error::from(io::ErrorKind::AlreadyExists),
                &left,
                &right,
                4
            ),
            Err(Error::DestinationExists)
        ));
        fs::remove_file(left).unwrap();
        fs::remove_file(right).unwrap();
    }

    #[test]
    fn prepared_cleanup_is_idempotent_but_preserves_real_errors() {
        let path = temporary("remove-preparation");
        remove_preparation(&path).unwrap();
        fs::write(&path, b"prepared").unwrap();
        remove_preparation(&path).unwrap();
        assert!(!path.exists());
        fs::create_dir(&path).unwrap();
        assert!(matches!(remove_preparation(&path), Err(Error::Io(_))));
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn verified_pack_can_be_reloaded_after_cache_eviction() {
        let source = temporary("repeated-pack-source");
        let bundle = temporary("repeated-pack-bundle");
        let destination = temporary("repeated-pack-destination");
        let receipt = temporary("repeated-pack-receipt.cbor");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("a"), [0x11]).unwrap();
        fs::write(source.join("b"), vec![0x31; CANDIDATE_MAX + 1]).unwrap();
        fs::write(source.join("c"), [0x22]).unwrap();
        fs::write(source.join("d"), vec![0x32; CANDIDATE_MAX + 1]).unwrap();
        fs::write(source.join("e"), [0x11]).unwrap();
        build_bundle(&source, &bundle).unwrap();
        receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &[7; 32],
            "2026-07-31T23:59:59Z",
        )
        .unwrap();
        assert_eq!(fs::read(destination.join("a")).unwrap(), [0x11]);
        assert_eq!(fs::read(destination.join("c")).unwrap(), [0x22]);
        assert_eq!(fs::read(destination.join("e")).unwrap(), [0x11]);

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(receipt.with_extension("json")).unwrap();
        fs::remove_file(receipt).unwrap();
    }

    #[test]
    fn repeated_direct_object_is_reverified_before_copy() {
        let object = temporary("repeated-direct-object");
        let first = temporary("repeated-direct-first");
        let second = temporary("repeated-direct-second");
        let bytes = vec![0x5a; CANDIDATE_MAX + 1];
        let root = vot_verifier::root(Suite::Sha256Bep52, &bytes).unwrap();
        fs::write(&object, &bytes).unwrap();
        let limit = (MAX_DATA_RECORD_BYTES + vot_verifier::GROUP_SIZE) as u64;
        let mut receiver = ReliableReceiver::new(
            limit,
            MAX_DATA_RECORD_BYTES as u64,
            MAX_DATA_RECORD_BYTES as u64,
        )
        .unwrap();
        receive_direct(
            &object,
            &first,
            root,
            bytes.len() as u64,
            Suite::Sha256Bep52,
            &mut receiver,
        )
        .unwrap();
        let mut corrupted = bytes;
        corrupted[0] ^= 1;
        fs::write(&object, corrupted).unwrap();
        assert!(matches!(
            receive_direct(
                &object,
                &second,
                root,
                fs::metadata(&object).unwrap().len(),
                Suite::Sha256Bep52,
                &mut receiver
            ),
            Err(Error::RootMismatch)
        ));
        fs::remove_file(object).unwrap();
        fs::remove_file(first).unwrap();
        fs::remove_file(second).unwrap();
    }

    #[test]
    fn suite_parser_accepts_every_public_alias() {
        assert_eq!(parse_suite("blake3").unwrap(), Suite::Blake3Bao64);
        assert_eq!(parse_suite("blake3-bao64").unwrap(), Suite::Blake3Bao64);
        assert_eq!(parse_suite("1").unwrap(), Suite::Blake3Bao64);
        assert_eq!(parse_suite("sha256").unwrap(), Suite::Sha256Bep52);
        assert_eq!(parse_suite("sha256-bep52").unwrap(), Suite::Sha256Bep52);
        assert_eq!(parse_suite("2").unwrap(), Suite::Sha256Bep52);
        assert!(matches!(
            parse_suite("unknown"),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn copy_and_verify_rejects_length_or_root_mismatch() {
        let source = temporary("copy-source");
        let data = b"copy-and-verify";
        fs::write(&source, data).unwrap();
        let root = vot_verifier::root(Suite::Sha256Bep52, data).unwrap();

        let valid_destination = temporary("copy-valid");
        copy_and_verify(
            &source,
            &valid_destination,
            data.len() as u64,
            root,
            Suite::Sha256Bep52,
        )
        .unwrap();
        fs::remove_file(valid_destination).unwrap();

        let length_destination = temporary("copy-length-mismatch");
        assert!(matches!(
            copy_and_verify(
                &source,
                &length_destination,
                data.len() as u64 + 1,
                root,
                Suite::Sha256Bep52,
            ),
            Err(Error::SourceMutation)
        ));
        fs::remove_file(length_destination).unwrap();

        let root_destination = temporary("copy-root-mismatch");
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(matches!(
            copy_and_verify(
                &source,
                &root_destination,
                data.len() as u64,
                wrong_root,
                Suite::Sha256Bep52,
            ),
            Err(Error::SourceMutation)
        ));
        fs::remove_file(root_destination).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn key_decoder_is_strict_and_bounded() {
        assert_eq!(MAX_KEY_SOURCE_BYTES, 133);
        assert!(decode_key(&"ab".repeat(34)).is_ok());
        assert_eq!(decode_key(&"ab".repeat(64)).unwrap(), vec![0xab; 64]);
        assert!(matches!(
            decode_key(&"ab".repeat(65)),
            Err(Error::InvalidArguments)
        ));
        assert!(matches!(
            decode_key(&"a".repeat(65)),
            Err(Error::InvalidArguments)
        ));
        assert_eq!(decode_key(&"00".repeat(32)).unwrap(), vec![0; 32]);
        assert!(matches!(decode_key("0"), Err(Error::InvalidArguments)));
        assert!(matches!(
            decode_key(&"gg".repeat(32)),
            Err(Error::InvalidArguments)
        ));
        assert!(matches!(
            decode_key(&"00".repeat(31)),
            Err(Error::InvalidArguments)
        ));
        assert_eq!(
            decode_key(&"0123456789abcdef".repeat(4)).unwrap(),
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef,
            ]
        );
        assert_eq!(
            decode_key(&format!("{}0000", "ABCDEF".repeat(10))).unwrap()[..3],
            [0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn key_spec_loader_decodes_hex_and_preserves_raw_keys() {
        let hex_path = temporary("hex-key");
        fs::write(&hex_path, format!("hex:{}\n", "ab".repeat(32))).unwrap();
        assert_eq!(
            load_key_spec(hex_path.to_str().unwrap()).unwrap(),
            vec![0xab; 32]
        );
        fs::remove_file(&hex_path).unwrap();

        let raw_path = temporary("raw-key");
        fs::write(&raw_path, [7; 32]).unwrap();
        assert_eq!(
            load_key_spec(raw_path.to_str().unwrap()).unwrap(),
            vec![7; 32]
        );
        fs::remove_file(&raw_path).unwrap();

        let ambiguous_path = temporary("ambiguous-raw-key");
        fs::write(&ambiguous_path, [b'a'; 64]).unwrap();
        assert_eq!(
            load_key_spec(ambiguous_path.to_str().unwrap()).unwrap(),
            vec![b'a'; 64]
        );
        fs::remove_file(&ambiguous_path).unwrap();

        let short_path = temporary("short-key");
        fs::write(&short_path, [7; 31]).unwrap();
        assert!(matches!(
            load_key_spec(short_path.to_str().unwrap()),
            Err(Error::InvalidArguments)
        ));
        fs::remove_file(&short_path).unwrap();

        let oversized_path = temporary("oversized-key");
        fs::write(&oversized_path, [7; 65]).unwrap();
        assert!(matches!(
            load_key_spec(oversized_path.to_str().unwrap()),
            Err(Error::InvalidArguments)
        ));
        fs::remove_file(oversized_path).unwrap();
    }

    #[test]
    fn key_source_limit_is_exact_and_reads_are_bounded() {
        assert!(validate_key_source_length(MAX_KEY_SOURCE_BYTES).is_ok());
        assert!(matches!(
            validate_key_source_length(MAX_KEY_SOURCE_BYTES + 1),
            Err(Error::InvalidArguments)
        ));

        let exact = read_key_source(io::Cursor::new(vec![7; MAX_KEY_SOURCE_BYTES])).unwrap();
        assert_eq!(exact.len(), MAX_KEY_SOURCE_BYTES);
        assert!(matches!(
            read_key_source(io::Cursor::new(vec![7; MAX_KEY_SOURCE_BYTES + 1])),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn package_boundaries_and_conflicts_are_exact() {
        let missing = temporary("missing-source");
        let bundle = temporary("existing-bundle");
        fs::create_dir(&bundle).unwrap();
        assert!(matches!(
            build_bundle(&missing, &temporary("missing-bundle")),
            Err(Error::InvalidArguments)
        ));

        let source = temporary("conflict-source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"content").unwrap();
        assert!(matches!(
            build_bundle(&source, &bundle),
            Err(Error::InvalidArguments)
        ));
        let new_bundle = temporary("conflict-bundle");
        build_bundle(&source, &new_bundle).unwrap();
        let destination = temporary("existing-destination");
        fs::create_dir(&destination).unwrap();
        let receipt = temporary("conflict-receipt.cbor");
        assert!(matches!(
            receive_bundle(
                &new_bundle,
                &destination,
                &receipt,
                &[7; 32],
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::DestinationExists)
        ));
        fs::remove_dir(&destination).unwrap();
        fs::write(&receipt, b"exists").unwrap();
        assert!(matches!(
            receive_bundle(
                &new_bundle,
                &destination,
                &receipt,
                &[7; 32],
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::DestinationExists)
        ));

        fs::remove_dir(bundle).unwrap();
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(new_bundle).unwrap();
        fs::remove_file(receipt).unwrap();
    }

    #[test]
    fn existing_destination_must_match_before_receipt_recovery() {
        let source = temporary("recovery-validation-source");
        let bundle = temporary("recovery-validation-bundle");
        let destination = temporary("recovery-validation-destination");
        let receipt = temporary("recovery-validation-receipt.cbor");
        let summary = receipt.with_extension("json");
        let key = [9; 32];
        fs::create_dir(&source).unwrap();
        fs::write(source.join("expected"), b"verified contents").unwrap();
        let package = build_bundle(&source, &bundle).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("unrelated"), b"wrong contents").unwrap();
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt = prepared_receipt.path().unwrap();
        let prepared_summary = prepared_summary.path().unwrap();

        assert!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &key,
                "2026-07-31T23:59:59Z",
            )
            .is_err()
        );
        assert!(!receipt.exists());
        assert!(!summary.exists());
        assert!(prepared_receipt.exists());
        assert!(prepared_summary.exists());

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(prepared_receipt).unwrap();
        fs::remove_file(prepared_summary).unwrap();
    }

    #[test]
    fn published_destination_validation_checks_every_boundary() {
        let source = temporary("published-validation-source");
        let bundle = temporary("published-validation-bundle");
        let destination = temporary("published-validation-destination");
        let receipt = temporary("published-validation-receipt.cbor");
        let summary = receipt.with_extension("json");
        let key = [7; 32];
        fs::create_dir(&source).unwrap();
        fs::write(source.join("expected"), b"verified contents").unwrap();
        let package = build_bundle(&source, &bundle).unwrap();
        receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &key,
            "2026-07-31T23:59:59Z",
        )
        .unwrap();

        validate_published_destination(&bundle, &destination, &package).unwrap();
        fs::write(destination.join("expected"), b"corruptd contents").unwrap();
        assert!(matches!(
            validate_published_destination(&bundle, &destination, &package),
            Err(Error::RootMismatch)
        ));
        fs::write(destination.join("expected"), b"verified contents").unwrap();
        fs::write(destination.join("extra"), b"extra").unwrap();
        assert!(matches!(
            validate_published_destination(&bundle, &destination, &package),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(destination.join("extra")).unwrap();

        fs::remove_file(&receipt).unwrap();
        assert!(matches!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &key,
                "2026-07-31T23:59:59Z",
            ),
            Err(Error::InvalidBundle)
        ));

        let not_directory = temporary("published-validation-file");
        fs::write(&not_directory, b"file").unwrap();
        assert!(matches!(
            validate_published_destination(&bundle, &not_directory, &package),
            Err(Error::InvalidBundle)
        ));

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(summary).unwrap();
        fs::remove_file(not_directory).unwrap();
    }

    #[test]
    fn published_destination_walk_has_exact_depth_and_count_bounds() {
        let single = temporary("published-count-single");
        fs::create_dir(&single).unwrap();
        fs::write(single.join("file"), b"file").unwrap();
        let mut count = 0;
        count_published_files(&single, vot_manifest::MAX_PATH_COMPONENTS, &mut count).unwrap();
        assert_eq!(count, 1);
        assert!(matches!(
            count_published_files(&single, vot_manifest::MAX_PATH_COMPONENTS + 1, &mut count,),
            Err(Error::InvalidBundle)
        ));
        fs::remove_dir_all(single).unwrap();

        let deep = temporary("published-count-deep");
        fs::create_dir_all(deep.join("d")).unwrap();
        assert!(matches!(
            count_published_files(&deep, vot_manifest::MAX_PATH_COMPONENTS, &mut 0),
            Err(Error::InvalidBundle)
        ));
        fs::remove_dir_all(deep).unwrap();
    }

    #[test]
    fn empty_canonical_manifest_cannot_publish() {
        let bundle = temporary("empty-canonical-bundle");
        let manifest_directory = bundle.join(MANIFEST_DIRECTORY);
        fs::create_dir_all(&manifest_directory).unwrap();
        let package = PackageRootBuilder::new().unwrap().finish().unwrap();
        let mut manifest_id = [0; 16];
        manifest_id.copy_from_slice(&package.root[..16]);
        let page = ManifestPage {
            manifest_id,
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: Vec::new(),
        };
        let encoded_page = encode_page(&page).unwrap();
        let page_digest = *blake3::hash(&encoded_page).as_bytes();
        let seal = Seal {
            manifest_id,
            final_page_count: 1,
            final_page_digest: page_digest,
            package: ObjectId {
                suite: 1,
                root: package.root,
                length: 0,
            },
            pages: vec![PageCommitment {
                index: 0,
                digest: page_digest,
            }],
        };
        fs::write(manifest_page_path(&manifest_directory, 0), encoded_page).unwrap();
        fs::write(
            manifest_directory.join(MANIFEST_SEAL),
            encode_seal(&seal).unwrap(),
        )
        .unwrap();
        let destination = temporary("empty-canonical-destination");
        let receipt = temporary("empty-canonical-receipt.cbor");
        assert!(matches!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &[7; 32],
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::InvalidBundle)
        ));
        assert!(!destination.exists());
        assert!(!receipt.exists());
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn helpers_enforce_exact_bounds_and_identity() {
        let directory = temporary("objects");
        fs::create_dir(&directory).unwrap();
        let root = [3; 32];
        write_object(&directory, &root, b"bytes").unwrap();
        write_object(&directory, &root, b"bytes").unwrap();
        assert!(matches!(
            write_object(&directory, &root, b"other"),
            Err(Error::RootMismatch)
        ));

        let over = directory.join("over");
        fs::write(&over, vec![0; 5]).unwrap();
        assert_eq!(read_bounded_file(&over, 5).unwrap(), vec![0; 5]);
        assert!(matches!(
            read_bounded_file(&over, 4),
            Err(Error::InvalidBundle)
        ));

        assert_eq!(parent_directory(Path::new("receipt")), Path::new("."));
        assert_eq!(
            parent_directory(Path::new("nested/receipt")),
            Path::new("nested")
        );
        let cached = (Suite::Sha256Bep52, [5; 32], 9, Vec::new());
        assert!(!pack_needs_load(
            Some(&cached),
            Suite::Sha256Bep52,
            [5; 32],
            9
        ));
        assert!(pack_needs_load(
            Some(&cached),
            Suite::Blake3Bao64,
            [5; 32],
            9
        ));
        assert!(pack_needs_load(
            Some(&cached),
            Suite::Sha256Bep52,
            [6; 32],
            9
        ));
        assert!(pack_needs_load(
            Some(&cached),
            Suite::Sha256Bep52,
            [5; 32],
            10
        ));
        assert!(pack_needs_load(None, Suite::Sha256Bep52, [5; 32], 9));

        let mut receiver = ReliableReceiver::new(
            (MAX_DATA_RECORD_BYTES + vot_verifier::GROUP_SIZE) as u64,
            MAX_DATA_RECORD_BYTES as u64,
            MAX_DATA_RECORD_BYTES as u64,
        )
        .unwrap();
        assert!(matches!(
            receive_object(
                Path::new("does-not-exist"),
                [0; 32],
                vot_pack::HARD_MAX as u64 + 1,
                Suite::Sha256Bep52,
                &mut receiver
            ),
            Err(Error::InvalidBundle)
        ));
        assert!(matches!(
            receive_object(
                Path::new("does-not-exist"),
                [0; 32],
                vot_pack::HARD_MAX as u64,
                Suite::Sha256Bep52,
                &mut receiver
            ),
            Err(Error::Io(_))
        ));
        let short = directory.join("short");
        fs::write(&short, b"x").unwrap();
        assert!(matches!(
            receive_object(&short, [0; 32], 2, Suite::Sha256Bep52, &mut receiver),
            Err(Error::InvalidBundle)
        ));
        fs::create_dir(directory.join("nested")).unwrap();
        assert_eq!(sync_directories(&directory).unwrap(), 2);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn manifest_record_validation_rejects_each_wrong_field() {
        let logical = ObjectId {
            suite: 2,
            root: [3; 32],
            length: 3,
        };
        let direct = ManifestEntry {
            path: vec![Component::Text("file".to_owned())],
            kind: EntryKind::File,
            length: Some(3),
            storage: Some(StorageRef::Direct(logical.clone())),
            metadata: None,
        };
        assert!(EntryRecord::from_manifest(direct.clone()).is_ok());

        let mut wrong = direct.clone();
        wrong.kind = EntryKind::Directory;
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.metadata = Some(vot_manifest::FileMetadata::default());
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.length = None;
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.storage = None;
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.storage = Some(StorageRef::Direct(ObjectId {
            suite: 1,
            ..logical.clone()
        }));
        assert!(EntryRecord::from_manifest(wrong).is_ok());
        wrong = direct.clone();
        wrong.storage = Some(StorageRef::Direct(ObjectId {
            suite: 99,
            ..logical.clone()
        }));
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.storage = Some(StorageRef::Direct(ObjectId {
            length: 2,
            ..logical.clone()
        }));
        assert!(EntryRecord::from_manifest(wrong).is_err());

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
                logical.clone()
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
                }
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
                }
            ))
            .is_err()
        );
    }

    #[test]
    fn manifest_page_bounds_and_envelope_checks_are_exact() {
        assert!(!page_needs_flush(0, vot_manifest::MAX_PAGE_BYTES, 1).unwrap());
        assert!(page_needs_flush(vot_manifest::MAX_ENTRIES_PER_PAGE, 0, 1).unwrap());
        assert!(!page_needs_flush(1, vot_manifest::MAX_PAGE_BYTES - 1, 1).unwrap());
        assert!(page_needs_flush(1, vot_manifest::MAX_PAGE_BYTES, 1).unwrap());
        assert!(page_needs_flush(1, usize::MAX, 1).is_err());

        let mut page = ManifestPage {
            manifest_id: [1; 16],
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: Vec::new(),
        };
        let seal = Seal {
            manifest_id: [1; 16],
            final_page_count: 1,
            final_page_digest: [2; 32],
            package: ObjectId {
                suite: 1,
                root: [3; 32],
                length: 0,
            },
            pages: vec![PageCommitment {
                index: 0,
                digest: [2; 32],
            }],
        };
        let mut commitment = seal.pages[0].clone();
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_ok());
        page.manifest_id = [9; 16];
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        page.manifest_id = seal.manifest_id;
        page.index = 1;
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        page.index = 0;
        page.total = Some(2);
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        page.total = Some(1);
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_ok());
        page.previous_digest = [8; 32];
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        page.previous_digest = [0; 32];
        commitment.index = 1;
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        commitment.index = 0;
        commitment.digest = [7; 32];
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
    }

    #[test]
    fn package_root_builder_contributes_every_record_field() {
        let record = EntryRecord {
            path: vec![Component::Text("a".to_owned())],
            suite: DEFAULT_LOGICAL_SUITE,
            logical_root: [5; 32],
            logical_length: 3,
            storage: Storage::Direct,
        };
        let path = encode_path(&record.path).unwrap();
        assert_eq!(path, [0, 1, 0, 1, b'a']);
        let mut transcript = Vec::from(PACKAGE_DOMAIN);
        transcript.extend_from_slice(&u32::try_from(path.len()).unwrap().to_be_bytes());
        transcript.extend_from_slice(&path);
        transcript.extend_from_slice(&2_u16.to_be_bytes());
        transcript.extend_from_slice(&record.logical_length.to_be_bytes());
        transcript.extend_from_slice(&record.logical_root);
        let expected = vot_verifier::root(Suite::Blake3Bao64, &transcript).unwrap();
        let mut builder = PackageRootBuilder::new().unwrap();
        builder.push(&record).unwrap();
        let package = builder.finish().unwrap();
        assert_eq!(package.root, expected);
        assert_eq!(package.logical_length, 3);
        assert_eq!(package.entries, 1);
    }
}
