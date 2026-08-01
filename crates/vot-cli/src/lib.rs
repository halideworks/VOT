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
    encode_authenticated,
};
use vot_scheduler::ReliableReceiver;
use vot_transport_api::{MAX_DATA_RECORD_BYTES, SubjectId};
use vot_verifier::{StreamVerifier, Suite};

const PACKAGE_DOMAIN: &[u8] = b"VOT package v0\0";
const MANIFEST_DIRECTORY: &str = "manifest";
const MANIFEST_SEAL: &str = "seal.cbor";

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
    logical_root: [u8; 32],
    logical_length: u64,
    storage: Storage,
}

impl EntryRecord {
    fn manifest_entry(&self) -> ManifestEntry {
        let logical = ObjectId {
            suite: 2,
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
                    suite: 2,
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
        let (logical_root, storage) = match storage {
            StorageRef::Direct(object) => {
                if object.suite != 2 || object.length != logical_length {
                    return Err(Error::InvalidBundle);
                }
                (object.root, Storage::Direct)
            }
            StorageRef::Pack {
                pack,
                offset,
                length,
                logical,
            } => {
                if pack.suite != 2
                    || logical.suite != 2
                    || length != logical_length
                    || logical.length != logical_length
                {
                    return Err(Error::InvalidBundle);
                }
                (
                    logical.root,
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
        self.verifier.update(&2_u16.to_be_bytes())?;
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
    if actual.root != expected.root {
        return Err(Error::RootMismatch);
    }
    if actual.logical_length != expected.logical_length {
        return Err(Error::RootMismatch);
    }
    Ok(actual)
}

fn manifest_page_path(directory: &Path, index: u64) -> PathBuf {
    directory.join(format!("{index:016}.cbor"))
}

fn manifest_spool_path(directory: &Path, index: u64) -> PathBuf {
    directory.join(format!(".spool-{index:016}.cbor"))
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, Error> {
    let length = fs::metadata(path)?.len();
    if length > maximum as u64 {
        return Err(Error::InvalidBundle);
    }
    fs::read(path).map_err(Error::Io)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn build_bundle(source: &Path, bundle: &Path) -> Result<PackageSummary, Error> {
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
    let mut packer = StreamingPacker::new(PathProfile::Portable);
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
            emit_direct(&objects, &mut manifest, &mut package, &source_file)?;
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
        if recover_prepared_receipts(receipt_path, &receipt_summary_path, &expected)? {
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
    clear_stale_prepared_receipts(receipt_path, &receipt_summary_path, &expected)?;
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
    let mut cached_pack: Option<([u8; 32], u64, Vec<u8>)> = None;

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
                    &mut receiver,
                )?;
            }
            Storage::Pack {
                root,
                length,
                offset,
            } => {
                let needs_load = pack_needs_load(cached_pack.as_ref(), root, length);
                if needs_load {
                    let bytes = receive_object(
                        &bundle.join("objects").join(object_name(&root)),
                        root,
                        length,
                        &mut receiver,
                    )?;
                    cached_pack = Some((root, length, bytes));
                }
                let (_, _, bytes) = cached_pack.as_ref().ok_or(Error::InvalidBundle)?;
                let start = usize::try_from(offset).map_err(|_| Error::InvalidBundle)?;
                let logical =
                    usize::try_from(record.logical_length).map_err(|_| Error::InvalidBundle)?;
                let end = start.checked_add(logical).ok_or(Error::InvalidBundle)?;
                let extracted = bytes.get(start..end).ok_or(Error::InvalidBundle)?;
                if vot_verifier::root(Suite::Sha256Bep52, extracted)? != record.logical_root {
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
    let freshness = fresh_receipt_identifiers()?;
    let receipt = publication_receipt(&actual, observed_at, freshness);
    let authenticated = authenticate_hmac_sha256(receipt, b"vot-cli", key)?;
    let encoded = encode_authenticated(&authenticated)?;
    let summary = receipt_summary_bytes(&actual);
    let suffix = object_name(&actual.root);
    let suffix = suffix.strip_suffix(".obj").ok_or(Error::InvalidBundle)?;
    let mut prepared_receipt = PreparedFile::new(receipt_path, &encoded, suffix, "receipt")?;
    let mut prepared_summary =
        PreparedFile::new(&receipt_summary_path, summary.as_bytes(), suffix, "summary")?;
    if sync_directories(&staging)? == 0 {
        return Err(Error::InvalidBundle);
    }
    atomic_rename_noreplace(&staging, destination)?;
    File::open(parent_directory(destination))?.sync_all()?;
    prepared_receipt.preserve_for_recovery();
    prepared_summary.preserve_for_recovery();
    finalize_prepared_receipts(
        receipt_path,
        &receipt_summary_path,
        &prepared_receipt.path()?,
        &prepared_summary.path()?,
    )?;
    Ok(ReceiveReport {
        package: actual,
        peak_staging: receiver.peak_staging(),
    })
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
) -> Result<(), Error> {
    let root = stream_root(&source.source, source.length)?;
    let object = objects.join(object_name(&root));
    if object.exists() {
        if stream_root(&object, source.length)? != root {
            return Err(Error::RootMismatch);
        }
    } else {
        let mut input = File::open(&source.source)?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&object)?;
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        if stream_root(&object, source.length)? != root {
            return Err(Error::SourceMutation);
        }
    }
    let record = EntryRecord {
        path: source.path.clone(),
        logical_root: root,
        logical_length: source.length,
        storage: Storage::Direct,
    };
    package.push(&record)?;
    manifest.push(record.manifest_entry())?;
    Ok(())
}

fn stream_root(path: &Path, expected_length: u64) -> Result<[u8; 32], Error> {
    let mut input = File::open(path)?;
    let mut verifier = StreamVerifier::new(Suite::Sha256Bep52);
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
        if fs::read(&path)? == bytes {
            return Ok(());
        }
        return Err(Error::RootMismatch);
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn receive_direct(
    object: &Path,
    output: &Path,
    root: [u8; 32],
    length: u64,
    receiver: &mut ReliableReceiver,
) -> Result<(), Error> {
    create_parent(output)?;
    let mut source = File::open(object)?;
    if source.metadata()?.len() != length {
        return Err(Error::InvalidBundle);
    }
    let subject = SubjectId {
        suite: 2,
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
    let mut verifier = already_verified.then(|| StreamVerifier::new(Suite::Sha256Bep52));
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
        suite: 2,
        root,
        length,
    };
    let already_verified = receiver.is_verified(subject);
    if !already_verified {
        receiver.begin(subject)?;
    }
    let mut verifier = already_verified.then(|| StreamVerifier::new(Suite::Sha256Bep52));
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

fn pack_needs_load(cached: Option<&([u8; 32], u64, Vec<u8>)>, root: [u8; 32], length: u64) -> bool {
    cached.is_none_or(|(cached_root, cached_length, _)| {
        *cached_root != root || *cached_length != length
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

fn clear_stale_prepared_receipts(
    receipt: &Path,
    summary: &Path,
    package: &PackageSummary,
) -> Result<(), Error> {
    let suffix = object_name(&package.root);
    let suffix = suffix.strip_suffix(".obj").ok_or(Error::InvalidBundle)?;
    for path in [
        prepared_output_path(receipt, suffix, "receipt")?,
        prepared_output_path(summary, suffix, "summary")?,
    ] {
        remove_if_exists(&path)?;
    }
    Ok(())
}

fn recover_prepared_receipts(
    receipt: &Path,
    summary: &Path,
    package: &PackageSummary,
) -> Result<bool, Error> {
    let suffix = object_name(&package.root);
    let suffix = suffix.strip_suffix(".obj").ok_or(Error::InvalidBundle)?;
    let prepared_receipt = prepared_output_path(receipt, suffix, "receipt")?;
    let prepared_summary = prepared_output_path(summary, suffix, "summary")?;
    let receipt_prepared = prepared_receipt.exists();
    let summary_prepared = prepared_summary.exists();
    if !receipt_prepared {
        if !summary_prepared {
            return Ok(false);
        }
        return Err(Error::InvalidBundle);
    }
    if !summary_prepared {
        return Err(Error::InvalidBundle);
    }
    if receipt.exists() && summary.exists() {
        if !bounded_files_equal(&prepared_receipt, receipt, 65_536)? {
            return Err(Error::DestinationExists);
        }
        if !bounded_files_equal(&prepared_summary, summary, 4096)? {
            return Err(Error::DestinationExists);
        }
        fs::remove_file(prepared_receipt)?;
        fs::remove_file(prepared_summary)?;
        File::open(parent_directory(receipt))?.sync_all()?;
        return Ok(true);
    }
    finalize_prepared_receipts(receipt, summary, &prepared_receipt, &prepared_summary)?;
    Ok(true)
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

fn link_or_match(prepared: &Path, destination: &Path, maximum: u64) -> Result<(), Error> {
    match fs::hard_link(prepared, destination) {
        Ok(()) => Ok(()),
        Err(error) => resolve_link_error(error, prepared, destination, maximum),
    }
}

fn bounded_files_equal(left: &Path, right: &Path, maximum: u64) -> Result<bool, Error> {
    let left_length = fs::metadata(left)?.len();
    let right_length = fs::metadata(right)?.len();
    if left_length > maximum {
        return Ok(false);
    }
    if right_length > maximum {
        return Ok(false);
    }
    if left_length != right_length {
        return Ok(false);
    }
    Ok(fs::read(left)? == fs::read(right)?)
}

fn remove_if_exists(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) => resolve_remove_error(error),
    }
}

fn resolve_remove_error(error: io::Error) -> Result<(), Error> {
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(Error::Io(error))
    }
}

fn resolve_link_error(
    error: io::Error,
    prepared: &Path,
    destination: &Path,
    maximum: u64,
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

pub fn decode_key(value: &str) -> Result<Vec<u8>, Error> {
    if value.len() % 2 != 0 {
        return Err(Error::InvalidArguments);
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex(pair[0]).ok_or(Error::InvalidArguments)?;
        let low = hex(pair[1]).ok_or(Error::InvalidArguments)?;
        output.push(high * 16 + low);
    }
    if output.len() < 32 {
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

    #[test]
    fn receipt_publication_recovers_after_destination_publish() {
        let receipt = temporary("recover-receipt.cbor");
        let summary = receipt.with_extension("json");
        let package = PackageSummary {
            root: [4; 32],
            logical_length: 7,
            entries: 1,
        };
        let suffix = object_name(&package.root);
        let suffix = suffix.strip_suffix(".obj").unwrap();
        let mut prepared_receipt =
            PreparedFile::new(&receipt, b"authenticated", suffix, "receipt").unwrap();
        let mut prepared_summary =
            PreparedFile::new(&summary, b"{\"complete\":true}\\n", suffix, "summary").unwrap();
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        drop(prepared_receipt);
        drop(prepared_summary);
        assert!(prepared_receipt_path.exists());
        assert!(prepared_summary_path.exists());
        fs::hard_link(&prepared_receipt_path, &receipt).unwrap();

        assert!(recover_prepared_receipts(&receipt, &summary, &package).unwrap());
        assert_eq!(fs::read(&receipt).unwrap(), b"authenticated");
        assert_eq!(fs::read(&summary).unwrap(), b"{\"complete\":true}\\n");
        assert!(!prepared_receipt_path.exists());
        assert!(!prepared_summary_path.exists());
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
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

        let receipt = temporary("only-receipt.cbor");
        let summary = receipt.with_extension("json");
        let prepared_receipt = prepared_output_path(&receipt, suffix, "receipt").unwrap();
        fs::write(&prepared_receipt, b"receipt").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(prepared_receipt).unwrap();

        let receipt = temporary("only-summary.cbor");
        let summary = receipt.with_extension("json");
        let prepared_summary = prepared_output_path(&summary, suffix, "summary").unwrap();
        fs::write(&prepared_summary, b"summary").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(prepared_summary).unwrap();

        let receipt = temporary("conflicting-receipt.cbor");
        let summary = receipt.with_extension("json");
        let prepared_receipt = prepared_output_path(&receipt, suffix, "receipt").unwrap();
        let prepared_summary = prepared_output_path(&summary, suffix, "summary").unwrap();
        fs::write(&prepared_receipt, b"expected").unwrap();
        fs::write(&prepared_summary, b"summary").unwrap();
        fs::write(&receipt, b"conflict").unwrap();
        fs::write(&summary, b"summary").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package),
            Err(Error::DestinationExists)
        ));
        fs::remove_file(prepared_receipt).unwrap();
        fs::remove_file(prepared_summary).unwrap();
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();

        let receipt = temporary("conflicting-summary.cbor");
        let summary = receipt.with_extension("json");
        let prepared_receipt = prepared_output_path(&receipt, suffix, "receipt").unwrap();
        let prepared_summary = prepared_output_path(&summary, suffix, "summary").unwrap();
        fs::write(&prepared_receipt, b"receipt").unwrap();
        fs::write(&prepared_summary, b"expected").unwrap();
        fs::write(&receipt, b"receipt").unwrap();
        fs::write(&summary, b"conflict").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package),
            Err(Error::DestinationExists)
        ));
        fs::remove_file(prepared_receipt).unwrap();
        fs::remove_file(prepared_summary).unwrap();
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn receipt_preparation_cleanup_and_file_bounds_are_exact() {
        let package = PackageSummary {
            root: [7; 32],
            logical_length: 1,
            entries: 1,
        };
        let receipt = temporary("stale-receipt.cbor");
        let summary = receipt.with_extension("json");
        let suffix = object_name(&package.root);
        let suffix = suffix.strip_suffix(".obj").unwrap();
        let prepared_receipt = prepared_output_path(&receipt, suffix, "receipt").unwrap();
        let prepared_summary = prepared_output_path(&summary, suffix, "summary").unwrap();
        fs::write(&prepared_receipt, b"stale").unwrap();
        fs::write(&prepared_summary, b"stale").unwrap();
        clear_stale_prepared_receipts(&receipt, &summary, &package).unwrap();
        assert!(!prepared_receipt.exists());
        assert!(!prepared_summary.exists());
        clear_stale_prepared_receipts(&receipt, &summary, &package).unwrap();
        assert!(resolve_remove_error(io::Error::from(io::ErrorKind::NotFound)).is_ok());
        assert!(matches!(
            resolve_remove_error(io::Error::from(io::ErrorKind::PermissionDenied)),
            Err(Error::Io(_))
        ));

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
        receive_direct(&object, &first, root, bytes.len() as u64, &mut receiver).unwrap();
        let mut corrupted = bytes;
        corrupted[0] ^= 1;
        fs::write(&object, corrupted).unwrap();
        assert!(matches!(
            receive_direct(
                &object,
                &second,
                root,
                fs::metadata(&object).unwrap().len(),
                &mut receiver
            ),
            Err(Error::RootMismatch)
        ));
        fs::remove_file(object).unwrap();
        fs::remove_file(first).unwrap();
        fs::remove_file(second).unwrap();
    }

    #[test]
    fn key_decoder_is_strict_and_bounded() {
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
            decode_key(&"ABCDEF".repeat(11)).unwrap()[..3],
            [0xab, 0xcd, 0xef]
        );
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
        let cached = ([5; 32], 9, Vec::new());
        assert!(!pack_needs_load(Some(&cached), [5; 32], 9));
        assert!(pack_needs_load(Some(&cached), [6; 32], 9));
        assert!(pack_needs_load(Some(&cached), [5; 32], 10));
        assert!(pack_needs_load(None, [5; 32], 9));

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
                &mut receiver
            ),
            Err(Error::InvalidBundle)
        ));
        assert!(matches!(
            receive_object(
                Path::new("does-not-exist"),
                [0; 32],
                vot_pack::HARD_MAX as u64,
                &mut receiver
            ),
            Err(Error::Io(_))
        ));
        let short = directory.join("short");
        fs::write(&short, b"x").unwrap();
        assert!(matches!(
            receive_object(&short, [0; 32], 2, &mut receiver),
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
