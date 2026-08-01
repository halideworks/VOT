//! Bounded package construction, reliable verification, and durable publication.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use vot_manifest::{Component, PackagePath, PathProfile, canonical_path_key};
use vot_pack::{CANDIDATE_MAX, LogicalFile, Pack, StreamingPacker};
use vot_receipt::{
    AssuranceLevel, CommitProfile, Receipt, SubjectKind, authenticate_hmac_sha256,
    encode_authenticated,
};
use vot_scheduler::ReliableReceiver;
use vot_transport_api::{MAX_DATA_RECORD_BYTES, SubjectId};
use vot_verifier::{StreamVerifier, Suite};

const BUNDLE_MAGIC: [u8; 8] = *b"VOTPKG0\n";
const PACKAGE_DOMAIN: &[u8] = b"VOT package v0\0";
const HEADER_BYTES: u64 = 8 + 32 + 8 + 8;
const MAX_PATH_RECORD_BYTES: usize = 1_048_576;
const STORAGE_DIRECT: u8 = 0;
const STORAGE_PACK: u8 = 1;

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
    let manifest_path = bundle.join("manifest.vot");
    let mut manifest = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&manifest_path)?;
    manifest.write_all(&BUNDLE_MAGIC)?;
    manifest.write_all(&[0; 32])?;
    manifest.write_all(&0_u64.to_be_bytes())?;
    manifest.write_all(&0_u64.to_be_bytes())?;

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
    manifest.seek(SeekFrom::Start(8))?;
    manifest.write_all(&summary.root)?;
    manifest.write_all(&summary.logical_length.to_be_bytes())?;
    manifest.write_all(&summary.entries.to_be_bytes())?;
    manifest.sync_all()?;
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
    if destination.exists() {
        return Err(Error::DestinationExists);
    }
    if receipt_path.exists() {
        return Err(Error::DestinationExists);
    }
    if receipt_summary_path.exists() {
        return Err(Error::DestinationExists);
    }
    let (expected, mut manifest) = read_header(&bundle.join("manifest.vot"))?;
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

    for _ in 0..expected.entries {
        let record = read_record(&mut manifest)?;
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
    let mut trailing = [0; 1];
    if manifest.read(&mut trailing)? != 0 {
        return Err(Error::InvalidBundle);
    }
    let actual = package.finish()?;
    if actual != expected {
        return Err(Error::RootMismatch);
    }
    let freshness = fresh_receipt_identifiers()?;
    let mut session_id = [0; 16];
    session_id.copy_from_slice(&freshness[..16]);
    let mut incarnation_id = [0; 16];
    incarnation_id.copy_from_slice(&freshness[16..]);
    let receipt = Receipt {
        subject_kind: SubjectKind::Package,
        suite_id: 1,
        subject_digest: actual.root,
        subject_length: actual.logical_length,
        assurance: AssuranceLevel::Published,
        profile: CommitProfile::Balanced,
        actual_predecessor: AssuranceLevel::Durable,
        provider: 1,
        provider_version: [0, 3, 0],
        session_id,
        incarnation_id,
        sequence: 1,
        observed_at: observed_at.to_owned(),
        clock_source: 1,
        flags: 0,
    };
    let authenticated = authenticate_hmac_sha256(receipt, b"vot-cli", key)?;
    let encoded = encode_authenticated(&authenticated)?;
    let summary = receipt_summary_bytes(&actual);
    let suffix = object_name(&freshness);
    let suffix = suffix.strip_suffix(".obj").ok_or(Error::InvalidBundle)?;
    let prepared_receipt = PreparedFile::new(receipt_path, &encoded, suffix, "receipt")?;
    let prepared_summary =
        PreparedFile::new(&receipt_summary_path, summary.as_bytes(), suffix, "summary")?;
    if sync_directories(&staging)? == 0 {
        return Err(Error::InvalidBundle);
    }
    atomic_rename_noreplace(&staging, destination)?;
    File::open(parent_directory(destination))?.sync_all()?;
    prepared_receipt.publish()?;
    prepared_summary.publish()?;
    File::open(parent_directory(receipt_path))?.sync_all()?;
    Ok(ReceiveReport {
        package: actual,
        peak_staging: receiver.peak_staging(),
    })
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
    manifest: &mut File,
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
        write_record(manifest, &record)?;
    }
    Ok(())
}

fn emit_direct(
    objects: &Path,
    manifest: &mut File,
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
    write_record(manifest, &record)?;
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

fn write_record(writer: &mut impl Write, record: &EntryRecord) -> Result<(), Error> {
    let path = encode_path(&record.path)?;
    writer.write_all(&u32_len(path.len())?.to_be_bytes())?;
    writer.write_all(&path)?;
    writer.write_all(&record.logical_length.to_be_bytes())?;
    writer.write_all(&record.logical_root)?;
    match record.storage {
        Storage::Direct => writer.write_all(&[STORAGE_DIRECT])?,
        Storage::Pack {
            root,
            length,
            offset,
        } => {
            writer.write_all(&[STORAGE_PACK])?;
            writer.write_all(&root)?;
            writer.write_all(&length.to_be_bytes())?;
            writer.write_all(&offset.to_be_bytes())?;
        }
    }
    Ok(())
}

fn read_header(path: &Path) -> Result<(PackageSummary, File), Error> {
    let mut file = File::open(path)?;
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    if magic != BUNDLE_MAGIC || file.metadata()?.len() < HEADER_BYTES {
        return Err(Error::InvalidBundle);
    }
    let root = read_array(&mut file)?;
    let logical_length = read_u64(&mut file)?;
    let entries = read_u64(&mut file)?;
    if entries == 0 {
        return Err(Error::InvalidBundle);
    }
    Ok((
        PackageSummary {
            root,
            logical_length,
            entries,
        },
        file,
    ))
}

fn read_record(reader: &mut impl Read) -> Result<EntryRecord, Error> {
    let path_bytes = read_bounded(reader, MAX_PATH_RECORD_BYTES)?;
    let path = decode_path(&path_bytes)?;
    let logical_length = read_u64(reader)?;
    let logical_root = read_array(reader)?;
    let mut kind = [0; 1];
    reader.read_exact(&mut kind)?;
    let storage = match kind[0] {
        STORAGE_DIRECT => Storage::Direct,
        STORAGE_PACK => Storage::Pack {
            root: read_array(reader)?,
            length: read_u64(reader)?,
            offset: read_u64(reader)?,
        },
        _ => return Err(Error::InvalidBundle),
    };
    Ok(EntryRecord {
        path,
        logical_root,
        logical_length,
        storage,
    })
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

fn decode_path(mut input: &[u8]) -> Result<PackagePath, Error> {
    let count = read_u16(&mut input)?;
    let mut path = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let length = read_u16(&mut input)? as usize;
        if input.len() < length {
            return Err(Error::InvalidBundle);
        }
        let text = std::str::from_utf8(&input[..length]).map_err(|_| Error::InvalidBundle)?;
        path.push(Component::Text(text.to_owned()));
        input = &input[length..];
    }
    if !input.is_empty() {
        return Err(Error::InvalidBundle);
    }
    Ok(path)
}

fn read_bounded(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>, Error> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > maximum {
        return Err(Error::InvalidBundle);
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_u16(reader: &mut impl Read) -> Result<u16, Error> {
    let mut bytes = [0; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> Result<u64, Error> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_array(reader: &mut impl Read) -> Result<[u8; 32], Error> {
    let mut bytes = [0; 32];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
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
    destination: PathBuf,
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
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::InvalidPath)?;
        let temporary = destination.with_file_name(format!(".{name}.vot-{kind}-{suffix}"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(Self {
            temporary: Some(temporary),
            destination: destination.to_owned(),
        })
    }

    fn publish(mut self) -> Result<(), Error> {
        let temporary = self.temporary.as_ref().ok_or(Error::InvalidBundle)?;
        atomic_rename_noreplace(temporary, &self.destination)?;
        self.temporary = None;
        Ok(())
    }
}

impl Drop for PreparedFile {
    fn drop(&mut self) {
        if let Some(temporary) = &self.temporary {
            let _ = fs::remove_file(temporary);
        }
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
    fn mixed_package_publishes_with_matching_authenticated_receipt() {
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
        assert_eq!(HEADER_BYTES, 56);
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

        let mut exact = Vec::new();
        exact.extend_from_slice(&4_u32.to_be_bytes());
        exact.extend_from_slice(b"four");
        assert_eq!(read_bounded(&mut exact.as_slice(), 4).unwrap(), b"four");
        let mut over = Vec::new();
        over.extend_from_slice(&5_u32.to_be_bytes());
        over.extend_from_slice(b"12345");
        assert!(matches!(
            read_bounded(&mut over.as_slice(), 4),
            Err(Error::InvalidBundle)
        ));

        let header = temporary("header");
        let mut valid = Vec::new();
        valid.extend_from_slice(&BUNDLE_MAGIC);
        valid.extend_from_slice(&[4; 32]);
        valid.extend_from_slice(&0_u64.to_be_bytes());
        valid.extend_from_slice(&1_u64.to_be_bytes());
        fs::write(&header, &valid).unwrap();
        assert!(read_header(&header).is_ok());
        valid[0] ^= 1;
        fs::write(&header, &valid).unwrap();
        assert!(matches!(read_header(&header), Err(Error::InvalidBundle)));
        fs::write(&header, &valid[..55]).unwrap();
        assert!(matches!(
            read_header(&header),
            Err(Error::InvalidBundle | Error::Io(_))
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

        fs::remove_file(header).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
