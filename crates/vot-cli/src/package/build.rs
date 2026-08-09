//! Package construction from a source tree.

use crate::{
    CANDIDATE_MAX, Component, DEFAULT_LOGICAL_SUITE, EntryKind, Error, File, LogicalFile,
    MANIFEST_DIRECTORY, MANIFEST_SEAL, MAX_DATA_RECORD_BYTES, ManifestEntry, ManifestPage,
    ObjectId, OpenOptions, PACKAGE_DOMAIN, Pack, PackagePath, PackageSummary, PageCommitment, Path,
    PathBuf, PathProfile, Read, Seal, StorageRef, StreamVerifier, StreamingPacker, Suite, Write,
    canonical_path_key, decode_page, encode_page, encode_path, encode_seal, file_matches_bytes, fs,
    manifest_page_path, manifest_spool_path, object_name, read_bounded_file, suite_from_id,
    suite_id, sync_directory, u32_len, write_new_synced,
};

pub(crate) struct SourceFile {
    pub(crate) path: PackagePath,
    pub(crate) key: Vec<u8>,
    pub(crate) source: PathBuf,
    pub(crate) length: u64,
}

#[derive(Clone)]
pub(crate) enum Storage {
    Direct,
    Pack {
        root: [u8; 32],
        length: u64,
        offset: u64,
    },
}

pub(crate) struct EntryRecord {
    pub(crate) path: PackagePath,
    pub(crate) suite: Suite,
    pub(crate) logical_root: [u8; 32],
    pub(crate) logical_length: u64,
    pub(crate) storage: Storage,
}

impl EntryRecord {
    pub(crate) fn manifest_entry(&self) -> ManifestEntry {
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

    pub(crate) fn from_manifest(entry: ManifestEntry) -> Result<Self, Error> {
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

pub(crate) struct PackageRootBuilder {
    pub(crate) verifier: StreamVerifier,
    pub(crate) last_key: Option<Vec<u8>>,
    pub(crate) logical_length: u64,
    pub(crate) entries: u64,
}

impl PackageRootBuilder {
    pub(crate) fn new() -> Result<Self, Error> {
        let mut verifier = StreamVerifier::new(Suite::Blake3Bao64);
        verifier.update(PACKAGE_DOMAIN)?;
        Ok(Self {
            verifier,
            last_key: None,
            logical_length: 0,
            entries: 0,
        })
    }

    pub(crate) fn push(&mut self, record: &EntryRecord) -> Result<(), Error> {
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

    pub(crate) fn finish(self) -> Result<PackageSummary, Error> {
        Ok(PackageSummary {
            root: self.verifier.finish()?,
            logical_length: self.logical_length,
            entries: self.entries,
        })
    }
}

pub(crate) struct ManifestSpool {
    pub(crate) directory: PathBuf,
    pub(crate) entries: Vec<ManifestEntry>,
    pub(crate) estimated_bytes: usize,
    pub(crate) page_count: u64,
}

impl ManifestSpool {
    pub(crate) fn new(bundle: &Path) -> Result<Self, Error> {
        let directory = bundle.join(MANIFEST_DIRECTORY);
        fs::create_dir(&directory)?;
        Ok(Self {
            directory,
            entries: Vec::new(),
            estimated_bytes: 0,
            page_count: 0,
        })
    }

    pub(crate) fn push(&mut self, entry: ManifestEntry) -> Result<(), Error> {
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

    pub(crate) fn finish(mut self, package: PackageSummary) -> Result<(), Error> {
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
        sync_directory(&self.directory)?;
        Ok(())
    }

    pub(crate) fn flush_placeholder(&mut self) -> Result<(), Error> {
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

    pub(crate) fn placeholder_page(&self) -> ManifestPage {
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

pub(crate) fn page_needs_flush(
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
    sync_directory(&objects)?;
    sync_directory(bundle)?;
    Ok(summary)
}

pub(crate) fn collect_sources(root: &Path) -> Result<Vec<SourceFile>, Error> {
    pub(crate) fn visit(
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

pub(crate) fn emit_pack(
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

pub(crate) fn emit_direct(
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

pub(crate) fn copy_and_verify(
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

pub(crate) fn stream_root(
    path: &Path,
    expected_length: u64,
    suite: Suite,
) -> Result<[u8; 32], Error> {
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

pub(crate) fn write_object(objects: &Path, root: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
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
