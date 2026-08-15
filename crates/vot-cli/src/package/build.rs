//! Package construction from a source tree.

use crate::{
    CANDIDATE_MAX, DEFAULT_LOGICAL_SUITE, EntryRecord, Error, File, LogicalFile,
    MANIFEST_DIRECTORY, MANIFEST_SEAL, MAX_DATA_RECORD_BYTES, OpenOptions, Pack, PackageAssembly,
    PackageBuilder, PackagePath, PackageSummary, PageDraft, Path, PathBuf, PathProfile, Read,
    Storage, StreamVerifier, StreamingPacker, Suite, Write, canonical_path_key, file_matches_bytes,
    fs, manifest_page_path, manifest_spool_path, object_name, read_bounded_file, sync_directory,
    write_new_synced,
};

pub(crate) struct SourceFile {
    pub(crate) path: PackagePath,
    pub(crate) key: Vec<u8>,
    pub(crate) source: PathBuf,
    pub(crate) length: u64,
}

pub(crate) struct ManifestSpool {
    pub(crate) directory: PathBuf,
    pub(crate) page_count: u64,
}

impl ManifestSpool {
    pub(crate) fn new(bundle: &Path) -> Result<Self, Error> {
        let directory = bundle.join(MANIFEST_DIRECTORY);
        fs::create_dir(&directory)?;
        Ok(Self {
            directory,
            page_count: 0,
        })
    }

    pub(crate) fn push(&mut self, draft: &PageDraft) -> Result<(), Error> {
        if draft.index() != self.page_count {
            return Err(Error::InvalidBundle);
        }
        let encoded = draft.encode()?;
        write_new_synced(
            &manifest_spool_path(&self.directory, self.page_count),
            &encoded,
        )?;
        self.page_count = self.page_count.checked_add(1).ok_or(Error::InvalidBundle)?;
        Ok(())
    }

    pub(crate) fn finish(mut self, assembly: PackageAssembly) -> Result<PackageSummary, Error> {
        let PackageAssembly {
            summary,
            final_page,
            mut finalizer,
        } = assembly;
        self.push(&final_page)?;
        for index in 0..self.page_count {
            let spool = manifest_spool_path(&self.directory, index);
            let encoded = read_bounded_file(&spool, vot_manifest::MAX_PAGE_BYTES)?;
            let completed = finalizer.push(PageDraft::decode(&encoded)?)?;
            write_new_synced(
                &manifest_page_path(&self.directory, index),
                &completed.bytes,
            )?;
            fs::remove_file(spool)?;
        }
        let seal = finalizer.finish()?;
        write_new_synced(&self.directory.join(MANIFEST_SEAL), &seal.bytes)?;
        sync_directory(&self.directory)?;
        Ok(summary)
    }
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
    let mut package = PackageBuilder::new()?;
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

    let summary = manifest.finish(package.finish()?)?;
    sync_directory(&objects)?;
    sync_directory(bundle)?;
    Ok(summary)
}

pub(crate) fn collect_sources(root: &Path) -> Result<Vec<SourceFile>, Error> {
    pub(crate) fn visit(
        root: &Path,
        directory: &Path,
        components: &mut Vec<String>,
        output: &mut Vec<SourceFile>,
    ) -> Result<(), Error> {
        let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_unstable_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::InvalidPath)?;
            components.push(name);
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(Error::InvalidPath);
            }
            if metadata.is_dir() {
                visit(root, &path, components, output)?;
            } else if metadata.is_file() {
                let package_path = PackagePath::portable(components.iter().cloned())
                    .map_err(|_| Error::InvalidPath)?;
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
    package: &mut PackageBuilder,
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
        if let Some(draft) = package.push(&record)? {
            manifest.push(&draft)?;
        }
    }
    Ok(())
}

pub(crate) fn emit_direct(
    objects: &Path,
    manifest: &mut ManifestSpool,
    package: &mut PackageBuilder,
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
    if let Some(draft) = package.push(&record)? {
        manifest.push(&draft)?;
    }
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
