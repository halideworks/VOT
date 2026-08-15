//! Receiving and publishing a bundle.

use crate::{
    Error, File, KeyMaterial, MAX_DATA_RECORD_BYTES, ManifestReader, OpenOptions,
    PackageRootBuilder, PackageSummary, Path, PreparedFile, Read, ReceiveReport, ReliableReceiver,
    Storage, StreamVerifier, SubjectId, Suite, Write, atomic_rename_noreplace, create_parent,
    encode_authenticated, existing_prepared_receipts, finalize_prepared_receipts,
    fresh_receipt_identifiers, fs, object_name, output_path, parent_directory,
    prepared_receipt_paths, publication_receipt, receipt_summary_bytes, recover_prepared_receipts,
    scan_manifest, staging_path, stream_root, suite_id, sync_directories, sync_directory,
};
use vot_verifier::ExpectedObject;

pub(crate) fn validate_published_destination(
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

pub(crate) fn count_published_files(
    directory: &Path,
    depth: usize,
    count: &mut u64,
) -> Result<(), Error> {
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

pub fn receive_bundle(
    bundle: &Path,
    destination: &Path,
    receipt_path: &Path,
    key: &KeyMaterial,
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
    // A receipt is signed below only when an interrupted run did not already
    // leave one, so that is exactly when a private key is required. Checking
    // here rather than at signing time matters: by then the whole bundle has
    // been copied into staging, and nothing removes that tree on the way out,
    // so a misconfigured key would leave a full hidden copy of the package
    // behind and another one for every retry. It cannot move any earlier
    // either, because reusing or recovering a prepared receipt only verifies
    // one that is already signed, and an operator holding just the public key
    // has to be able to finish those.
    if existing_preparation.is_none() && matches!(key, KeyMaterial::Verifying(_)) {
        return Err(Error::InvalidArguments);
    }
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
        let authenticated = key.sign(receipt)?;
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
            sync_directory(parent)?;
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

pub(crate) fn publish_staging_with(
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

pub(crate) fn receive_direct(
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
    let subject =
        SubjectId::new(suite_id(suite), root, length).map_err(|_| Error::InvalidBundle)?;
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
        verifier.finish(ExpectedObject::new(suite, root, length))?;
    } else {
        receiver.finish(subject)?;
    }
    destination.sync_all()?;
    Ok(())
}

pub(crate) fn receive_object(
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
    let subject =
        SubjectId::new(suite_id(suite), root, length).map_err(|_| Error::InvalidBundle)?;
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
        verifier.finish(ExpectedObject::new(suite, root, length))?;
    } else {
        receiver.finish(subject)?;
    }
    Ok(bytes)
}

pub(crate) fn write_published_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    create_parent(path)?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn pack_needs_load(
    cached: Option<&(Suite, [u8; 32], u64, Vec<u8>)>,
    suite: Suite,
    root: [u8; 32],
    length: u64,
) -> bool {
    cached.is_none_or(|(cached_suite, cached_root, cached_length, _)| {
        *cached_suite != suite || *cached_root != root || *cached_length != length
    })
}
