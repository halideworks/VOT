//! Prepared receipt files, their recovery, and verification.

use crate::{
    AssuranceLevel, AuthenticatedReceipt, CommitProfile, Error, KEY_ID, KeyMaterial, OpenOptions,
    PackageSummary, Path, PathBuf, Receipt, SubjectKind, Write, bounded_files_equal,
    decode_authenticated, fs, io, link_or_match, object_name, parent_directory, read_bounded_file,
    sync_directory,
};

pub(crate) fn publication_receipt(
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
        previous: None,
    }
}

pub(crate) fn receipt_summary_bytes(package: &PackageSummary) -> String {
    let root = object_name(&package.root);
    let root = root.strip_suffix(".obj").expect("known suffix");
    format!(
        "{{\"assurance\":\"PUBLISHED\",\"suite\":1,\"root\":\"{root}\",\"length\":{},\"entries\":{}}}\n",
        package.logical_length, package.entries
    )
}

pub(crate) fn fresh_receipt_identifiers() -> Result<[u8; 32], Error> {
    let mut identifiers = [0; 32];
    getrandom::fill(&mut identifiers).map_err(|_| Error::Randomness)?;
    Ok(identifiers)
}

pub(crate) struct PreparedFile {
    pub(crate) temporary: Option<PathBuf>,
    pub(crate) cleanup: bool,
}

impl PreparedFile {
    pub(crate) fn new(
        destination: &Path,
        bytes: &[u8],
        suffix: &str,
        kind: &str,
    ) -> Result<Self, Error> {
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

    pub(crate) fn preserve_for_recovery(&mut self) {
        self.cleanup = false;
    }

    pub(crate) fn path(&self) -> Result<PathBuf, Error> {
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

pub(crate) fn prepared_output_path(
    destination: &Path,
    suffix: &str,
    kind: &str,
) -> Result<PathBuf, Error> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::InvalidPath)?;
    Ok(destination.with_file_name(format!(".{name}.vot-{kind}-{suffix}")))
}

pub(crate) fn prepared_receipt_paths(
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

pub(crate) fn existing_prepared_receipts(
    receipt: &Path,
    summary: &Path,
    package: &PackageSummary,
    key: &KeyMaterial,
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

pub(crate) fn recover_prepared_receipts(
    receipt: &Path,
    summary: &Path,
    package: &PackageSummary,
    key: &KeyMaterial,
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
        sync_directory(parent_directory(receipt))?;
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

pub(crate) fn remove_preparation(prepared: &Path) -> Result<(), Error> {
    match fs::remove_file(prepared) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Every field a CLI publication receipt must carry, whichever package it is
/// about.
///
/// Shared by the bundle check and the auditor's command so the two cannot
/// disagree about what counts as a publication.
pub(crate) fn validate_publication_shape(
    authenticated: &AuthenticatedReceipt,
) -> Result<(), Error> {
    let receipt = &authenticated.receipt;
    // The key identifier separates contexts here, so it has to be authentic.
    // vot-receipt binds it into the signed input for that reason; if it ever
    // stopped, a receipt this issuer signed for something else could be
    // relabelled and would pass this check.
    if authenticated.key_id != KEY_ID
        || receipt.subject_kind != SubjectKind::Package
        || receipt.suite_id != 1
        || receipt.assurance != AssuranceLevel::Published
        || receipt.profile != CommitProfile::Fast
        || receipt.actual_predecessor != AssuranceLevel::TransitVerified
        || receipt.provider != 1
    {
        return Err(Error::InvalidBundle);
    }
    Ok(())
}

/// Checks a receipt with nothing but the issuer's public key.
///
/// This is the auditor's position, and the reason receipts moved to Ed25519: a
/// party holding only the public half can confirm what was published without
/// being able to produce a receipt of its own. Handing a shared secret to an
/// auditor would have made them capable of both.
///
/// # Errors
/// Rejects an unreadable or malformed receipt, one that does not verify, or a
/// key that cannot check the scheme the receipt was made with.
pub fn verify_receipt_file(
    receipt_path: &Path,
    key: &KeyMaterial,
) -> Result<VerifiedReceipt, Error> {
    let encoded = read_bounded_file(receipt_path, 65_536)?;
    let authenticated = decode_authenticated(&encoded).map_err(|_| Error::InvalidBundle)?;
    key.verify(&authenticated)?;
    // A valid signature says who wrote the receipt, not what it claims. Without
    // the shape check an issuer's signature over any lower observation, or over
    // an object rather than a package, would print as a published package.
    validate_publication_shape(&authenticated)?;
    Ok(VerifiedReceipt {
        root: authenticated.receipt.subject_digest,
        logical_length: authenticated.receipt.subject_length,
        assurance: authenticated.receipt.assurance,
        third_party_verifiable: key.is_third_party_verifiable(),
    })
}

/// What a checked receipt says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedReceipt {
    pub root: [u8; 32],
    pub logical_length: u64,
    pub assurance: AssuranceLevel,
    /// False when the check used a shared secret, so the caller can say whether
    /// the result means anything to a third party.
    pub third_party_verifiable: bool,
}

pub(crate) fn validate_receipt_files(
    receipt_path: &Path,
    summary_path: &Path,
    package: &PackageSummary,
    key: &KeyMaterial,
) -> Result<(), Error> {
    let encoded = read_bounded_file(receipt_path, 65_536)?;
    let authenticated = decode_authenticated(&encoded).map_err(|_| Error::InvalidBundle)?;
    key.verify(&authenticated)?;
    validate_publication_shape(&authenticated)?;
    let receipt = &authenticated.receipt;
    if receipt.subject_digest != package.root || receipt.subject_length != package.logical_length {
        return Err(Error::InvalidBundle);
    }
    let summary = read_bounded_file(summary_path, 4096)?;
    if summary != receipt_summary_bytes(package).as_bytes() {
        return Err(Error::InvalidBundle);
    }
    Ok(())
}

pub(crate) fn finalize_prepared_receipts(
    receipt: &Path,
    summary: &Path,
    prepared_receipt: &Path,
    prepared_summary: &Path,
) -> Result<(), Error> {
    link_or_match(prepared_receipt, receipt, 65_536)?;
    link_or_match(prepared_summary, summary, 4096)?;
    sync_directory(parent_directory(receipt))?;
    fs::remove_file(prepared_receipt)?;
    fs::remove_file(prepared_summary)?;
    sync_directory(parent_directory(receipt))?;
    Ok(())
}
