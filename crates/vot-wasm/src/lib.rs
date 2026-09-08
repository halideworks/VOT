//! Thin host-neutral WebAssembly bindings for the stable VOT SDK.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

mod error;
mod object;
mod package;
mod proof;
mod receipt;

pub use error::{ErrorCode, VotError};
pub use object::{
    CoverageAcceptance, CoverageUpdate, ObjectBuilder, ObjectCoverage, ObjectId, PreparedObject,
    RangeProof, Suite, VerifiedRange, proof_leaf_size, proof_leaves_at, verify_range,
};
pub use package::{
    EncodedManifestPage, EncodedSeal, ManifestFinalizer, ManifestPage, PackageAssembly,
    PackageBuilder, PackageEntry, PackageIngest, PackagePath, PackageSummary, PageDraft,
    StorageKind,
};
pub use proof::{CatalogEntry, CatalogHeader, decode_catalog_header, validate_catalog};
pub use receipt::{
    AssuranceLevel, CommitProfile, ReceiptChain, SubjectKind, VerifiedReceipt,
    verify_receipt_ed25519,
};
