//! Extent and unit conversion between resume state and fetch coverage.

use super::{BTreeMap, Error, Path, SubjectId, UnitRanges};

/// Resume store beside the manifest directory; removed on completion.
pub(crate) const RESUME_STORE: &str = "resume.vot";

/// Store entry binding a store to the package it continues. Suite zero
/// never collides with a stored object; its root is checked before resume.
pub(crate) const fn package_sentinel(root: [u8; 32]) -> SubjectId {
    SubjectId::marker(root)
}

/// Checkpoint units of an object, in the receiver's own range currency.
pub(crate) fn total_units_of(length: u64) -> u64 {
    length.div_ceil(vot_scheduler::RANGE_UNIT_BYTES)
}

/// The byte extents `units` stand for, clipped to the object.
pub(crate) fn resumed_extents(units: &UnitRanges, length: u64) -> BTreeMap<u64, u64> {
    let mut extents = BTreeMap::new();
    for (start, count) in units.runs() {
        let at = start.saturating_mul(vot_scheduler::RANGE_UNIT_BYTES);
        let end = start
            .saturating_add(count)
            .saturating_mul(vot_scheduler::RANGE_UNIT_BYTES)
            .min(length);
        if at < end {
            extents.insert(at, end - at);
        }
    }
    extents
}

/// The units wholly inside `covered`, which is what may be checkpointed:
/// a unit only partly placed reads back with a hole, so it is owed again.
pub(crate) fn durable_units(covered: &BTreeMap<u64, u64>, length: u64) -> UnitRanges {
    let unit = vot_scheduler::RANGE_UNIT_BYTES;
    let mut units = UnitRanges::new();
    for (at, len) in covered {
        let first = at.div_ceil(unit);
        let end = at.saturating_add(*len);
        let past = if end >= length {
            total_units_of(length)
        } else {
            end / unit
        }
        // Capped at the object to avoid naming a unit it does not have.
        .min(total_units_of(length));
        units.extend_units(first..past);
    }
    units
}

/// Removes the resume store beside a bundle that is now whole, lock file
/// and all, so the completed bundle looks exactly as one fetched without
/// a store.
pub(crate) fn remove_store_files(bundle: &Path) -> Result<(), Error> {
    // No need to decode a store in order to delete it.
    vot_resume::remove_files(&bundle.join(RESUME_STORE), true).map_err(resume_failure)
}

/// What a store's refusal means to the fetch that asked.
///
/// An identity conflict is the same refusal a wrong pin gets; anything
/// else is the store file itself failing.
pub(crate) fn resume_failure(error: vot_resume::Error) -> Error {
    match error {
        vot_resume::Error::Io(error) => Error::Io(error),
        vot_resume::Error::IdentityMismatch => Error::RootMismatch,
        _ => Error::InvalidBundle,
    }
}
