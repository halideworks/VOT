//! A served object and its source-mutation witness.

use super::{
    Error, File, GROUP_SIZE, ObjectBuilder, Path, PathBuf, PreparedObject, Read, Seek, SeekFrom,
    Suite, SystemTime, frames, io,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Plaintext bytes per data record. Bounded by the codec record limit and the
/// largest cover across the bundle's record cap.
pub(crate) const RECORD_PLAINTEXT_BYTES: usize = 258_048;

/// One stored object: its wire identity, proving layer, and file.
/// The proving layer rebuilt from leaves kept beside the object, when they
/// describe the object this bundle names.
///
/// `None` for no cache, a cache for another suite or length, one whose leaf
/// count cannot describe the object, or one whose tree names a different
/// root. Every one of those means reading the object instead, which is what
/// this end did before the cache existed.
pub(crate) fn prepared_from_cache(
    objects: &Path,
    root: [u8; 32],
    suite: Suite,
    length: u64,
) -> Option<PreparedObject> {
    let leaves = crate::package::proof_cache::read(objects, &root, suite, length)?;
    let layer = PreparedObject::from_proof_leaves(suite, length, leaves).ok()?;
    if layer.object_id().root != root {
        return None;
    }
    // The object is still the authority. Its length and its first and last
    // groups are checked here, which is what an object replaced or truncated
    // since the leaves were kept fails, and every later read is checked
    // against the layer as well. Any doubt answers `None`, and reading the
    // object in full is what says why.
    let path = objects.join(crate::object_name(&root));
    let mut file = File::open(&path).ok()?;
    if file.metadata().ok()?.len() != length {
        return None;
    }
    let group = GROUP_SIZE as u64;
    let last = length.saturating_sub(1) / group * group;
    for offset in [0, last] {
        let take = usize::try_from(group.min(length - offset)).ok()?;
        let mut bytes = vec![0u8; take];
        file.seek(SeekFrom::Start(offset)).ok()?;
        file.read_exact(&mut bytes).ok()?;
        if !layer.holds(offset, &bytes) {
            return None;
        }
    }
    Some(layer)
}

pub(crate) struct ServedObject {
    pub(crate) object: frames::ObjectId,
    pub(crate) layer: PreparedObject,
    pub(crate) path: PathBuf,
    pub(crate) witness: Witness,
    /// The groups already checked against the proving layer, when this end
    /// prepared from the leaves beside the object rather than by reading it.
    ///
    /// `None` where the object was read at open, because reading it checked
    /// every group already. Otherwise nothing has read the bytes yet and the
    /// witness only says they have not changed since open, so a group is
    /// hashed the first time it is served and remembered.
    pub(crate) verified: Option<GroupSet>,
}

/// The groups of one object already checked against its proving layer.
///
/// Shared by every connection thread, so a group one served pays for is free
/// to the rest.
pub(crate) struct GroupSet {
    words: Vec<AtomicU64>,
}

impl GroupSet {
    /// A set holding nothing, sized for an object of `length`.
    fn for_length(length: u64) -> Self {
        let groups = length.div_ceil(GROUP_SIZE as u64);
        let words = usize::try_from(groups.div_ceil(u64::BITS.into())).unwrap_or(usize::MAX);
        Self {
            words: (0..words).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// True when every group of the span is held. A span reaching past the
    /// object is not held, which leaves the read to hash it.
    fn holds_span(&self, first: usize, count: usize) -> bool {
        let Some(end) = first.checked_add(count) else {
            return false;
        };
        (first..end).all(|group| {
            self.words
                .get(group / 64)
                .is_some_and(|word| word.load(Ordering::Relaxed) & bit(group) != 0)
        })
    }

    /// Records every group of the span. Groups past the object are dropped
    /// rather than wrapping into another word.
    fn insert_span(&self, first: usize, count: usize) {
        let Some(end) = first.checked_add(count) else {
            return;
        };
        for group in first..end {
            if let Some(word) = self.words.get(group / 64) {
                word.fetch_or(bit(group), Ordering::Relaxed);
            }
        }
    }
}

/// The bit one group occupies in its word.
const fn bit(group: usize) -> u64 {
    1_u64 << (group % 64)
}

/// The groups a cover of `length` bytes at `offset` spans, or `None` where
/// the cover is not group-aligned or does not fit a `usize`.
fn spanned_groups(offset: u64, length: usize) -> Option<(usize, usize)> {
    if !offset.is_multiple_of(GROUP_SIZE as u64) {
        return None;
    }
    let first = usize::try_from(offset / GROUP_SIZE as u64).ok()?;
    Some((first, length.div_ceil(GROUP_SIZE)))
}

/// A file's length and modification time at open, for cheap mutation detection.
/// Not a proof: a rewrite that restores both is missed, but the peer verifies
/// every range against the object root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Witness {
    pub(crate) length: u64,
    /// `None` where the platform reports no modification time.
    pub(crate) modified: Option<SystemTime>,
}

impl Witness {
    pub(crate) fn of(file: &File) -> Result<Self, Error> {
        let metadata = file.metadata()?;
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    /// True when no write is reported since the witness was taken.
    pub(crate) fn reports_untouched(&self, current: &Self) -> bool {
        self.modified.is_some() && self == current
    }
}

impl ServedObject {
    /// Streams the object once, verifying its root while keeping only the
    /// chaining values a proof needs.
    pub(crate) fn build(
        objects: &Path,
        root: [u8; 32],
        suite: Suite,
        length: u64,
    ) -> Result<Self, Error> {
        let path = objects.join(crate::object_name(&root));
        let mut file = File::open(&path)?;
        // Take the witness before reading: a mid-read write would otherwise
        // stamp into the witness.
        let witness = Witness::of(&file)?;
        // The leaves a previous pass kept, if they describe this object. The
        // cache is not an authority: what it rebuilds names an object, and
        // that name has to be the root this bundle already claims, or it is
        // ignored and the object is read.
        if let Some(layer) = prepared_from_cache(objects, root, suite, length) {
            return Ok(Self {
                object: frames::ObjectId {
                    suite: crate::suite_id(suite),
                    root,
                    length,
                },
                layer,
                path,
                witness,
                verified: Some(GroupSet::for_length(length)),
            });
        }
        let mut builder = ObjectBuilder::new(suite, Some(length))?;
        let mut group = vec![0u8; GROUP_SIZE];
        let mut remaining = length;
        while remaining > 0 {
            let take = usize::try_from(remaining.min(GROUP_SIZE as u64))
                .map_err(|_| Error::InvalidBundle)?;
            file.read_exact(&mut group[..take]).map_err(short_read)?;
            builder.update(&group[..take])?;
            remaining -= take as u64;
        }
        // Trailing bytes mean the file is not the object it is named as.
        if file.read(&mut [0u8; 1])? != 0 {
            return Err(Error::RootMismatch);
        }
        let layer = builder.finish()?;
        if layer.object_id().root != root {
            return Err(Error::RootMismatch);
        }
        Ok(Self {
            object: frames::ObjectId {
                suite: crate::suite_id(suite),
                root,
                length,
            },
            layer,
            path,
            witness,
            verified: None,
        })
    }

    /// Reads the cover's bytes and checks they match what the layer was built
    /// from. Uses the witness stat first; falls back to hashing only when
    /// metadata can't vouch for the file.
    pub(crate) fn read_covered(&self, offset: u64, length: u64) -> Result<Vec<u8>, Error> {
        let mut file = File::open(&self.path).map_err(missing_object)?;
        file.seek(SeekFrom::Start(offset))?;
        let size = usize::try_from(length).map_err(|_| Error::InvalidBundle)?;
        let mut plaintext = vec![0u8; size];
        file.read_exact(&mut plaintext).map_err(short_read)?;
        let span = spanned_groups(offset, plaintext.len());
        let checked = self.verified.as_ref().is_none_or(|verified| {
            span.is_some_and(|(first, count)| verified.holds_span(first, count))
        });
        if checked && self.witness.reports_untouched(&Witness::of(&file)?) {
            return Ok(plaintext);
        }
        if !self.layer.holds(offset, &plaintext) {
            return Err(Error::SourceMutation);
        }
        if let (Some(verified), Some((first, count))) = (self.verified.as_ref(), span) {
            verified.insert_span(first, count);
        }
        Ok(plaintext)
    }
}

/// A missing object is treated as a source mutation: the peer is told why
/// rather than left waiting.
pub(crate) fn missing_object(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::NotFound {
        Error::SourceMutation
    } else {
        Error::Io(error)
    }
}

/// A file shorter than its layer promised was mutated after open.
pub(crate) fn short_read(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        Error::SourceMutation
    } else {
        Error::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{GROUP_SIZE, GroupSet, spanned_groups};

    #[test]
    fn a_group_set_holds_only_the_spans_it_was_given() {
        let object = GROUP_SIZE as u64 * 65 + 1;
        let set = GroupSet::for_length(object);
        // 66 groups need two words, and nothing is held before a read.
        assert_eq!(set.words.len(), 2);
        assert!(!set.holds_span(0, 1));

        // A span crossing the word boundary holds both sides and neither
        // neighbour.
        set.insert_span(63, 2);
        assert!(set.holds_span(63, 2));
        assert!(set.holds_span(63, 1));
        assert!(set.holds_span(64, 1));
        assert!(!set.holds_span(62, 1));
        assert!(!set.holds_span(62, 2));
        assert!(!set.holds_span(65, 1));

        // A span reaching past the object is never held, however far it
        // reaches, so the read hashes it rather than trusting the set.
        assert!(!set.holds_span(65, 2));
        assert!(!set.holds_span(usize::MAX, 1));
        set.insert_span(usize::MAX, 2);
        assert!(
            !set.holds_span(0, 1),
            "a span past the end wrapped into a word"
        );
    }

    #[test]
    fn an_empty_object_holds_no_group() {
        let set = GroupSet::for_length(0);
        assert_eq!(set.words.len(), 0);
        assert!(!set.holds_span(0, 1));
    }

    #[test]
    fn covers_name_the_groups_they_span() {
        let group = GROUP_SIZE as u64;
        assert_eq!(spanned_groups(0, GROUP_SIZE), Some((0, 1)));
        assert_eq!(spanned_groups(0, GROUP_SIZE + 1), Some((0, 2)));
        assert_eq!(spanned_groups(group * 3, GROUP_SIZE * 2), Some((3, 2)));
        // A partial final group still counts, and an empty cover spans none.
        assert_eq!(spanned_groups(group, 1), Some((1, 1)));
        assert_eq!(spanned_groups(group, 0), Some((1, 0)));
        // Only a group-aligned cover can name groups.
        assert_eq!(spanned_groups(1, GROUP_SIZE), None);
        assert_eq!(spanned_groups(group + 1, GROUP_SIZE), None);
    }
}
