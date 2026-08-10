//! A served object and its source-mutation witness.

use super::{
    Error, File, GROUP_SIZE, Path, PathBuf, ProverLayer, Read, Seek, SeekFrom, StreamVerifier,
    Suite, SystemTime, frames, io,
};

/// Plaintext bytes per data record. Bounded by the codec record limit and the
/// largest cover across the bundle's record cap.
pub(crate) const RECORD_PLAINTEXT_BYTES: usize = 258_048;

/// One stored object: its wire identity, proving layer, and file.
pub(crate) struct ServedObject {
    pub(crate) object: frames::ObjectId,
    pub(crate) layer: ProverLayer,
    pub(crate) path: PathBuf,
    pub(crate) witness: Witness,
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
        let mut verifier = StreamVerifier::new(suite);
        let mut layer = ProverLayer::empty(suite);
        let mut group = vec![0u8; GROUP_SIZE];
        let mut remaining = length;
        while remaining > 0 {
            let take = usize::try_from(remaining.min(GROUP_SIZE as u64))
                .map_err(|_| Error::InvalidBundle)?;
            file.read_exact(&mut group[..take]).map_err(short_read)?;
            verifier.update(&group[..take])?;
            layer.push(&group[..take])?;
            remaining -= take as u64;
        }
        // Trailing bytes mean the file is not the object it is named as.
        if file.read(&mut [0u8; 1])? != 0 {
            return Err(Error::RootMismatch);
        }
        if verifier.finish()? != root {
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
        if self.witness.reports_untouched(&Witness::of(&file)?) {
            return Ok(plaintext);
        }
        if !self.layer.holds(offset, &plaintext) {
            return Err(Error::SourceMutation);
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
