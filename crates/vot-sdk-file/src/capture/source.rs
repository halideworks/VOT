use std::fs::File;
use std::ops::Range;
use std::path::Path;

use vot_object::ObjectCheckpoint;
use vot_platform_fs::{file_identity, read_exact_at};
use vot_verifier::{ExpectedObject, StreamVerifier};

use super::{CaptureFile, Error, ErrorKind, GROUP, ObjectId, RetainedRange, Suite, invalid};

const GROUP_BYTES: usize = 65_536;
const WINDOW: usize = GROUP_BYTES + 1;

#[cfg(test)]
thread_local! {
    static READ_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Captures an externally written file into private, authenticated disk storage.
///
/// Draft roots describe captured bytes, which may combine observations from
/// different times. Dirty ranges are hints, not source-coherence evidence.
/// [`Self::finish`] requires the host to stop the producer and preserve the
/// source through verification. Neither quiet time nor metadata implies this.
///
/// The source must be an independently opened regular-file handle. In particular,
/// do not clone the producer's cursor-bearing handle on Windows. Path replacement
/// does not replace a retained handle; the host detects it and calls `replace`.
/// The source-owned window is 65,537 bytes. Shared proof metadata grows with the
/// group count, bounded by the capture's group limit. No old payload history is retained.
pub struct CaptureSource {
    source: File,
    capture: CaptureFile,
    checkpoint: Option<ObjectCheckpoint>,
    buffer: Vec<u8>,
    finished: bool,
    #[cfg(test)]
    after_read: Option<Box<dyn FnOnce()>>,
}

impl CaptureSource {
    /// Creates empty staging using the same private-directory contract as `CaptureFile`.
    pub fn create(
        source: File,
        path: impl AsRef<Path>,
        incarnation: [u8; 16],
        suite: Suite,
        max_groups: u64,
    ) -> Result<Self, Error> {
        source_length(&source)?;
        let checkpoint = ObjectCheckpoint::new(suite).map_err(|_| invalid())?;
        let capture = CaptureFile::create(path, incarnation, checkpoint.object_id(), max_groups)?;
        Ok(Self {
            source,
            capture,
            checkpoint: Some(checkpoint),
            buffer: vec![0; WINDOW],
            finished: false,
            #[cfg(test)]
            after_read: None,
        })
    }

    /// Reopens staging and rebuilds proof metadata from its owned bytes.
    /// Incomplete or damaged staging requires a full refresh, performed by the
    /// next `refresh` call. Producer completion never survives a process restart.
    pub fn open(
        source: File,
        path: impl AsRef<Path>,
        incarnation: [u8; 16],
    ) -> Result<Self, Error> {
        source_length(&source)?;
        let mut capture = CaptureFile::open(path, incarnation)?;
        distinct_source(&source, &capture)?;
        let progress = capture.progress()?;
        let mut buffer = vec![0; WINDOW];
        let mut checkpoint = None;
        if progress.cached_groups == progress.object.length.div_ceil(GROUP) {
            let empty = ObjectCheckpoint::new(super::validate_object(&progress.object)?)
                .map_err(|_| invalid())?;
            let restored = prepare(
                &capture.file,
                empty,
                progress.object.length,
                std::slice::from_ref(&(0..progress.object.length)),
                &mut buffer,
            )?;
            if restored.object_id() == &progress.object {
                let prepared = restored.prepared();
                let mut complete = true;
                for offset in (0..progress.object.length).step_by(GROUP_BYTES) {
                    let proof = prepared.prove(offset, 1).map_err(|_| invalid())?;
                    if capture
                        .table
                        .get(offset)?
                        .is_none_or(|group| group.verify(&progress.object, proof.proof()).is_err())
                    {
                        complete = false;
                        break;
                    }
                }
                if complete {
                    checkpoint = Some(restored);
                }
            }
        }
        Ok(Self {
            source,
            capture,
            checkpoint,
            buffer,
            finished: false,
            #[cfg(test)]
            after_read: None,
        })
    }

    /// Identity of the retained source handle, for host-managed path replacement detection.
    pub fn source_identity(&self) -> Result<(u64, u64), Error> {
        file_identity(&self.source).map_err(Error::io)
    }

    /// Refreshes one dirty byte range plus any observed growth or shortened tail.
    /// Use `0..0` for growth alone, or `0..source_length` for full reconciliation.
    /// Unreported old writes remain absent from the draft and are caught at finish.
    ///
    /// Preparation reads only affected groups. Installation selects one target,
    /// then rereads and authenticates changed bytes before writing them. A failed
    /// installation requires full reconciliation on the next call; ambiguous
    /// storage errors still require dropping and reopening the owner.
    pub fn refresh(&mut self, changed: Range<u64>) -> Result<ObjectId, Error> {
        self.editable()?;
        let length = source_length(&self.source)?;
        if length.div_ceil(GROUP) > self.capture.state.limit {
            return Err(Error::plain(ErrorKind::ResourceExhausted));
        }
        let suite = super::validate_object(&self.capture.state.object)?;
        let (previous, ranges) = if let Some(previous) = &self.checkpoint {
            (
                previous.clone(),
                plan(previous.object_id().length, length, changed)?,
            )
        } else {
            plan(0, length, changed)?;
            (
                ObjectCheckpoint::new(suite).map_err(|_| invalid())?,
                [0..length, 0..0],
            )
        };
        let candidate = prepare(&self.source, previous, length, &ranges, &mut self.buffer)?;
        #[cfg(test)]
        if let Some(hook) = self.after_read.take() {
            hook();
        }
        let object = candidate.object_id().clone();
        self.checkpoint = None;
        if self.capture.state.object != object {
            self.capture.select(&object)?;
        }
        let prepared = candidate.prepared();
        for range in ranges {
            for offset in range.step_by(GROUP_BYTES) {
                let proof = prepared.prove(offset, 1).map_err(|_| invalid())?;
                if let Some(group) = self.capture.table.get(offset)?
                    && group.verify(&object, proof.proof()).is_ok()
                {
                    continue;
                }
                let bytes = read_group(
                    &self.source,
                    offset,
                    proof.covered_length(),
                    &mut self.buffer,
                )?;
                let verified = vot_sdk::verify::verify_range(&object, offset, bytes, proof.proof())
                    .map_err(|error| crate::map_sdk_code(error.code()))?;
                self.capture.accept(&verified)?;
            }
        }
        self.checkpoint = Some(candidate);
        Ok(object)
    }

    /// Proof metadata for the current captured bytes. Old metadata does not retain old bytes.
    pub fn checkpoint(&self) -> Result<&ObjectCheckpoint, Error> {
        self.capture.ready()?;
        self.checkpoint.as_ref().ok_or_else(invalid)
    }

    /// Reads and authenticates one staged group against the current draft root.
    pub fn read(&mut self, offset: u64) -> Result<RetainedRange, Error> {
        let proof = self
            .checkpoint()?
            .prepared()
            .prove(offset, 1)
            .map_err(|_| invalid())?;
        let result = self.capture.read(proof.covered_offset(), proof.proof());
        if result.is_err() {
            self.checkpoint = None;
            self.finished = false;
        }
        result
    }

    /// Explicit producer-completion boundary. The host must keep the producer
    /// stopped and the source stable until this returns. A full streamed source
    /// verification catches missed rewrites; mismatch requires refresh and retry.
    /// Success freezes this owner, but is not publication or an at-rest receipt.
    pub fn finish(&mut self) -> Result<ObjectId, Error> {
        self.editable()?;
        let prepared = self.checkpoint()?.prepared();
        let object = prepared.object_id();
        if source_length(&self.source)? != object.length {
            return Err(Error::plain(ErrorKind::IdentityMismatch));
        }
        let mut verifier = StreamVerifier::new(super::validate_object(object)?);
        for offset in (0..object.length).step_by(GROUP_BYTES) {
            let bytes = read_group(
                &self.source,
                offset,
                GROUP.min(object.length - offset),
                &mut self.buffer,
            )?;
            verifier.update(bytes).map_err(|_| invalid())?;
        }
        verifier
            .finish(ExpectedObject::new(
                super::validate_object(object)?,
                object.root,
                object.length,
            ))
            .map_err(|_| Error::plain(ErrorKind::IdentityMismatch))?;
        #[cfg(test)]
        if let Some(hook) = self.after_read.take() {
            hook();
        }
        if source_length(&self.source)? != object.length {
            return Err(Error::plain(ErrorKind::IdentityMismatch));
        }
        for offset in (0..object.length).step_by(GROUP_BYTES) {
            let proof = prepared.prove(offset, 1).map_err(|_| invalid())?;
            self.capture.reuse(offset, proof.proof())?;
        }
        self.capture.checkpoint()?;
        self.finished = true;
        Ok(object.clone())
    }

    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Explicitly replaces the source and discards the old draft, including after finish.
    pub fn replace(&mut self, source: File) -> Result<(), Error> {
        source_length(&source)?;
        distinct_source(&source, &self.capture)?;
        let empty = ObjectCheckpoint::new(super::validate_object(&self.capture.state.object)?)
            .map_err(|_| invalid())?;
        self.checkpoint = None;
        self.capture.select(empty.object_id())?;
        self.source = source;
        self.checkpoint = Some(empty);
        self.finished = false;
        Ok(())
    }

    fn editable(&self) -> Result<(), Error> {
        self.capture.ready()?;
        if self.finished {
            return Err(invalid());
        }
        Ok(())
    }
}

fn distinct_source(source: &File, capture: &CaptureFile) -> Result<(), Error> {
    let identity = file_identity(source).map_err(Error::io)?;
    let binding = capture.state.binding;
    if [
        (binding[0], binding[1]),
        (binding[4], binding[5]),
        capture.journal_identity,
    ]
    .contains(&identity)
    {
        return Err(invalid());
    }
    Ok(())
}

fn source_length(source: &File) -> Result<u64, Error> {
    let metadata = source.metadata().map_err(Error::io)?;
    if !metadata.is_file() {
        return Err(Error::plain(ErrorKind::InvalidDestination));
    }
    Ok(metadata.len())
}

fn plan(previous: u64, length: u64, changed: Range<u64>) -> Result<[Range<u64>; 2], Error> {
    if length > vot_object::MAX_OBJECT_LENGTH || changed.start > changed.end || changed.end > length
    {
        return Err(invalid());
    }
    let dirty = if changed.is_empty() {
        0..0
    } else {
        changed.start / GROUP * GROUP
            ..changed
                .end
                .div_ceil(GROUP)
                .saturating_mul(GROUP)
                .min(length)
    };
    let resized = if length == previous {
        0..0
    } else {
        let start = if previous <= GROUP || length <= GROUP {
            0
        } else {
            previous.min(length) / GROUP * GROUP
        };
        start..length
    };
    let (first, second) = if dirty.start <= resized.start {
        (dirty, resized)
    } else {
        (resized, dirty)
    };
    if first.end >= second.start {
        Ok([first.start..first.end.max(second.end), 0..0])
    } else {
        Ok([first, second])
    }
}

fn prepare(
    file: &File,
    mut checkpoint: ObjectCheckpoint,
    length: u64,
    ranges: &[Range<u64>],
    buffer: &mut [u8],
) -> Result<ObjectCheckpoint, Error> {
    if length < checkpoint.object_id().length {
        let offset = if length <= GROUP {
            0
        } else {
            length / GROUP * GROUP
        };
        let bytes = read_group(file, offset, length - offset, buffer)?;
        checkpoint = checkpoint
            .updated(offset, bytes, length)
            .map_err(|_| invalid())?;
    }
    for range in ranges {
        for offset in range.clone().step_by(GROUP_BYTES) {
            // Promotion resupplies the first group and one byte of the next group.
            let window = if offset == 0 && checkpoint.object_id().length <= GROUP {
                GROUP + 1
            } else {
                GROUP
            };
            let count = window.min(range.end - offset);
            let bytes = read_group(file, offset, count, buffer)?;
            let end = offset + count;
            checkpoint = checkpoint
                .updated(offset, bytes, checkpoint.object_id().length.max(end))
                .map_err(|_| invalid())?;
        }
    }
    Ok(checkpoint)
}

fn read_group<'a>(
    file: &File,
    offset: u64,
    length: u64,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let bytes = buffer
        .get_mut(..usize::try_from(length).map_err(|_| invalid())?)
        .ok_or_else(invalid)?;
    read_exact_at(file, bytes, offset).map_err(Error::io)?;
    #[cfg(test)]
    READ_BYTES.set(READ_BYTES.get() + length);
    Ok(bytes)
}

#[cfg(test)]
mod tests;
