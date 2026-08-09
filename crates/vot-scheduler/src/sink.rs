//! Where verified ranges go: the sink trait and the file-backed sink.

use super::Error;

/// A sink's refusal. It carries no cause because the receiver's answer is
/// the same whatever it was: the range is refused and stays retryable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinkError;

impl From<SinkError> for Error {
    fn from(_: SinkError) -> Self {
        Self::Sink
    }
}

/// Where a subject's verified bytes go. `write_at` takes `&self` because
/// accepted writes commute (disjoint or identical), so sinks are thread-safe.
pub trait RangeSink: Send + Sync {
    /// # Errors
    /// Refuses a write it cannot take; the receiver keeps the range retryable.
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), SinkError>;
}

/// A sink that drops what it is given, for measurements and tests whose
/// subject is transport and verification rather than the bytes' destination.
pub struct DiscardSink;

impl RangeSink for DiscardSink {
    fn write_at(&self, _covered_offset: u64, _data: &[u8]) -> Result<(), SinkError> {
        Ok(())
    }
}

/// A shared sink is a sink, which is what lets a caller keep a handle to
/// the destination it registered.
impl<S: RangeSink + ?Sized> RangeSink for std::sync::Arc<S> {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), SinkError> {
        (**self).write_at(covered_offset, data)
    }
}

/// A sink that places each verified range at its offset in one file.
/// Positional writes only; durability is the caller's contract.
pub struct FileSink {
    file: std::fs::File,
}

impl FileSink {
    /// Creates or truncates the destination and sizes it to the object, so
    /// every verified range writes into place rather than extending.
    ///
    /// # Errors
    /// Surfaces the platform's refusal to create or size the file.
    pub fn create(path: &std::path::Path, length: u64) -> std::io::Result<Self> {
        let file = std::fs::File::create(path)?;
        file.set_len(length)?;
        // Best effort: avoids NTFS valid-data zero-fill on out-of-order writes.
        let _ = vot_platform_fs::allow_unordered_writes(&file);
        Ok(Self { file })
    }

    /// Opens an existing destination without truncating what it holds,
    /// sized to the object, so a fetch continuing a partial bundle keeps
    /// every byte a previous fetch placed (ADR-0032).
    ///
    /// # Errors
    /// Surfaces a destination that does not exist or will not open.
    pub fn resume(path: &std::path::Path, length: u64) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        file.set_len(length)?;
        let _ = vot_platform_fs::allow_unordered_writes(&file);
        Ok(Self { file })
    }

    /// The handle writes went through. Sync through this one to catch
    /// writeback failures from before the first write.
    #[must_use]
    pub fn file(&self) -> &std::fs::File {
        &self.file
    }
}

#[cfg(unix)]
pub(super) fn write_all_at(file: &std::fs::File, offset: u64, data: &[u8]) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, data, offset)
}

#[cfg(windows)]
pub(super) fn write_all_at_windows(
    file: &std::fs::File,
    offset: u64,
    data: &[u8],
) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt as _;
    let mut offset = offset;
    let mut data = data;
    while !data.is_empty() {
        let written = file.seek_write(data, offset)?;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        data = &data[written..];
        offset = offset.saturating_add(written as u64);
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(super) fn write_all_at_unsupported(
    _file: &std::fs::File,
    _offset: u64,
    _data: &[u8],
) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

impl RangeSink for FileSink {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), SinkError> {
        #[cfg(unix)]
        let written = write_all_at(&self.file, covered_offset, data);
        #[cfg(windows)]
        let written = write_all_at_windows(&self.file, covered_offset, data);
        #[cfg(not(any(unix, windows)))]
        let written = write_all_at_unsupported(&self.file, covered_offset, data);
        written.map_err(|_| SinkError)
    }
}
