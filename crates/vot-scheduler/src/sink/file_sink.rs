//! File-backed range placement.

use super::{RangeSink, SinkError};

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
fn write_all_at(file: &std::fs::File, offset: u64, data: &[u8]) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, data, offset)
}

#[cfg(windows)]
fn write_all_at_windows(file: &std::fs::File, offset: u64, data: &[u8]) -> std::io::Result<()> {
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
fn write_all_at_unsupported(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RANGE_UNIT_BYTES;

    #[test]
    fn a_file_sink_places_ranges_at_their_offsets() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let mut bytes = Vec::with_capacity(unit * 3);
        for index in 0..3_u8 {
            bytes.extend(std::iter::repeat_n(index + 1, unit));
        }
        let path = std::env::temp_dir().join(format!(
            "vot-file-sink-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        let sink = FileSink::create(&path, bytes.len() as u64).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes.len() as u64);
        sink.write_at(2 * RANGE_UNIT_BYTES, &bytes[unit * 2..])
            .unwrap();
        sink.write_at(0, &bytes[..unit]).unwrap();
        sink.write_at(RANGE_UNIT_BYTES, &bytes[unit..unit * 2])
            .unwrap();
        sink.write_at(0, &bytes[..unit]).unwrap();
        drop(sink);
        let written = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(written, bytes);
    }

    #[test]
    fn a_resumed_sink_keeps_what_the_last_fetch_placed() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vot-file-sink-resume-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        let length = 3 * RANGE_UNIT_BYTES;
        let first = FileSink::create(&path, length).unwrap();
        first.write_at(RANGE_UNIT_BYTES, &vec![0x42; unit]).unwrap();
        drop(first);

        assert!(
            FileSink::resume(std::path::Path::new("/vot-missing/none"), length).is_err(),
            "resume opens what exists, never invents it"
        );
        let resumed = FileSink::resume(&path, length).unwrap();
        resumed.write_at(0, &vec![0x41; unit]).unwrap();
        drop(resumed);
        let written = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(written.len() as u64, length, "sized on reopen");
        assert!(
            written[unit..unit * 2].iter().all(|byte| *byte == 0x42),
            "the last fetch's bytes survived the reopen"
        );
        assert!(written[..unit].iter().all(|byte| *byte == 0x41));
    }
}
