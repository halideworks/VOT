#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle as _;
use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::FILE_ALLOCATED_RANGE_BUFFER;
use windows_sys::Win32::System::Ioctl::FSCTL_QUERY_ALLOCATED_RANGES;

/// Returns the next offset that may contain data without enumerating every extent.
///
/// # Errors
/// Propagates failed or malformed native queries; local NTFS supports this operation.
pub fn next_file_data_offset(file: &File, offset: u64) -> io::Result<Option<u64>> {
    let length = file.metadata()?.len();
    if offset >= length {
        return Ok(None);
    }
    let input = FILE_ALLOCATED_RANGE_BUFFER {
        FileOffset: i64::try_from(offset).map_err(|_| io::ErrorKind::InvalidInput)?,
        Length: i64::try_from(length - offset).map_err(|_| io::ErrorKind::InvalidInput)?,
    };
    let mut output = FILE_ALLOCATED_RANGE_BUFFER::default();
    let mut returned = 0;
    let size =
        u32::try_from(std::mem::size_of_val(&input)).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: the synchronous query uses live, correctly sized input and output ranges.
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_QUERY_ALLOCATED_RANGES,
            (&raw const input).cast(),
            size,
            (&raw mut output).cast(),
            size,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_MORE_DATA.cast_signed()) {
            return Err(error);
        }
    }
    if returned == 0 {
        return Ok(None);
    }
    let start = u64::try_from(output.FileOffset).map_err(|_| io::ErrorKind::InvalidData)?;
    let count = u64::try_from(output.Length).map_err(|_| io::ErrorKind::InvalidData)?;
    if returned != size
        || count == 0
        || start >= length
        || start.checked_add(count).is_none_or(|end| end <= offset)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(start.max(offset)))
}
