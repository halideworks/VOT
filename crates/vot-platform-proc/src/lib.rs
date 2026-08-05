//! Small, isolated platform process measurements that require native FFI.

#![deny(unsafe_code)]

use std::io;

/// Reads this process's peak resident memory, in bytes.
///
/// Linux is deliberately absent: `/proc/self/status` carries `VmHWM` and needs
/// no FFI, so the reader for it lives with its caller. This crate covers the
/// platforms whose only source is a native call.
///
/// # Errors
/// Returns the operating-system error when the measurement cannot be taken,
/// and `Unsupported` where no native source exists; the caller owns saying a
/// metric has no measured source rather than inventing a zero.
pub fn peak_resident_bytes() -> io::Result<u64> {
    #[cfg(windows)]
    {
        peak_resident_bytes_windows()
    }
    #[cfg(target_os = "macos")]
    {
        peak_resident_bytes_macos()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn peak_resident_bytes_windows() -> io::Result<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: 0,
        PageFaultCount: 0,
        PeakWorkingSetSize: 0,
        WorkingSetSize: 0,
        QuotaPeakPagedPoolUsage: 0,
        QuotaPagedPoolUsage: 0,
        QuotaPeakNonPagedPoolUsage: 0,
        QuotaNonPagedPoolUsage: 0,
        PagefileUsage: 0,
        PeakPagefileUsage: 0,
    };
    let size = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS>())
        .expect("a counter block's length fits its own field");
    counters.cb = size;
    // SAFETY: the pseudo-handle names this process and needs no closing, and
    // the pointer and length describe the one counter block being filled.
    let result = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &raw mut counters, size) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(counters.PeakWorkingSetSize)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn peak_resident_bytes_macos() -> io::Result<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: RUSAGE_SELF asks about this process, and the pointer names one
    // rusage the call fills before the return is inspected.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getrusage returned zero, so the block is initialised.
    let usage = unsafe { usage.assume_init() };
    // ru_maxrss is bytes on this platform, unlike Linux's kilobytes.
    u64::try_from(usage.ru_maxrss).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

#[cfg(test)]
mod tests {
    use super::peak_resident_bytes;

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn a_process_that_allocates_has_a_peak_to_report() {
        // Touch a buffer first, so the peak provably covers it: a peak below
        // the buffer would be a number from somewhere else.
        let buffer = vec![0x27_u8; 4 * 1024 * 1024];
        std::hint::black_box(&buffer);
        let peak = peak_resident_bytes().expect("a measurement");
        assert!(peak >= 4 * 1024 * 1024, "peak {peak} misses the buffer");
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn an_unmeasurable_platform_says_so() {
        assert!(peak_resident_bytes().is_err());
    }
}
