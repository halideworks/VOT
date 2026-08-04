//! The cycle counter behind the report's `cycles` field.
//!
//! `perf_event_open` counting `PERF_COUNT_HW_CPU_CYCLES`, opened with inherit
//! before the transfer spawns its threads so every thread the measurement
//! creates is counted with it. A host that refuses the counter (Linux with
//! `kernel.perf_event_paranoid` above 2 and no `CAP_PERFMON`, or any other
//! platform) yields `None`, which the report renders as the honest null the
//! contract allows.
//!
//! Excluded from the mutation gate, though for a different reason than the
//! backend files: this compiles everywhere, but whether the host grants a
//! counter is a runtime decision, so a mutant here flips between caught and
//! missed with `kernel.perf_event_paranoid`. Everything that decides what a
//! `Measurement` says from the counter's answer lives in `lib.rs` under the
//! gate.

/// One raw reading: the count and how long the PMU actually kept it on.
pub(crate) struct CycleReading {
    pub(crate) count: u64,
    pub(crate) time_enabled: u64,
    pub(crate) time_running: u64,
}

#[cfg(target_os = "linux")]
pub(crate) struct CycleCounter(perf_event::Counter);

#[cfg(target_os = "linux")]
impl CycleCounter {
    /// Starts counting this process, threads to come included.
    pub(crate) fn start() -> Option<Self> {
        let mut counter = perf_event::Builder::new(perf_event::events::Hardware::CPU_CYCLES)
            .inherit(true)
            .build()
            .ok()?;
        counter.enable().ok()?;
        Some(Self(counter))
    }

    /// Stops counting and hands back the raw reading; what it means is
    /// `settle_cycles`'s decision, which lives under the mutation gate.
    pub(crate) fn read(mut self) -> Option<CycleReading> {
        self.0.disable().ok()?;
        let value = self.0.read_count_and_time().ok()?;
        Some(CycleReading {
            count: value.count,
            time_enabled: value.time_enabled,
            time_running: value.time_running,
        })
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) struct CycleCounter;

#[cfg(not(target_os = "linux"))]
impl CycleCounter {
    /// No syscall to make here; the field stays null.
    pub(crate) fn start() -> Option<Self> {
        None
    }

    pub(crate) fn read(self) -> Option<CycleReading> {
        None
    }
}
