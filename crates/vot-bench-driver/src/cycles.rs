//! The cycle counter behind the report's `cycles` field.
//!
//! `perf_event_open` counting `PERF_COUNT_HW_CPU_CYCLES`, opened with inherit
//! before the transfer spawns its threads so every thread the measurement
//! creates is counted with it. A host that refuses the counter (Linux with
//! `kernel.perf_event_paranoid` above 2 and no `CAP_PERFMON`, or any other
//! platform) yields `None`, which the report renders as the honest null the
//! contract allows.
//!
//! Excluded from the mutation gate like the backend files: whether this host
//! grants a perf counter is the host's decision, so no test can pin both
//! outcomes on one machine. Everything that decides what a `Measurement` says
//! from the counter's answer lives in `lib.rs` under the gate.

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

    /// Stops counting and reports what was spent.
    pub(crate) fn read(mut self) -> Option<u64> {
        self.0.disable().ok()?;
        self.0.read().ok()
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

    pub(crate) fn read(self) -> Option<u64> {
        None
    }
}
