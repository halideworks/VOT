//! Hardware cycle counter using Linux `perf_event_open` with inheritance.
//! Non-Linux hosts and restricted environments yield `None`.

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

    /// Stops counting and returns the raw reading.
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
    pub(crate) fn start() -> Option<Self> {
        None
    }

    pub(crate) fn read(self) -> Option<CycleReading> {
        None
    }
}
