//! The counting sink, its durability hook, and stride flushing.

use super::{
    Arc, AtomicU64, FetchPlan, FileSink, Mutex, Ordering, Path, ResumeStore, SubjectId,
    durable_units, subject_of, total_units_of,
};

/// Bytes placed between stride flushes.
///
/// The completion sync is serial; flushing each stride spreads that work
/// across the transfer so the final sync covers at most a stride.
pub(crate) const FLUSH_STRIDE_BYTES: u64 = 67_108_864;

/// A sink that counts what it places, and keeps durability in stride.
///
/// The fetch cannot see answers arrive; the placed-byte count is the only
/// signal that paces requests and reports progress.
pub(crate) struct CountingSink {
    pub(crate) file: FileSink,
    pub(crate) placed: AtomicU64,
    /// Next placed-byte crossing due a flush; the exchange keeps two
    /// writers from flushing the same stride.
    pub(crate) flush_due: AtomicU64,
    /// Stride flushes taken.
    pub(crate) flushes: AtomicU64,
    /// Stride flush checkpoint hook, when a store rides the fetch.
    pub(crate) durable: Option<DurableHook>,
}

/// What a stride flush needs to turn durability into a checkpoint.
///
/// Coverage is snapshotted before the sync: checkpointing a range that
/// settles mid-sync would claim durability the disk never promised.
pub(crate) struct DurableHook {
    /// Weak, because the plan holds the sink that holds this.
    pub(crate) plan: std::sync::Weak<Mutex<FetchPlan>>,
    pub(crate) store: Arc<Mutex<ResumeStore>>,
    pub(crate) subject: SubjectId,
}

impl DurableHook {
    /// One stride's durability: snapshot, sync, checkpoint.
    pub(crate) fn flush(&self, file: &FileSink) {
        let covered = self.plan.upgrade().and_then(|plan| {
            let plan = plan.lock().ok()?;
            // Coverage is the current object's; a sink outliving its
            // object flushes without a claim to make.
            (plan.objects.get(plan.current).map(subject_of) == Some(self.subject))
                .then(|| plan.covered.extents().clone())
        });
        if file.file().sync_data().is_err() {
            // Nothing durable to claim; the completion sync will tell
            // the truth loudly.
            return;
        }
        let Some(covered) = covered else {
            return;
        };
        let units = durable_units(&covered, self.subject.length());
        if units.is_empty() {
            return;
        }
        if let Ok(mut store) = self.store.lock() {
            let _ =
                store.checkpoint_units(self.subject, total_units_of(self.subject.length()), &units);
        }
    }
}

/// The stride crossing after `placed`: where the next flush is due.
pub(crate) const fn stride_after(placed: u64) -> u64 {
    placed
        .saturating_sub(placed % FLUSH_STRIDE_BYTES)
        .saturating_add(FLUSH_STRIDE_BYTES)
}

impl CountingSink {
    /// Counters seeded from `placed`, so pacing and reporting start true
    /// whether the file is fresh or reopened.
    fn opened(file: FileSink, placed: u64, durable: Option<DurableHook>) -> Self {
        Self {
            file,
            placed: AtomicU64::new(placed),
            flush_due: AtomicU64::new(stride_after(placed)),
            flushes: AtomicU64::new(0),
            durable,
        }
    }

    pub(crate) fn create(
        path: &Path,
        length: u64,
        durable: Option<DurableHook>,
    ) -> std::io::Result<Self> {
        Ok(Self::opened(FileSink::create(path, length)?, 0, durable))
    }

    /// Reopens a partial object with what the last fetch already placed.
    pub(crate) fn resume(
        path: &Path,
        length: u64,
        placed: u64,
        durable: Option<DurableHook>,
    ) -> std::io::Result<Self> {
        Ok(Self::opened(
            FileSink::resume(path, length)?,
            placed,
            durable,
        ))
    }

    pub(crate) fn placed(&self) -> u64 {
        self.placed.load(Ordering::Relaxed)
    }
}

impl vot_scheduler::RangeSink for CountingSink {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), vot_scheduler::SinkError> {
        self.file.write_at(covered_offset, data)?;
        let placed = self
            .placed
            .fetch_add(data.len() as u64, Ordering::Relaxed)
            .saturating_add(data.len() as u64);
        let due = self.flush_due.load(Ordering::Relaxed);
        if placed >= due
            && self
                .flush_due
                .compare_exchange(
                    due,
                    // The crossing after what is placed, however many
                    // strides this write spanned.
                    stride_after(placed),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            // Best effort; the completion sync still runs, and a failure
            // here costs only the tail.
            self.flushes.fetch_add(1, Ordering::Relaxed);
            match &self.durable {
                Some(hook) => hook.flush(&self.file),
                None => {
                    let _ = self.file.file().sync_data();
                }
            }
        }
        Ok(())
    }
}

/// A caller's window onto placed bytes, paced by the bytes themselves.
pub(crate) struct PlacedReport {
    pub(crate) quantum: u64,
    /// The next crossing worth a report. Starts at one quantum: zero is
    /// where every fetch begins, not news.
    pub(crate) next_at: u64,
    pub(crate) observer: Box<dyn FnMut(u64, Option<u64>) + Send>,
}

/// The crossing after `placed`, if `placed` reached the one due.
///
/// Pure mapping, so a test can hold the boundary exactly.
pub(crate) const fn crossing(placed: u64, next_at: u64, quantum: u64) -> Option<u64> {
    if placed < next_at {
        return None;
    }
    Some(
        placed
            .saturating_sub(placed % quantum)
            .saturating_add(quantum),
    )
}
