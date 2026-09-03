//! The counting sink, its durability hook, and stride flushing.

use super::{
    Arc, AtomicU64, Error, FetchPlan, FileSink, Mutex, Ordering, Path, PathBuf, ReceiveSink,
    ResumeStore, SubjectId, durable_units, total_units_of,
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
pub struct CountingSink {
    pub(crate) sink: Box<dyn ReceiveSink>,
    /// Serializes placement with abandonment. Once abandoned, no prover on
    /// any rail may recreate bytes after `discard_partial` returns.
    gate: Mutex<bool>,
    pub(crate) placed: AtomicU64,
    /// Next placed-byte crossing due a flush; the exchange keeps two
    /// writers from flushing the same stride.
    pub(crate) flush_due: AtomicU64,
    /// Stride flushes taken.
    pub(crate) flushes: AtomicU64,
    /// Stride flush checkpoint hook, when a store rides the fetch.
    pub(crate) durable: Option<DurableHook>,
}

struct DirectorySink {
    file: FileSink,
    path: PathBuf,
}

impl vot_scheduler::RangeSink for DirectorySink {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), vot_scheduler::SinkError> {
        self.file.write_at(covered_offset, data)
    }
}

impl ReceiveSink for DirectorySink {
    fn flush(&self) -> Result<(), Error> {
        self.file.file().sync_all().map_err(Error::Io)
    }

    fn discard_partial(&self) -> Result<(), Error> {
        if let Err(error) = std::fs::symlink_metadata(&self.path) {
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(Error::Io(error))
            };
        }
        match vot_platform_fs::remove_file_handle(self.file.file(), &self.path) {
            Ok(()) => Ok(()),
            Err(error) => Err(Error::Io(error)),
        }
    }
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
    pub(crate) fn flush(&self, sink: &dyn ReceiveSink) {
        let covered = self.plan.upgrade().and_then(|plan| {
            let plan = plan.lock().ok()?;
            // Coverage is that object's own; a sink outliving its object
            // leaves the window and flushes without a claim to make.
            let (_, active) = plan.in_window(self.subject)?;
            Some(active.covered.extents().clone())
        });
        if sink.flush().is_err() {
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
    fn opened(sink: Box<dyn ReceiveSink>, placed: u64, durable: Option<DurableHook>) -> Self {
        Self {
            sink,
            gate: Mutex::new(false),
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
        let file = FileSink::create_new(path, length)?;
        Ok(Self::opened(
            Box::new(DirectorySink {
                file,
                path: path.to_owned(),
            }),
            0,
            durable,
        ))
    }

    /// Reopens a partial object with what the last fetch already placed.
    pub(crate) fn resume(
        path: &Path,
        length: u64,
        placed: u64,
        durable: Option<DurableHook>,
    ) -> std::io::Result<Self> {
        let file = FileSink::resume(path, length)?;
        Ok(Self::opened(
            Box::new(DirectorySink {
                file,
                path: path.to_owned(),
            }),
            placed,
            durable,
        ))
    }

    pub(crate) fn custom(sink: Box<dyn ReceiveSink>) -> Self {
        Self::opened(sink, 0, None)
    }

    /// Creates the directory-backed sink used by a normal fetch.
    pub fn at(path: &Path, length: u64) -> std::io::Result<Self> {
        Self::create(path, length, None)
    }

    pub(crate) fn placed(&self) -> u64 {
        self.placed.load(Ordering::Relaxed)
    }

    pub(crate) fn flush(&self) -> Result<(), Error> {
        let discarded = self.gate.lock().map_err(|_| Error::InvalidBundle)?;
        if *discarded {
            return Err(Error::InvalidBundle);
        }
        self.sink.flush()
    }

    pub(crate) fn discard_partial(&self) -> Result<(), Error> {
        let mut discarded = self.gate.lock().map_err(|_| Error::InvalidBundle)?;
        *discarded = true;
        self.sink.discard_partial()
    }
}

impl vot_scheduler::RangeSink for CountingSink {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), vot_scheduler::SinkError> {
        let discarded = self.gate.lock().map_err(|_| vot_scheduler::SinkError)?;
        if *discarded {
            return Err(vot_scheduler::SinkError);
        }
        self.sink.write_at(covered_offset, data)?;
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
                Some(hook) => hook.flush(self.sink.as_ref()),
                None => {
                    let _ = self.sink.flush();
                }
            }
        }
        drop(discarded);
        Ok(())
    }
}

impl ReceiveSink for CountingSink {
    fn flush(&self) -> Result<(), Error> {
        CountingSink::flush(self)
    }

    fn discard_partial(&self) -> Result<(), Error> {
        CountingSink::discard_partial(self)
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

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use vot_scheduler::RangeSink as _;

    /// A sink that fails everything asked of it.
    pub(in crate::fetch) struct FailingSink;

    impl vot_scheduler::RangeSink for FailingSink {
        fn write_at(&self, _: u64, _: &[u8]) -> Result<(), vot_scheduler::SinkError> {
            Err(vot_scheduler::SinkError)
        }
    }

    impl ReceiveSink for FailingSink {
        fn flush(&self) -> Result<(), Error> {
            Err(Error::InvalidBundle)
        }

        fn discard_partial(&self) -> Result<(), Error> {
            Err(Error::InvalidBundle)
        }
    }

    #[derive(Default)]
    struct BlockingState {
        started: bool,
        release: bool,
        discarded: bool,
        writes: usize,
    }

    #[derive(Default)]
    struct BlockingSink {
        shared: Arc<(std::sync::Mutex<BlockingState>, std::sync::Condvar)>,
    }

    impl Clone for BlockingSink {
        fn clone(&self) -> Self {
            Self {
                shared: Arc::clone(&self.shared),
            }
        }
    }

    impl vot_scheduler::RangeSink for BlockingSink {
        fn write_at(&self, _: u64, _: &[u8]) -> Result<(), vot_scheduler::SinkError> {
            let mut state = self.shared.0.lock().map_err(|_| vot_scheduler::SinkError)?;
            state.started = true;
            self.shared.1.notify_all();
            while !state.release {
                state = self
                    .shared
                    .1
                    .wait(state)
                    .map_err(|_| vot_scheduler::SinkError)?;
            }
            state.writes += 1;
            Ok(())
        }
    }

    impl ReceiveSink for BlockingSink {
        fn flush(&self) -> Result<(), Error> {
            Ok(())
        }

        fn discard_partial(&self) -> Result<(), Error> {
            self.shared
                .0
                .lock()
                .map_err(|_| Error::InvalidBundle)?
                .discarded = true;
            Ok(())
        }
    }

    #[test]
    fn discard_waits_for_a_writer_and_refuses_every_later_write() {
        let inner = Arc::new(BlockingSink::default());
        let sink = Arc::new(CountingSink::custom(Box::new((*inner).clone())));
        let writing = {
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || sink.write_at(0, &[1]))
        };
        {
            let mut state = inner.shared.0.lock().unwrap();
            while !state.started {
                let (next, timeout) = inner
                    .shared
                    .1
                    .wait_timeout(state, std::time::Duration::from_secs(1))
                    .unwrap();
                state = next;
                assert!(!timeout.timed_out(), "the write never reached the sink");
            }
        }
        let discarding = {
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || sink.discard_partial())
        };
        {
            let mut state = inner.shared.0.lock().unwrap();
            state.release = true;
            inner.shared.1.notify_all();
        }
        writing.join().unwrap().unwrap();
        discarding.join().unwrap().unwrap();
        assert!(sink.write_at(1, &[2]).is_err());
        let state = inner.shared.0.lock().unwrap();
        assert!(state.discarded);
        assert_eq!(state.writes, 1);
    }

    #[test]
    fn counting_sink_propagates_inner_failures() {
        let sink = CountingSink::custom(Box::new(FailingSink));
        assert!(sink.write_at(0, &[1]).is_err());
        assert!(<CountingSink as ReceiveSink>::flush(&sink).is_err());
        assert!(<CountingSink as ReceiveSink>::discard_partial(&sink).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn directory_discard_is_idempotent_and_reports_other_errors() {
        let root = std::env::temp_dir().join(format!(
            "vot-directory-sink-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        crate::create_private_directory(&root).unwrap();
        let path = root.join("object");
        let sink = DirectorySink {
            file: FileSink::create(&path, 0).unwrap(),
            path: path.clone(),
        };
        sink.discard_partial().unwrap();
        sink.discard_partial().unwrap();

        let directory = root.join("not-a-file");
        std::fs::create_dir(&directory).unwrap();
        let sink = DirectorySink {
            file: FileSink::create(&path, 0).unwrap(),
            path: directory,
        };
        assert!(sink.discard_partial().is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
