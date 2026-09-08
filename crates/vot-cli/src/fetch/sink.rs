//! The counting sink, its durability hook, and stride flushing.

use super::{
    Arc, AtomicU64, Error, FetchPlan, FileSink, Mutex, Ordering, Path, PathBuf, ReceiveSink,
    ResumeStore, SubjectId, durable_units, subject_of, total_units_of,
};
use std::sync::{RwLock, atomic::AtomicBool};

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
    /// Serializes placement with abandonment. Once abandoned, no prover on
    /// any rail may recreate bytes after `discard_partial` returns.
    pub(crate) sink: RwLock<Option<Box<dyn ReceiveSink>>>,
    failed: AtomicBool,
    stride_flush: Mutex<()>,
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
    pub(crate) fn flush(&self, sink: &dyn ReceiveSink) -> Result<(), Error> {
        let covered = self.plan.upgrade().and_then(|plan| {
            let plan = plan.lock().ok()?;
            // Coverage is the current object's; a sink outliving its
            // object flushes without a claim to make.
            (plan.objects.get(plan.current).map(subject_of) == Some(self.subject))
                .then(|| plan.covered.extents().clone())
        });
        sink.flush()?;
        let Some(covered) = covered else {
            return Ok(());
        };
        let units = durable_units(&covered, self.subject.length());
        if units.is_empty() {
            return Ok(());
        }
        if let Ok(mut store) = self.store.lock() {
            let _ =
                store.checkpoint_units(self.subject, total_units_of(self.subject.length()), &units);
        }
        Ok(())
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
            sink: RwLock::new(Some(sink)),
            failed: AtomicBool::new(false),
            stride_flush: Mutex::new(()),
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
        let held = self.sink.write().map_err(|_| Error::InvalidBundle)?;
        let sink = held.as_deref().ok_or(Error::InvalidBundle)?;
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::InvalidBundle);
        }
        sink.flush().inspect_err(|_| {
            self.failed.store(true, Ordering::Release);
        })
    }

    pub(crate) fn discard_partial(&self) -> Result<(), Error> {
        let mut held = self.sink.write().map_err(|_| Error::InvalidBundle)?;
        self.failed.store(true, Ordering::Release);
        if let Some(sink) = held.as_ref() {
            sink.discard_partial()?;
        }
        // Legacy SMB deletion finishes when the last staging handle closes.
        held.take();
        Ok(())
    }
}

impl vot_scheduler::RangeSink for CountingSink {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), vot_scheduler::SinkError> {
        let held = self.sink.read().map_err(|_| vot_scheduler::SinkError)?;
        let sink = held.as_deref().ok_or(vot_scheduler::SinkError)?;
        if self.failed.load(Ordering::Acquire) {
            return Err(vot_scheduler::SinkError);
        }
        sink.write_at(covered_offset, data).inspect_err(|_| {
            self.failed.store(true, Ordering::Release);
        })?;
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
            // Serialize snapshots and checkpoints so an older one cannot
            // complete after a newer one. Disjoint writes may continue.
            let _flushing = self
                .stride_flush
                .lock()
                .map_err(|_| vot_scheduler::SinkError)?;
            if self.failed.load(Ordering::Acquire) {
                return Err(vot_scheduler::SinkError);
            }
            self.flushes.fetch_add(1, Ordering::Relaxed);
            let flushed = match &self.durable {
                Some(hook) => hook.flush(sink),
                None => sink.flush(),
            };
            if flushed.is_err() {
                self.failed.store(true, Ordering::Release);
                return Err(vot_scheduler::SinkError);
            }
        }
        drop(held);
        if self.failed.load(Ordering::Acquire) {
            Err(vot_scheduler::SinkError)
        } else {
            Ok(())
        }
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
mod tests {
    use super::*;
    use vot_scheduler::RangeSink as _;

    struct FailingSink;

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
    struct OnceFailingFlush(AtomicU64);

    impl vot_scheduler::RangeSink for OnceFailingFlush {
        fn write_at(&self, _: u64, _: &[u8]) -> Result<(), vot_scheduler::SinkError> {
            Ok(())
        }
    }

    impl ReceiveSink for OnceFailingFlush {
        fn flush(&self) -> Result<(), Error> {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(Error::Io(std::io::Error::other("writeback failed")))
            } else {
                Ok(())
            }
        }

        fn discard_partial(&self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_flush_cannot_be_rehabilitated_by_a_later_success() {
        for periodic in [false, true] {
            let inner = Arc::new(OnceFailingFlush::default());
            let sink = CountingSink::custom(Box::new(Arc::clone(&inner)));
            if periodic {
                sink.flush_due.store(1, Ordering::Relaxed);
                assert!(sink.write_at(0, &[1]).is_err());
            } else {
                assert!(sink.flush().is_err());
            }
            assert!(sink.write_at(1, &[2]).is_err());
            assert!(sink.flush().is_err());
            assert_eq!(inner.0.load(Ordering::Relaxed), 1);
            sink.discard_partial().unwrap();
        }
    }

    #[test]
    fn a_checkpoint_hook_propagates_a_failed_data_flush() {
        let directory = crate::tests::temporary("failed-hook");
        crate::create_private_directory(&directory).unwrap();
        let store = ResumeStore::create(directory.join("resume")).unwrap();
        let hook = DurableHook {
            plan: std::sync::Weak::new(),
            store: Arc::new(Mutex::new(store)),
            subject: SubjectId::new(1, [0; 32], 1).unwrap(),
        };
        let inner = Arc::new(OnceFailingFlush::default());
        let sink = CountingSink::opened(Box::new(inner.clone()), 0, Some(hook));
        sink.flush_due.store(1, Ordering::Relaxed);
        assert!(sink.write_at(0, &[1]).is_err());
        assert!(sink.flush().is_err());
        assert_eq!(inner.0.load(Ordering::Relaxed), 1);
    }

    #[derive(Default)]
    struct BlockingState {
        started: bool,
        entered: usize,
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
            state.entered += 1;
            self.shared.1.notify_all();
            let (mut state, timeout) = self
                .shared
                .1
                .wait_timeout_while(state, std::time::Duration::from_secs(5), |state| {
                    !state.release
                })
                .map_err(|_| vot_scheduler::SinkError)?;
            assert!(!timeout.timed_out(), "write was never released");
            state.writes += 1;
            Ok(())
        }
    }

    #[test]
    fn disjoint_writers_reach_the_sink_concurrently() {
        let inner = BlockingSink::default();
        let sink = Arc::new(CountingSink::custom(Box::new(inner.clone())));
        let writers: Vec<_> = (0..2)
            .map(|offset| {
                let sink = Arc::clone(&sink);
                std::thread::spawn(move || sink.write_at(offset, &[1]))
            })
            .collect();
        let state = inner.shared.0.lock().unwrap();
        let (mut state, timeout) = inner
            .shared
            .1
            .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
                state.entered != 2
            })
            .unwrap();
        state.release = true;
        inner.shared.1.notify_all();
        drop(state);
        for writer in writers {
            writer.join().unwrap().unwrap();
        }
        assert!(!timeout.timed_out(), "writes were serialized");
        sink.flush().unwrap();
        assert_eq!(sink.placed(), 2);
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
