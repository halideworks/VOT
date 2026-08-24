//! The prover pool and its worker lifecycle.

use super::{Arc, CompletedBundle, CountingSink, ReliableReceiver, mpsc};

/// Threads that prove and place covers, beside the session thread.
///
/// One thread cannot receive a cover while it proves the one before, so
/// both steps move here and the witness returns through `settle`.
pub(crate) const DEFAULT_PROVING_THREADS: usize = 4;

/// How long a pass waits for a prover it is already owed.
///
/// Only reached when the pass would otherwise book nothing; the work is
/// this end's own and already in hand.
pub(crate) const PROVER_WAIT: std::time::Duration = std::time::Duration::from_millis(50);

/// What a test's pass waits instead: a test round waits for the witness it
/// is owed, so starvation cannot turn a counted round budget into a clock.
pub(crate) const TEST_PROVER_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// What a prover is handed: a bundle to prove and where its bytes go.
pub(crate) struct Proving {
    pub(crate) completed: CompletedBundle,
    pub(crate) sink: Arc<CountingSink>,
}

/// What comes back: the bundle, and the witness that it is written.
pub(crate) struct Proved {
    pub(crate) completed: CompletedBundle,
    pub(crate) written: vot_scheduler::WrittenRange,
}

/// The provers and the two channels they sit between.
pub(crate) struct ProvingPool {
    pub(crate) work: mpsc::SyncSender<Proving>,
    pub(crate) proved: mpsc::Receiver<Result<Proved, vot_scheduler::Error>>,
    pub(crate) threads: Vec<std::thread::JoinHandle<()>>,
    /// The receiving half the provers share. Held here too, so a probe of
    /// this handle can tell provers that were joined from provers merely
    /// abandoned: after a drop, no other owner may remain.
    pub(crate) taking: Arc<std::sync::Mutex<mpsc::Receiver<Proving>>>,
    /// Bundles handed out and not yet settled, which is what decides
    /// whether this end has room to take another.
    pub(crate) in_flight: usize,
    /// Witnesses booked over the pool's life.
    pub(crate) witnesses: u64,
    pub(crate) width: usize,
}

impl ProvingPool {
    /// Starts `width` provers. Each holds a clone of the work channel's
    /// receiving half behind a lock, so a bundle goes to whichever is free.
    pub(crate) fn start(width: usize) -> Self {
        // Bounded at twice the width: enough that no prover waits on the
        // session thread for its next bundle, small enough that what is in
        // flight is a few covers rather than an object.
        let (work, taking) = mpsc::sync_channel::<Proving>(width.saturating_mul(2));
        let (finished, proved) = mpsc::channel::<Result<Proved, vot_scheduler::Error>>();
        let taking = Arc::new(std::sync::Mutex::new(taking));
        let mut threads = Vec::with_capacity(width);
        for _ in 0..width {
            let taking = Arc::clone(&taking);
            let finished = finished.clone();
            threads.push(std::thread::spawn(move || {
                loop {
                    let Ok(queue) = taking.lock() else {
                        return;
                    };
                    let Ok(next) = queue.recv() else {
                        return;
                    };
                    drop(queue);
                    if finished.send(prove(next)).is_err() {
                        return;
                    }
                }
            }));
        }
        Self {
            work,
            proved,
            threads,
            taking,
            in_flight: 0,
            witnesses: 0,
            width,
        }
    }

    /// Whether another bundle can be handed over without waiting.
    pub(crate) const fn has_room(&self) -> bool {
        self.in_flight < self.width.saturating_mul(2)
    }

    /// Whether anything is out with a prover.
    pub(crate) const fn busy(&self) -> bool {
        self.in_flight > 0
    }
}

impl Drop for ProvingPool {
    fn drop(&mut self) {
        // The provers end when the work channel closes, which is what
        // dropping this sender does; the joins then cannot outlive them.
        let (closed, _) = mpsc::sync_channel::<Proving>(1);
        drop(std::mem::replace(&mut self.work, closed));
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        // Every prover has been joined, so no other owner of the work
        // queue can remain.
        debug_assert_eq!(std::sync::Arc::strong_count(&self.taking), 1);
    }
}

/// Proves one bundle and places its bytes.
pub(crate) fn prove(work: Proving) -> Result<Proved, vot_scheduler::Error> {
    let records = work.completed.records();
    let range = ReliableReceiver::verify_typed_bundle(
        work.completed.subject(),
        work.completed.bundle(),
        &records,
    )?;
    let written = range.write_to(work.sink.as_ref())?;
    Ok(Proved {
        completed: work.completed,
        written,
    })
}
