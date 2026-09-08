//! The threads beside the session: the prover pool and the plan's
//! completion flusher, and their worker lifecycles.

use super::{
    Arc, COMPLETION_GRACE, CompletedBundle, CompletionHook, CountingSink, Error, FetchPlan, Mutex,
    ReceiveObject, ReceiveSessionId, ReliableReceiver, ResumeStore, SubjectId, UnitRanges, mpsc,
    total_units_of,
};

/// Threads that prove and place covers, beside the session thread.
///
/// One thread cannot receive a cover while it proves the one before, so
/// both steps move here and the witness returns through `settle`.
pub(crate) const DEFAULT_PROVING_THREADS: usize = 4;

/// Threads that retire whole objects, beside the rails that fetch them.
///
/// One, because nothing measured asked for more. On a 256-object sequence
/// onto ZFS, ten reps interleaved against the same control, the widths 1, 4,
/// 8 and 16 all land inside the control's own spread once the pool's write
/// throttle stalls are set aside: 3.8, 4.0, 3.6 and 4.2 seconds against a
/// control of 3.7 to 3.8, and width 8 measured 3.6 in one run and 3.7 in the
/// next. What separates the runs is how many throttle stalls each drew, not
/// how many threads were syncing. One is the fewest that takes the fsync off
/// the rails, and a pool that serializes its commits gains nothing from a
/// second.
pub(crate) const COMPLETION_FLUSHERS: usize = 1;

/// One whole object to make durable: sync what was placed, checkpoint it
/// whole, and tell the consumer.
///
/// Everything the sequence needs travels with the job, so the flusher takes
/// the plan lock exactly once, to retire it.
pub(crate) struct CompletionJob {
    /// The object's index in the plan, which is what it is retired by.
    pub(crate) index: usize,
    pub(crate) sink: Arc<CountingSink>,
    pub(crate) subject: SubjectId,
    pub(crate) length: u64,
    pub(crate) hook: Option<CompletionHook>,
    pub(crate) receive_session: ReceiveSessionId,
    pub(crate) receive_object: Option<ReceiveObject>,
    pub(crate) store: Option<Arc<Mutex<ResumeStore>>>,
}

/// The plan's completion flusher: the threads that run [`complete`] off the
/// rails, and the plan they retire into.
pub(crate) struct CompletionFlusher {
    /// Weak, because the plan holds the queue that feeds this.
    plan: std::sync::Weak<Mutex<FetchPlan>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl CompletionFlusher {
    /// Starts `width` flushers on `jobs`, retiring into `plan`.
    ///
    /// Each holds a clone of the queue's receiving half behind a lock, so a
    /// job goes to whichever is free, exactly as a prover takes a bundle.
    pub(crate) fn start(
        width: usize,
        plan: std::sync::Weak<Mutex<FetchPlan>>,
        jobs: mpsc::Receiver<CompletionJob>,
    ) -> Self {
        let jobs = Arc::new(Mutex::new(jobs));
        let mut threads = Vec::with_capacity(width);
        for _ in 0..width {
            let jobs = Arc::clone(&jobs);
            let plan = plan.clone();
            threads.push(std::thread::spawn(move || {
                loop {
                    let Ok(queue) = jobs.lock() else {
                        return;
                    };
                    let Ok(job) = queue.recv() else {
                        return;
                    };
                    drop(queue);
                    // A hook is a caller's code: a panic in it fails the
                    // plan the way a refusal does, rather than leaving the
                    // object it names syncing forever.
                    let outcome =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| complete(&job)))
                            .unwrap_or(Err(Error::InvalidBundle));
                    retire(&plan, &job, outcome);
                }
            }));
        }
        Self { plan, threads }
    }

    /// Ends the flusher: nothing more is queued, what is queued drains, and
    /// the threads are joined.
    ///
    /// Draining rather than discarding, because the objects those jobs
    /// retire are already durable and their hooks are owed.
    pub(crate) fn finish(&mut self) -> Result<(), Error> {
        if let Some(plan) = self.plan.upgrade() {
            // Through a poisoned lock as well as a sound one. A panic
            // holding the plan poisons it, this runs while that panic
            // unwinds, and a queue left open would leave the threads
            // below waiting on a sender nothing will ever drop.
            let mut plan = plan
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            plan.completions.queue = None;
        }
        let mut outcome = Ok(());
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                outcome = Err(Error::InvalidBundle);
            }
        }
        outcome
    }
}

impl Drop for CompletionFlusher {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// One object's durability, outside every plan lock: sync what the rails
/// placed, checkpoint the whole object, then tell the consumer.
fn complete(job: &CompletionJob) -> Result<(), Error> {
    job.sink.flush()?;
    // The whole object is now durable; a resume never asks for it again.
    if let Some(store) = &job.store
        && let Ok(mut store) = store.lock()
    {
        let mut units = UnitRanges::new();
        units.extend_units(0..total_units_of(job.length));
        let _ = store.checkpoint_units(job.subject, total_units_of(job.length), &units);
    }
    match (&job.hook, &job.receive_object) {
        (Some(hook), Some(object)) => hook(job.receive_session, object),
        _ => Ok(()),
    }
}

/// Books what [`complete`] answered into the plan, under its lock once.
fn retire(
    plan: &std::sync::Weak<Mutex<FetchPlan>>,
    job: &CompletionJob,
    outcome: Result<(), Error>,
) {
    let Some(plan) = plan.upgrade() else {
        return;
    };
    let Ok(mut plan) = plan.lock() else {
        return;
    };
    if let Some(active) = plan.active.get_mut(&job.index) {
        active.syncing = false;
    }
    plan.completions.outstanding = plan.completions.outstanding.saturating_sub(1);
    plan.completions.steps = plan.completions.steps.saturating_add(1);
    // The job behind this one gets its own grace, counted from here.
    plan.completions.graced_until = Some(std::time::Instant::now() + COMPLETION_GRACE);
    let Err(error) = outcome else {
        plan.placed_before = plan.placed_before.saturating_add(job.length);
        plan.active.remove(&job.index);
        if let Some(planned) = plan.objects.get_mut(job.index) {
            planned.done = true;
        }
        plan.advance_cursor();
        return;
    };
    plan.completions.parked.get_or_insert(error);
    plan.abandoned = true;
}

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
