# ADR-0052: Completion syncs run on a per-plan flusher

- Status: Accepted
- Date: 2026-09-03
- Decision owners: A00 architecture; A10 transport
- Applies to: `crates/vot-cli` (`fetch`, `drive`, `wire/push`). Supersedes
  ADR-0051 section 3 and the invariant comment in `fetch/protocol.rs` that
  said a pass which takes the last object's bytes has a whole bundle. No
  change to any frame encoding, to `spec/wire.md`, to `spec/registries.md`,
  or to `vot-transport-api`.

## Context

ADR-0051 gave the fetch a window of objects in flight and made completion
per object: the first rail to see an object covered whole raises that
object's `syncing`, drops the plan lock, flushes the sink, checkpoints the
whole object in the resume store, runs the completion hook, retakes the lock,
and marks the object done. All of that runs on that rail's own service
thread. While it runs, that rail makes no pass: its connection idles, its
serve queue drains, and its credit sits unused.

That is the cost the window was meant to hide, and onto ZFS it is not
hidden. A 256-object sequence of 16 MiB objects is 256 completion syncs, each
one parking a rail for the length of an fsync that serializes through the
pool's intent log. Measured on erebus at rails 8, the sequence caps near
three cores of CPU and a build that skips the completion sync entirely runs
it 23% faster: 2.63 seconds against 3.6. The single 4 GiB object is one sync
and does not show it.

Nothing about the work requires the rail. The sink, the store, the object
record and the hook are all reachable without the session, and ADR-0051
already made completion hooks any-order, so no consumer depends on which
thread or which order they run in.

## Decision

**The plan carries one completion flusher. The rail that sees an object
whole queues that object's sync and goes back to its loop; the flusher makes
the object durable and retires it into the plan. Nothing on the wire
changes, and neither does the cursor.**

1. **The flusher belongs to the plan and is started with it.** The fetch
   that builds the plan starts `COMPLETION_FLUSHERS` threads beside the
   proving pool, holding `Weak<Mutex<FetchPlan>>` as the durable hook does,
   fed by a bounded `sync_channel` whose sender lives on the plan so every
   rail reaches it. The bound is the window: an object is queued only when
   it is covered whole and stays in flight until the flusher retires it, so
   a stalled disk backs the fetch up through `in_flight` rather than through
   the queue. The handle lives in the primary `BundleFetcher`, not in the
   plan. `fetch_striped` joins the flusher after the rails and before it
   returns, on success and on failure, outside the plan lock; the push
   receiver joins it as its session ends. A thread that died is an error
   from that join.

2. **The rail queues, the flusher completes.** `advance` raises `syncing`,
   builds the job (`index`, `sink`, `subject`, `length`, `hook`,
   `receive_session`, `receive_object`, `store`), drops the plan lock, sends,
   and returns to its loop. The send is always after the lock is down: the
   flusher takes that lock to retire what it holds, so a full queue must
   never wait under it. The flusher runs today's sequence outside every plan
   lock, in today's order (`sink.flush()`, whole-object checkpoint into the
   store, completion hook), and then takes the plan lock once: clear
   `syncing`, `placed_before += length`, remove the object from the window,
   mark it done, advance the cursor. It never calls `sink.flush()` under the
   plan lock, because a sink's gate is taken before that lock.

3. **A failed job parks its cause on the plan.** The flusher puts the first
   failure in a slot on the plan and marks the plan abandoned, leaving the
   object in the window with `syncing` cleared. Every rail's `service` takes
   that slot and returns the error before it reports either the carrier or
   the abandoned plan, so the cause reaches the caller where an abandoned
   rail would otherwise report only the carrier it then closed. A hook that
   panics is caught and becomes such a failure, rather than a thread that
   dies leaving an object syncing forever.

4. **A disconnected or abandoned session waits for the work it owes.**
   Completion is no longer the same pass as coverage, so a disconnect
   delivered with the last object's bytes would end a fetch whose bundle is
   about to be whole. While a completion job is outstanding, a disconnected
   or abandoned session reports `Active` and re-reads what the job settled
   next pass, which is the shape cancellation already used for a reserved
   transition. A seal in flight counts as such work too: it runs outside the
   plan lock on one rail, and a second rail passing through that window would
   otherwise report a carrier that has gone over a bundle a moment from whole
   whose store files are already removed. `has_backlog` is true while either
   is out, so the driving loop waits its busy bound rather than its idle one.
   A disconnected pass still seals a bundle whose cursor has reached the end:
   sealing is this end's own work and needs no carrier. Nothing new is
   started on an abandoned plan: a completion that failed leaves its object
   in the window with `syncing` cleared and its coverage whole, so the settle
   choice refuses an abandoned plan rather than queue that object a second
   time and run its hook twice.

5. **An outstanding job suspends the stall budget, for a bounded while.**
   Completing an object moves bytes from covered to `placed_before` and is
   invisible to `progress`, so a window all of whose objects are syncing
   would charge the budget with nothing to show. The plan counts a job when
   it is queued and again when it retires, which `progress` folds in so a
   drain is movement; and a pass that finds a job outstanding counts itself,
   so a single sync slower than the whole budget is read as a slow disk
   rather than a stuck session. That last part is bounded: the plan carries
   a deadline, set afresh whenever a job is queued or retired, and past it
   the budget runs again and the driving loop gives the fetch up as stalled
   like any other that settles nothing. Half a minute, which is the stall
   budget's own patience and what the same sync had when it ran on the rail;
   two seconds in a test build, where the flusher is made to fail on purpose
   and every such test would otherwise wait the live grace out.
   The grace ends the loop, not the job: the join that follows waits for a
   wedged flush or hook to return, exactly as the rail waited for it inline
   before this decision, and that wait is deliberately not bounded, because
   a hook already told an object is complete has to be let finish saying
   so.

6. **Queued jobs are drained, never discarded.** Abandoning the plan does not
   throw the queue away: those objects are already durable and their hooks
   are owed, and dropping them would leave `syncing` raised with nothing to
   clear it. The flusher is ended by clearing the plan's sender, which closes
   the channel behind what is already queued. That clearing reaches through a
   poisoned plan lock as well as a sound one: a panic holding the plan
   poisons it, the flusher is joined while that panic unwinds, and a queue
   left open would leave its threads waiting on a sender nothing will drop.

7. **Backpressure stays where it was.** A syncing object is still counted by
   `in_flight`, so the window is the pipeline depth and a full drain is the
   worst case; per-object staging is per admitted object and must not go
   backwards. Cancellation still waits while any object is `syncing`, which
   now covers a job that is queued as well as one that is running, and
   reports the cursor the drain leaves.

8. **One flusher.** `COMPLETION_FLUSHERS` is one. Measured at 1, 4, 8 and
   16 against the same control, ten reps each interleaved, no width is
   separable from the control or from the others once the pool's write
   throttle stalls are set aside. One is the fewest that takes the fsync off
   the rails, and nothing measured asks for a second.

The stride flush is unchanged: it runs inside `CountingSink::write_at` on a
prover thread and stays there. The seal is unchanged. The proving pool is per
rail and dies with it, which is why it is the wrong home for this job.

## Consequences

- The rails keep their connections fed across a completion, and the fetch
  spends less CPU to move the same bytes: the 256-object sequence onto ZFS
  falls from about 12.4 to about 9.5 to 11.1 CPU-seconds for 4 GiB. It does
  not go faster. Measured on erebus, rails 8, ten reps interleaved with a
  `sync` and twelve seconds between them, 4 GiB in one object and 4 GiB as
  256 objects of 16 MiB onto ZFS and into tmpfs, byte-compared clean every
  rep: the sequence's steady-state median is 3.8 seconds before and 3.6 to
  4.0 after, inside the run-to-run spread either way, and the single object
  and both tmpfs rows are unchanged. The expectation this was built on, 3.6
  seconds toward the 2.6 of a build that skips the completion sync entirely,
  is not met: the sync itself is the cost, and moving it off the rail does
  not remove it. What the pool's wall clock is bounded by is its write
  throttle, which the deployment note (item D) is for. The table is in the
  commit that carries this decision.
- The completion hook of a transferred object now runs on the flusher rather
  than on a rail. The two kinds that are never transferred keep theirs where
  they were, inline in the rail's `advance`: a zero-length object, and one a
  previous fetch already made whole. Neither has a sink to sync or a job to
  queue, so there is nothing for the flusher to carry. Hooks were already
  any-order (ADR-0051), and votport's push receive keys its hook per object,
  so nothing that consumes them changes. A hook that blocks blocks the
  flusher, and the objects behind it queue.
- A fetch that fails while a job is outstanding still runs that job. A
  consumer told an object was complete is told so exactly once whether the
  fetch went on to succeed or not, which is what it was before.
- The bundle is whole a pass or more after the pass that took its last bytes.
  Any test that asserted completion on that same pass now drives until the
  flusher has retired the object.

## Rejected alternatives

- **Completing on the proving pool.** The pool belongs to a rail and dies
  with it; a job outliving its rail would be dropped mid-sync.
- **Discarding queued jobs when the plan is abandoned.** Leaves objects
  durable on disk with their hooks unrun and `syncing` raised, which
  cancellation then waits on forever.
- **Keeping the disconnect check ahead of the outstanding job.** Throws away
  a bundle that is whole on disk because the carrier that delivered it went
  first, which is the failure ADR-0050's acknowledgement exists to avoid.
- **Moving the stride flush too.** It already runs on a prover rather than a
  rail (ADR-0046's sink gate), so it costs one prover for the fsync and
  serializes nothing; a separate decision if that changes.

## Required verification

- A blocking completion hook: the rail's pass returns while the hook is
  inside, and the object is neither done, nor out of the window, nor past the
  cursor until the hook returns.
- A disconnect delivered on the pass that completes the last object still
  finishes the fetch.
- A failing flush surfaces the flush error itself from `fetch_striped`, not
  the carrier, both when the primary takes it and when a rail does.
- One rail and a completion eight times the stall budget it was driven
  under still completes, and a pass with no job outstanding, or with one
  whose grace has run out, is not movement.
- An abandoned plan runs the job queued behind the failure before
  `fetch_striped` answers.
- Cancelling during a job waits for it and reports the cursor after the
  drain.
- A completion queued after the flusher was joined abandons the plan rather
  than waiting on a job nobody holds.
- An abandoned plan queues no second job for the object whose completion
  failed.
- A disconnect delivered while another rail is inside the seal does not end
  the fetch, and the bundle still completes.
- A disconnected pass whose cursor is short of the end opens nothing.
- Dropping a fetch waits for the completion its flusher is running.
- Joining the flusher reports what a job parked, once.
- The existing completion, cancel, resume and window tests pass unchanged.
- Measured before and after on the same host and method, at flusher width 1
  and 4: a 4 GiB single object and a 256-object sequence, into tmpfs and onto
  ZFS, rails 8.
