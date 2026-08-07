# ADR-0031: rails carry the fetch past one thread

Status: Accepted

## Context

ADR-0030 settled the fetch as sequential per-object with pipelined
ranges over one rail, and that shape is now measured to its ceiling. On
the erebus to tr-desktop link (path MTU 8972, 9.45 Gbit/s TCP ceiling)
the single-rail fetch verifies and writes 512 MiB in 1.04 s, 4.13
Gbit/s, with the fetch session thread busy 793 ms of the wall on frame
decode, bundle reassembly, staging, and admission while provers carry
verification and placement beside it. One thread's receive path is
worth about 5.3 Gbit/s and nothing else on the wire is close to binding:
the serve side idles 83%, losses are zero, and the transport alone
carries 9.4 single-lane on loopback (docs/perf-engineering.md,
2026-08-06). The tool intends to scale to 40 and 100 Gbit/s links, so
the receive path itself has to parallelise. The bench already proved
the shape that works: share-nothing rails, one connection each, took
the ranged role mode from 5.2 to 9.21 Gbit/s at W=6 (PERF-002,
accepted), where lanes multiplexed on one connection did not scale at
all (ADR-0026's spine matrix). The registry reserved
`PUBLIC_MULTI_RAIL` for this from the start.

## Decision

**A fetch runs W rails: W connections, each a full session against the
same server, striping range requests over one shared plan into one
shared sink.** Amends ADR-0030's "one rail" ruling; everything else it
settled stands.

- **A rail is a whole session.** Each rail dials its own connection,
  negotiates, reads the descriptor and seal, and requests ranges. No
  new frames and no rail-group handshake: the server cannot tell a rail
  from a lone fetch, so a v1 server serves a v2 client's rails and the
  reverse. The cost is one manifest transfer per rail, bounded and
  small against the objects; a rail-group extension can remove it later
  without moving this decision.
- **The plan is the striping point.** One `FetchPlan` behind a lock
  hands out range requests; rails take the next range when their
  pipeline has room, which is work stealing by construction: a slow
  rail simply takes fewer ranges. Nothing is pre-partitioned, so rail
  skew cannot strand a tail (the lesson of PR 88's rotating handout).
- **Placement is already concurrent.** Rails verify on their own
  provers and place through the one shared sink: `RangeSink` is
  `Send + Sync` with positional `&self` writes, which is what ADR-0029
  built `WrittenRange` for. Admission stays per-rail in each rail's
  receiver; the object completes when the shared plan has every range
  placed and the manifest-validated digests hold.
- **The server serves sessions concurrently, one thread each.**
  `BundleServer::service` is `&self` over read-only state, so the
  accept loop moves to a thread per accepted session with a bound on
  how many run at once. The per-session engine, budget, and failure
  policy (a session's failure ends the session, PR 111) do not change.
  The carrier is one socket, one session, so this concurrency is real
  only where every session gets its own port: on a fixed port the next
  bind waits for the session holding it (PR 118), which serializes
  exactly the rails this ADR wants together. Step 3 therefore includes
  a demultiplexing listener: one socket on the served address, routing
  datagrams to per-session pumps by connection ID. A carrier change,
  not an engine one, and the engines cannot tell.
- **Width is chosen at the fetch, bounded by the machine.** Default
  `min(4, available cores)` rails, `VOT_FETCH_RAILS` to override, 1
  restoring today's shape exactly. The server bounds concurrent
  sessions with the same kind of number and refuses the excess by not
  accepting it, which backpressures rather than fails.
- **Memory scales with W and is bounded.** Each rail carries the
  existing per-session budgets (staging, pending, orphan, deferred);
  the whole fetch is W times one rail's bound plus the sink, which the
  extent map bounds (ADR-0029). W stays a small number; this is not a
  fan-out to hundreds.

## Consequences

- The fetch ceiling becomes W times one thread's receive path against
  the link, which is what the bench measured at 9.21 of 9.45 on this
  rig at W=6.
- The serve process grows threads; its memory is bounded by the
  session budget times the session bound.
- `vot fetch` and `vot pull` behavior, output, and receipts are
  unchanged; a single-rail fetch remains byte-identical in effect.
- The wire sees W connections where it saw one; anyone shaping per
  connection sees a fetch as W flows. The seamless goal accepts this:
  it is how the numbers are reached.

## Sequence

1. Serve accepts sessions concurrently (thread per session, bounded),
   with the sim test driving two sessions at once.
2. The fetch engine splits its plan from its session so a plan can be
   shared: `FetchPlan` behind a lock, request handout as a method, one
   rail using it exactly as today. No behavior change, gate stays
   zero-missed.
3. Rails: W sessions over the shared plan and sink, provers per rail
   or pooled, `VOT_FETCH_RAILS`, sim test at W=2 with interleaved
   pumps. The serve side grows the demultiplexing listener here, so W
   rails reach one fixed address.
4. Wire runs on the rig at W=1,2,4,6 against the bench's 9.21, logged
   in the perf log; the acceptance target is parity with the bench at
   the same W within its spread.
