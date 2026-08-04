# ADR-0026: MsQuic is the default backend, and quiche stays

Status: Accepted

Closes PERF-001's `selected_default_backend_ADR`. The evidence is
`bench/results/perf-001-quic-bakeoff.md`; this ADR states the choice and what
was weighed, and does not restate the tables.

## Context

Both backends carry the same transfer loop, framing, and inline verification
behind one `Carrier` seam (ruling 1), so the bakeoff's differences are carrier
differences. Three results decide, one robustness fact qualifies, and one axis
is deliberately not speed.

1. **Wire, matched packets: MsQuic leads 6.4x.** On the one real path measured
   (tr-desktop to erebus at ~1250-byte packets), MsQuic carried 2480 Mbit/s
   against quiche's 387, and the quiche sender was CPU-bound on per-packet
   work. Loopback with jumbo datagrams narrows this to 1.4x, but no deployed
   path grants jumbo datagrams.
2. **The spine verdict is per-carrier.** The serialized-spine hypothesis holds
   for quiche and not for MsQuic: at W=4, quiche's provisioned rails beat its
   shared connection 1.66-1.75x (each quiche connection is one CPU-bound pump
   thread, so rails are pumps), while MsQuic's two arms are equal inside
   spread and its single connection is not its ceiling. A default that scales
   without asking the caller to provision connections favors MsQuic.
3. **Multi-worker on one connection scales neither backend.** Both lose
   throughput from W=1 to W=2 on the ranged path at this scale; parallelism
   is not a reason to prefer either today.
4. **quiche blackholes on paths narrower than its configured datagram.** It
   does no path-MTU discovery: the handshake completes at 1200 bytes, then
   data packets vanish and only the driver's round budget turns the hang into
   an error. MsQuic probes and settles unaided. The datagram lever that wins
   quiche its loopback throughput is, unset, the thing that hangs it.

Against MsQuic: ADR-0012 isolates it because it is a C FFI dependency, pinned
to a git revision, building a bundled C library the binary needs at run time,
and requiring unsafe code at the boundary. quiche is sans-IO Rust with no
unsafe in its adapter, and ADR-0024 chose it precisely for explicit control of
I/O, pacing, and congestion; the bakeoff's own datagram finding is evidence
that control matters.

## Decision

MsQuic is the default backend. Fastest on the only wire path measured, robust
to narrow paths without configuration, and not the party whose scaling needs
provisioned rails.

quiche stays, as the second backend ADR-0024 wanted and as the control
surface: it is the backend where packetization is ours to set, the natural
host for PERF-002's offload work, and the sans-IO fallback for any deployment
that cannot carry a bundled C library.

Neither backend's multi-worker path is a default: workers above one cost
throughput on one connection at this scale, and provisioned rails are a
measured configuration, not a recommendation.

## Consequences

- Anything selecting a backend by default selects MsQuic and inherits
  ADR-0012's isolation rules; quiche remains a supported explicit choice.
- The spine result is loopback-scoped. Role mode carries one worker, so a
  two-machine spine run needs a ranged role mode first; if one is built and
  contradicts the loopback verdict, this ADR is the one to amend.
- PERF-002 owns closing quiche's per-packet CPU cost (segmentation offload);
  a result there that closes the wire gap reopens the default question with
  numbers rather than by fiat.
