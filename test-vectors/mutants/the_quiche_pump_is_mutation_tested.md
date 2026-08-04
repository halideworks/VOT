# The quiche pump is mutation tested

Criterion: the assembled quiche transport, the default backend as of ADR-0027,
is measured by the same standard as every other crate, and what is not covered
is written down rather than left out of the run.

`.cargo/mutants.toml` excludes the pump file outright because the default
configuration cannot compile it; its own comment said a live mutation run
belongs beside the msquic one, and until the `quiche-mutation` job nothing ran
one. The first sweep found 223 mutants with 57 surviving; unit tests for the
inbound budget, the assembly budget, the connection-id derivation, the
coalesced-read fallback, the shared adapter surface, and a flow-control split
write killed 25 of them, and the 32 that remain are classified below.

Passing evidence: `.cargo/mutants-live.toml` is the configuration without the
exclusion, and the `quiche-mutation` job runs it with the feature on, diff-only
on pull requests and in full on main, the same shape as `msquic-mutation`.
`tools/check_live_mutants.py` reads the table below on every run via its
`--evidence` argument, fails on any survivor not in it, and says so when a row
no longer survives.

A row names the mutant as `cargo-mutants` prints it, without the file position,
so one row covers a mutant that exists in a compiled and an uncompiled twin of
the same function. The reasons fall into five classes:

- **not compiled here**: the non-Linux twin of a `cfg`-gated function. The
  mutated code never builds in this job, so the suite cannot see it. The
  non-Linux read and send fallbacks run nowhere in CI today; that gap is
  recorded here rather than hidden by a name-based exclusion.
- **optional by design**: receive and send offload are cost savings and never
  requirements. Disabling them, claiming them absent, or taking the per-packet
  fallback produces a correct, slower transfer that only a throughput
  measurement distinguishes.
- **burst geometry**: how packets share a burst decides syscall count and
  pacing, not bytes delivered. The loopback suite asserts delivery, so a flip
  that reshapes bursts without corrupting them survives; the bench numbers in
  `bench/results/perf-001-quic-bakeoff.md` are what measure this.
- **needs fault injection**: only a socket that fails with a specific error
  kind can reach the flipped branch, and the suite has no way to make the
  kernel do that on loopback.
- **equivalent behavior**: the mutation changes the path taken, not the
  outcome, within what any test can observe. The completion check in
  `write_outbox` sat here wrongly until review showed a split write hangs the
  stream under it; a small-window sans-IO pair now kills it, which is the
  fate a row in this table should hope for.

| mutant | class | reason |
| --- | --- | --- |
| `replace receive_segmented -> std::io::Result<(usize, SocketAddr, Option<usize>)> with Ok((0, Default::default(), None))` | not compiled here | non-Linux `recv_from` twin |
| `replace receive_segmented -> std::io::Result<(usize, SocketAddr, Option<usize>)> with Ok((0, Default::default(), Some(0)))` | not compiled here | non-Linux `recv_from` twin |
| `replace receive_segmented -> std::io::Result<(usize, SocketAddr, Option<usize>)> with Ok((0, Default::default(), Some(1)))` | not compiled here | non-Linux `recv_from` twin |
| `replace receive_segmented -> std::io::Result<(usize, SocketAddr, Option<usize>)> with Ok((1, Default::default(), None))` | not compiled here | non-Linux `recv_from` twin |
| `replace receive_segmented -> std::io::Result<(usize, SocketAddr, Option<usize>)> with Ok((1, Default::default(), Some(0)))` | not compiled here | non-Linux `recv_from` twin |
| `replace receive_segmented -> std::io::Result<(usize, SocketAddr, Option<usize>)> with Ok((1, Default::default(), Some(1)))` | not compiled here | non-Linux `recv_from` twin |
| `replace receive_space -> Vec<u8> with vec![]` | not compiled here | the empty vec is the non-Linux body; the Linux twin's control-message space is asserted by every coalesced read |
| `replace receive_space -> Vec<u8> with vec![0]` | not compiled here | non-Linux twin |
| `replace receive_space -> Vec<u8> with vec![1]` | not compiled here | non-Linux twin |
| `replace send_segmented -> Result<(), Error> with Ok(())` | not compiled here | one row for two twins: the non-Linux stub never compiles, and the Linux body's mutant hangs the suite, which the timeout records as this same name |
| `replace enable_receive_offload with ()` | optional by design | a kernel without coalescing leaves each datagram its own read, and the feed path handles both shapes |
| `replace offload_available -> bool with true` | optional by design | claiming offload where the probe would refuse it falls back per burst |
| `replace offload_available -> bool with false` | optional by design | denying offload takes the per-packet fallback, correct and slower |
| `replace drain_arrivals -> Result<(), Error> with Ok(())` | optional by design | without the drain every pass reads once, the lockstep shape the drain exists to amortise; delivery holds and only throughput falls |
| `replace > with == in flush_burst` | optional by design | routes single-packet bursts through the offload or per-packet path; both carry the burst |
| `replace > with < in flush_burst` | optional by design | as above |
| `replace > with >= in flush_burst` | optional by design | as above |
| `replace && with \|\| in flush_burst` | optional by design | attempts the offload where it was not asked for; the fallback carries the burst, and the slower shape hangs a loaded run, which the timeout records |
| `replace != with == in send_all` | burst geometry | destination comparison; every test speaks to one peer, so no burst ever splits by address |
| `replace + with - in send_all` | burst geometry | the moved-packet arithmetic behind the destination split, unreachable with one peer |
| `replace + with * in send_all` | burst geometry | as above |
| `replace > with == in send_all` | burst geometry | the pacing deadline comparison; ignoring the pacer reshapes bursts without corrupting them |
| `replace > with < in send_all` | burst geometry | as above |
| `replace > with >= in send_all` | burst geometry | as above |
| `replace < with == in send_all` | burst geometry | the short-packet burst close; a misdrawn boundary costs flushes, not bytes |
| `replace < with > in send_all` | burst geometry | as above |
| `replace < with <= in send_all` | burst geometry | as above |
| `replace == with != in send_all` | burst geometry | the reopened-burst check; the flip re-runs or ends bursts early, and the slower shape hangs a loaded run, which the timeout records |
| `replace match guard error.kind() == std::io::ErrorKind::WouldBlock \|\| error.kind() == std::io::ErrorKind::TimedOut with true in drive` | needs fault injection | treats a fatal socket error as an idle timeout; loopback never produces one |
| `replace == with != in drive` | needs fault injection | swaps which timeout kind matches; this platform reports the other kind, so the guard holds either way |
| `replace drain_datagrams with ()` | equivalent behavior | received datagrams are dropped by design because the API has no inbound datagram event; not draining them stalls only datagram credit, which nothing here extends |
