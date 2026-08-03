# ADR-0024: The quiche backend owns its socket on a driver thread

Status: Accepted

## Context

VOT has one assembled QUIC backend, `vot-transport-msquic`, and the plan has
always called for a second one on quiche for explicit UDP I/O, pacing, offload,
and congestion-control experiments. PERF-001 then compares them on the same
workload and ADR-0012's isolation argument gets a second data point.

The two libraries are opposites in the one respect that decides this adapter's
shape. MsQuic owns worker threads, owns the socket, and hands the process
callbacks; the adapter's job is to translate them and keep the bounds. quiche is
sans-IO: it parses and generates packets, tracks congestion and loss, and tells
the caller when its timer expires, but it opens no socket, spawns no thread, and
sleeps for nothing. Everything MsQuic does for us is ours to do.

`TransportAdapter` is synchronous and never blocks. `poll` returns what has
already arrived and `flush` hands submissions to the carrier. That surface can
be satisfied two ways, and the difference is not a style preference.

**Pumped by the caller.** `flush` drains the queue into quiche and writes
datagrams; `poll` reads datagrams and feeds reassembly. No thread and no
synchronisation.

**A driver thread.** The thread owns the socket, the `quiche::Connection`, and
the timer, and exchanges commands and events with the adapter through the same
bounded queue every backend uses.

Pumped by the caller is less code, and it is wrong for this protocol. quiche's
`timeout()` is how loss detection, probe timeouts, and idle timeout happen at
all. Nothing fires it but a caller that keeps calling, so retransmission would be
paced by the driver's loop rate rather than by the connection's own timers. A
caller that stops polling for a hundred milliseconds because it is hashing a
range does not fall behind under that arrangement; it breaks the connection. VOT
verifies as it receives, so pauses like that are the normal case, not the
pathological one.

It also makes PERF-001 measure the wrong thing. MsQuic would be running its own
workers while quiche ran on the benchmark's loop, so the comparison would be
between one engine and the other engine plus our scheduling. The acceptance
criteria name `one_rail_one_worker_and_multi_worker_measured` and
`serialized_spine_hypothesis_tested`; neither is answerable if one side's
packet-processing thread is the measurement harness.

## Decision

The quiche backend owns its socket and its `quiche::Connection` on a driver
thread of its own, and exchanges `vot-transport-queue`'s commands and events with
the adapter. Both QUIC backends therefore have the same arrangement, and
PERF-001 compares two engines rather than two schedulings.

The thread's loop is: send what quiche has generated, wait on the socket with a
deadline of `conn.timeout()`, read what arrived, run `on_timeout` when the
deadline passed, then drain the adapter's queue into quiche. The wait is what
makes the timer real without a spin.

Four mappings follow, and each is a rule rather than a convention:

**The control stream is the first client-initiated bidirectional stream.**
`spec/wire.md` section 7 says so directly, which for QUIC means stream 0. The
server never opens it. Reliable lanes are the client-initiated bidirectional
streams above it, and a peer-initiated stream is reported under a peer lane
identifier exactly as the MsQuic backend reports one, so a session cannot
mistake a reply for a request.

**Reassembly is `vot-transport-framing`, with a budget of its own.** This
backend's inbound bytes do not share an account with anything else, so it takes
`StandaloneBudget` rather than the shared one MsQuic needs. The bound is the same
`MAX_CALLBACK_BYTES` reasoning: a burst of the largest frames either lane
carries, so the driver may be briefly behind without the connection failing.

**Receive credit is not applied per call.** quiche manages connection flow
control from `set_initial_max_data` and extends it as the application reads.
There is no absolute credit to set, so `set_receive_credit` reports
`Error::Unsupported` at the assembled transport, which is what the MsQuic
backend already reports, and the bound in force is the one `ReceiveLimits`
advertised at construction. An adapter that accepted the call and did nothing
would let an endpoint advertise a credit no carrier enforces, which is the
failure `ReceiveLimits::match_settings` exists to catch.

**Datagrams report only what was observed.** quiche carries DATAGRAM frames, so
this backend can send one where MsQuic's assembled transport refuses to. What it
cannot do is acknowledge one: there is no per-datagram signal, so the only states
it reports are `Queued` and `Sent`, and `Canceled` when the send is refused. It
never reports `Acknowledged`. Reporting an acknowledgement that was not observed
is worse than reporting less, for the same reason ADR-0013 gives for a backend
that cannot expose path state: the value is read to make a decision, and a
fabricated one makes it wrongly.

Test credentials are generated with `openssl` into a temporary directory once
per process, as the MsQuic live tests already do. No new dependency, and the
certificate never leaves the test.

## Consequences

The adapter is two pieces: a translation layer with no quiche in it, which the
mutation gate measures, and the pump, which the live tests drive over loopback.
The pump lives in its own file behind the `live` feature, and its matrix entry
carries that feature, because a mutant in a module the tests never compile is
reported missed whatever the tests say.

quiche builds BoringSSL through cmake, so a cold build costs minutes where the
rest of the workspace costs seconds. The mutation job pays it once per job rather
than once per mutant, because cargo-mutants reuses one target directory across
the mutants it tests.

A driver thread means the adapter and the carrier are on opposite sides of a
bounded queue, so a peer cannot make either grow without limit, and a slow
application is backpressure rather than a broken connection. It also means this
backend can report path statistics, unlike the TLS carrier, so Careful Resume
under ADR-0013 stays available on both QUIC backends.

Nothing here changes the wire. The frame bytes, the negotiation, and the session
are the same on both backends by construction, because both sit on the same queue
and the same reassembly.
