# macOS loopback defaults and interrupted reads

Direct macOS loopback fetch and push now default to one QUIC connection.
Explicit `VOT_FETCH_RAILS` choices still apply. IPv4, IPv6, and mapped IPv4
loopback addresses use the same policy. Other platforms, non-loopback
destinations, and rendezvous retain their existing defaults. Push uses the
same selection helper; the throughput measurements below are fetches.

Interrupted socket reads now retry in the QUIC pump, listener, relay,
rendezvous service, and resolution waits. Resolution preserves its elapsed
budget rather than consuming an entire retry on an interrupt. The single-socket
accept path also spends one total timeout across stray packets and interrupted
reads. Previously each stray could restart the timeout.

## Loopback measurements

All transfer measurements used `127.0.0.1` on the Mac Studio (M3 Ultra,
32 cores, 256 GB RAM, macOS 26.6.2, APFS). Rust 1.97.1 release builds,
default BBR2, `VOT_DATAGRAM_FEC=off`, and one zero-filled 2 GiB file named
`media`. Package root:
`355704d9f4d00326c3b32d6b83035e997489ddb7ef2a50df37d4a16ec9f992a6`.
All 38 transfers, 76 GiB total, verified the root and byte count.

Each run started a fresh server, waited 500 ms, and fetched into a new
destination. Variants alternated order between repetitions. The server was
terminated and reaped after each fetch, and the destination was removed.
Reported time comes from `VOT_FETCH_STATS=1`; CPU is the sum of both child
processes' user and system times from Python `resource.getrusage`, including
startup and shutdown. Source generation is excluded. Sources were cached;
this does not measure cold storage, SMB, or a physical network.

Three paired runs of the final binaries with the default datagram ceiling
and no rail override:

| Measure | Before | After |
| --- | ---: | ---: |
| Median transfer | 12.837 s | 2.228 s |
| Range | 5.461-18.907 s | 2.204-2.285 s |
| Median payload goodput | 1.34 Gbit/s | 7.71 Gbit/s |
| Median total CPU | 78.511 s | 5.172 s |

The baseline is variable. These samples show a 5.76x median improvement on
this host, not a promised multiplier on other systems or workloads.

Before changing the default, three paired runs used the same baseline
binary with explicit rail settings:

| Datagram ceiling | Eight rails median | One rail median |
| --- | ---: | ---: |
| 1,472 bytes | 17.468 s | 5.658 s |
| 65,507 bytes, PMTU discovery | 6.609 s | 2.248 s |

At 1,472 bytes, median total CPU fell from 103.462 s to 13.762 s. With
discovery, it fell from 42.251 s to 5.160 s. The kernel-heavy CPU cost and
improvement with fewer connections indicate contention in this Mac's
loopback path; these measurements do not identify a particular kernel lock.

## Rejected send batching

A bounded `sendmsg_x` prototype was tested for IPv4/IPv6, shared sockets,
partial message counts, missing APIs, and connected-socket rejection.
Five paired runs per datagram ceiling gave:

| Datagram ceiling | Baseline median | Batch-send median |
| --- | ---: | ---: |
| 1,472 bytes | 17.441 s | 17.466 s |
| 65,507 bytes, PMTU discovery | 7.358 s | 13.783 s |

The small-packet case was flat and the discovery case remained erratic.
The prototype was removed. The added private API and error handling were
not justified by these results. Apple's implementation also has distinct
connected/unconnected behavior and partial-error rules; see
[XNU sendmsg_x](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_syscalls.c).

Raw data for all experiments: [CSV](macos-loopback-2026-09-08.csv).

## Validation

- Full Linux workspace tests passed with four test threads (1,521 passed,
  12 ignored before the final CLI-only additions); the final CLI suite passed
  353 tests with one opt-in mounted-share test ignored.
- Native Mac platform, QUIC, and CLI tests passed: 467 tests, two ignored.
- Linux workspace and native Mac affected-package all-target clippy passed
  with warnings denied. Formatting and diff checks passed.
- The stray-packet test failed after restoring the original timeout behavior
  and passed after restoring the fix.
- An initial unrestricted-parallel Linux suite run failed one existing relay
  test. That test passed alone, and the four-thread full suite passed. No fix
  for that intermittent test failure is claimed.

Baseline executable SHA-256:
`0d3fb55e0f88419a786918aba42927fc5d0f04ece736e499ccdfeb2d8449e5e8`.
Rejected batch executable SHA-256:
`3aac3639a65a2ed9e6ccc09a2a4371f422d32396d6898ff3a6ff75b598c3fc98`.

Final executable SHA-256:
`ba84884f477afcc1f9ec139a01f854c870fa053dd393fc655f145e92202d8781`.
