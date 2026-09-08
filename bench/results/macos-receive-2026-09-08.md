# macOS receive path

macOS now uses the existing `nix::recvmsg` wrapper with per-call
`MSG_DONTWAIT` during a receive drain. This removes the two socket-wide
blocking-mode changes per drain. The ordinary receive still uses the
socket's read timeout. No new dependency version or unsafe code was added.

The shared address conversion also preserves IPv6 scope and flow information.
The previous Linux conversion discarded both. Tests cover a scoped IPv6
address, an empty nonblocking receive, and a subsequent blocking receive
on IPv4 and IPv6. The Linux and native Mac QUIC suites passed (108 tests
before the additional address regression); both final receive regressions
and deny-warning all-target QUIC clippy checks passed on both hosts.

## Measurement

Host: Mac Studio, M3 Ultra, 32 cores, 256 GB RAM, macOS 26.6.2, APFS.
Rust 1.97.1 release builds. Five alternating before/after pairs fetched
the same 2 GiB BLAKE3 bundle over IPv4 loopback with eight rails and
`VOT_DATAGRAM_FEC=off`. The baseline server stayed running throughout;
only the client executable changed. Each fetch used a new destination,
verified the expected root and byte count, and removed the destination.
Both endpoints shared the Mac's resources. No hardware or OS settings changed.

The source was one zero-filled file named `media`, with package root
`355704d9f4d00326c3b32d6b83035e997489ddb7ef2a50df37d4a16ec9f992a6`.
Generation was outside the timed section; results use `VOT_FETCH_STATS=1`.
All 20 GiB verified. The source was cached and this does not measure cold
storage or SMB.

| Transfer time | Before | After |
| --- | ---: | ---: |
| Median | 8.311 s | 4.276 s |
| Minimum | 3.538 s | 3.472 s |
| Maximum | 12.685 s | 13.778 s |

The large spread and mixed paired results do not establish a reliable
throughput improvement. The change removes two mode-setting syscalls per
drain; it is not evidence of a particular end-to-end speedup.
Raw samples: [CSV](macos-receive-2026-09-08.csv).

Executable SHA-256:

- Before: `3bbbcd2b0d37c448212d298a889b04eefe50a616ec5caf1b8065c34eb57c950d`.
- After: `0d3fb55e0f88419a786918aba42927fc5d0f04ece736e499ccdfeb2d8449e5e8`.

## Remaining Mac work

The active `en0` Ethernet interface negotiated `1000baseT`, MTU 1500.
`ifconfig -m en0` lists support through `10Gbase-T`. Check the switch port
and cable before expecting multi-gigabit LAN transfers. The link's raw
ceiling is currently 125 MB/s, before protocol overhead.

Packet batching remains a candidate for a separate controlled measurement.
[Quinn's implementation](https://github.com/quinn-rs/quinn/blob/main/quinn-udp/src/unix.rs)
keeps Apple's private fast APIs optional and checks availability. VOT would
also need to handle partial batch sends without retransmitting the already
sent prefix. This change does not enable those APIs.

Mac SMB destinations still need native mounted-share tests for cancellation,
resume, publication conflicts, and the supported durability profiles.
Local APFS results do not qualify SMB behavior.
