# Windows UDP segmentation and ext4 contention

## Native Windows transmit offload

VOT now sends Windows QUIC bursts through `WSASendMsg` with per-message
`UDP_SEND_MSG_SIZE`. Each burst carries its own segmentation size, so
connections sharing a listener socket cannot change each other's packet
boundaries. A refused offload falls back to the existing individual sends.
The receive path is unchanged; Windows receive coalescing is not enabled.
The API semantics are documented by Microsoft for
[WSASendMsg](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg)
and [UDP options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options).

Five alternating baseline/changed pairs transferred the same 2 GiB BLAKE3
bundle from native Windows on tr-desktop to the Linux host over the existing
10 GbE LAN. The Windows source was on local storage; the Linux destination
was on the NVMe ZFS pool, not SMB. Both endpoints used Rust 1.97.1 release
builds, eight rails, `VOT_DATAGRAM_FEC=off`, and the existing congestion-control
defaults. The baseline was the completed changes in `9fef1ee`; only the Windows
sender gained offload. The Linux receiver binary stayed identical.

Windows binary SHA-256 values:

- Before: `7dc78b43dc9c1043e341892cf67efa09e6a2681e420781ab3b6edd6b19ff8382`.
- After: `905b37845d594b923eba950f93bb94bfd0d187771e30405487fe3ca40589244e`.

| Measure | Before median | After median |
| --- | ---: | ---: |
| Verified transfer time | 6.662 s | 1.974 s |
| Payload goodput | 2.58 Gbit/s | 8.70 Gbit/s |
| Windows server CPU time | 29.656 s | 7.797 s |

This is 3.37 times the goodput, 70.4% less transfer time, and 73.7% less server
CPU time on this setup. Every changed run (1.960-1.991 s) beat every baseline
run (5.346-7.103 s). All ten runs verified 2,147,483,648 bytes and package root
`355704d9f4d00326c3b32d6b83035e997489ddb7ef2a50df37d4a16ec9f992a6`.
[Individual samples](windows-udp-2026-09-08.csv) include first-byte times.

The dataset was one zero-filled file, reused from cache, with a fresh destination
for each run. VOT did not compress the wire payload; ZFS may compress stored
data. Transfer time comes from `VOT_FETCH_STATS=1`; CPU time is the Windows
server process's accumulated CPU after fetch completion. These are native LAN
results, not WAN, receive-offload, or power-loss results. No NIC, firewall,
live share, or system networking configuration was changed for this comparison.

## Buffered ext4 writes

The retained `measure_file_contention` example tests two alternatives to
concurrent buffered writes: a userspace mutex and native preallocation using
`fallocate`. Each run writes 512 MiB in interleaved 64 KiB ranges, flushes the
file, then checks every byte outside the timer. Preallocation time is included.
Each row contains five alternating pairs on this Linux host's ext4 `/tmp`.

| Workers | Concurrent / mutex total ms | Concurrent / preallocated total ms |
| --- | ---: | ---: |
| 1 | 669.471 / 659.204 | 624.126 / 613.065 |
| 4 | 728.145 / 692.116 | 661.410 / 643.927 |
| 8 | 723.216 / 718.815 | 666.191 / 645.107 |

The two campaigns ran separately; compare arms within a column. Mutex timings
overlapped, especially at eight workers. Preallocation reduced the eight-worker
write phase from 179.649 to 157.341 ms, but total time including flush fell only
3.2%. All 60 runs passed their byte checks. The
[samples](ext4-contention-2026-09-08.csv) retain both write-only and total times.

Neither alternative changes the production file sink in this patch. The mutex
did not establish a useful general gain, and preallocation needs an end-to-end
comparison on fast ext4 storage plus a policy for very large, partial, or
resumed transfers before reserving entire objects by default.

```sh
cargo +1.97.1 run --release -p vot-cli --example measure_file_contention -- /PRIVATE/EXT4/TEST/DIR 8 concurrent
cargo +1.97.1 run --release -p vot-cli --example measure_file_contention -- /PRIVATE/EXT4/TEST/DIR 8 serialized
cargo +1.97.1 run --release -p vot-cli --example measure_file_contention -- /PRIVATE/EXT4/TEST/DIR 8 preallocated
```

## Portability

Windows checks cover IPv4/IPv6, concurrent sends with different segment sizes
on one socket, a short final datagram, subsequent ordinary sends, invalid
inputs, and forced fallback after a segmentation refusal. Actual unsupported
older Windows versions have not been exercised.

The Mac Studio live suite exposed an existing test assumption that loopback
could carry a 64 KiB IP packet. Its 16 KiB MTU correctly limited discovery to
16,356-byte UDP payloads. The test now uses that platform's ceiling, while
Linux and Windows continue testing the larger ceiling. Production PMTU logic
was already correct and is unchanged.

Validation passed the Linux workspace with live QUIC enabled (1,518 tests),
the Windows platform and live QUIC suites (5 and 108 tests), and the Mac Studio
platform and live QUIC suites (4 and 107 tests). Deny-warnings clippy passed
on all three hosts.
