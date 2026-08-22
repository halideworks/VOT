# ADR-0043: Startup prefix datagram duplication

- Status: Accepted
- Date: 2026-08-22
- Decision owners: A00 architecture; A10 transport
- Applies to: the quiche pump's outbound path
  (`crates/vot-transport-quiche/src/live.rs`); no wire frame, spec
  section, or negotiation state changes

## Context

A fetch pays a serial prefix of about five round trips before its first
record: the TLS handshake (the server's first flight is amplification-shaped
to one datagram until the client's next packet arrives), one VOT negotiation
round trip with the announcement pushed alongside it (ADR-0041), the serial
manifest page round trips (`request_pages` issues one span and waits for
it), and the first `RANGE_REQUEST` with its proof. Every packet in the
prefix is small and serial, so a loss there costs a full recovery round
trip at best and a cold PTO at worst, and little else is in flight to keep
the loss detector's ack clock ticking; PR 355's ping cadence bounds the
detection delay but cannot remove the recovery round itself.

Measured on the netem rig (256 MB, 200 ms, 5% loss both ways, seeded
window): first byte runs 1.5-6.7 s against 1.03 s clean, and the walls
track first byte nearly one for one at this size; the certification sweep
put the medians at 1588 ms lossy against 1052 clean. The data phase's own
~1.8x under loss belongs to ADR-0042 and its named policy residuals. The
prefix is the part no coding reaches, because the FEC extension protects
only bulk range answers.

A probe answered the mechanism question. Duplicating every outbound
datagram at the socket while a connection's sent count was under 200, both
ends, removed the 2.3-3.5 s first-byte outliers at 5% entirely and left
the median near 1.5 s. Two facts follow. The first-byte tail is
retransmission timing on a serial flight, and duplication removes it. The
residual median is one recovery round entangled with the first data
flight, which engagement timing owns (the real-path forced-coded arm's
first bytes sit at 0.6-0.8 s on a lossy 100 ms path), so it is out of this
ADR's scope. The probe is not shippable as it stands: it duplicated below
quiche, so the server's copies were invisible to quiche's pre-validation
anti-amplification accounting, the three-times-received-byte rule that
spec/security.md section 7 requires.

The mechanics allow a small change. Every QUIC datagram either role sends
leaves through one function, `flush_burst` in
`crates/vot-transport-quiche/src/live.rs`, because the client and server
share the same pump loop (`run`). The only sends that bypass it are
stateless version negotiation and the non-QUIC side channel.

## Decision

While a connection is in its startup phase, the pump transmits every
outbound QUIC datagram twice.

1. **Duplication happens at `flush_burst`,** as a second transmission of
   the already-encrypted datagram. A QUIC receiver discards duplicate
   packet numbers natively, so the copy is pure loss insurance; nothing
   above the pump changes and no spec text moves.

2. **The phase is a datagram count, not a clock.** Duplication applies
   while the connection's total sent-datagram count is below a bound,
   default 200, which is the probe's measured shape, overridable as
   `VOT_PREFIX_DUP` with zero disabling it. The count spans the client's
   handshake and, on both roles, the negotiation, announcement, manifest
   pages, and the leading edge of the first data flight. The cost ceiling is ~200 extra
   datagrams of at most 1200 bytes, ~240 KB per connection, paid once.

3. **The server duplicates only after the handshake is established.**
   Before address validation completes the server sends exactly what
   quiche accounts, so the three-times rule stands untouched; from
   `is_established` onward the limit no longer applies and the copies are
   legal. The client duplicates from its first flight, where no
   amplification rule exists.

The target, which the netem rig holds this to: at 5% loss the first-byte
tail collapses to the clean shape, p99 first byte within 2x of clean and
no run above 3 s, with the p50 explicitly out of scope as the entangled
recovery round named above. Clean-path walls stay within noise.

## Consequences

- Every connection, clean paths included, pays the ~240 KB once. It is
  invisible next to a seeded window and buys the tail on paths whose loss
  is not yet measurable, which is exactly when the prefix runs.
- The server's own handshake flight remains unprotected, because the
  amplification shape is the point of that rule. The client's copies
  protect the client half of the handshake; the server's copies protect
  the negotiation reply, announcement, and manifest pages. If part of the
  probe's tail win was server handshake loss, the legal shape gives some
  of it back; the verification list settles that empirically rather than
  by assertion.
- On the GSO path (`send_segmented`) the copy is a second flush of the
  same burst, so segmentation offload is retained for both transmissions.
- The knob is a calibration point, not a config surface: one integer with
  a measured default, in the same style as `VOT_INITIAL_CWND`.

## Rejected alternatives

- **0-RTT frame sequencing on session resumption:** PR 344 already gives
  ticket resumption and it measured wall-neutral, because the resumed
  handshake pays the same round trips; this build deliberately sends no
  early data (spec/wire.md section 4's replay rules). Shortening the
  prefix cuts both arms and barely moves the lossy ratio, which is the
  number this ADR exists to move.
- **Manifest page in the announcement:** saves one round trip on both
  arms, ratio near unchanged, and collides with spec/security.md
  section 7's ban on pre-authentication manifest pages, so it prices an
  authentication redesign against a ratio-neutral round trip.
- **Eager rail connection:** measured 31% worse (branch `rail-overlap`).
- **Deeper request pipeline:** re-tested after the window-seed fix, still
  worse.
- **Duplicating bulk data:** rejected in ADR-0042 and stays rejected; this
  ADR's scope is the counted startup prefix only.

## Required verification

- The multi-second first-byte outliers at 5% loss are gone: nine runs an
  arm minimum, 256 MB at 200 ms, p99 first byte within 2x of clean and no
  run above 3 s.
- Clean cells unchanged: 16 MB seeded and 256 MB walls within noise of
  main, both arms.
- Amplification conformance: a wire test holds the server's
  pre-establishment sent-byte count identical with the feature on and off.
- `VOT_PREFIX_DUP=0` reproduces main's send behavior exactly, held by the
  same test.

## Measured outcome (2026-08-22)

Merged as PR 359. Measured on the netem rig at 200 ms with MTU 1500,
seeded 7100 both ends, one binary and two arms by environment: the
default 200-datagram budget against `VOT_PREFIX_DUP=0`, which is the
prior behavior exactly, reps interleaved.

At 256 MB and 5% loss both ways, n=12 an arm, the duplicated arm's first
byte ran a median of 1498 ms with a p90 of 1675 and a maximum of 1681,
against 1688, 2942 and 7825 without. The tail is the finding: the
undulicated arm reaches a 7.8 s first byte and a 14.3 s wall, where the
duplicated arm's worst first byte in twelve runs is 1681 ms and its
worst wall 5.15 s. Wall medians were 3.63 s against 4.00 s. Against this
ADR's target, p99 first byte within 2x of clean (1040 ms) and no run
above 3 s: met, with the whole duplicated distribution inside 1.7 s.

At 16 MB and 5% loss, n=9 an arm, the same shape at the size where the
prefix is most of the wall: wall median 2.23 s against 2.67, first byte
median 1515 ms against 1794 and p90 1805 against 2615.

Clean cells cost nothing measurable, n=5 an arm: 256 MB at 2.21 s and
16 MB at 1.33 s in both arms, first byte 1040 ms against 1044 and 1038
against 1043. All 62 runs completed with the full byte count and zero
abandoned, refused, or dropped symbols.

The empirical risk this ADR named is answered: the amplification-legal
shape, which leaves the server's own handshake flight unprotected, keeps
the probe's tail win in full. What it does not answer is the residual
median, ~1.5 s against 1.03 clean, which this ADR placed out of scope
and attributed to a recovery round entangled with the first data flight;
that remains with engagement timing.

One observation for the loss policy rather than the transport: the arms
offer different coded counts (1280 against 896 in the first lossy pair)
because a faster prefix changes when the policy's first sample closes.
