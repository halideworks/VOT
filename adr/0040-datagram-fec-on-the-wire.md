# ADR-0040: datagram FEC on the wire

Status: Accepted

## Context

ADR-0039 fixed the erasure code and `vot-fec` implements it. Nothing yet says
how a symbol travels, how a receiver knows which object bytes a generation
covers, what the five registered `DATAGRAM_FEC` frames carry, or what the
credit that `spec/architecture.md` section 3 requires actually caps.

The constraints already written down: datagram mode begins with zero credit; a
monotonic `credit_epoch` supersedes older credit and places absolute caps on
unretired bytes, active generations, and decode work; wall-clock expiry is
not a correctness mechanism; sequences and epochs are scoped fields of their
owning payload (`spec/wire.md` section 4); every parser bounds before it
allocates; the frames are invalid unless `DATAGRAM_FEC` is negotiated. The
default quiche datagram carries about 1350 bytes; the integrity group is
64 KiB.

## Decision

**A coding epoch is a sender-owned, reliably announced binding of one geometry
to one contiguous byte range of one object. Generations under it are
sequential and implicit. Symbols travel as unreliable datagrams with a
nine-byte fixed header. The receiver owns credit and per-generation outcome;
the sender owns open and close. Everything is in `spec/fec.md` sections 9
through 12.**

- `CODING_EPOCH_OPEN` (sender to receiver, reliable) names the epoch, the
  object, a byte offset and length, and `(k, r, L)`. Generation `g` covers
  bytes `[offset + g*k*L, ...)`; only the last generation may be short and its
  short symbols are zero-padded to `L`. Nothing else announces a generation.
- A symbol datagram is `epoch: u32 | generation: u32 | esi: u8 | L bytes`.
  Total length must be exactly `9 + L` for the epoch's `L`.
- `GEN_STATE` (receiver to sender, reliable, advisory) reports for one
  generation how many distinct symbols have arrived and which source ESIs
  are still missing, under a per-generation sequence; a stale sequence is
  ignored. `GEN_DONE` (receiver to sender) is terminal for the generation:
  `decoded` or `abandoned`. `CODING_EPOCH_CLOSE` (sender to receiver) is
  terminal for the epoch and retires every generation under it that has not
  already reported.
- `DATAGRAM_CREDIT` (receiver to sender) carries a `credit_epoch` and four
  caps: unretired bytes, active generations, open epochs, and decode work.
  A newer epoch replaces older credit whole and may shrink. Before the first
  credit frame every cap is zero, so no epoch may be opened and no symbol
  may be sent. The first three are levels both ends count from what they
  exchanged; decode work is a budget only the receiver counts, spent in
  symbol bytes handed to elimination, and when it is spent the receiver
  abandons generations that need elimination until a newer credit epoch.
- Retirement is event-driven: a generation's bytes retire on its `GEN_DONE`
  or on `CODING_EPOCH_CLOSE`, and a closed epoch is forgotten entirely;
  because identifiers are never reused, anything that later names it is
  simply unknown. Active generations are those opened by an arriving symbol
  and not yet retired. Source symbols of a short last generation that lie
  entirely past the range are all zero, never sent, and count as received.
- The profile this project ships is `k = 64, L = 1024`: one generation is
  exactly one 64 KiB integrity group, its datagram is 1033 bytes, and the
  bytes a generation yields verify by the same range proof machinery as a
  reliable `DATA_RECORD` for that group. Proofs still travel reliably.
- What a receiver drops and what it treats as misbehaviour is a table in
  `spec/fec.md` section 12. Datagrams overtake the control stream, the two
  reliable directions are independent, and credit can shrink in flight, so
  a symbol or frame for state the receiver no longer holds, or past credit
  it no longer extends, is normal operation: dropped or ignored, never a
  session error. Session errors are reserved for what only a broken sender
  produces: a payload outside its constraints (`MALFORMED_FRAME`) and one
  epoch identifier opened twice with different content
  (`CODING_EPOCH_CONFLICT`, new, `0x0703`).
- No timer anywhere in the lifecycle. A receiver that wants a generation's
  missing bytes asks for them on the reliable path exactly as it would have
  without FEC; abandonment is a decision it reports, not a timeout.

Frame payloads are CBOR maps with integer keys in the style every existing
payload uses. The datagram header is fixed-width because a symbol is parsed
on the receive path per packet and its three fields never need a varint.

## Consequences

- A generation that loses at most `r` symbols completes with no round trip;
  one that loses more falls back to reliable repair for the missing bytes,
  which is what happens today for every byte. FEC can cost bandwidth
  (`r/k` overhead) and never correctness.
- Every allocation on the receive path is bounded by credit the receiver
  granted: active generations times `k * L` bytes, plus decode work.
- Because generations are implicit, an epoch's whole plan is one reliable
  frame; a lost datagram costs its symbol and nothing else.
- The codec, the receiver-side ledger and generation table, and the session
  hooks are three further implementation slices. The frame payload codec
  is covered by the existing frame codec fuzz target once its variants exist.
- VCRC, when it comes, decides `r` and which generations get repair; this
  ADR gives it the knobs and the feedback (`GEN_STATE`).
