# Prior Art and Standards Positioning

Status: living engineering record, not legal advice or exhaustive search

VOT's research claim is deliberately narrow: online tail-risk control of
durable, verified coflow completion under joint network, source, receiver, and
storage uncertainty. Content addressing, Merkle proofs, verified streaming,
multi-source retrieval, hedging, QUIC, FEC, congestion control, and CVaR are
existing ingredients and are not individually claimed inventions.

## Object identity and proofs

- BLAKE3 specification and implementation:
  <https://github.com/BLAKE3-team/BLAKE3>
- Bao verified streaming and range encoding:
  <https://github.com/oconnor663/bao>
- Grouped Bao trees and range sets:
  <https://github.com/n0-computer/bao-tree>
- BitTorrent Protocol v2 / BEP 52 SHA-256 Merkle trees:
  <https://www.bittorrent.org/beps/bep_0052.html>
- RFC 8949 deterministic CBOR and RFC 8610 CDDL.

## Transport and recovery

- QUIC transport, TLS, recovery, datagrams, and related IETF RFCs.
- RFC 9000 QUIC, RFC 9001 QUIC TLS, RFC 9002 loss detection, RFC 9221 QUIC
  DATAGRAM, RFC 8382 shared bottleneck detection, and RFC 9959 Careful Resume.
- Established parallel HTTP/TCP and reliable QUIC transfer systems.

## Congestion control and multipath

- CUBIC, Reno-family controllers, BBR, Copa, PCC/Vivace, Veno, Westwood, and
  LIA/OLIA-class coupled multipath controllers.
- RFC 9743 congestion-control evaluation criteria.

No custom congestion controller or public-path multi-rail behavior is required
for the production-capable release.

## Coding and scheduling

- Reed-Solomon erasure coding over GF(2^8), ARQ, hybrid ARQ/FEC, adaptive FEC,
  hedged requests, coflow scheduling, tail-latency scheduling, CVaR optimization,
  scenario sampling, block bootstrap, common random numbers, and online resource
  pricing.

VCRC remains experimental and its certificate covers a defined first-wave
frontier failure event, not end-to-end deadline attainment.

## Commercial systems

Commercial transfer products may be measured only through black-box operation
under license terms approved for the benchmark. Their binaries, traces exposing
private protocol details, decompiled behavior, and proprietary source are not
implementation references. Public reports use neutral labels until legal review
authorizes a named comparison.
