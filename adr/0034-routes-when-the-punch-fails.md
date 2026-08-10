# ADR-0034: the routes a fetch tries when the punch cannot work

Status: Accepted

## Context

ADR-0033 removed the port forward for the networks it could: two ends
behind ordinary NAT now pair by the package root and punch. Step 4
measured what that leaves out, and the gap is not small.

The network the tool was written for is one of them. Its router presents
one socket to two destinations under two different external ports,
measured as 58148 and 6387 at the same instant, which is a symmetric NAT:
the mapping the rendezvous service observes is never the mapping the
Initial comes from, so no ordering of warmings can help. Its allocation is
random rather than sequential, so predicting the peer's port is not open
either. It answers no port-mapping protocol, deliberately, and that is a
reasonable policy rather than a misconfiguration: a router that hands out
inbound ports to whatever asks is a router that hands them to anything
running on the network. Carrier-grade NAT produces the same shape without
even a router to ask.

Two other things step 4 measured decide the answer.

A punch, where it works, is cheap: 64 MiB across two conntrack NATs in
0.610 seconds, with the whole traversal inside the first tenth of it.
Nothing here is about making the punch better.

And IPv6 removes the problem rather than working around it. Serving from
that same home network over IPv6, the service observed the serve's real
address and the same port it had bound, with no translation in front of
it at all, and a 64 MiB fetch crossed in 1.703 seconds with no port
forward. The code cannot currently prefer that route: a serve registers
one mapping, in whichever family it reached the service over, because
ADR-0033 settled on one mapping per key. On a dual-stack network that
throws away the route that needs no traversal at all.

Both gaps have the same shape. A fetch has one route today and needs
several, tried in an order that prefers the ones that cost nothing.

## Decision

**A root-addressed fetch tries an ordered ladder of routes and moves the
bytes by the first that works: a literal address, an IPv6 mapping, a
punched IPv4 mapping, and last a relay that forwards datagrams for a
bounded slot. Which route carried the transfer is reported, not
inferred.**

- **The service holds one mapping per family per key, and a resolve is
  answered in the family it arrived over.** A serve whose listener is
  dual-stack registers with the service at each address it has, and is
  findable at both. A fetch tries the service's IPv6 address before its
  IPv4 one, and what comes back is the serve's mapping in that same
  family, so nothing on the wire has to carry two addresses and the
  amplification bound is untouched. IPv6 goes first because a global
  address has no translation in front of it: no mapping to keep alive,
  and no NAT to take one. This is what ADR-0033's fallback bullet
  described before the one-mapping-per-key shape made it unwritable.
- **A relay forwards datagrams and reads none of them.** It carries
  opaque UDP payloads between the two ends of a slot. The QUIC session,
  its congestion control, the manifest, and every proof stay end to end.
  The relay sees ciphertext, two addresses, and byte counts, and it never
  speaks the session protocol.
- **A slot is a port on the relay**, so a relayed datagram is exactly the
  size of a direct one. Nothing is wrapped, path-MTU discovery still
  measures the real path, and the jumbo-datagram work applies unchanged.
- **Both ends reach the relay outbound**, which is the whole reason it
  works where a punch does not: neither end has to accept a packet it did
  not ask for. The fetch takes a slot and the invitation travels to the
  serve by the path the rendezvous service already uses to say a fetch is
  coming. On the serving end an invitation is exactly a Coming whose
  address is the relay slot: the same warmings, from the same socket,
  claim the slot's first end, under the same source check and the same
  per-cadence budget, so an invitation cannot make a serve a reflector
  any more than a Coming can. The service passes one invitation to one
  live mapping and answers the asker nothing, so the invite leg amplifies
  nothing either. The slot pairs its first two distinct sources in
  whichever order they arrive, so neither end waits on the other to go
  first.
- **A slot is keyed by the rendezvous key, bounded, and short.** The
  relay never learns a root, exactly as the rendezvous service never
  does. A slot carries a TTL and a byte ceiling, and a relay refuses new
  slots past what its operator configured, so relaying is a bounded
  donation of bandwidth rather than an open proxy.
- **Relaying is named, never assumed.** `VOT_RELAY` names one the way
  `VOT_RENDEZVOUS` names a rendezvous, with nothing baked into the
  binary. A fetch with no relay named and no punchable route fails as it
  does today, by name. A deployment may run a relay and a rendezvous
  service on one host, but the rendezvous service does not relay by
  default: pairing costs a datagram and relaying costs a transfer.
- **The relay rung runs at width one.** A slot pairs exactly two ends,
  and a wider fetch through a donated path would multiply the donation
  without adding a path. Rails are for routes this end can open for
  itself.

## Consequences

- A fetch from a network that cannot punch works, at the cost of a third
  party carrying ciphertext and knowing that two addresses exchanged a
  volume of bytes under one key.
- That third party is a withholding point. It can stall or drop and it
  cannot forge, because every range still proves to the root; this is the
  trust story ADR-0030 already carries for the unauthenticated channel,
  and the pin still decides.
- A relay operator pays bandwidth. The ceilings are theirs to set, and
  self-hosting removes the third party entirely.
- Preferring IPv6 changes which path most dual-stack transfers take. That
  is a reachability change and a performance one: no NAT mapping to
  refresh, and no punch wait in front of the handshake.
- More rungs means a worse worst case for time to first byte, so the
  ladder is ordered to fail cheaply: a literal address is immediate, an
  unreachable IPv6 candidate fails at the handshake bound, and the punch
  is already bounded.
- The rendezvous protocol grows: a mapping per family, and the datagrams
  that carry a relay invitation. `spec/registries.md` still owes the
  section ADR-0033 deferred, and it should be written once for both.

## Sequence

1. One mapping per family per key, and the ordered ladder without a
   relay: `VOT_RENDEZVOUS` names a service by every address it has,
   a serve registers at each, a resolve is answered in the family it
   came over, a fetch tries IPv6 before punched IPv4, and the route the
   transfer took is reported.
2. The relay protocol and the `vot relay` verb: slot allocation keyed by
   the rendezvous key, forwarding, the TTL and byte ceilings, loopback
   tests, and the bounds held by construction rather than by policy.
3. Fetch and serve take a relay as the last rung when one is named.
4. Validation on a network that cannot punch, which is the measured
   symmetric NAT of step 4, end to end and logged.
