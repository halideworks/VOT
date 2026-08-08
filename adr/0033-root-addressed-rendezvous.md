# ADR-0033: the root is the address

Status: Accepted

## Context

A fetch today needs two things from the serving side: the package root,
which `send` prints and which pins what the fetch will accept, and a
reachable `ADDR:PORT`, which on an unmanaged network means a router
port-forward. The first is inherent: the root is the capability to
verify, and exchanging it is the protocol's trust story. The second is
pure operations, and it is the step that stops a freelancer or a small
office from using the tool at all: most consumer NATs will not pass an
unsolicited inbound datagram, and asking a counterparty to forward a
port is asking them to reconfigure a router they may not control.

The pieces to remove that step already exist in the shape of the code.
Both ends own their sockets outright: the serve's demultiplexing
listener (ADR-0031) holds one socket every session arrives at, and the
fetch binds its own socket per rail. A NAT opens a return path for any
outbound datagram, so two ends that each send one packet toward the
other's public mapping open both directions; the only missing knowledge
is each end's public mapping, and the only missing choreography is who
sends when. That is a rendezvous, and the identifier the two humans
already exchange, the root, is enough to key it.

## Decision

**A fetch may name a package root in place of an address. A rendezvous
service pairs the two ends by a hash of the root and tells each the
other's public mapping; both ends punch; the session proceeds exactly
as if the address had been typed.** Nothing about sessions, proofs,
receipts, or the wire protocol changes; the rendezvous only replaces
the human-carried `ADDR:PORT` with a machine-carried one.

- **One round trip observes and pairs.** A serve registers by sending a
  small datagram from its own listener socket to the rendezvous
  service; the datagram's source address as the service sees it IS the
  serve's public mapping for exactly the socket sessions arrive at, so
  there is no separate STUN step and no second socket whose mapping
  could differ. A fetch resolves the same way from the socket it will
  connect with. The service answers the fetch with the serve's mapping
  and forwards the fetch's mapping to the serve; the serve sends a few
  warming datagrams toward the fetch's mapping, opening its own NAT for
  the fetch's Initial, and the fetch connects.
- **The key is a hash of the root, not the root.** Both ends derive the
  rendezvous key as a keyed hash of the package root under a fixed
  context string. The service never learns a root, and holding a key is
  the same thing as holding the root, which is already the capability
  to fetch. A forged registration under a known key can at worst point
  a fetch at an endpoint whose proofs fail, which is the unauthenticated
  channel's existing trust story (ADR-0030); the pin still decides.
- **The service is small, bounded, and self-hostable.** `vot rendezvous
  LISTEN_ADDR` runs it: a table of key to mapping with a TTL of
  minutes, refreshed by the serve's periodic re-registration (which is
  also what keeps the serve's NAT mapping alive). Replies are no larger
  than requests and go only to the observed source, so the service
  amplifies nothing. No endpoint is baked into the
  binary: `VOT_RENDEZVOUS` names one, as an address or a name, and both
  ends name the same one. Running your own is one command, and which one
  to run is a deployment's choice rather than the tool's.
- **Rendezvous datagrams share the serve's socket and are told apart by
  a magic prefix** that is not a valid QUIC long or short header lead
  byte. The listener's router hands them to the registration state and
  sheds them from session routing; the fetch side speaks the exchange
  before its connection exists and owns its socket alone.
- **Fallbacks are ordered and explicit.** A literal address argument
  behaves exactly as today and involves no rendezvous. A root argument
  uses the one mapping the service observed, which is already the
  directly reachable address when nothing translates it, and is an IPv6
  address when the serve registered over IPv6; the service holds one
  mapping per key, so there is no candidate list to order. A punch that
  cannot complete, which is what a symmetric or carrier-grade NAT
  produces, fails within a bounded number of attempts and says so by
  name, pointing at the direct-address and overlay routes rather than
  timing out silently.

## Consequences

- `vot fetch ROOT DEST` and `vot pull ROOT ...` become sufficient on
  unmanaged networks: the string the humans already exchange is the
  whole coordination.
- The serving end gains a background registration cadence (one small
  datagram every ~20 seconds) and the listener's router gains one
  branch; neither touches the data path.
- A third party, the rendezvous service, learns pairing metadata: which
  hashed keys exist and which IP pairs met under them, for the TTL.
  Self-hosting removes even that; the protocol carries nothing else.
- Symmetric NAT on either end defeats the punch by construction; the
  failure is named, not worked around, and the direct and overlay
  routes remain.

## Sequence

1. The rendezvous protocol module and the `vot rendezvous` service
   verb: frames, keyed hashing, TTL table, loopback pairing tests, and
   the amplification bound held by construction.
2. Serve-side registration: the listener socket registers and
   re-registers under the bundle's key, and the router recognizes and
   sheds rendezvous datagrams; warming sends on a forwarded fetch
   mapping.
3. Fetch-side resolution: a root in address position resolves, orders
   candidate mappings, punches, and falls back by the explicit order;
   the named failure for the unpunchable case.
4. Two-NAT validation on real networks: home NAT to home NAT via a
   hosted rendezvous, logged with mapping types and punch success, and
   the runbook updated so a live test needs no port-forward.
