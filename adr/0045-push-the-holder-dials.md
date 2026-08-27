# ADR-0045: Push, the holder dials

- Status: Proposed
- Date: 2026-08-27
- Decision owners: A00 architecture; A10 transport
- Applies to: `spec/wire.md` section 1 (the `GOAWAY` payload, and a new
  section 1.2), `spec/registries.md` sections 4 and 12, `crates/vot-session`
  (`frame_policy.rs`), `crates/vot-cli` (`serve`, `fetch`, `wire`, `drive`),
  `crates/vot-transport-quiche` (`Listener` stateless retry), and the CLI
  surface. No change to any existing frame encoding or to
  `vot-transport-api`.

## Context

ADR-0030 fixed the wire's shape: `vot serve` binds a socket and answers
sessions from one bundle, `vot fetch` dials it. The holder of the data is the
QUIC server, the party that wants the data is the QUIC client. The spec
states the request direction once, in `spec/registries.md` section 12: each
capability operation "names the frames it authorizes, in the direction the
holder sends them", where the holder is the end that presented the
capability at `SESSION_OPEN`, which section 1.1 of `spec/wire.md` makes the
client. `READ_MANIFEST` covers `MANIFEST_REQUEST`; `READ_RANGES` covers
`HAVE`, `RANGE_REQUEST`, and `RANGE_CANCEL`. The engines enforce that
direction implicitly: `serve/server.rs` handles `MANIFEST_REQUEST` and
`RANGE_REQUEST` and nothing else asks for them, and `vot-session`'s
`frame_policy::check_frame` checks lane, exchange-frame origin, extension,
and payload limit, but not which role sent a frame.

That shape serves a publisher. It does not serve a receiver. A receive
portal, a drop box, an ingest server for a studio: each is one fixed,
reachable address that many senders push into. Under ADR-0030 every sender
must instead be reachable, so a laptop on hotel Wi-Fi, a desktop behind a
home router, or a server that only permits outbound traffic has to punch
(ADR-0033) or relay (ADR-0034) before a single byte moves. Those routes exist
for the peer-to-peer case where neither end is fixed. For the receiver case
they are overhead: a rendezvous service to run, a relay to size, a route
ladder to walk, when the receiver was reachable all along and the sender
could simply have dialed it.

The spec already names the missing operation. Section 12 defines `PUBLISH`
as "offering an object and causing its publication": `PACKAGE_DESCRIPTOR`,
`MANIFEST_PAGE`, `PROGRESSIVE_PAGE`, `SEAL`, `PROOF_BUNDLE`, `DATA_RECORD`,
with the assurance frames that come back being "the receiver's answer to it
rather than separate operations". No engine grants or presents `PUBLISH`
today. The holder of a `PUBLISH` capability is, by section 12's own rule, a
client that sends the frames a server sends today.

The pieces to make that real are already separate, they are only wired
together one way. `Session::client` and `Session::server` in
`crates/vot-session/src/session.rs` take an explicit role; nothing derives it
from the transport. `TransportAdapter` has no notion of dialer or listener.
The serve loop (`drive::serve_sessions`, `ServeSession`) and the fetch loop
(`fetch/protocol.rs`) are generic over the adapter. What ties them to a
direction is that `wire/serve.rs` calls `Listener::bind` and then the serve
engine constructs `Session::server`, and `wire/fetch.rs` calls
`Transport::connect` and the fetch engine constructs `Session::client`.

Two ways of untying were considered. One inverts the session roles: the
dialer opens the QUIC connection and then runs `Session::server`. That fights
the wire at three points. The control stream is stream 0, which only the QUIC
client can open, so the session client's `HELLO` would have to travel on a
server-opened stream and section 1's opening sentence would be false.
`Role` in `vot-transport-quiche` decides lane stream identifiers by QUIC side,
so lanes and session roles would disagree. And the TLS certificate is loaded
for `Role::Server` only, so the dialing holder would be the end without an
identity, the opposite of what a receiver wants to pin. The other way keeps
every role where the QUIC handshake put it and flips only the one thing that
needs flipping: which end holds the data. That is this decision.

## Decision

**The holder may dial. A negotiated extension, `PUSH`, says that in this
session the client presents `PUBLISH` and sends the frames that operation
covers, and the server sends the request frames. Nothing else about the
session changes: the client still opens stream 0 and sends `HELLO` first,
the server still sends `AUTH_CONTEXT` and decides the grant, the frames keep
their encodings, and every verification rule keeps its place.**

1. **`PUSH` is extension `0x08`, experimental, disabled by default.** The
   client offers it in `HELLO`; a server that will receive answers with it in
   the intersection (ADR-0041). A server that does not accept pushes omits
   it. The client then has nothing to fetch and nothing to offer, so it
   closes the connection on reading the server's `HELLO`, which ADR-0041
   places ahead of the server's `SETTINGS`; no session was opened and no
   error frame is owed. Negotiation is the only signal; there is no separate
   push frame.

2. **Under `PUSH` the operations keep their frames and the roles that send
   them swap.** `spec/wire.md` gains section 1.2: when `PUSH` is negotiated,
   the client sends the `PUBLISH` frames, `PACKAGE_DESCRIPTOR`,
   `MANIFEST_PAGE`, `PROGRESSIVE_PAGE`, `SEAL`, `PROOF_BUNDLE`, and
   `DATA_RECORD`, and the server sends the `READ_MANIFEST` and `READ_RANGES`
   frames, `MANIFEST_REQUEST`, `HAVE`, `RANGE_REQUEST`, and `RANGE_CANCEL`.
   Ten frames change hands and no other. `HAVE` travels with the requests
   because `spec/object.md` section 10 defines it as the receiver's verified
   coverage, and under `PUSH` the receiver is the server. `CAPACITY` is
   advisory, has no stated direction today, and either end may send it as
   now. Datagram FEC frames are already stated relative to sender and
   receiver of records (`spec/fec.md`) and reverse with them. Section 12
   registers `MANIFEST_REQUEST` under `READ_MANIFEST` and `HAVE`,
   `RANGE_REQUEST`, and `RANGE_CANCEL` under `READ_RANGES`, "in the
   direction the holder sends them". Under `PUSH` the grantor sends those
   four frames while holding no capability, so section 12 gains one
   sentence: when `PUSH` is negotiated, `READ_MANIFEST` and `READ_RANGES`
   are not consulted, and the request frames are the receiver's answer to
   the `PUBLISH` offer, the way section 12 already treats the assurance
   frames as the receiver's answer rather than an operation. The frame
   behavior registry in `spec/wire.md` section 5 is unchanged: maxima,
   idempotence, and auth requirements are properties of the frame, not of
   who sends it.

3. **Direction becomes a checked rule instead of an accident of which
   engine is running.** `frame_policy::check_frame` already receives the
   negotiated set; it gains the local role, and refuses a `PUBLISH` frame
   from the end that does not hold `PUBLISH` in this session and a request
   frame from the end that does, with `MALFORMED_FRAME`. Today no such
   check exists at all: a serve that received a `DATA_RECORD` would fail
   somewhere downstream. The rule
   is written once, in `vot-session`, and covers both negotiation states, so
   the mutation gate has a table to kill rather than a code path to guess
   at.

4. **Authorization runs in the direction it was designed for.** The receiver
   is the session server, so ADR-0036 applies unchanged: it advertises the
   VOT capability format, the dialing holder presents a capability at
   `SESSION_OPEN`, and the receiver grants or refuses. The operation is the
   existing `PUBLISH` (`0x0001`); no new operation is registered. The
   scope's key `1` is the package root under suite 1 as ADR-0036 defines
   package identity, and under `PUSH` the scope's key `2`, which
   `spec/capability.cddl` allows to be null, MUST carry the exact package
   length: a receiver admits on that number before it has read a byte, and a
   capability with a null length is refused with `AUTHORIZATION_FAILED`. A
   capability without `PUBLISH` for that exact root is refused the same way.
   `SESSION_ACCEPT` carries the granted scope as it does today and nothing
   new; the client learns the grant from acceptance itself.

5. **A descriptor that disagrees with the grant ends the session.** A
   `PACKAGE_DESCRIPTOR` whose root or length differs from the accepted scope
   is answered with `ERROR` `OBJECT_IDENTITY_MISMATCH` (`0x0302`) and the
   session closes. `SESSION_REJECT` is not reused; it answers `SESSION_OPEN`
   only.

6. **Identity pins reverse with the roles, using the same mechanism, and
   the push pin is mandatory.** The receiver, as QUIC server, presents a
   certificate. The holder pins its digest exactly as
   `VOT_FETCH_SERVE_IDENTITY` pins a serve: blake3 over the DER, compared
   before anything is sent. A fetch may run unpinned because the package
   root catches a forged server before any byte is accepted; a push has no
   such backstop, since an impostor receiver simply receives, so `vot push`
   refuses to dial without `VOT_PUSH_IDENTITY` and the library entry point
   takes the digest as a required argument. The receiver learns who the
   holder is from the capability's holder key and the proof of possession
   over the `AUTH_CONTEXT` nonce, not from TLS. ADR-0037 channel binding is
   symmetric and needs nothing.

7. **The engines stop constructing their own session.** `ServeSession` and
   the fetch protocol take a `Session<A>` of either role. Today
   `drive.rs` calls `Session::server` and `fetch/protocol.rs` calls
   `Session::client`; after this the caller constructs the session and hands
   it in. This is what lets one binary be a receiver without a second copy
   of the fetch logic.

8. **The receive engine grows the seams an embedder needs.** A process that
   embeds a receiver is not a bundle directory; it is a store with its own
   admission, its own placement, its own publication step, and its own idea of
   what it already has. The consumer this is written for is a receive portal
   that publishes each object with a signed receipt as it completes and
   refuses a package before its first range on grounds the manifest reveals.
   The fetch engine therefore takes a `ReceiveSeams` value with four members,
   all with defaults that reproduce today's directory behavior: a manifest
   hook, called once with the sealed manifest after the chain check and before
   any `RANGE_REQUEST`, returning admit or a refusal that ends the session
   with `ADMISSION_DENIED`; a sink factory, called once per object with the
   object's root, length, and manifest entry, returning a `Box<dyn RangeSink>`
   or a decision to skip the object, in which case no `RANGE_REQUEST` is
   issued for it; a completion callback per object, called after the object's
   last range is verified and the sink flushed; and a cancellation handle the
   embedder can trigger from another thread, which sends `GOAWAY` and returns
   from the fetch loop with the objects completed so far. `GOAWAY` (`0x83`) is
   registered with a 4 KiB limit and the rule "lower or equal final accepted
   ID is idempotent; increase rejected" but has never had a payload written
   down and has no encoder in `vot-codec`. This ADR defines the payload in
   `spec/wire.md` section 1, beside the other base frames, since `GOAWAY` is a
   base frame any endpoint may send: one QUIC varint, the plan cursor, which
   is the count of objects in manifest order the sender of `GOAWAY` is
   finished with, whether by accepting the final range, skipping the
   object, finding it already whole, or its being empty. Zero means no
   object is finished. Section 1.2 adds the `PUSH` reading: the server is
   both requester and acceptor, the cursor bounds objects and not request
   identifiers, and a holder that receives `GOAWAY` with cursor `n` sends no
   `PUBLISH` frame for any object at manifest index `n` or above. The cursor
   is `plan.current` verbatim and is monotonic because the fetch plan
   advances it by one and finishes one object at a time. `CountingSink`
   becomes public and implements `RangeSink` so the
   default factory is the sink `fetch_bundle` uses today; `fetch_bundle`
   itself is unchanged.

9. **CLI and library surface.** `vot push BUNDLE_DIR CONNECT_ADDR
   CAPABILITY.cbor KEY_SOURCE` dials, pins with `VOT_PUSH_IDENTITY`, and
   serves the bundle into the session. `vot receive-push LISTEN_ADDR
   BUNDLE_DIR CERT.pem KEY.pem` listens, requires a capability under the
   issuer anchor exactly as `vot serve` does with `VOT_SERVE_ISSUER`, and
   fetches each accepted session into `BUNDLE_DIR/<root-hex>/`. The library
   exposes `push_bundle` and `receive_push` beside `serve_bundle` and
   `fetch_bundle`, and `receive_push_on(listener, policy)`, which takes a
   bound `Listener` and an admission policy the embedder supplies. The
   engine owns the accept loop; the policy is called once per
   `SESSION_OPEN` with the presented capability and the peer address, and
   returns either a refusal or the grant together with the `ReceiveSeams`
   for that session, so the embedding process owns the socket, the
   certificate, the grant, and the placement, and every seam call carries
   the session it belongs to. `Listener` gains stateless retry
   (`quiche::retry`, token binding the source address and the original
   destination connection id, which `accept` then receives as `odcid`
   where today it is passed `None`), off by default and
   on for `receive_push_on`: a public receiver takes handshakes from anyone,
   and today `accept_one` creates connection state for any source with only
   quiche's three-times amplification bound behind it. With retry, a
   connection exists only for an address that answered. An embedder that
   receives a bundle directory
   publishes it with `vot receive` or the SDK, as ADR-0030 already
   separates replication from publication.

10. **Rendezvous and relay stay for peers.** Nothing in ADR-0033 or ADR-0034
    changes. A holder that can reach the receiver dials it; a pair that
    cannot reach each other still walks the route ladder. `vot push` accepts
    the same `VOT_RENDEZVOUS` and `VOT_RELAY` settings `vot fetch` does, so a
    push can also be punched when the receiver is not fixed, but that is a
    composition of existing routes, not new ones.

## Consequences

- A receiver becomes one address, one certificate digest, and one issuer
  key. A sender needs a capability from that receiver and an outbound UDP
  path. That is the deployment shape of a receive portal, and it is reached
  without a rendezvous service or a relay.
- Everything the transport learned since ADR-0030 applies to a push exactly
  as to a fetch, because the carrier does not know which way the data goes:
  multi-rail (ADR-0031), resume (ADR-0032), the datagram FEC line
  (ADR-0039 to ADR-0044), pacing and window sizing, and the quiche fork's
  loss floor. The holder sends `DATA_RECORD`s and paces them; the receiver
  verifies ranges and issues credit. `FecPolicy` in `serve/connection.rs`
  runs on the holder unchanged, since it already lives with the sender of
  records.
- `PUBLISH` gets its first consumer. It was registered with a receiver in
  mind and has waited for one; this ADR does not widen it.
- `frame_policy::check_frame` learns the local role, which it never needed
  before. The mutation gate gains that table: for each of the ten frames,
  under each negotiation state, a mutant that accepts the frame from the
  wrong end must fail a test.
- Admission moves earlier for a receiver than for a fetcher. A fetcher
  learns the package length from `PACKAGE_DESCRIPTOR`; a receiver needs it
  before granting, which is why the scope length is mandatory under `PUSH`
  and why a descriptor that disagrees is an `OBJECT_IDENTITY_MISMATCH`
  rather than a surprise.
- Lanes need nothing. The engines address logical lanes and the quiche
  adapter maps them by `Role`; a holder that is the QUIC client sends
  records on client-initiated streams and the receiver's `lane_for_stream`
  already accepts peer lanes on either parity.
- `PUSH` is disabled by default so nothing already deployed changes
  behavior. A `vot fetch` never sees `PUSH`: `Negotiation` computes the
  usable set as the intersection of what it offered and what the server
  answered (`negotiation.rs`), so an extension the client did not offer is
  dropped at that intersection.

## Rejected alternatives

- **Inverting session roles at the dialer**, described in Context. It
  breaks stream 0 ownership, lane numbering, and the TLS identity, and it
  would need the session layer to learn a fourth role. The extension keeps
  every role and moves one bit.
- **A new operation, `PUSH_PACKAGE`.** Section 12 already has `PUBLISH`
  covering exactly the six frames a holder sends, defined as causing
  publication at a receiver. A second name for the same authorization would
  leave `PUBLISH` registered and unused.
- **Reversing the QUIC connection after the handshake**, so the holder
  dials, then the ends behave as if the receiver had dialed. QUIC has no
  such operation; it would be a second connection, which is the route
  ladder again.
- **A push frame carrying root, length, and ticket on stream 0 before
  `HELLO`.** It duplicates `SESSION_OPEN` and the capability, and puts an
  unauthenticated frame in front of negotiation. The capability already
  carries root and length in its scope, which is where a receiver wants to
  read them.
- **Leaving direction unchecked, as today.** With one direction the
  accident is harmless. With two, a frame from the wrong end is either a bug
  or an attack, and the place to refuse it is the one policy function that
  already sees every frame.
- **Running the receive portal as a fetcher behind a rendezvous.** It works
  today and is why ADR-0033 exists, but it makes the fixed end pay the
  peer-to-peer cost on every transfer and adds a service the portal
  operator must run and secure.

## Required verification

- Simulator loopback: build a bundle, `receive_push` on one end, `push`
  from the other, `vot receive` the result, diff against the source. The
  same test with the capability refused ends at `SESSION_REJECT` with no
  descriptor accepted. The same test with a descriptor whose root differs
  from the granted scope ends with `OBJECT_IDENTITY_MISMATCH` and leaves no
  partial object in `BUNDLE_DIR`. The same test with a null scope length is
  refused at `SESSION_OPEN`.
- Direction policy: for each of the ten frames, a test that the frame is
  refused from the wrong end when `PUSH` is negotiated and from the other
  wrong end when it is not, pinned as a table in `frame_policy` tests.
- Seams: a manifest hook that refuses ends the session with
  `ADMISSION_DENIED` and no `RANGE_REQUEST` issued; a sink factory that
  skips one object of three yields a bundle missing exactly that object and
  a session that issued no `RANGE_REQUEST` for it; the completion callback
  fires once per completed object, after its bytes are on disk, and not for
  the skipped one; a cancellation triggered mid-object sends `GOAWAY`
  carrying the count of finished objects, the holder sends nothing for
  that index or above, and the loop returns with the completed objects
  intact and the partial one absent. `GOAWAY` round-trips through
  the codec with a golden vector.
- Retry: a `receive_push_on` listener answers an initial packet from an
  unseen address with a retry and creates no connection; a spoofed source
  that never answers leaves no state behind.
- quiche-live job: a push over loopback at one rail and at four, pinned
  identity, with the receiver's certificate digest mismatched once and the
  connection dropped before `HELLO`, and a push attempted without a pin
  refused before dialing.
- Bench rig: a 4 GiB push and a 4 GiB fetch of the same bundle over the same
  loopback, interleaved three reps each. The push is within noise of the
  fetch; a gap is a defect in the reversed credit or pacing path, not a
  tuning question.
