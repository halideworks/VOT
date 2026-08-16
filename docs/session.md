# Sessions and negotiation

A VOT session is the wire exchange defined in `spec/wire.md` section 1, plus
the readiness gate it enforces. Implemented in `vot-session`.

## Negotiation exchange

Runs on QUIC stream zero (first client-initiated bidirectional stream).

| Step | Client | Server |
| --- | --- | --- |
| 1 | sends `HELLO` | |
| 2 | sends `SETTINGS` | |
| 3 | | reads `HELLO` |
| 4 | | reads `SETTINGS`, sends own `HELLO` (the accepted extensions), own `SETTINGS`, `SETTINGS_ACK` |
| 5 | reads the server's `HELLO`, then `SETTINGS`, then `SETTINGS_ACK` | |

`HELLO` and `SETTINGS` are once per direction (ADR-0041).

States: `Connecting`, `ControlReserved`, `HelloSent`, `SettingsExchanged`,
`Negotiated`, `Authenticated`, `Closed`.

## Two readiness gates

`Negotiated`: version and limits agreed. Application frames are refused until
this point.

`Authenticated`: the section 1.1 exchange concluded. Frames the registry marks
`auth: yes` are refused until this point.

A `PING` between the two states is fine; a `DATA_RECORD` is not.

`requires_authentication` in `vot-codec` defines the auth-gated subset.
`tools/validate_registries.py` cross-checks it against the frame table in
`spec/registries.yaml` and the `Auth` column in `spec/wire.md`.

## Authentication exchange

The server sends `AUTH_CONTEXT` immediately after `SETTINGS_ACK`. The
concluding frame depends on the server's stance:

| Stance | Role | Behavior |
| --- | --- | --- |
| `NotRequired` | either | No format advertised; no challenge |
| `Capability` | server | Advertises formats, runs exchange to `SESSION_ACCEPT` |
| `Presenting` | client | Answers challenge with presented credentials |

`Session::begin` refuses a stance inconsistent with the role.

The nonce is caller-supplied. This crate has no randomness.

A client with nothing to present closes with `AUTHENTICATION_FAILED` when a
challenge advertises a format.

### Capability verification lives outside this crate

`accept_control` returns `Accepted::AuthorizationRequired` (server) or
`Accepted::PresentationRequired` (client). The caller decides through
`pending_authorization`/`grant`/`refuse` or `pending_presentation`/`present`.

`poll` returns `None` while a decision waits. A loop that only drains events
without checking pending decisions will stall silently.

A refusal leaves the session open (the client may retry). The fourth attempt
closes with `AUTHENTICATION_FAILED`.

### Rules checked in both directions

Each rule is enforced both when reading a request and when building one.

| Rule | Reading | Building |
| --- | --- | --- |
| Format offered by server | `CapabilityFormatNotOffered` | `FormatNotOffered` |
| Fresh identifier | `SessionIdentifierReused` | `IdentifierReused` |
| At most 3 attempts | `TooManyAuthenticationAttempts` | `AttemptsSpent` |
| Binding proof matches | `BindingProofMismatch` | `BindingProof` |
| Answer repeats request ID | `SessionIdentifierMismatch` | carried by answer |

Exchange frames are measured against the peer's negotiated control-frame limit
before sending.

## Asymmetric gate

Sending application data before local readiness is refused. QUIC does not order
the negotiation stream relative to application lanes, so remote records may
arrive before local readiness. They remain in a bounded buffer until the gate
opens.

The buffer is bounded by bytes and count. Exceeding it fails with
`RESOURCE_LIMIT`. `Session::set_pending_limits` adjusts the bounds.

## Close codes

Every failure carries a registered close code on `Error::close_code`. Whether it
reaches the wire depends on fault:

| Cause | Sent to peer |
| --- | --- |
| Bad `HELLO`/`SETTINGS`, undecodable frame | yes |
| Frame out of sequence, application frame before readiness | yes |
| Pre-readiness buffer exhausted | yes |
| Application used data plane too early | no |
| Backend refused a submission | no |
| Carrier already gone | no |

## Negotiated limits

On readiness, the peer's `MAX_CONTROL_FRAME_PAYLOAD` becomes the outbound
control-frame bound via `set_control_payload_limit`. The reverse (this
endpoint's reassembly bound) must be set before `Session::begin`.

| Carrier | Peer control bound | Advertised limits | Close code |
| --- | --- | --- | --- |
| MsQuic | applied | enforced | sent |
| TCP | applied, clamped to queue | enforced | not signalled |
| Simulator | applied | enforced once set | recorded |

A carrier that cannot honour a method returns `Unsupported`, not `Ok`.
`Session::control_limit_applied` reports whether it took effect.

## Settings

Five settings are defined. Four are enforced by `vot-session`:

| Setting | Enforced | Where |
| --- | --- | --- |
| `MAX_CONTROL_FRAME_PAYLOAD` | yes | payload limit table |
| `MAX_DATA_RECORD_PAYLOAD` | yes | payload limit table |
| `MAX_MANIFEST_PAGE_PAYLOAD` | yes | payload limit table |
| `RELIABLE_LANE_LIMIT` | yes | outbound in session, inbound in transport |
| `IDLE_TIMEOUT_MS` | no | see below |

The four payload limits go through one table. A proof (`PROOF_BUNDLE`) is on
the control stream and bounded by the control ceiling, not the record limit.

`IDLE_TIMEOUT_MS` is negotiated but not installed. QUIC configures its timeout
before VOT negotiation, and `vot-session` has no timer. Quiche uses 30 seconds;
MsQuic uses its default. Configure the carrier when a deployment requires a
specific timeout. See ADR-0035.

Lane limit is split: the session counts outbound lanes; the transport counts
inbound peer streams. MsQuic counts concurrent streams; TCP counts distinct
identifiers (only grows).

## Extensions

The client's `HELLO` carries its offered extensions; the server's `HELLO`
answers with exactly the intersection of that offer and its own support, so
both ends hold the same negotiated set (`Session::extension_negotiated`).
An experimental frame is refused with `EXPERIMENT_NOT_NEGOTIATED` in both
directions unless its extension is in that set (ADR-0041).

## Lane identity

Application lanes are numbered by the application. Peer lanes are offset from
`PEER_LANE_BASE` (past the QUIC varint range). Each peer stream gets a unique
lane.

## Early data

No v0.3 application frame is valid in 0-RTT. The MsQuic receive path checks
the replay flag before framing and closes with `REPLAY_REJECTED`.

## Driving a session

`Session` owns its backend. The readiness gate prevents applications from
reaching the raw adapter. `Session::driver` exposes the adapter for backend
driver code (TCP byte pumping, MsQuic flush/poll) that the contract does not
cover.

## Transports

- `MsQuicTransport::connect` - client connection, claims stream zero for
  negotiation.
- `MsQuicServer::listen` - accepts connections, hands out `AcceptedTransport`.
- `TcpAdapter` - TLS/TCP carrier with bounded queue.
- `SimulatorAdapter` - deterministic in-process carrier.
