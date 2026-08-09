# ADR-0035: a setting is advertised only if something installs it

Status: Accepted

## Context

`spec/registries.md` section 3 registers eight settings. Both peers encode
them, both decode them, both validate them against their ranges, and a
duplicate or an out-of-range value is a protocol error. Four of them then
reach nothing.

`MAX_CONTROL_FRAME_PAYLOAD`, `MAX_DATA_RECORD_PAYLOAD`,
`MAX_MANIFEST_PAGE_PAYLOAD`, and `RELIABLE_LANE_LIMIT` are installed: the
receive limits come from them and the carrier enforces them.

`ACTIVE_KEEPALIVE_MS`, `COMPRESSION_MIN_GAIN_BPS`, and `TELEMETRY_LEVEL` are
read by nothing but the codec oracle that echoes them back for vector
generation. There is no keepalive timer, no compressor, and no telemetry
level. `COMPRESSION_MIN_GAIN_BPS` in particular is a threshold for deciding
whether compressing a record paid off, and no record is ever compressed.

`IDLE_TIMEOUT_MS` is the interesting one. It is negotiated, and the quiche
carrier has a field of the same name that it does install, through
`set_max_idle_timeout`. They are not the same number. The registered default
is 90000 and the carrier's is 30000, and nothing connects them. A reader who
found both would reasonably assume the negotiated value was the installed
one.

An advertised setting that nothing installs is worse than an absent one. A
peer that reads the registry and sets `ACTIVE_KEEPALIVE_MS` to 10000 has been
told its keepalive is 10 seconds. It is not; there is no keepalive. The
registry is a promise about behaviour, and three of these are promises
nothing keeps.

## Decision

**Retire `ACTIVE_KEEPALIVE_MS`, `COMPRESSION_MIN_GAIN_BPS`, and
`TELEMETRY_LEVEL`.** They leave the registry, the `Settings` type, and the
negotiation vectors. Their identifiers `0x0b`, `0x20`, and `0x22` are recorded
as retired and are not reassigned.

(`security/abuse-cases.yaml` is untouched. Its `default_telemetry_level` is
about what telemetry may record, not about the wire setting, and the two
happen to share a word.)

**The ALPN moves to `vot-draft-05`, and the draft revision to 5.** `0x0b` is
odd, so it is critical, and criticality is derived from the identifier rather
than declared: there is no way to retire it that an older peer treats as
anything but an unknown critical setting. `Settings::advertised` sends every
registered setting on every connection, so a peer built before this change
puts `0x0b` in every `SETTINGS` frame and a peer built after it closes the
session with `INVALID_SETTING`. `spec/wire.md` is normative that a major
incompatible protocol change uses a new ALPN, and this is one.

Without the bump both ends would complete the QUIC handshake, agree on the
ALPN, exchange a `HELLO` that each accepted at revision 4, and only then tear
down on the first `SETTINGS` frame, with the version machinery that exists to
catch exactly this reporting a match. Upgrading one end of a working
deployment would kill every session in both directions. With the bump they
fail at ALPN negotiation, which is where a version mismatch belongs.

Each returns when the thing it configures exists. A keepalive setting belongs
with a keepalive timer, a compression threshold with a compressor, a telemetry
level with telemetry. Registering the knob first gains nothing and costs a
false promise.

**`IDLE_TIMEOUT_MS` stays, and the two numbers become one.** The carrier's
default is taken from the registered default rather than written again beside
it, so the drift cannot recur.

**The negotiated value is not installed, and this ADR does not install it.**
Two facts stand in the way, and both are worth stating rather than working
around badly.

QUIC's `max_idle_timeout` is a transport parameter fixed during the handshake.
VOT negotiates its settings over a session that exists only after that
handshake completes. There is no point at which a negotiated number can become
the carrier's transport parameter for the connection carrying the negotiation.

And `vot-session` has no clock. It is a pure state machine over frames, with
no `now`, no deadline, and no timer. Enforcing an inactivity timeout at the
VOT layer means giving the session a notion of time, which changes its shape:
every non-terminal state gains a deadline and the driver gains an obligation
to honour it. That is a design worth doing and it is not this one.

Until then `IDLE_TIMEOUT_MS` is negotiated and validated, and what actually
closes an idle connection is the carrier's own timeout, from the same default.
`docs/session.md` says so in those words.

## Consequences

A peer cannot ask for a keepalive, a compression threshold, or a telemetry
level. None of the three did anything, so nothing a peer could observe
changes, except that asking now closes the session for `0x0b` instead of being
silently ignored.

The negotiation vectors lose three settings, and the encoded settings frame
gets shorter. This is a wire change to a draft, which is what an ADR is for.

The gap between the negotiated idle timeout and the installed one is now
written down in the ADR, in the registry, and in `docs/session.md`, rather
than being discoverable only by reading two crates and noticing that two
fields with one name hold different numbers.
