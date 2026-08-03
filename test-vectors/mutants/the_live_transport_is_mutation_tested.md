# The live transport is mutation tested

Criterion: the assembled MsQuic transport is measured by the same standard as
every other crate, and what is not covered is written down rather than left out
of the run.

`.cargo/mutants.toml` excluded `live::` outright, so nothing measured it. The
note beside that exclusion recorded 277 mutants, 33 missed, and 9 timeouts.
Re-running it produced 265, 28, and 2. The figure had gone stale without anyone
noticing, which is what an exclusion with a number attached will do.

Passing evidence: `.cargo/mutants-live.toml` is the same configuration without
that exclusion, and the `msquic-mutation` job runs it with the feature on, so
the measurement cannot silently rot again.

The tests written against what the run found:
`a_skipped_frame_counts_down_exactly_what_is_left_of_it` covers the discard
remainder across read boundaries, including a read that ends exactly where the
discard does. `a_frame_at_the_holding_limit_is_accepted_and_one_past_it_is_not`
covers the bound at its own maximum, which only bites for a frame type whose
registered limit is larger than the lane carries.
`the_callback_budget_admits_the_bound_it_states` lands the last event exactly on
the budget, which is the only place an off-by-one there can live.
`each_accepted_connection_gets_its_own_identity_and_reports_its_own_close`
accepts two connections, because the test it replaces asserted the identifier
equalled one and a constant returns that too.
`assert_delegates_to_its_carrier` covers the four adapter methods an accepted
connection only forwards.

Mutants: return a constant from the framing discard remainder; accept a frame
one byte past the holding limit, or refuse one exactly at it; refuse a callback
event that lands exactly on the byte budget; answer `receive_limits`,
`send_reliable_shared`, `preflight_reliable_batch`, or
`set_control_payload_limit` without reaching the carrier; give every accepted
connection the same identifier.

Observed failure:

```text
assertion `left == right` failed: split at 5
  left: []
 right: [[128, 0]]
assertion `left == right` failed
  left: 1048592
 right: 1048593
refused at 16 of 16, inside its own bound
two connections, two identities
```

## What still survives, and why

Kept here rather than in the configuration, because a list of exclusions with no
reasoning is what produced the stale note in the first place.

Resource release: `Control::release`, `Carrier::teardown`, and the `Drop`
implementations for `MsQuicTransport`, `AcceptedTransport`, and `MsQuicServer`.
Deleting a release body frees nothing, and no functional assertion can see that.
The `msquic-sanitizer` job runs the whole live suite under AddressSanitizer and
LeakSanitizer, which is what found a send buffer leaking once per send in a test
listener. These are covered by a job `cargo-mutants` does not run, not by
nothing.

Path statistics: `measured` returning a constant. The values are advisory
telemetry, and asserting a real round-trip time on loopback would be a flaky
test bought for a mutant that cannot affect a transfer.

`AcceptedTransport::sample_path` returning `Ok(())` without sampling. The call
is exercised; its effect is the telemetry above.

Client-side connection events: deleting `PeerStreamStarted` or
`ShutdownComplete` from `MsQuicTransport::connect`. Both are the client learning
about a stream the server opened, and a VOT server answers on the stream the
client opened, so nothing in the suite makes a server open one. Reachable only
by a peer this protocol does not describe.

Stream events: deleting `SendComplete` or `PeerSendShutdown` from
`stream_handler`. `SendComplete` is where a send buffer is released, so deleting
it leaks, which again is the sanitizer's to catch rather than a functional
test's.

The two timeouts are the test harness rather than a hang: `local_port`
returning `Ok(0)` makes a test dial port zero and wait out its own deadline.
