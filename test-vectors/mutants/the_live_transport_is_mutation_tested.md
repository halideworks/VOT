# The live transport is mutation tested

Criterion: the assembled MsQuic transport is measured by the same standard as
every other crate, and what is not covered is written down rather than left out
of the run.

`.cargo/mutants.toml` excluded `live::` outright, so nothing measured it. The
note beside that exclusion recorded 277 mutants, 33 missed, and 9 timeouts.
Re-running it produced 265, 28, and 2. The figure had gone stale without anyone
noticing, which is what an exclusion with a number attached will do, and is why
the run now happens in CI rather than being written down.

Passing evidence: `.cargo/mutants-live.toml` is the same configuration without
that exclusion, and the `msquic-mutation` job runs it with the feature on, so
the measurement cannot silently rot again.

The job fails when a survivor is not in the table below, and says so when a row
in it no longer survives. `cargo-mutants` exits non-zero whenever anything
survives at all, and a check that is red for a known list teaches people to
ignore red. The list is here rather than in a comment, which is the whole
difference: `tools/check_live_mutants.py` reads it every run, and a record
nothing checks is what went stale and started this.

It compares the set and not the count. A count cannot tell one survivor from
another, so a run that killed a classified mutant and grew a new one reported the
same total and passed: the bound this replaces was 15 while the reasons written
underneath it accounted for 14, and nothing noticed. Comparing mutants also
settles the missed and timed-out split, which depends on how loaded the runner is
rather than on the code. Two CI runs of the same commit reported 13 missed with 2
timeouts, then 12 with 3; the same mutants either way.

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
connection the same identifier; drop the accepted side's `Connected` event.

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
an accepted connection reports ConnectionId(1)
```

## What still survives, and why

Kept here rather than in the configuration, because a list of exclusions with no
reasoning is what produced the stale note in the first place. Each row is the
mutant exactly as `cargo-mutants` prints it, which is what the checker matches
on; the file, line, and column it prints beside them move with every edit and are
not part of the identity.

| Survivor | Why it survives |
| --- | --- |
| `replace live::Control::release with ()` | Resource release. Deleting a release body frees nothing, and no functional assertion can see that. `msquic-sanitizer` runs the whole live suite under AddressSanitizer and LeakSanitizer, which is what found a send buffer leaking once per send in a test listener. Covered by a job `cargo-mutants` does not run, not by nothing. |
| `replace live::Carrier::teardown with ()` | Resource release, as above. |
| `replace live::<impl Drop for MsQuicTransport>::drop with ()` | Resource release, as above. |
| `replace live::<impl Drop for AcceptedTransport>::drop with ()` | Resource release, as above. |
| `replace live::<impl Drop for MsQuicServer>::drop with ()` | Resource release, as above. |
| `replace live::measured -> Option<u64> with Some(0)` | Path statistics. The values are advisory telemetry, and asserting a real round-trip time on loopback would be a flaky test bought for a mutant that cannot affect a transfer. |
| `replace live::measured -> Option<u64> with Some(1)` | Path statistics, as above. |
| `replace live::AcceptedTransport::sample_path -> Result<(), msquic::Status> with Ok(())` | The call is exercised; its effect is the telemetry above. |
| `delete match arm ConnectionEvent::PeerStreamStarted{stream, ..} in live::MsQuicTransport::connect` | A client learning about a stream the server opened. A VOT server answers on the stream the client opened, so nothing in the suite makes a server open one. Reachable only by a peer this protocol does not describe. |
| `delete match arm ConnectionEvent::ShutdownComplete{..} in live::MsQuicTransport::connect` | The client-side arm, as above. |
| `delete match arm StreamEvent::SendComplete{client_context, ..} in live::stream_handler` | Where a send buffer is released, so deleting it leaks, which is the sanitizer's to catch rather than a functional test's. |
| `delete match arm StreamEvent::PeerSendShutdown in live::stream_handler` | The peer half-closing a stream nothing in the suite half-closes. |
| `replace live::MsQuicServer::local_port -> Result<u16, msquic::Status> with Ok(0)` | Times out rather than fails: a test dials port zero and waits out its own deadline. A mutant that hangs says less than one that fails either way. |
| `replace match guard callback_owned with false in live::stream_handler` | Times out for the same reason: the guard turned off breaks the handshake the test is waiting on. |

The fifteenth entry was `delete match arm ConnectionEvent::Connected{..} in
live::accept_connection`, which the count bound admitted and no reason
accounted for. It has a test now:
`each_accepted_connection_gets_its_own_identity_and_reports_its_own_close`
requires each accepted connection to report `Event::Connected` under its own
identifier. The connecting side was asserted on and the accepted side was not, so
a callback that dropped the event looked the same as one that reported it, and a
driver waiting to be told would have waited for ever.

Two more appeared partway through this work, from a `push` that always accepts.
They are gone: the callback budget test that lands its last event exactly on the
bound now refuses the one past it, which fails fast instead of letting a queue
grow until a deadline expires. Recorded because the intermediate run said
otherwise and the write-up said so too.
