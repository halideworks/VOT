# A capability is presented and authorized

Criterion: both halves of the `spec/wire.md` section 1.1 exchange run, and every
rule the section puts on a request holds in the direction that reads one and in
the direction that builds one.

Passing evidence:
`a_challenge_is_presented_and_authorized_over_the_real_carrier` runs the whole
exchange between the assembled client and the assembled server over MsQuic: the
server asks for a capability, the caller presents one, the server authorizes a
narrower scope than was requested, and only then does a record cross a lane.
`a_challenge_is_answered_with_the_capability_the_caller_presents` is the same
sequence over a loopback, and checks that the client learns the granted scope,
which it has no other way to see.

`a_refused_attempt_is_followed_by_another_until_the_bound_is_reached` refuses
three attempts, proves the session stays open and the refusal reaches the caller
with its reason and detail, and proves the fourth request is refused locally
rather than sent for the server to close on.

`a_request_section_1_1_forbids_never_reaches_the_carrier` covers the rules a
request has to satisfy: a client that presents nothing has nothing to present, a
format the server did not advertise is refused, a binding proof under a binding
that asks for none is refused, one attempt is out at a time, and an identifier an
earlier attempt used is refused. Each leaves the attempt unspent and the carrier
open.

`the_binding_proof_rule_holds_in_both_directions` is the reciprocal pair: the
server refuses a request whose proof does not match the binding it named, and the
client refuses to build one. A length bound cannot express this rule, since only
the challenge says which binding is in force and the challenge is a different
frame from the request.

`an_answer_naming_another_attempt_is_refused` proves an answer must repeat the
identifier of the request it answers, that an answer to a request nothing made is
out of sequence, that a server holding a request still refuses an answer to it,
and that an answer that does not decode is the peer's fault rather than the
caller's.

`a_second_challenge_cannot_replace_the_one_an_attempt_answers` proves the
challenge is read once. A demanding challenge leaves the client `Negotiated`,
which is the state `AUTH_CONTEXT` arrives in, so a second would otherwise replace
the nonce a proof was computed over.

`a_frame_the_peer_will_not_carry_is_refused_before_it_is_sent` proves an exchange
frame is measured against the peer's negotiated control-frame limit before it
goes out, in both directions. A capability may be 48 KiB and a peer may advertise
a maximum of 1 KiB, and these frames do not travel the application send path that
would otherwise measure them.

`a_stance_the_role_cannot_act_on_is_refused` proves `begin` refuses a server
given a client's stance and a client given a server's, either of which used to
pass and quietly do nothing.

`a_client_that_can_present_asks_for_nothing_until_it_is_asked` proves a client
that can present still works against a deployment requiring none, and has nothing
pending in the window between negotiating and reading the challenge.

Mutants, each applied and observed to fail: accept a second `AUTH_CONTEXT`; let a
server read an answer to the request it holds; treat a proof of possession with no
proof in it as agreeing; skip the peer control-frame limit on an outbound request;
drop the attempt bound from the client half; read an acceptance without concluding
the exchange; clear the attempt on a rejection that names another one; spend the
attempt before the request is encoded.

Observed failure:

```text
called `Result::unwrap_err()` on an `Ok` value: PresentationRequired
called `Result::unwrap_err()` on an `Ok` value: Consumed { reply: [] }
called `Result::unwrap_err()` on an `Ok` value: AuthorizationRequired
assertion `left == right` failed
  left: Negotiated
 right: Authenticated
assertion failed: rejected.pending_presentation().is_none(): the attempt this client is waiting on was not cleared
assertion `left == right` failed
  left: 2
 right: 3
```

The required `vot-session` mutation run reports 232 mutants, 183 caught, 49
unviable, and 0 missed. The live MsQuic suite runs 58 tests in debug and in
release. The totals move with every change to the crate, so a number written here
is stale before it is read; what the runs have to say is that nothing survived.
