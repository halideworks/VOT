# Sessions are served at the same time

Criterion: a serve drives accepted sessions concurrently, up to
`CONCURRENT_SESSIONS` at once; the next accepted client past the bound
waits for a running session to settle rather than being refused.

This exists for ADR-0031: a fetch's rails are whole sessions against the
same server, and a serve that drove them one at a time would serialize
the rails it exists to parallelise. The session-failure policy of
`an_unbounded_serve_outlives_a_failed_session` is unchanged, with one
consequence made explicit: a bounded serve accepts its whole bound before
the first failure can surface, because a session's end is detected at its
join rather than at the next accept.

Passing evidence: `sessions_are_served_at_the_same_time` hands the serve
two carriers whose waits meet at a shared rendezvous
(`harness::Rendezvous`, bounded at ten seconds so a deadlock fails the
suite rather than hanging it). The gate fills only if both sessions are
inside their driving loops at once; each then receives its scripted
disconnect and settles. A serve that drives sessions one after another
leaves the first session waiting at the gate forever.

Mutant: `CONCURRENT_SESSIONS` from 8 to 1, which is the sequential loop
by another name.

Observed failure:

```text
thread '<unnamed>' panicked at crates/vot-cli/src/harness.rs:75:9:
the rendezvous never filled: sessions were driven one at a time
thread 'drive::tests::sessions_are_served_at_the_same_time' panicked at crates/vot-cli/src/drive.rs:230:22:
a session thread never panics
test result: FAILED. 0 passed; 1 failed
```
