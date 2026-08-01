# Inbound transport events are bounded

Criterion: native transport callbacks cannot enqueue unbounded memory or pass
an oversized VOT record across the backend-neutral boundary.

Passing evidence: `inbound_events_apply_record_count_and_byte_backpressure`
and `inbound_queue_applies_record_count_and_byte_backpressure` exercise TCP and
MsQuic respectively. Both accept exact control and queue-byte limits, reject
the next byte, reject a full event count, reject oversized reliable records,
and return queued byte credit when an event is polled.

Mutants: omit the configured inbound byte limit, accept an exact control limit
only as oversized, remove the event count or byte comparison, stop accounting
payload bytes, or skip reliable-record validation.

Observed failure:

```text
expected InboundQueueFull, received Ok(())
expected exact-limit Control event, received RecordTooLarge
oversized inbound Reliable event was queued
```

The required `vot-transport-tcp` run reports 90 total, 81 caught, 9 unviable,
and 0 missed. The required `vot-transport-msquic` run reports 45 total, 43
caught, 2 unviable, and 0 missed. The shared `vot-transport-api` run reports 22
total, 21 caught, 1 unviable, and 0 missed.
