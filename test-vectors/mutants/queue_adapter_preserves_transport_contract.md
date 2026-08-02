# queue_adapter_preserves_transport_contract

The queue adapter preserves the transport command order and keeps VOT bytes
unchanged. This is a unit-level contract test; the feature-gated live test is
tracked separately as `localhost_reliable_stream_round_trip`.

Mutant:

```diff
-self.commands.push_back(Command::Reliable { stream, bytes: record.to_vec() });
+return Ok(());
```

Observed failure:

```text
test tests::queue_adapter_preserves_transport_contract ... FAILED
assertion `left == right` failed
left: Some(ReceiveCredit(4096))
right: Some(Reliable { stream: StreamId(2), bytes: [...] })
```

The required bridge mutation run reported 13 caught and 2 unviable mutants,
with no surviving mutant.
