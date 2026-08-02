# reliable_transfer_uses_transport_adapter_contract

The deterministic simulator scenario and the loopback `SimulatorAdapter` both
feed the scheduler's receiver, which verifies the declared object root.

Mutant:

```diff
-self.verified.insert(subject);
+return Ok(());
```

Observed failure:

```text
test tests::reliable_transfer_uses_transport_adapter_contract ... FAILED
assertion failed: receiver.is_verified(subject)
```

The required mutation runs reported 28 caught and 4 unviable scheduler mutants,
with no surviving mutant.
