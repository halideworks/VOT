# versioned_failure_trace_archived

Stored scenarios and failure traces begin with an explicit V1 schema marker.
The parser accepts only that version, and replay tests compare stored trace
digests or exact canonical trace text.

Mutant:

```diff
-VOT_SIM_SCENARIO_V1
+VOT_SIM_SCENARIO_V2
```

Observed failure:

```text
tests::public_scenarios_round_trip --- FAILED
called `Result::unwrap()` on an `Err` value: InvalidHeader
```

The supported V1 marker was restored.
