# flow_control_tracks_staging_capacity

Advertised receive credit is calculated directly from remaining staging
capacity, the BDP target, and the configured maximum. There is no second credit
counter to synchronize.

Mutant:

```diff
-self.used = next;
+self.used = bytes;
```

Observed failure:

```text
test tests::flow_credit_is_derived_from_remaining_staging ... FAILED
assertion `left == right` failed
left: 424
right: 24
```

The required mutation run reported 21 caught and 1 unviable transport API
mutants, with no surviving mutant.
