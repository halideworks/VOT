# cross_process_trace_is_identical

CI starts two independent replay processes with different random `RUST_SEED`
values. It compares both canonical trace bytes and the separately written trace
digest. The scoped Clippy configuration also rejects standard randomized hash
maps and sets in the simulator crate.

Mutant:

```diff
-use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
+use std::collections::{BinaryHeap, HashMap, HashSet};
```

Observed failure:

```text
error: use of a disallowed type `std::collections::HashMap`
error: use of a disallowed type `std::collections::HashSet`
```

For changes that preserve compilation but leak process-specific ordering, the
two `cmp` commands are the second independent gate.
