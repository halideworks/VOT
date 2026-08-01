# no_real_sleep

Simulator code denies ambient clock, sleep methods, `HashMap`, and `HashSet`
through `crates/vot-transport-sim/clippy.toml`. CI supplies that directory only
to the simulator Clippy invocation, so unrelated workspace crates can use hash
containers without weakening the simulator rule. A direct CI source guard also
rejects sleep calls.

Mutant:

```diff
 pub fn new(seed: u64) -> Self {
+    std::thread::sleep(std::time::Duration::ZERO);
```

Observed CI guard failure:

```text
crates/vot-transport-sim/src/lib.rs:679:        std::thread::sleep(std::time::Duration::ZERO);
```

The guard exited with status 1 and the mutant was removed.
