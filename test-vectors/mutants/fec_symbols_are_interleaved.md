# FEC symbols are interleaved

A coded piece sends one ESI from every active generation before sending the
next ESI, so one adjacent datagram-loss burst is spread across generations.

Mutant:

```diff
-for esi in 0..plan.geometry().symbol_count() {
-    for (generation, symbols) in &mut coded {
+for (generation, symbols) in &mut coded {
+    for esi in 0..plan.geometry().symbol_count() {
```

Observed failure:

```text
test serve::tests::a_negotiated_credited_session_is_answered_over_the_datagram_path ... FAILED
left: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
right: [0, 1, 2, 3, 4, 0, 1, 2, 3, 4]
```
