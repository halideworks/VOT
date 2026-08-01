# buffered_control_demonstrably_does_not

The same one-line mutant and captured failure are recorded in
`strict_catches_backing_corruption.md`. Removing `O_DIRECT` makes the strict
arm use the page cache, exactly like the control, and the test rejects it with:

```text
direct read returned cached bytes instead of backing corruption
```
