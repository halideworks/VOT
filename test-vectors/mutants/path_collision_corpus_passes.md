# path_collision_corpus_passes

The corpus is cross-checked against Microsoft Win32 naming rules and Unicode
UTS 39. It includes normalization, Turkish case pairs, reserved device names,
dot compatibility forms, malformed UTF-8, join controls, and bidi overrides.

Mutant:

```diff
-| '\u{200d}'
```

Observed failure:

```text
assertion left == right failed
left: Ok([106, 111, 105, 110, 226, 128, 141, 101, 114])
right: Err(InvalidPath)
test result: FAILED. 0 passed; 1 failed
```
