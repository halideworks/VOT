# Checkpoint window blocks completion

Criterion: completed uncheckpointed units never exceed the configured
checkpoint window, including while another unit is already active.

Passing evidence: `full_window_blocks_completion_until_checkpoint_succeeds`
fills a two-unit window, proves a third active unit cannot complete, persists
the checkpoint, and then completes the retained active unit.

Mutant: remove the full-window check from `ResumeTracker::complete_unit`.

Observed failure:

```text
expected CheckpointRequired, received Ok(true)
```

The required `vot-resume` mutation run reports 144 total, 137 caught, 7
unviable, and 0 missed.
