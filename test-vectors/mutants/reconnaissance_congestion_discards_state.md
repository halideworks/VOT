# Reconnaissance congestion discards state

Criterion: congestion observed during a Careful Resume reconnaissance flight
invalidates the saved congestion-control parameters.

Passing evidence: `reconnaissance_congestion_discards_saved_state` exercises
both acknowledged and unacknowledged reconnaissance samples containing
congestion. Both return `Congestion`, and the next attempt is `Unknown`.

Mutant: check `initial_flight_acknowledged` before
`congestion_detected`, or return `Congestion` without removing the entry.

Observed failure:

```text
left: Err(InitialFlightUnacknowledged)
right: Err(Congestion)
```

The required `vot-resume` mutation run reports 153 total, 146 caught, 7
unviable, and 0 missed.
