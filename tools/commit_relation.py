#!/usr/bin/env python3
"""The commit transition relation, read from spec/commit.md.

One independent implementation, used by both the fixture executor and the
exhaustive cross-check. Two copies is what the two of them had, and they had
already drifted: the fixture one carried no `Abort` branch at all, so it
called a legal abort an invalid transition and nothing noticed, because no
fixture aborts.

Independent of the Rust model on purpose. That is the whole point of
comparing them; sharing this between the two Python callers costs nothing of
that, because neither of them is the Rust side.
"""

TERMINAL = {"Published", "Poisoned", "Aborted"}
# The assurance a profile must have performed before it can publish, and the
# only state it may link a namespace from.
REQUIRED = {"Fast": "TransitVerified", "Balanced": "Durable", "Strict": "AtRestVerified"}
POISONING = {"DataFlushFailed", "JournalFlushFailed", "AtRestVerificationFailed"}
RECOVERING = {"NamespaceLinkAmbiguous", "NamespaceFlushFailed", "Crash"}
ABORTABLE = {
    "New",
    "Admitted",
    "TransitVerified",
    "DataFlushed",
    "Durable",
    "AtRestVerified",
}
ADVANCES = {
    ("New", "Admit"): ("Admitted", "Admitted"),
    ("Admitted", "TransitVerified"): ("TransitVerified", "TransitVerified"),
    ("TransitVerified", "DataFlushSucceeded"): ("DataFlushed", None),
    ("DataFlushed", "JournalFlushSucceeded"): ("Durable", "Durable"),
    ("Durable", "AtRestVerified"): ("AtRestVerified", "AtRestVerified"),
    ("NamespaceLinked", "NamespaceDurable"): ("Published", "Published"),
}


def step(profile, state, event, recovery, performed, current=True):
    """What the machine does with `event`.

    Returns (error, next_state, next_recovery_state, observation,
    next_performed). A rejection leaves everything as it was, which is the
    property both callers exist to hold the model to.
    """
    unchanged = (state, recovery, None, performed)

    if not current:
        return ("StaleIncarnation", *unchanged)
    if state in TERMINAL:
        return ("Terminal", *unchanged)

    if event == "Recover":
        if state != "RecoveryRequired" or recovery is None:
            return ("InvalidTransition", *unchanged)
        return (None, recovery, None, None, performed)
    if event in POISONING:
        return (None, "Poisoned", recovery, None, performed)
    if event in RECOVERING:
        if state == "RecoveryRequired":
            return ("InvalidTransition", *unchanged)
        return (None, "RecoveryRequired", state, None, performed)
    if event == "Abort":
        if state not in ABORTABLE:
            return ("InvalidTransition", *unchanged)
        return (None, "Aborted", recovery, None, performed)
    if event == "NamespaceLinked":
        if state != REQUIRED[profile]:
            return ("InvalidTransition", *unchanged)
        return (None, "NamespaceLinked", recovery, None, performed)

    advance = ADVANCES.get((state, event))
    if advance is None:
        return ("InvalidTransition", *unchanged)
    next_state, observation = advance
    if observation == "Published" and REQUIRED[profile] not in performed:
        return ("MissingPredecessor", *unchanged)
    recorded = performed + [observation] if observation else performed
    return (None, next_state, recovery, observation, recorded)
