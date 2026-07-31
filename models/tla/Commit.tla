------------------------------ MODULE Commit ------------------------------
EXTENDS Naturals, FiniteSets, TLC

Profiles == {"Fast", "Balanced", "Strict"}
Assurances == {"ADMITTED", "TRANSIT_VERIFIED", "DURABLE", "AT_REST_VERIFIED", "PUBLISHED"}
Terminal == {"PUBLISHED", "POISONED", "ABORTED"}

VARIABLES state, profile, current, performed, receipts
vars == <<state, profile, current, performed, receipts>>

Required(p) ==
    CASE p = "Fast" -> "TRANSIT_VERIFIED"
      [] p = "Balanced" -> "DURABLE"
      [] p = "Strict" -> "AT_REST_VERIFIED"

Init ==
    /\ state = "NEW"
    /\ profile \in Profiles
    /\ current = TRUE
    /\ performed = {}
    /\ receipts = {}

Step(from, to, assurance) ==
    /\ current
    /\ state = from
    /\ state' = to
    /\ performed' = performed \cup {assurance}
    /\ receipts' = receipts \cup {assurance}
    /\ UNCHANGED <<profile, current>>

Admit == Step("NEW", "ADMITTED", "ADMITTED")
VerifyTransit == Step("ADMITTED", "TRANSIT_VERIFIED", "TRANSIT_VERIFIED")

FlushData ==
    /\ current /\ state = "TRANSIT_VERIFIED"
    /\ state' = "DATA_FLUSHED"
    /\ UNCHANGED <<profile, current, performed, receipts>>

FlushJournal == Step("DATA_FLUSHED", "DURABLE", "DURABLE")
VerifyAtRest == Step("DURABLE", "AT_REST_VERIFIED", "AT_REST_VERIFIED")

LinkNamespace ==
    /\ current /\ state = Required(profile)
    /\ state' = "NAMESPACE_LINKED"
    /\ UNCHANGED <<profile, current, performed, receipts>>

Publish ==
    /\ current /\ state = "NAMESPACE_LINKED"
    /\ Required(profile) \in performed
    /\ state' = "PUBLISHED"
    /\ performed' = performed \cup {"PUBLISHED"}
    /\ receipts' = receipts \cup {"PUBLISHED"}
    /\ UNCHANGED <<profile, current>>

Poison ==
    /\ current /\ state \notin Terminal
    /\ state' = "POISONED"
    /\ UNCHANGED <<profile, current, performed, receipts>>

Crash ==
    /\ current /\ state \notin Terminal
    /\ state' = "RECOVERY_REQUIRED"
    /\ UNCHANGED <<profile, current, performed, receipts>>

Abort ==
    /\ current /\ state \in {"NEW", "ADMITTED", "TRANSIT_VERIFIED", "DATA_FLUSHED", "DURABLE", "AT_REST_VERIFIED"}
    /\ state' = "ABORTED"
    /\ UNCHANGED <<profile, current, performed, receipts>>

MakeStale ==
    /\ current /\ state \notin Terminal
    /\ current' = FALSE
    /\ UNCHANGED <<state, profile, performed, receipts>>

Next == Admit \/ VerifyTransit \/ FlushData \/ FlushJournal \/ VerifyAtRest
        \/ LinkNamespace \/ Publish \/ Poison \/ Crash \/ Abort \/ MakeStale

PublishedHasPredecessor == state = "PUBLISHED" => Required(profile) \in performed
ReceiptWasPerformed == receipts \subseteq performed
PoisonedNeverPublished == state = "POISONED" => "PUBLISHED" \notin performed
StaleNeverPublished == ~current => state # "PUBLISHED"

Spec == Init /\ [][Next]_vars

=============================================================================
