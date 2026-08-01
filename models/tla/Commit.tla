------------------------------ MODULE Commit ------------------------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS InjectUnsafeReceipt, InjectStalePublish, InjectUnsafePublish,
          InjectPoisonAfterPublish, InjectRetrySuccess, InjectRecoverySink,
          InjectUnsupportedAdvance

\* Keep these mappings synchronized with the Rust Event enum. CI verifies that
\* every Rust event names a model action and every named action exists.
\* RUST_EVENT Admit -> Admit
\* RUST_EVENT TransitVerified -> VerifyTransit
\* RUST_EVENT DataFlushSucceeded -> FlushData
\* RUST_EVENT DataFlushFailed -> FlushFailure
\* RUST_EVENT JournalFlushSucceeded -> FlushJournal
\* RUST_EVENT JournalFlushFailed -> FlushFailure
\* RUST_EVENT AtRestVerified -> VerifyAtRest
\* RUST_EVENT AtRestVerificationFailed -> FlushFailure
\* RUST_EVENT NamespaceLinked -> LinkNamespace
\* RUST_EVENT NamespaceLinkAmbiguous -> EnterRecovery
\* RUST_EVENT NamespaceDurable -> Publish
\* RUST_EVENT NamespaceFlushFailed -> EnterRecovery
\* RUST_EVENT Crash -> EnterRecovery
\* RUST_EVENT Recover -> Recover
\* RUST_EVENT Abort -> Abort

Profiles == {"Fast", "Balanced", "Strict"}
Incarnations == {0, 1}
Assurances == {"ADMITTED", "TRANSIT_VERIFIED", "DURABLE", "AT_REST_VERIFIED", "PUBLISHED"}
Terminal == {"PUBLISHED", "POISONED", "ABORTED", "REJECTED_UNSUPPORTED"}
States == {"NEW", "ADMITTED", "TRANSIT_VERIFIED", "DATA_FLUSHED", "DURABLE",
           "AT_REST_VERIFIED", "NAMESPACE_LINKED", "PUBLISHED",
           "RECOVERY_REQUIRED", "POISONED", "ABORTED", "REJECTED_UNSUPPORTED"}

VARIABLES state, profile, supported, current, performed, receipts, recovery,
          flushFailed, rejectedRetries, staleAttempts, staleRejected,
          unsupportedRejected

vars == <<state, profile, supported, current, performed, receipts, recovery,
          flushFailed, rejectedRetries, staleAttempts, staleRejected,
          unsupportedRejected>>

Required(p) ==
    CASE p = "Fast" -> "TRANSIT_VERIFIED"
      [] p = "Balanced" -> "DURABLE"
      [] p = "Strict" -> "AT_REST_VERIFIED"

Observation(i, level) == [incarnation |-> i, assurance |-> level]

Init ==
    /\ state = [i \in Incarnations |-> "NEW"]
    /\ profile \in Profiles
    /\ supported \in SUBSET Profiles
    /\ current = 0
    /\ performed = [i \in Incarnations |-> {}]
    /\ receipts = {}
    /\ recovery = [i \in Incarnations |-> "NEW"]
    /\ flushFailed = {}
    /\ rejectedRetries = {}
    /\ staleAttempts = {}
    /\ staleRejected = {}
    /\ unsupportedRejected = {}

Step(i, from, to, assurance) ==
    /\ i = current
    /\ state[i] = from
    /\ state' = [state EXCEPT ![i] = to]
    /\ performed' = [performed EXCEPT ![i] = @ \cup {assurance}]
    /\ UNCHANGED <<profile, supported, current, receipts, recovery, flushFailed,
                    rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

Admit(i) ==
    /\ profile \in supported
    /\ Step(i, "NEW", "ADMITTED", "ADMITTED")

RejectUnsupported(i) ==
    /\ i = current
    /\ state[i] = "NEW"
    /\ profile \notin supported
    /\ state' = [state EXCEPT ![i] = "REJECTED_UNSUPPORTED"]
    /\ unsupportedRejected' = unsupportedRejected \cup {i}
    /\ UNCHANGED <<profile, supported, current, performed, receipts, recovery,
                    flushFailed, rejectedRetries, staleAttempts, staleRejected>>
VerifyTransit(i) == Step(i, "ADMITTED", "TRANSIT_VERIFIED", "TRANSIT_VERIFIED")

FlushData(i) ==
    /\ i = current
    /\ state[i] = "TRANSIT_VERIFIED"
    /\ state' = [state EXCEPT ![i] = "DATA_FLUSHED"]
    /\ UNCHANGED <<profile, supported, current, performed, receipts, recovery, flushFailed,
                    rejectedRetries, staleAttempts, staleRejected, unsupportedRejected>>

FlushJournal(i) == Step(i, "DATA_FLUSHED", "DURABLE", "DURABLE")
VerifyAtRest(i) == Step(i, "DURABLE", "AT_REST_VERIFIED", "AT_REST_VERIFIED")

LinkNamespace(i) ==
    /\ i = current
    /\ state[i] = Required(profile)
    /\ state' = [state EXCEPT ![i] = "NAMESPACE_LINKED"]
    /\ UNCHANGED <<profile, supported, current, performed, receipts, recovery,
                    flushFailed, rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

Publish(i) ==
    /\ i = current
    /\ state[i] = "NAMESPACE_LINKED"
    /\ Required(profile) \in performed[i]
    /\ state' = [state EXCEPT ![i] = "PUBLISHED"]
    /\ performed' = [performed EXCEPT ![i] = @ \cup {"PUBLISHED"}]
    /\ UNCHANGED <<profile, supported, current, receipts, recovery, flushFailed,
                    rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

EmitReceipt(i, level) ==
    /\ i = current
    /\ level \in Assurances
    /\ Observation(i, level) \notin receipts
    /\ \/ level \in performed[i]
       \/ InjectUnsafeReceipt
    /\ receipts' = receipts \cup {Observation(i, level)}
    /\ UNCHANGED <<state, profile, supported, current, performed, recovery,
                    flushFailed, rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

FlushFailure(i, from) ==
    /\ i = current
    /\ state[i] = from
    /\ state' = [state EXCEPT ![i] = "POISONED"]
    /\ flushFailed' = flushFailed \cup {i}
    /\ UNCHANGED <<profile, supported, current, performed, receipts, recovery,
                    rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

RetryFailedFlush(i) ==
    /\ i = current
    /\ i \in flushFailed
    /\ i \notin rejectedRetries
    /\ state[i] = "POISONED"
    /\ rejectedRetries' = rejectedRetries \cup {i}
    /\ UNCHANGED <<state, profile, supported, current, performed, receipts,
                    recovery, flushFailed, staleAttempts, staleRejected,
                    unsupportedRejected>>

EnterRecovery(i) ==
    /\ i = current
    /\ state[i] \notin Terminal \cup {"RECOVERY_REQUIRED"}
    /\ recovery' = [recovery EXCEPT ![i] = state[i]]
    /\ state' = [state EXCEPT ![i] = "RECOVERY_REQUIRED"]
    /\ UNCHANGED <<profile, supported, current, performed, receipts, flushFailed,
                    rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

Recover(i) ==
    /\ i = current
    /\ ~InjectRecoverySink
    /\ state[i] = "RECOVERY_REQUIRED"
    /\ recovery[i] \in States \ {"RECOVERY_REQUIRED"}
    /\ state' = [state EXCEPT ![i] = recovery[i]]
    /\ UNCHANGED <<profile, supported, current, performed, receipts, recovery,
                    flushFailed, rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

Abort(i) ==
    /\ i = current
    /\ state[i] \notin Terminal \cup {"RECOVERY_REQUIRED", "NAMESPACE_LINKED"}
    /\ state' = [state EXCEPT ![i] = "ABORTED"]
    /\ UNCHANGED <<profile, supported, current, performed, receipts, recovery,
                    flushFailed, rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

RotateIncarnation ==
    /\ current = 0
    /\ state[0] \notin Terminal \cup {"RECOVERY_REQUIRED"}
    /\ current' = 1
    /\ UNCHANGED <<state, profile, supported, performed, receipts, recovery,
                    flushFailed, rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

RejectStalePublish(i) ==
    /\ i # current
    /\ state[i] = "NAMESPACE_LINKED"
    /\ i \notin staleAttempts
    /\ staleAttempts' = staleAttempts \cup {i}
    /\ staleRejected' = staleRejected \cup {i}
    /\ UNCHANGED <<state, profile, supported, current, performed, receipts,
                    recovery, flushFailed, rejectedRetries, unsupportedRejected>>

UnsafeStalePublish(i) ==
    /\ InjectStalePublish
    /\ i # current
    /\ state[i] = "NAMESPACE_LINKED"
    /\ i \notin staleAttempts
    /\ staleAttempts' = staleAttempts \cup {i}
    /\ state' = [state EXCEPT ![i] = "PUBLISHED"]
    /\ performed' = [performed EXCEPT ![i] = @ \cup {"PUBLISHED"}]
    /\ UNCHANGED <<profile, supported, current, receipts, recovery, flushFailed,
                    rejectedRetries, staleRejected, unsupportedRejected>>

UnsafePublishWithoutPredecessor(i) ==
    /\ InjectUnsafePublish
    /\ i = current
    /\ state[i] = "NEW"
    /\ state' = [state EXCEPT ![i] = "PUBLISHED"]
    /\ performed' = [performed EXCEPT ![i] = @ \cup {"PUBLISHED"}]
    /\ UNCHANGED <<profile, supported, current, receipts, recovery, flushFailed,
                    rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

UnsafePoisonAfterPublish(i) ==
    /\ InjectPoisonAfterPublish
    /\ i = current
    /\ state[i] = "PUBLISHED"
    /\ state' = [state EXCEPT ![i] = "POISONED"]
    /\ UNCHANGED <<profile, supported, current, performed, receipts, recovery,
                    flushFailed, rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

UnsafeRetrySuccess(i) ==
    /\ InjectRetrySuccess
    /\ i = current
    /\ i \in flushFailed
    /\ state[i] = "POISONED"
    /\ state' = [state EXCEPT ![i] = "PUBLISHED"]
    /\ performed' = [performed EXCEPT ![i] = @ \cup {"PUBLISHED"}]
    /\ UNCHANGED <<profile, supported, current, receipts, recovery, flushFailed,
                    rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

UnsafeUnsupportedAdvance(i) ==
    /\ InjectUnsupportedAdvance
    /\ i = current
    /\ state[i] = "NEW"
    /\ profile \notin supported
    /\ state' = [state EXCEPT ![i] = "PUBLISHED"]
    /\ performed' = [performed EXCEPT ![i] = @ \cup {"PUBLISHED"}]
    /\ UNCHANGED <<profile, supported, current, receipts, recovery, flushFailed,
                    rejectedRetries, staleAttempts, staleRejected,
                    unsupportedRejected>>

TerminalStutter ==
    /\ state[current] \in Terminal
    /\ UNCHANGED vars

Next ==
    \/ \E i \in Incarnations : Admit(i) \/ RejectUnsupported(i)
                                \/ VerifyTransit(i) \/ FlushData(i)
                                \/ FlushJournal(i) \/ VerifyAtRest(i)
                                \/ LinkNamespace(i) \/ Publish(i)
                                \/ FlushFailure(i, "TRANSIT_VERIFIED")
                                \/ FlushFailure(i, "DATA_FLUSHED")
                                \/ FlushFailure(i, "DURABLE")
                                \/ RetryFailedFlush(i) \/ EnterRecovery(i)
                                \/ Recover(i) \/ Abort(i)
                                \/ RejectStalePublish(i) \/ UnsafeStalePublish(i)
                                \/ UnsafePublishWithoutPredecessor(i)
                                \/ UnsafePoisonAfterPublish(i) \/ UnsafeRetrySuccess(i)
                                \/ UnsafeUnsupportedAdvance(i)
                                \/ \E level \in Assurances : EmitReceipt(i, level)
    \/ RotateIncarnation
    \/ TerminalStutter

TypeOK ==
    /\ state \in [Incarnations -> States]
    /\ profile \in Profiles
    /\ supported \subseteq Profiles
    /\ current \in Incarnations
    /\ performed \in [Incarnations -> SUBSET Assurances]
    /\ receipts \subseteq {Observation(i, level) : i \in Incarnations, level \in Assurances}
    /\ recovery \in [Incarnations -> States]
    /\ flushFailed \subseteq Incarnations
    /\ rejectedRetries \subseteq Incarnations
    /\ staleAttempts \subseteq Incarnations
    /\ staleRejected \subseteq Incarnations
    /\ unsupportedRejected \subseteq Incarnations

PublishedHasPredecessor ==
    \A i \in Incarnations : state[i] = "PUBLISHED" => Required(profile) \in performed[i]

ReceiptWasPerformed ==
    \A receipt \in receipts : receipt.assurance \in performed[receipt.incarnation]

PoisonedNeverPublished ==
    \A i \in Incarnations : state[i] = "POISONED" => "PUBLISHED" \notin performed[i]

FailedFlushNeverAdvances ==
    \A i \in flushFailed : state[i] = "POISONED" /\ "PUBLISHED" \notin performed[i]

StaleAttemptsRejected == staleAttempts \subseteq staleRejected

StaleNeverPublished ==
    \A i \in Incarnations : i # current => "PUBLISHED" \notin performed[i]

UnsupportedNeverAdvanced ==
    profile \notin supported => \A i \in Incarnations : performed[i] = {}

RecoveryEventuallyProgresses ==
    \A i \in Incarnations : state[i] = "RECOVERY_REQUIRED" ~> state[i] # "RECOVERY_REQUIRED"

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A i \in Incarnations : WF_vars(Recover(i))

=============================================================================
