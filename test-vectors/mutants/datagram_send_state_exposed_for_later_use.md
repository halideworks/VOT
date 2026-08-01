# datagram_send_state_exposed_for_later_use

Every native MsQuic datagram send state maps to a backend-neutral VOT event with
its application context retained.

Mutant:

```diff
-NativeDatagramSendState::LostSuspect => DatagramSendState::SuspectedLost,
+NativeDatagramSendState::LostSuspect => DatagramSendState::Sent,
```

Observed failure:

```text
test tests::datagram_send_state_is_exposed_for_later_use ... FAILED
assertion `left == right` failed
left: Some(DatagramState { context: 77, state: Sent })
right: Some(DatagramState { context: 77, state: SuspectedLost })
```
