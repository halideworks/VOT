# network_and_storage_faults_composable

The stored scenario combines reordering, a loss burst, and a journal queue
fault. The test requires both the network-loss trace entry and the final journal
queue failure.

Mutant:

```diff
-at 3 queue-fault journal 1
+# mutant removed the storage fault
```

Observed failure:

```text
tests::network_and_storage_faults_compose --- FAILED
left: Complete { published: 1 }
right: Failed(QueueFault { queue: Journal })
```

The fault was restored and the scenario passed with its archived digest.
