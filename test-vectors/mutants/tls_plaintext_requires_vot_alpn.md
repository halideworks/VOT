# TLS plaintext requires VOT ALPN

Criterion: authenticated TLS exposes VOT plaintext only after the peer selects
the `vot-draft-05` application protocol.

Passing evidence: `completed_tls_without_vot_alpn_exposes_no_plaintext`
completes a certificate-authenticated handshake against a server that omits
ALPN, then proves both plaintext read and write remain blocked.

Mutant:

```diff
-!connection.is_handshaking() && connection.alpn_protocol() == Some(ALPN)
+!connection.is_handshaking()
```

Observed failure:

```text
assertion failed: !client.is_authenticated()
```

The required `vot-transport-tcp` mutation run reports 90 total, 81 caught, 9
unviable, and 0 missed.
