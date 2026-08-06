# VOT

Verified Object Transport is a protocol and implementation for transferring
immutable objects and publishing them with explicit receiver assurance.

The project is in early development. The v0.3 specifications are in `spec/`.
Implementation order and acceptance gates are defined in
`VOT_v0.3_Agent_Backlog.yaml`.

## Documentation

- [Validation](docs/validation.md) lists every check and what each one covers.
- [Sessions and negotiation](docs/session.md) describes the handshake, what
  readiness does and does not mean, and how lanes are identified.
- Decisions and their reasoning are in `adr/`.

The quickest useful check is:

```sh
cargo test --workspace --locked
```

## Package transfer

Build a deterministic transfer bundle:

```sh
cargo run -p vot-cli -- send SOURCE_DIRECTORY BUNDLE_DIRECTORY
```

It prints the package root and the logical length: `ROOT LENGTH`. That root
is what a fetch can be pinned to, so it is worth keeping.

An explicit logical-object suite can be selected with:

```sh
cargo run -p vot-cli -- send SUITE SOURCE_DIRECTORY BUNDLE_DIRECTORY
```

SUITE is `blake3` or `sha256`; the default is `sha256`.

Verify and publish a bundle, then write an authenticated receipt:

```sh
cargo run -p vot-cli -- receive BUNDLE_DIRECTORY DESTINATION_DIRECTORY RECEIPT.cbor KEY_SOURCE 2026-07-31T20:00:00Z
```

The last argument is when the receiver observed the bundle, as an RFC 3339
timestamp. It prints `ROOT LENGTH PUBLISHED`, and refuses to replace an
existing destination or receipt.

Check a receipt without the bundle:

```sh
cargo run -p vot-cli -- verify-receipt RECEIPT.cbor KEY_SOURCE
```

It prints `ROOT LENGTH ASSURANCE` and then either `THIRD-PARTY-VERIFIABLE` or
`SHARED-SECRET`, which is the difference the [Keys](#keys) section describes.

## Over the wire

The wire commands need a build with the `wire` feature, which carries a QUIC
endpoint and builds BoringSSL through cmake to get one. Without it they report
the feature they need rather than failing as though the arguments were wrong:

```sh
cargo run -p vot-cli --features wire -- serve BUNDLE_DIRECTORY 0.0.0.0:4433
```

`serve` answers sessions from one bundle, one at a time, until it is stopped.
It prints `listening ADDRESS` whenever it is ready for the next one, which is
also how a caller that asked for port zero learns what it got. It presents a
throwaway certificate; a real one can be given instead:

```sh
cargo run -p vot-cli --features wire -- serve BUNDLE_DIRECTORY 0.0.0.0:4433 CERT.pem KEY.pem
```

`fetch` writes a bundle directory that `receive` then consumes unchanged:

```sh
cargo run -p vot-cli --features wire -- fetch SERVER:4433 BUNDLE_DIRECTORY [PACKAGE_ROOT]
```

`pull` is the two in one invocation, for the common case:

```sh
cargo run -p vot-cli --features wire -- pull SERVER:4433 BUNDLE_DIRECTORY DESTINATION_DIRECTORY RECEIPT.cbor KEY_SOURCE 2026-07-31T20:00:00Z [PACKAGE_ROOT]
```

`fetch` prints `ROOT LENGTH FETCHED` and `pull` prints `ROOT LENGTH PUBLISHED`,
the same line `receive` gives.

The channel is **not** authenticated. The server presents a throwaway
certificate and the client does not verify it, so anyone in the middle can see
what you fetch and can refuse to serve it. What they cannot do is give you
different bytes: every range proves to its object's root, every root is named
by the manifest, and the manifest proves to the seal. The optional
PACKAGE_ROOT, as printed by `send`, says which package you will accept, and a
fetch given one takes nothing else.

`cargo run -p vot-cli -- help` prints the exhaustive argument reference.

## Keys

KEY_SOURCE says where to read the key from: `env:NAME`, `-` for standard input,
or a file path. What it reads decides the kind of key:

| Contents | Meaning |
| --- | --- |
| `ed25519-secret:HEX` | signs; 64 hex characters. `receive` and `pull` only |
| `ed25519-public:HEX` | checks a signature; 64 hex characters |
| `hex:HEX` | shared secret, 32 to 64 bytes |
| `raw:TEXT` | shared secret as text |
| anything else | shared secret as raw bytes, 32 to 64 bytes |

An Ed25519 key is labelled because a secret and a public key are both 32 bytes,
and using one as the other would either leak the secret or produce receipts
nobody can check.

A receipt signed with `ed25519-secret` can be checked by anyone holding only the
matching `ed25519-public` key, and `verify-receipt` reports
`THIRD-PARTY-VERIFIABLE`. A shared secret cannot: whoever can check it can also
forge it, so those report `SHARED-SECRET`.

An auditor holding only the public key can run `verify-receipt`, but not
`receive`, which has to sign. The one exception is finishing a publication that
was interrupted after its receipt was already signed.

## License

The Rust implementation and project files are licensed under
AGPL-3.0-only. The protocol specifications, test vectors, and formal models in
`spec/`, `test-vectors/`, and `models/` are licensed under Apache-2.0. See
`LICENSE`, `LICENSE-APACHE`, and the license marker in each permissive directory.
