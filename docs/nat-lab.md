# Rendezvous NAT lab

`tools/nat_lab.sh` creates two NAT sites and an internet between them with Linux
network namespaces, then runs rendezvous, serve, and fetch processes. It uses
an unprivileged user namespace and requires kernel support for that feature.

```sh
cargo build -p vot-cli --features wire
tools/nat_lab.sh --matrix
tools/nat_lab.sh --serve-nat permissive --fetch-nat cone
```

A single run exits 0 for a completed fetch and 1 for a failed fetch. Matrix
runs always exit 0. Harness failures exit 2 and do not produce NAT results.

`--bundle` requires `--root`. Without them, the lab builds a 1 MiB bundle and
uses the root reported by `vot send`.

## What the flavours model

| Flavour | Rules | What it is |
|---|---|---|
| `direct` | none, the site is routed | IPv6, or a host with a public address |
| `cone` | MASQUERADE, unsolicited inbound dropped | a consumer router |
| `permissive` | MASQUERADE, nothing dropped | a router that tracks unsolicited inbound |
| `symmetric` | MASQUERADE `--random-fully`, unsolicited inbound dropped | a router that allocates a fresh external port per flow |

## The matrix

Measured 2026-08-08 on erebus with a 1 MiB bundle and four rails. Times include
rendezvous resolution. The script fixes the rail count for comparable runs.

| Serve | Fetch | Outcome | Elapsed |
|---|---|---|---|
| direct | direct | fetched | 0.63s |
| direct | cone | fetched | 0.62s |
| direct | permissive | fetched | 0.62s |
| direct | symmetric | fetched | 3.59s |
| cone | direct | fetched | 1.15s |
| cone | cone | fetched | 1.14s |
| cone | permissive | fetched | 1.15s |
| cone | symmetric | failed | 17.07s |
| permissive | direct | failed | 15.51s |
| permissive | cone | failed | 17.04s |
| permissive | permissive | failed | 17.04s |
| permissive | symmetric | failed | 17.01s |
| symmetric | direct | failed | 15.51s |
| symmetric | cone | failed | 17.05s |
| symmetric | permissive | failed | 17.02s |
| symmetric | symmetric | failed | 17.07s |

A direct serve is reachable from every fetch. A cone serve is reachable except
from a symmetric fetch. Permissive and symmetric serves are unreachable in
this matrix. All failures return `RendezvousUnpunched` after the punch timeout.
ADR-0034 tries direct routing before NAT traversal and relay fallback.

## The matrix with a relay

Measured 2026-08-10 on erebus with the same bundle, rails, and machine.

| Serve | Fetch | Outcome | Elapsed |
|---|---|---|---|
| direct | direct | fetched | 0.63s |
| direct | cone | fetched | 0.63s |
| direct | permissive | fetched | 0.63s |
| direct | symmetric | fetched | 3.63s |
| cone | direct | fetched | 1.15s |
| cone | cone | fetched | 1.15s |
| cone | permissive | fetched | 1.15s |
| cone | symmetric | fetched | 17.11s |
| permissive | direct | fetched | 15.55s |
| permissive | cone | fetched | 17.07s |
| permissive | permissive | fetched | 17.27s |
| permissive | symmetric | fetched | 17.11s |
| symmetric | direct | fetched | 15.75s |
| symmetric | cone | fetched | 17.11s |
| symmetric | permissive | fetched | 17.07s |
| symmetric | symmetric | fetched | 17.10s |

Every row completes. Direct and punchable routes retain their earlier times.
Other routes incur the 15--17 second punch timeout before relay transfer. The
fetch logs relayed routes as `route ADDRESS relayed`.

## Why a permissive router cannot be punched

Consider a serve at `10.1.0.2:40956` behind MASQUERADE. Rendezvous observes
`192.168.1.2:40956`. The fetch sends its warming packet before the serve has
sent to it, so the packet is unsolicited at the serve router.

If the router drops unsolicited inbound traffic, conntrack does not confirm the
flow and the serve retains external port 40956.

If the router accepts it, conntrack reserves the reply tuple needed by the
serve. The serve warming packet then receives a different external port, while
the fetch continues sending to 40956.

Captured on the serve's WAN, the whole thing in one frame:

```
192.168.1.2.40956 > 192.168.1.1.7777    register, mapping is the socket's port
192.168.1.1.7777  > 192.168.1.2.40956   the service says a fetch is coming
192.168.2.2.48663 > 192.168.1.2.40956   the fetch's warming, unsolicited
192.168.1.2.9738  > 192.168.2.2.48663   the serve's warming, a different port
192.168.2.2.48663 > 192.168.1.2.40956   Initial, and every retry after it
```

ADR-0033 requires both endpoints to send warming packets. The first packet is
unsolicited at the peer router; ordinary routers preserve traversal by dropping
it instead of reserving its tuple.

## Adding a topology

`site NAME LAN_PREFIX WAN_PREFIX FLAVOUR` builds one endpoint namespace behind
one router namespace and puts the router's WAN on the internet. A new flavour
is a new arm of the `case` in `site`. Double NAT is two chained routers and is
not built yet.
