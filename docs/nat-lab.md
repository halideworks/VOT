# Rendezvous NAT lab

`tools/nat_lab.sh` builds two NAT'd sites and an internet between them out of
Linux network namespaces, runs a rendezvous service, a serve, and a fetch
across them, and reports whether the fetch completed.

It needs no root. It runs inside an unprivileged user namespace, where the
caller is root for the namespaces it creates and nothing else. A kernel with
unprivileged user namespaces disabled cannot run it, and it says so.

```sh
cargo build -p vot-cli --features wire
tools/nat_lab.sh --matrix
tools/nat_lab.sh --serve-nat permissive --fetch-nat cone
```

## What the flavours model

| Flavour | Rules | What it is |
|---|---|---|
| `direct` | none, the site is routed | IPv6, or a host with a public address |
| `cone` | MASQUERADE, unsolicited inbound dropped | a consumer router |
| `permissive` | MASQUERADE, nothing dropped | a router that tracks unsolicited inbound |
| `symmetric` | MASQUERADE `--random-fully`, unsolicited inbound dropped | a router that allocates a fresh external port per flow |

`cone` and `permissive` differ by one pair of filter rules and behave very
differently, which is the lab's main result. See below.

## The matrix

Measured 2026-08-08 on erebus, a 256 KiB bundle, one rail. Times are the whole
fetch including resolve.

| Serve | Fetch | Outcome | Elapsed |
|---|---|---|---|
| direct | direct | fetched | 0.62s |
| direct | cone | fetched | 0.62s |
| direct | permissive | fetched | 0.63s |
| direct | symmetric | fetched | 3.64s |
| cone | direct | fetched | 1.15s |
| cone | cone | fetched | 1.15s |
| cone | permissive | fetched | 1.15s |
| cone | symmetric | failed | 17.01s |
| permissive | any | failed | 15-17s |
| symmetric | any | failed | 15-17s |

Two things fall out of it.

**The serve side decides.** A serve that is `direct` is reachable from every
fetch, symmetric included. A serve that is `cone` is reachable from every
fetch except a symmetric one. A serve that is `permissive` or `symmetric` is
reachable from nothing, not even a fetch with no NAT at all. This is why
ADR-0034 tries a direct route before the punch, and why the relay is the
answer for the rest.

**Every failure is the named one.** `RendezvousUnpunched` after the punch
wait, never a hang and never a wrong-bytes result.

## Why a permissive router cannot be punched

This is the lab's finding, and it explains punch failures that look random.

Take a serve whose socket is `10.1.0.2:40956` behind a MASQUERADE router. It
registers, and the service observes `192.168.1.2:40956`: conntrack kept the
source port because it was free. The fetch resolves that mapping and sends its
warming toward it. The serve has not sent anything to the fetch yet, so at the
serve's router that datagram is unsolicited.

On a router that drops unsolicited inbound, nothing happens. A dropped
packet's conntrack entry is never confirmed. When the serve's own warming goes
out moments later, `192.168.1.2:40956` is still free and the mapping holds.

On a router that does not drop it, conntrack records the flow
`192.168.2.2:48663 -> 192.168.1.2:40956`. Nothing is translated, because the
destination is the router's own address, so the packet goes to the router's
stack and dies there. But the entry is confirmed, and its reply tuple is
exactly `192.168.1.2:40956 -> 192.168.2.2:48663`, which is the mapping the
serve's warming needs. NAT cannot reuse it, so the warming leaves as
`192.168.1.2:9738`. The fetch's Initial keeps going to 40956, where the
router, not the serve, is listening.

Captured on the serve's WAN, the whole thing in one frame:

```
192.168.1.2.40956 > 192.168.1.1.7777    register, mapping is the socket's port
192.168.1.1.7777  > 192.168.1.2.40956   the service says a fetch is coming
192.168.2.2.48663 > 192.168.1.2.40956   the fetch's warming, unsolicited
192.168.1.2.9738  > 192.168.2.2.48663   the serve's warming, a different port
192.168.2.2.48663 > 192.168.1.2.40956   Initial, and every retry after it
```

The fetch warms first on purpose: ADR-0033 step 4 made both ends send, because
a fetch that receives before it has sent loses its own mapping the same way.
Whichever end sends first, its packet is unsolicited at the other end. What
saves the exchange on ordinary routers is that they drop it rather than track
it.

## Adding a topology

`site NAME LAN_PREFIX WAN_PREFIX FLAVOUR` builds one endpoint namespace behind
one router namespace and puts the router's WAN on the internet. A new flavour
is a new arm of the `case` in `site`. Double NAT is two chained routers and is
not built yet.

The lab found one defect that has nothing to do with NAT: a serve wrote its
ephemeral credentials to a directory named from its process ID, and inside a
PID namespace that number repeats every run, so the second run failed to
start. The name is 128 random bits now, and the lab needs no workaround.
