#!/bin/sh
# Rendezvous NAT topology lab.
#
# Builds two NAT'd sites and an "internet" between them out of Linux network
# namespaces, runs a rendezvous service, a serve, and a fetch across them, and
# reports whether the fetch completed. The point is the matrix: which NAT
# behaviours a punch can cross and which it cannot.
#
# No root. It runs inside an unprivileged user namespace, where the caller is
# root for the namespaces it creates and nothing else. A kernel with
# unprivileged user namespaces disabled cannot run this.
#
#   tools/nat_lab.sh --matrix
#   tools/nat_lab.sh --serve-nat symmetric --fetch-nat cone
#   tools/nat_lab.sh --bundle path/to/bundle --root <hex>
#
# Options:
#   --serve-nat, --fetch-nat  the flavour at each end, cone by default
#   --binary                  the vot-cli to run, target/debug/vot-cli by default
#   --bundle, --root          a bundle to move and the root it publishes.
#                             Both or neither: without them the lab builds a
#                             1 MiB bundle of its own and reads the root off
#                             the send that built it.
#   --matrix                  every flavour against every flavour
#
# Exit status: 0 when the fetch completed, 1 when it did not, 2 when the rig
# itself failed. A matrix is a report, so it exits 0 whatever the rows say.
#
# NAT flavours:
#   direct      no translation, the site is routable. Models IPv6.
#   cone        MASQUERADE, and unsolicited inbound dropped. conntrack keeps
#               the source port when it is free, so the mapping is the same
#               whoever the destination is. A consumer router.
#   permissive  MASQUERADE with nothing dropped. Not a lax router: a router
#               that tracks an unsolicited inbound datagram records a flow
#               whose reply tuple is the very mapping the punch needs, and
#               the next outbound to that peer is given a different port.
#               This is the topology in which a punch cannot complete even
#               though both mappings are endpoint independent.
#   symmetric   MASQUERADE --random-fully. A fresh external port per flow, so
#               the mapping the service observed is not the one the session
#               leaves under. No punch can cross this.
#
# Addresses. The unshare's own namespace is the internet and holds the
# service:
#
#   serve 10.1.0.2 -- nat-s 10.1.0.1 | 192.168.1.2 -- 192.168.1.1 internet
#   fetch 10.2.0.2 -- nat-f 10.2.0.1 | 192.168.2.2 -- 192.168.2.1 internet

set -eu

SERVE_NAT=cone
FETCH_NAT=cone
BINARY=
BUNDLE=
ROOT=
MATRIX=no
SERVICE_PORT=7777
FETCH_TIMEOUT=40
# Pinned, because the default is the machine's core count and a row's elapsed
# time is not comparable across two machines that punched a different number
# of times for it.
RAILS=4

# The whole header comment, however long it grows.
usage() {
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --serve-nat) SERVE_NAT=$2; shift 2 ;;
        --fetch-nat) FETCH_NAT=$2; shift 2 ;;
        --binary) BINARY=$2; shift 2 ;;
        --bundle) BUNDLE=$2; shift 2 ;;
        --root) ROOT=$2; shift 2 ;;
        --matrix) MATRIX=yes; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done

# A bundle the lab did not build is a bundle whose root it cannot know.
if [ -n "$BUNDLE" ] && [ -z "$ROOT" ]; then
    echo "--bundle needs --root: the lab cannot read a root off a bundle" >&2
    exit 2
fi
if [ -n "$ROOT" ] && [ -z "$BUNDLE" ]; then
    echo "--root names the bundle at --bundle, and there is none" >&2
    exit 2
fi

# ---------------------------------------------------------------- outside

if [ "${NAT_LAB_INSIDE:-}" != "1" ]; then
    [ -n "$BINARY" ] || BINARY=$(pwd)/target/debug/vot-cli
    if [ ! -x "$BINARY" ]; then
        echo "no vot-cli at $BINARY" >&2
        echo "build one with: cargo build -p vot-cli --features wire" >&2
        exit 2
    fi
    if [ -z "$BUNDLE" ]; then
        work=$(mktemp -d)
        mkdir -p "$work/source"
        head -c 1048576 /dev/urandom > "$work/source/payload"
        ROOT=$("$BINARY" send blake3 "$work/source" "$work/bundle" | cut -d" " -f1)
        BUNDLE=$work/bundle
        # Named because nothing removes it: the lab replaces itself with the
        # unshare below, so no trap of this process outlives the build.
        echo "bundle at $work" >&2
    fi
    if ! unshare --user --map-root-user --net --mount --fork true 2>/dev/null; then
        echo "unprivileged user namespaces are unavailable on this kernel" >&2
        exit 2
    fi
    export NAT_LAB_INSIDE=1
    exec unshare --user --map-root-user --net --mount --fork --pid --mount-proc \
        "$0" --serve-nat "$SERVE_NAT" --fetch-nat "$FETCH_NAT" \
        --binary "$BINARY" --bundle "$BUNDLE" --root "$ROOT" \
        $([ "$MATRIX" = yes ] && echo --matrix)
fi

# ----------------------------------------------------------------- inside

mkdir -p /var/run/netns
mount -t tmpfs none /var/run/netns

# Drops inbound that no outbound flow invited. A dropped packet's conntrack
# entry is never confirmed, so tracking it cannot claim the mapping the punch
# is about to need.
drop_unsolicited() {
    for chain in INPUT FORWARD; do
        ip netns exec "$1-nat" iptables -A "$chain" -i "${1}w0" \
            -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        ip netns exec "$1-nat" iptables -A "$chain" -i "${1}w0" -j DROP
    done
}

# `site NAME LAN_PREFIX WAN_PREFIX FLAVOUR` builds one NAT'd site: an endpoint
# namespace behind a router namespace, with the router's WAN on the internet.
site() {
    name=$1 lan=$2 wan=$3 flavour=$4

    ip netns add "$name"
    ip netns add "$name-nat"

    ip link add "${name}0" type veth peer name "${name}1"
    ip link set "${name}0" netns "$name"
    ip link set "${name}1" netns "$name-nat"
    ip link add "${name}w0" type veth peer name "${name}w1"
    ip link set "${name}w0" netns "$name-nat"

    ip -n "$name" addr add "$lan.2/24" dev "${name}0"
    ip -n "$name" link set "${name}0" up
    ip -n "$name" link set lo up
    ip -n "$name" route add default via "$lan.1"

    ip -n "$name-nat" addr add "$lan.1/24" dev "${name}1"
    ip -n "$name-nat" addr add "$wan.2/24" dev "${name}w0"
    ip -n "$name-nat" link set "${name}1" up
    ip -n "$name-nat" link set "${name}w0" up
    ip -n "$name-nat" link set lo up
    ip -n "$name-nat" route add default via "$wan.1"
    ip netns exec "$name-nat" sysctl -qw net.ipv4.ip_forward=1

    ip addr add "$wan.1/24" dev "${name}w1"
    ip link set "${name}w1" up

    case "$flavour" in
        direct)
            # No translation. The internet routes back to the LAN.
            ip route add "$lan.0/24" via "$wan.2"
            ;;
        cone)
            ip netns exec "$name-nat" iptables -t nat -A POSTROUTING \
                -s "$lan.0/24" -o "${name}w0" -j MASQUERADE
            drop_unsolicited "$name"
            ;;
        permissive)
            ip netns exec "$name-nat" iptables -t nat -A POSTROUTING \
                -s "$lan.0/24" -o "${name}w0" -j MASQUERADE
            ;;
        symmetric)
            ip netns exec "$name-nat" iptables -t nat -A POSTROUTING \
                -s "$lan.0/24" -o "${name}w0" -j MASQUERADE --random-fully
            drop_unsolicited "$name"
            ;;
        *)
            echo "unknown NAT flavour: $flavour" >&2
            exit 2
            ;;
    esac
}

teardown() {
    for pid in $SERVICE_PID $SERVE_PID; do
        kill "$pid" 2>/dev/null || true
    done
    # Reaped, not only signalled. The next topology binds the same service
    # port, and a process that still holds it fails that bind.
    for pid in $SERVICE_PID $SERVE_PID; do
        wait "$pid" 2>/dev/null || true
    done
    SERVICE_PID= SERVE_PID=
    for ns in serve serve-nat fetch fetch-nat; do
        ip netns del "$ns" 2>/dev/null || true
    done
    for link in servew1 fetchw1; do
        ip link del "$link" 2>/dev/null || true
    done
    ip route del 10.1.0.0/24 2>/dev/null || true
    ip route del 10.2.0.0/24 2>/dev/null || true
}

# `run SERVE_FLAVOUR FETCH_FLAVOUR` builds one topology, moves a bundle across
# it, prints one result row, and leaves the outcome in `RUN_OUTCOME`.
#
# The outcome goes in a variable rather than the return status because a
# caller that tested the status would suppress `set -e` for everything this
# runs, and a topology that failed to build would then be reported as a NAT
# verdict. A rig failure exits the lab instead.
run() {
    SERVICE_PID= SERVE_PID= RUN_OUTCOME=
    trap teardown EXIT
    trap 'teardown; exit 130' INT TERM

    ip link set lo up
    sysctl -qw net.ipv4.ip_forward=1
    site serve 10.1.0 192.168.1 "$1"
    site fetch 10.2.0 192.168.2 "$2"

    work=$(mktemp -d)
    service="192.168.1.1:$SERVICE_PORT"

    "$BINARY" rendezvous "$service" > "$work/service.log" 2>&1 &
    SERVICE_PID=$!
    # The service has to be answering before the serve registers, and the
    # wait is counted rather than timed so it cannot run away.
    ready=no
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if grep -q rendezvous "$work/service.log" 2>/dev/null; then
            ready=yes
            break
        fi
        sleep 0.2
    done
    if [ "$ready" != yes ]; then
        echo "the service never came up" >&2
        sed 's/^/    /' "$work/service.log" >&2
        exit 2
    fi

    ip netns exec serve env VOT_RENDEZVOUS="$service" \
        "$BINARY" serve "$BUNDLE" 10.1.0.2:0 > "$work/serve.log" 2>&1 &
    SERVE_PID=$!

    began=$(date +%s.%N)
    if ip netns exec fetch env VOT_RENDEZVOUS="$service" VOT_FETCH_RAILS="$RAILS" \
        timeout "$FETCH_TIMEOUT" "$BINARY" fetch "$ROOT" "$work/out" "$ROOT" \
        > "$work/fetch.log" 2>&1
    then
        outcome=fetched
    else
        outcome=failed
    fi
    ended=$(date +%s.%N)
    printf '%-10s %-10s %-8s %ss\n' "$1" "$2" "$outcome" \
        "$(awk "BEGIN { printf \"%.2f\", $ended - $began }")"
    if [ "$outcome" != fetched ]; then
        tail -3 "$work/fetch.log" | sed 's/^/    fetch: /'
        [ -n "${NAT_LAB_VERBOSE:-}" ] && {
            tail -5 "$work/serve.log" | sed 's/^/    serve: /'
            tail -5 "$work/service.log" | sed 's/^/    service: /'
            ip netns exec serve-nat conntrack -L 2>/dev/null | sed 's/^/    conntrack: /'
        }
    fi

    teardown
    trap - EXIT INT TERM
    RUN_OUTCOME=$outcome
}

printf '%-10s %-10s %-8s %s\n' serve fetch outcome elapsed
if [ "$MATRIX" = yes ]; then
    for s in direct cone permissive symmetric; do
        for f in direct cone permissive symmetric; do
            run "$s" "$f"
        done
    done
    # A matrix is a report. Which rows fetched is its content, and the rig
    # failing is what exits non-zero, from inside `run`.
else
    run "$SERVE_NAT" "$FETCH_NAT"
    [ "$RUN_OUTCOME" = fetched ] || exit 1
fi
