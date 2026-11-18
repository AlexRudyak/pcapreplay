#!/usr/bin/env bash
# Helper: a throw-away "server" network namespace connected to the host by a veth pair.
#
#   host: pr_veth0 10.77.0.1/24  <----->  namespace pr_srv: pr_veth1 10.77.0.2/24
#
# Source this file, then call ns_up / ns_down. Requires root and iproute2.
NS=pr_srv
HOST_IP=10.77.0.1
SRV_IP=10.77.0.2

ns_down() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del pr_veth0 2>/dev/null || true
}

ns_up() {
    ns_down
    ip netns add "$NS"
    ip link add pr_veth0 type veth peer name pr_veth1
    ip link set pr_veth1 netns "$NS"
    ip addr add "$HOST_IP/24" dev pr_veth0
    ip link set pr_veth0 up
    ip netns exec "$NS" ip addr add "$SRV_IP/24" dev pr_veth1
    ip netns exec "$NS" ip link set pr_veth1 up
    ip netns exec "$NS" ip link set lo up
    # Checksum offload on veth would hand us "partial" checksums; we compute real ones.
    ethtool -K pr_veth0 tx off rx off >/dev/null 2>&1 || true
    ip netns exec "$NS" ethtool -K pr_veth1 tx off rx off >/dev/null 2>&1 || true
}
