#!/usr/bin/env bash
# End-to-end UDP replay over real AF_PACKET sockets and a veth pair (needs root).
# Usage: scripts/e2e-udp.sh <pcapreplay> <capture.pcap with UDP/53 packets>
set -euo pipefail
cd "$(dirname "$0")"
. ./netns.sh
BIN=${1:?path to pcapreplay}
CAP=${2:?capture}
trap ns_down EXIT
ns_up

ip netns exec "$NS" python3 - <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.77.0.2", 5000)); s.settimeout(3)
n = b = bad = 0
try:
    while True:
        d, _ = s.recvfrom(65535); n += 1; b += len(d)
        if not d.startswith(b"GET /index.html"):
            bad += 1
except socket.timeout:
    pass
print(f"server: received {n} datagrams, {b} bytes, bad payloads: {bad}")
PY
SERVER=$!
sleep 0.5
"$BIN" replay -mode udp -filter "proto == udp and dst_port == 53" \
    -src-ip "$HOST_IP" -dst-ip "$SRV_IP" -dst-port 5000 -pps 20000 "$CAP"
wait $SERVER
