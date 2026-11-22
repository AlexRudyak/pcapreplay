#!/usr/bin/env bash
# End-to-end stateful TCP replay against a real kernel TCP server (needs root + nftables/iptables).
# Usage: scripts/e2e-tcp.sh <pcapreplay> <stream-syn.pcap> <stream-mid.pcap>
# Capture files come from:  pcapgen -stream 3000 [-nosyn] -o file.pcap
set -euo pipefail
cd "$(dirname "$0")"
. ./netns.sh
BIN=${1:?path to pcapreplay}
SYN=${2:?capture with handshake}
MID=${3:?mid-stream capture}
trap ns_down EXIT
ns_up

N=3000
# run_case <name> <expected-skip-bytes> <pcapreplay args...>
run_case() {
    local name=$1 skip=$2; shift 2
    echo "=== $name"
    SKIP=$skip N=$N ip netns exec "$NS" python3 - <<'PY' &
import os, socket
n, skip = int(os.environ["N"]), int(os.environ["SKIP"])
want = b"".join(b"line %d\n" % i for i in range(n))[skip:]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("10.77.0.2", 9000)); srv.listen(1); srv.settimeout(15)
c, peer = srv.accept()
c.sendall(b"hello from server\n")
c.settimeout(8)
got = b""
try:
    while True:
        d = c.recv(65536)
        if not d: break
        got += d
        if len(got) >= len(want): break
except socket.timeout:
    pass
print(f"server: peer={peer[0]} received {len(got)}/{len(want)} bytes -> {'CONTENT OK' if got == want else 'MISMATCH'}")
c.close()
PY
    local srv=$!
    sleep 0.7
    "$BIN" replay -mode tcp -src-ip "$HOST_IP" -dst-ip "$SRV_IP" -dst-port 9000 "$@"
    wait $srv
    nft list tables 2>/dev/null | grep -q pcapreplay && echo "WARNING: nft table leaked" || echo "firewall rule cleaned up"
}

run_case "capture WITH handshake, line rate"            0    -burst "$SYN"
run_case "mid-stream capture (no SYN), paced 4000 pps"   0    -pps 4000 "$MID"
run_case "mid-stream, --tcp-skip-bytes 1000"            1000 -burst -tcp-skip-bytes 1000 "$MID"

echo "=== connection refused (nothing listening on 9001)"
"$BIN" replay -mode tcp -src-ip "$HOST_IP" -dst-ip "$SRV_IP" -dst-port 9001 -burst "$SYN" || echo "(exit $? as expected)"
echo "=== unreachable host (handshake timeout)"
"$BIN" replay -mode tcp -src-ip "$HOST_IP" -dst-ip 10.77.0.77 -dst-mac 02:00:00:00:00:77 -handshake-timeout 2s -burst "$SYN" || echo "(exit $? as expected)"
