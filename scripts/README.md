# scripts

**End-to-end tests** that replay into a real kernel (Linux or WSL2, root). They prove what unit tests cannot: that the
Linux backend, the RST guard and the TCP engine really interoperate with an operating-system TCP/UDP stack.

| Script | What it does |
|---|---|
| `netns.sh` | Helper: `ns_up` / `ns_down` create a throw-away server network namespace `pr_srv` joined to the host by a veth pair (`10.77.0.1` <-> `10.77.0.2`). |
| `e2e-udp.sh` | Starts a UDP listener in the namespace, replays a capture through `AF_PACKET` and checks that every datagram arrived. |
| `e2e-tcp.sh` | Starts a real TCP server in the namespace, replays a stream **with handshake**, a **mid-stream** capture, and one with `-tcp-skip-bytes`, verifying the received bytes and that the firewall rule was removed. |

```bash
go build -o bin/pcapgen ./cmd/pcapgen
bin/pcapgen -stream 3000 -o bin/stream-syn.pcap
bin/pcapgen -stream 3000 -nosyn -o bin/stream-mid.pcap
bin/pcapgen -n 200000 -o bin/udp200k.pcap
GOOS=linux go build -o bin/pktreplay-linux ./cmd/pktreplay
sudo scripts/e2e-udp.sh bin/pktreplay-linux bin/udp200k.pcap
sudo scripts/e2e-tcp.sh bin/pktreplay-linux bin/stream-syn.pcap bin/stream-mid.pcap
```

Requirements: root, `iproute2`, `python3`, and `nftables` or `iptables`.
