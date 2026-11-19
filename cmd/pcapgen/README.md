# cmd/pcapgen

Writes **synthetic captures** for tests, benchmarks and the bundled sample.

```bash
go run ./cmd/pcapgen -n 10000000 -o bin/big.pcap          # ~1.2 GB of UDP/TCP noise from 5000 hosts
go run ./cmd/pcapgen -n 2000000 -ng -o bin/big.pcapng     # PCAPNG
go run ./cmd/pcapgen -stream 3000 -o bin/stream-syn.pcap  # ONE TCP conversation, 3000 client segments
go run ./cmd/pcapgen -stream 3000 -nosyn -o bin/stream-mid.pcap   # capture that starts mid-stream
go run ./cmd/pcapgen -sample -o samples/sample-mixed.pcap # the small realistic capture
```

| Flag | Meaning |
|---|---|
| `-n` | Number of packets (default 1 000 000). |
| `-hosts` | Distinct client hosts (default 5000). |
| `-payload` | Payload bytes per packet (default 64). |
| `-ng` | Write PCAPNG instead of classic PCAP. |
| `-stream N` | Instead write one TCP conversation with N client data segments (deterministic payload so receivers can verify byte-for-byte). |
| `-nosyn` | With `-stream`: omit the handshake. |
| `-sample` | The 23-packet mixed capture: ARP, DNS, HTTP GET/200 with handshake and FIN, ICMP pings, UDP syslog. |
| `-o` | Output file. |

Files: `main.go` (flags and bulk generator), `stream.go` (single TCP conversation), `sample.go` (the realistic sample).
Frames are built with `internal/craft`.

The generated files are what the benchmarks in the README and `scripts/e2e-*.sh` use; big `.pcap` files are git-ignored.
