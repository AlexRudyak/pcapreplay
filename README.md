# pktreplay

High-throughput, low-memory PCAP/PCAPNG analysis and replay tool in pure Go: no cgo, no third-party
dependencies, one codebase for Windows and Linux. Design and measurements: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

> For lab and authorised testing on networks you own or are permitted to test. Replaying traffic with
> forged source addresses onto a network you do not control can disrupt others.

## Features
* **Streaming analysis**: `pktreplay stats` summarises 10 GB+ captures in one pass with a flat <100 MB footprint
  (packets, bytes, protocol mix, top talkers via a bounded sketch, active ports); `-start/-count` with an
  on-disk `-index` for O(1) range access.
* **Fast-path filters** with boolean logic, CIDR, port ranges, flags, payload substring/hex/regexp; header terms
  always run before payload terms.
* **Replay** in an explicit `-mode udp` (stateless) or `-mode tcp` (real handshake, mid-stream sequence
  rebasing, optional offsets, retransmission, FIN/ACK close).
* In-place rewrites (IP, port, payload text/hex/substitution) with automatic length and checksum repair; pooled buffers.
* Pacing: original timing (+speed), fixed delay, packets/s, Mbit/s, line rate.
* Backends: Linux `AF_PACKET` + `sendmmsg`, Windows WinDivert, and a `null` dry-run backend.

## Layout
```
cmd/pktreplay        CLI (stats, index, replay)
cmd/pcapgen          synthetic capture generator for tests and benchmarks
internal/pcapio      streaming PCAP/PCAPNG reader + sparse index
internal/decode      zero-allocation L2/L3/L4 header decoder
internal/filter      boolean filter compiler
internal/stats       bounded-memory statistics (Space-Saving sketch)
internal/checksum    RFC 1071 checksums
internal/craft       frame builder (handshake segments, tests)
internal/mutate      pooled packet rewriting
internal/pace        high-resolution pacing
internal/replay      producer/consumer pipeline, UDP and TCP engines
internal/backend     Backend interface; linux.go, windows.go, null
scripts/             WSL/Linux end-to-end tests (veth + netns)
docs/ARCHITECTURE.md design, sequence-mapping formulas, benchmarks, limitations
```

## Build
Requires Go 1.22+.
```bash
go build -o bin/pktreplay ./cmd/pktreplay
go test ./...

# cross-compile (CGO is not used)
GOOS=linux   GOARCH=amd64 go build -o bin/pktreplay-linux       ./cmd/pktreplay
GOOS=windows GOARCH=amd64 go build -o bin/pktreplay.exe         ./cmd/pktreplay
GOOS=linux   GOARCH=arm64 go build -o bin/pktreplay-linux-arm64 ./cmd/pktreplay
```
PowerShell: `$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o bin\pktreplay-linux .\cmd\pktreplay`.

## Setup

### Linux
Raw sockets need `CAP_NET_RAW`; the automatic RST-drop rule also needs `CAP_NET_ADMIN`; simplest is root.
```bash
sudo ./pktreplay replay -mode udp ...
# or grant capabilities and manage the firewall yourself:
sudo setcap cap_net_raw,cap_net_admin+ep ./pktreplay
```
In TCP mode pktreplay installs (and removes on exit) an nftables table that drops the kernel's outbound RSTs
for exactly the replay 4-tuple (falls back to `iptables`). To manage it yourself, pass `-no-firewall` and run:
```bash
sudo nft add table inet pktreplay
sudo nft 'add chain inet pktreplay out { type filter hook output priority -10; policy accept; }'
sudo nft add rule inet pktreplay out ip daddr 10.0.0.9 tcp sport 50000 tcp flags \& rst == rst drop
```

### Windows
1. Download the official **WinDivert 2.2.x** release from <https://reqrypt.org/windivert.html> and verify it.
2. Copy `WinDivert.dll` and `WinDivert64.sys` (x64) **into the same folder as `pktreplay.exe`**.
3. Run from an **elevated** prompt (Administrator). Common errors are explained by the tool (access denied,
   driver not found, signature rejected).
4. Loopback targets are not supported on Windows; use a real interface address.

## Usage

```bash
# 1. Summary statistics of a huge capture, filtered, with progress and timing
pktreplay stats -progress -filter "dst_port == 443 AND payload contains \"index.html\"" huge.pcapng

# 2. Index once, then inspect a packet range without scanning from the start
pktreplay index huge.pcap
pktreplay stats -index huge.pcap.idx -start 50000000 -count 1000 huge.pcap

# 3. UDP replay: original timing, rewrite destination, recompute checksums
sudo pktreplay replay -mode udp -filter "proto == udp AND dst_port == 5060" \
     -dst-ip 10.20.0.5 -dst-port 5060 capture.pcap

# 4. UDP at a rate cap with a payload substitution, looping 10 times
sudo pktreplay replay -mode udp -mbps 100 -loop 10 -replace "tenant-a=>tenant-b" capture.pcap

# 5. Full TCP replay (capture contains the SYN): real handshake, then the stream
sudo pktreplay replay -mode tcp -filter "dst_port == 8080" -dst-ip 10.20.0.5 -v capture.pcap

# 6. Mid-stream TCP replay (no SYN in the capture), starting 1500 bytes into the client stream
sudo pktreplay replay -mode tcp -dst-ip 10.20.0.5 -dst-port 8080 -tcp-skip-bytes 1500 midstream.pcap

# 7. Mid-stream with a manual sequence shift (formula in docs/ARCHITECTURE.md)
sudo pktreplay replay -mode tcp -dst-ip 10.20.0.5 -tcp-seq-offset -64 midstream.pcap

# 8. Windows (elevated PowerShell)
.\pktreplay.exe replay -mode tcp -dst-ip 10.20.0.5 -dst-port 8080 capture.pcap

# 9. Dry run: benchmark read + filter + rewrite without privileges or a network
pktreplay replay -mode udp -backend null -burst -dst-ip 10.9.9.9 huge.pcap
```
`-mode` is mandatory: replay never guesses between TCP and UDP. Run `pktreplay replay -h` for every flag.

Filter grammar: `src_ip|dst_ip|ip == addr[/cidr]`, `src_port|dst_port|port == N` or `in lo-hi`,
`proto == tcp|udp|icmp|icmp6|arp|ip|ipv6|N`, `tcp_flags == syn+ack`, `payload contains "text"|0xHEX`,
`payload ~ "regexp"`, combined with `AND`/`OR`/`NOT`/`&&`/`||`/`!` and parentheses.

## Benchmarking
```bash
go build -o bin/pcapgen ./cmd/pcapgen
bin/pcapgen -n 10000000 -o bin/big.pcap            # ~1.2 GB
bin/pcapgen -n 2000000 -ng -o bin/big.pcapng
bin/pktreplay stats -progress bin/big.pcap          # prints Mpps and MB/s
go test -bench . ./internal/checksum ./internal/filter
```
Peak memory on Linux: `/usr/bin/time -v bin/pktreplay stats bin/big.pcap` ("Maximum resident set size").
On Windows: poll `(Get-Process pktreplay).PeakWorkingSet64`.

## End-to-end tests (Linux / WSL2, root)
```bash
bin/pcapgen -stream 3000 -o bin/stream-syn.pcap
bin/pcapgen -stream 3000 -nosyn -o bin/stream-mid.pcap
bin/pcapgen -n 200000 -o bin/udp200k.pcap
sudo scripts/e2e-udp.sh bin/pktreplay-linux bin/udp200k.pcap
sudo scripts/e2e-tcp.sh bin/pktreplay-linux bin/stream-syn.pcap bin/stream-mid.pcap
```
They build a veth pair and a server network namespace, replay into a real kernel TCP/UDP server and verify
the received bytes. The Windows backend has no such automated test (see limitations in the architecture doc).
