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
* **Conversation analysis and per-conversation rewrites**: `pktreplay conversations` (and the GUI table) lists
  bidirectional flows with client/server roles, packet/byte counts and TCP state. A `-conv` rule changes the
  addresses, ports or payload of *one* conversation, applied consistently to both directions (replies come from
  the new server address); other conversations are untouched. The global `-src-ip/-dst-ip/...` flags remain for
  the explicit "rewrite every packet" case.
* In-place rewrites (IP, port, payload text/hex/substitution) with automatic length and checksum repair; pooled buffers.
* Pacing: original timing (+speed), fixed delay, packets/s, Mbit/s, line rate.
* **Recording** (-record file.pcap|.pcapng): saves the traffic actually transmitted, plus replies received in TCP mode\n  (-record-rx=false to omit them); raw-IP records with nanosecond timestamps, readable by tshark/Wireshark and by this tool.\n  Also available in the GUI and with the dry-run backend.\n* Backends: Linux `AF_PACKET` + `sendmmsg`, Windows WinDivert, and a `null` dry-run backend.

## GUI
```bash
pktreplay gui            # starts a local server and opens your browser
pktreplay gui -no-open   # just print the URL
```
The GUI is a web interface embedded in the binary (no extra files, works offline, same Windows/Linux builds).
The interface has three screens and one flow:

1. **Open a capture.** A welcome screen with *Open a capture file…*, a path box, the bundled example and your
   recent files. The file is analysed straight away, with a progress bar.
2. **Choose conversations** (left). Every exchange in the capture is one readable row (service name such as HTTP,
   DNS or Syslog, who talks to whom, size, TCP state). Tick the rows to send, filter by TCP/UDP or search. Nothing
   is sent unless you ticked it. *Change…* on a ticked row edits that conversation's destination, source or payload
   text, with a live "will be sent as" preview and the original shown underneath.
3. **Send** (right, always in view). Choose **TCP or UDP** (required, never guessed; the matching one is
   suggested), **Send on the network** or **Test run**, an optional address to send everything to, the speed
   (like the recording / faster / as fast as possible / custom) and whether to save a copy. A sentence states
   exactly what will happen, and a line under the button says why *Send* is disabled when it is. Progress and
   results replace the panel while it runs. Rare settings (repeat count, TCP stream offsets, network adapter,
   payload text for all selected) are under *More options…*.

When the program is not running as administrator, *Send on the network* is disabled and a *Restart as
administrator* button relaunches it elevated (after the Windows prompt).

### History and the pcap library
Every run is recorded (**History** in the header) in a small embedded database in your user data folder
(`%LOCALAPPDATA%\pktreplay\history` on Windows, `~/.local/share/pktreplay/history` on Linux; change it with
`pktreplay gui -data-dir DIR` or `PKTREPLAY_DATA`, or turn history off with `-no-history`).

* **Sent runs**: when, which capture, TCP/UDP, test run or network, the conversations and what was changed in
  them, speed, the result (packets, bytes, errors, TCP details) or why it failed. Search and filter, pin runs
  you want to keep, add notes, export to CSV/JSON, delete. **Send again** reopens the capture and restores the
  selection, edits and settings so you only have to review and press Send.
* **Pcap library**: every capture file you send is remembered by content, so an identical file is stored once
  however many runs used it. A copy is kept (default: files up to 512 MB, 4 GB in total, least recently used
  unpinned copies removed first), so a run can be sent again even if the original was moved or deleted; larger
  files, or when copies are switched off, are kept as references to the original. Add a capture without sending it
  with *Add the open capture*, download or remove a stored copy, pin or annotate entries.
* **Optional extra, off by default**: *History settings* can also keep a copy of the packets that were actually
  transmitted (rewritten as sent, plus replies in TCP mode) per run. The run details then show them decoded
  and you can download the PCAPNG.

Retention limits (number of runs, age, library size, packet copies) are in *History settings*. Uninstalling the
program leaves your history in place.

Security model: the server listens on **loopback only** (it refuses any other address), every request needs a
random per-launch token (the printed URL contains it and is exchanged for an HttpOnly, SameSite=Strict cookie),
and Host / Origin / content-type checks block DNS-rebinding and cross-site requests. Because it can inject
packets, do not forward its port to other machines.

## Layout
```
cmd/pktreplay        CLI (stats, index, replay, gui)
internal/gui         local web GUI: HTTP API, job manager, embedded web/ frontend
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

## Windows installer
`powershell -File installer\build.ps1 [-Version 0.2.0]` builds `dist\pktreplay-setup-<version>.exe` (plus a
`.sha256` file) with [Inno Setup](https://jrsoftware.org/isinfo.php) (`winget install JRSoftware.InnoSetup`).
It installs per user by default (no UAC prompt; "all users" is offered), adds Start Menu shortcuts
(**pktreplay**, and **pktreplay (Administrator)** for raw injection), an optional desktop shortcut and an
optional PATH entry, and registers a normal uninstaller that removes everything it added.
Two executables are installed: `pktreplay.exe` (console, CLI) and `pktreplay-gui.exe` (windowless; opens the
GUI, shows a dialog if it cannot start). Silent install for deployment:
`pktreplay-setup-0.1.0.exe /VERYSILENT /CURRENTUSER /TASKS=addpath` (use `/ALLUSERS` for a machine-wide install).
The installer bundles the WinDivert 2.2.2 driver when its files are staged in `installer\redist`: run
`installer\fetch-windivert.ps1` (downloads, or `-ZipPath` for a local `WinDivert-2.2.2-A.zip`), which checks pinned
SHA-256 hashes, the driver's Authenticode signature and the licence text, then rebuild. WinDivert is
LGPLv3/GPLv2: the installer ships `WinDivert-LICENSE.txt` and the binaries must stay unmodified. Some antivirus
products flag WinDivert (Windows Defender does), so the files may need an exclusion on the build machine. The installer is not code-signed, so Windows SmartScreen may show an
"unknown publisher" warning; sign it with `signtool` for distribution.

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

# 8b. Analyze conversations, then change ONE of them (both directions stay consistent)
pktreplay conversations capture.pcap
sudo pktreplay replay -mode udp \
     -conv "udp/192.168.1.50:40000/192.168.1.1:53,server-ip=10.50.0.9,server-port=5353" capture.pcap
# add -only-conv to replay just the listed conversation(s); -conv is repeatable

# 9. Record exactly what is transmitted (and the target's replies in TCP mode); .pcapng keeps direction
sudo pktreplay replay -mode tcp -dst-ip 10.20.0.5 -record sent.pcapng capture.pcap

# 10. Dry run: benchmark read + filter + rewrite without privileges or a network
pktreplay replay -mode udp -backend null -burst -dst-ip 10.9.9.9 huge.pcap
```
`-mode` is mandatory: replay never guesses between TCP and UDP. Run `pktreplay replay -h` for every flag.

Filter grammar: `src_ip|dst_ip|ip == addr[/cidr]`, `src_port|dst_port|port == N` or `in lo-hi`,
`proto == tcp|udp|icmp|icmp6|arp|ip|ipv6|N`, `tcp_flags == syn+ack`, `payload contains "text"|0xHEX`,
`payload ~ "regexp"`, combined with `AND`/`OR`/`NOT`/`&&`/`||`/`!` and parentheses.

## Sample capture
`samples/sample-mixed.pcap` is a 23-packet recording (ARP, DNS, an HTTP GET/200 over TCP with handshake and FIN,
ICMP pings, UDP syslog) that opens in tshark/Wireshark and in the GUI. Regenerate it with
`pcapgen -sample -o samples/sample-mixed.pcap`. For example:
```bash
pktreplay stats samples/sample-mixed.pcap
pktreplay replay -mode tcp -backend null -burst samples/sample-mixed.pcap   # picks the HTTP flow
```n
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
