# pktreplay command-line reference

`pktreplay` analyses and replays PCAP / PCAPNG captures. This document covers every command and flag of the
command-line tool. For the graphical interface see [README.md](README.md); for internals see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
pktreplay <command> [flags] <capture>

  stats           one-pass summary statistics
  conversations   list the bidirectional conversations (alias: convs)
  index           build a seek index for very large captures
  replay          replay filtered packets onto the network (or a dry run)
  gui             local web interface
  version         print the version
```

Run `pktreplay <command> -h` for the built-in flag list. Flags may be written `-flag value` or `-flag=value`
(Go syntax; `--flag` also works). **Flags must come before the capture file name.** Boolean flags
(`-burst`, `-vv`, ...) need no value; write `-record-rx=false` to turn a default-on boolean off.

Exit codes: `0` success, `1` the command failed (message on stderr), `2` bad usage, `3` internal crash.

Contents: [Capture files](#capture-files) | [Filters](#filter-expressions) | [stats](#stats) |
[conversations](#conversations) | [index](#index) | [replay](#replay) | [gui](#gui) | [Logging](#logging-and-verbosity) | [Recipes](#recipes) |
[Troubleshooting](#troubleshooting)

---

## Capture files

* Formats: classic **PCAP** (micro- and nanosecond, either byte order) and **PCAPNG**, detected automatically
  from the file contents (the extension does not matter).
* Files are read **as a stream** with a small fixed buffer, so a multi-gigabyte capture needs only a few tens
  of MB of RAM. Nothing is loaded whole.
* Link layers with Ethernet, raw IP, Linux cooked and similar framing are decoded; VLAN tags are skipped. The
  analysis understands IPv4 and IPv6. Replay injects IP datagrams and lets the backend add the link layer.
* Packet numbers (`-start`, `-count`) are **0-based** and count every record in the file, matching or not.

---

## Filter expressions

`-filter` is accepted by `stats`, `conversations` and `replay`. A filter is a boolean expression over packet
fields. A packet is processed only if the expression is true; an empty filter matches everything.
Filters are compiled once, and cheap header tests always run before payload tests, regardless of the order
you type them in, so adding a payload condition costs little for packets already rejected by headers.

| Term | Meaning |
|---|---|
| `src_ip == ADDR`, `dst_ip == ADDR`, `ip == ADDR` | Source / destination / either address. `ADDR` may be a CIDR, e.g. `10.0.0.0/8`. IPv4 and IPv6. |
| `src_port == N`, `dst_port == N`, `port == N` | Source / destination / either port. Use `in LO-HI` for a range: `dst_port in 8000-8100`. |
| `proto == NAME` | `tcp`, `udp`, `icmp`, `icmp6`, `arp`, `ip` (any IPv4), `ipv6`, or an IP protocol number. `protocol` is a synonym. |
| `tcp_flags == F` | TCP flags joined with `+`, e.g. `syn`, `syn+ack`, `fin+ack`, `rst`. `flags` is a synonym. |
| `payload contains "text"` | Transport payload contains the text. Hex form: `payload contains 0xdeadbeef`. |
| `payload ~ "regexp"` | Payload matches a Go (RE2) regular expression. |
| `!=` | Negates a comparison, e.g. `dst_port != 22`. |

Combine terms with `AND` / `OR` / `NOT` (or `&&` / `||` / `!`) and parentheses. Operators are case-insensitive.

```bash
pktreplay stats -filter "src_ip == 10.0.0.0/8 AND dst_port == 443" trace.pcap
pktreplay stats -filter "proto == udp AND NOT dst_port in 1-1023" trace.pcap
pktreplay stats -filter "(dst_port == 80 OR dst_port == 8080) AND payload contains \"POST \"" trace.pcap
pktreplay stats -filter "tcp_flags == syn" trace.pcap                       # connection attempts
pktreplay stats -filter "payload ~ \"User-Agent: (curl|wget)\"" trace.pcap
```

Quote the whole expression for your shell. Inside it, string literals use double quotes (escape them as
`\"` inside a double-quoted shell string, or use single quotes around the whole expression in bash).
A malformed filter stops the command with a message before any packet is processed.

---

## stats

One streaming pass that prints a summary of the capture.

```
pktreplay stats [flags] <capture>
```

| Flag | Default | Explanation |
|---|---|---|
| `-filter EXPR` | none | Count only packets matching the [filter](#filter-expressions). |
| `-top N` | 10 | Number of rows in the top-talker and port tables. |
| `-progress` | off | Print live progress to stderr and a final throughput line (packets/s, MB/s). |
| `-start N` | 0 | First packet number to process. |
| `-count N` | 0 (all) | Process at most N packets after `-start`. |
| `-index FILE` | none | Seek index (see [index](#index)). If the file exists it is used to jump straight to `-start` instead of reading everything before it; if it does not exist it is built and saved there. |

Output sections: file and format; packet count, bytes captured vs on the wire, truncated packets; time span and
average rate; first-packet time; per-protocol counts and share (TCP, UDP, ICMP, ARP, IPv4/IPv6 totals);
**top talkers** by bytes; **active TCP and UDP destination ports** by packet count.

Top talkers use a bounded heavy-hitter sketch (16 384 keys), so memory stays constant however many hosts appear;
very small hosts in a huge capture can be approximated (the `+a..b B` column gives the error bound).

```bash
pktreplay stats samples/sample-mixed.pcap
pktreplay stats -progress -top 25 -filter "proto == tcp" huge.pcapng
pktreplay stats -index huge.pcap.idx -start 50000000 -count 1000 huge.pcap   # a slice, no full scan
```

---

## conversations

Lists the **bidirectional conversations** in one streaming pass: a conversation is a protocol plus the pair of
endpoints, so both directions of an exchange are one row. Use it to decide what to replay and to copy a
`SELECTOR` into [`replay -conv`](#per-conversation-rewrites--conv--only-conv).

```
pktreplay conversations [flags] <capture>      (alias: convs)
```

| Flag | Default | Explanation |
|---|---|---|
| `-filter EXPR` | none | Count only packets matching the filter. |
| `-top N` | 50 | Rows to show; `0` shows every tracked conversation. |
| `-sort ORDER` | `bytes` | `bytes`, `packets`, or `time` (order of first appearance). |
| `-start N`, `-count N`, `-index FILE` | | Same meaning as in `stats`: analyse a packet range, optionally using a seek index. |

Columns:

| Column | Meaning |
|---|---|
| `#` | Order of first appearance in the capture (stable id, also shown by the GUI). |
| `SELECTOR` | `proto/client/server`, ready to paste into `-conv`. The **client** is the side that started the exchange: the sender of the SYN for TCP, otherwise the side talking to a well-known port, otherwise whoever spoke first. ICMP has no ports: `icmp/192.168.1.50/192.168.1.1`. IPv6 endpoints with ports are written `[addr]:port`. |
| `PKTS`, `C>S`, `S>C` | Total packets, and how many went client-to-server / server-to-client. |
| `BYTES`, `DURATION` | Bytes on the wire and time from first to last packet. |
| `STATE` | TCP only: how the connection ended in the capture (for example `closed`), `-` for other protocols. |

Conversation tracking is bounded in memory; if a capture holds more distinct conversations than the table
allows, the least active ones are dropped and the summary line says so.

```
$ pktreplay conversations samples/sample-mixed.pcap
#  SELECTOR (proto/client/server)           PKTS  C>S  S>C  BYTES  DURATION  STATE
1  tcp/192.168.1.50:51234/192.168.1.10:80   10    5    5    927    7ms       closed
2  icmp/192.168.1.50/192.168.1.1            6     3    3    588    2.004s    -
0  udp/192.168.1.50:40000/192.168.1.1:53    2     1    1    168    9ms       -
...
```

---

## index

Builds a **seek index**: one file offset per `-stride` packets. With it, `-start` jumps to any packet without
reading the ones before it. Worth building once for captures of many millions of packets that you inspect or
replay in ranges.

```
pktreplay index [flags] <capture>
```

| Flag | Default | Explanation |
|---|---|---|
| `-o FILE` | `<capture>.idx` | Where to write the index. |
| `-stride N` | 4096 | Packets between index entries. A smaller stride seeks faster but makes a larger index (16 bytes per entry; about 400 KB for 100 million packets at the default). Seeking skips at most `stride-1` packets. |

The index is tied to the capture it was built from. If the capture changes, rebuild it. Use it with
`-index FILE` on `stats`, `conversations` and `replay`.

```bash
pktreplay index huge.pcap                 # writes huge.pcap.idx
pktreplay stats -index huge.pcap.idx -start 50000000 -count 1000 huge.pcap
```

---

## replay

Reads a capture, selects and rewrites packets, and transmits them with controlled timing.

```
pktreplay replay -mode tcp|udp [flags] <capture>
```

Replaying can send real traffic. **Only use it on networks you own or are authorised to test**, and prefer a
dry run (`-backend null`) first.

### Pipeline in one paragraph

A reader goroutine decodes, filters and rewrites packets (fixing lengths and checksums) into a bounded queue; a
sender goroutine takes them out, waits according to the pacing mode and injects them. The queue is bounded
(`-queue`), so memory stays flat: a slow disk can only make sending later, never earlier, and a slow network
makes the reader wait.

### Transport mode (mandatory)

| Flag | Explanation |
|---|---|
| `-mode udp` | **Stateless injection.** Matching UDP datagrams are rewritten and sent as they are, one by one, with recomputed checksums. Only UDP packets are sent; other protocols in the capture are skipped (the result line counts them as skipped). No replies are processed. |
| `-mode tcp` | **A real TCP session.** The tool performs an actual three-way handshake with the target, then replays the captured **client-to-server** stream of one flow into it, with live sequence/ack numbers, window-aware sending, retransmission and a clean FIN close. Server packets in the capture are never sent; the live server's answers are what drive the session. |

There is no default: omitting `-mode` is an error, because guessing between a handshake and raw injection is
dangerous. TCP mode selects **one flow**: the first packet that passes `-filter` (and the `-conv` selection, if
any) decides the client and the server, so narrow the filter to pick a specific connection. UDP mode may send
many conversations in one run.

### Selection

| Flag | Default | Explanation |
|---|---|---|
| `-filter EXPR` | none | Only packets matching the [filter](#filter-expressions) are replayed. |
| `-start N`, `-count N` | 0, all | Replay a packet range (0-based, counted over the whole file). |
| `-index FILE` | none | Seek index so `-start` is O(1) on huge files (see [index](#index)). |
| `-loop N` | 1 | Number of passes over the selected packets. In TCP mode each pass is a fresh connection. |

### Rewrites applied to every packet (global)

These change every selected packet that does **not** belong to a conversation with a `-conv` rule (those use only their rule). Checksums
(IP header, TCP/UDP, including the IPv4/IPv6 pseudo-header) and length fields are recomputed after every change.

| Flag | Explanation |
|---|---|
| `-dst-ip IP` | New destination address. In TCP mode this is the machine you connect to. |
| `-dst-port N` | New destination port. |
| `-src-ip IP` | New source address. In TCP mode it must be an address of this machine (the real socket uses it). |
| `-src-port N` | New source port. In TCP mode it is the local port to connect from; otherwise the OS picks one. |
| `-payload VALUE` | Replace the whole transport payload. `VALUE` is text, `hex:de ad be ef` or `0xdeadbeef`. |
| `-replace 'old=>new'` | Substitute bytes inside the payload; repeatable and applied in order. Text, or hex with the same prefixes as `-payload`. Lengths and checksums are fixed up even if `new` is a different size. |
| `-src-mac MAC`, `-dst-mac MAC` | Ethernet source / next-hop MAC override (Linux only; the backend builds the link layer). |

> A global `-dst-ip` rewrites **every** conversation's destination. If a capture holds several conversations
> and you only want to change one, use `-conv` instead.

### Per-conversation rewrites: `-conv`, `-only-conv`

| Flag | Explanation |
|---|---|
| `-conv RULE` | Change **one conversation**, consistently in both directions, leaving the others untouched. Repeatable (one flag per conversation). |
| `-only-conv` | Replay only the conversations that have a `-conv` rule and skip everything else. Needs at least one `-conv`. Implied in TCP mode. |

Rule format (the selector is copied from [`conversations`](#conversations)):

```
-conv "SELECTOR[,client-ip=IP][,client-port=N][,server-ip=IP][,server-port=N][,replace=old=>new]"
```

| Rule part | Meaning |
|---|---|
| `SELECTOR` | `proto/client/server`, identifying the conversation. |
| `client-ip=`, `client-port=` | Change the client endpoint. Client-to-server packets get the new **source**, server-to-client packets the new **destination**. |
| `server-ip=`, `server-port=` | Change the server endpoint, applied to both directions the same way. |
| `replace=old=>new` | Payload substitution for this conversation only; may appear more than once. |

Rules are expressed as *endpoints*, not as raw source/destination, so you never have to think about packet
direction. A conversation with a `-conv` rule is **not** touched by any global rewrite (`-src-ip`, `-dst-ip`,
`-src-port`, `-dst-port`, `-payload`, `-replace`): the rule replaces them entirely for that conversation, so
give the rule its own `replace=` if it needs one. Two rules for the same conversation are rejected.

```bash
# find the conversation, then move only the DNS exchange to another resolver
pktreplay conversations capture.pcap
pktreplay replay -mode udp -only-conv \
   -conv "udp/192.168.1.50:40000/192.168.1.1:53,server-ip=10.50.0.9,server-port=5353" capture.pcap
```

### Pacing

At most one of the following may be given; with none, packets keep the **original capture timing**.

| Flag | Explanation |
|---|---|
| *(none)* | Reproduce the inter-packet gaps recorded in the capture. |
| `-speed X` | With original timing, play X times faster (`2` = twice as fast, `0.5` = half speed). Default 1. |
| `-max-gap D` | With original timing, never wait longer than D for one gap (`500ms`, `2s`), skipping long idle periods. |
| `-delay D` | A fixed delay D between every packet (`100us`, `2ms`). |
| `-pps N` | Cap at N packets per second. |
| `-mbps N` | Cap throughput at N megabits per second (counted on frame size). |
| `-burst` | No pacing at all: send as fast as the backend can, in batches (`-batch`). |

Durations use Go syntax: `250us`, `10ms`, `1.5s`, `2m`. Pacing uses a high-resolution clock (QueryPerformanceCounter
on Windows, monotonic clock plus a final spin on Linux) so rates stay accurate at small gaps.

### TCP mode options

| Flag | Default | Explanation |
|---|---|---|
| `-tcp-skip-bytes N` | 0 | Start N payload bytes into the captured client stream. For captures that begin mid-connection, or to skip a login exchange. |
| `-tcp-seq-offset N` | 0 | Signed byte shift applied to captured sequence numbers when rebasing onto the live connection. Use when the capture starts mid-stream and the first captured packet is not at the position you want (see the formula in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)). |
| `-tcp-ack-mode live\|capture` | `live` | What to acknowledge. `live`: acknowledge exactly what the real server sent. `capture`: rebase the ACK numbers recorded in the capture (never acknowledging data the live server did not send). `live` is correct unless you are deliberately reproducing odd ACK behaviour. |
| `-handshake-timeout D` | 5s | How long to wait for the server's SYN-ACK (the SYN is retransmitted meanwhile). Fails with "no SYN-ACK" or "connection refused". |

If the capture contains the SYN, the handshake is replayed from it. If it starts mid-stream, sequence numbers
are rebased: `live_isn + 1 + (captured_seq - capture_base + offset + delta)`, where `capture_base` is the first
client byte seen. TCP options that cannot be negotiated live (SACK, window scale from the capture) are
stripped or adjusted so segments stay valid for the new connection.

TCP-only flags are rejected in `-mode udp`.

### Backend and network interface

| Flag | Default | Explanation |
|---|---|---|
| `-backend auto\|null` | `auto` | `auto`: inject on the real network (Linux `AF_PACKET`+`sendmmsg`, Windows WinDivert). `null`: **dry run**: reads, filters and rewrites without sending, needs no privileges, ideal for checking a command or benchmarking. |
| `-iface NAME` | route lookup | Linux: egress interface (e.g. `eth0`). By default chosen from the routing table. |
| `-ifindex N` | route lookup | Windows: WinDivert network-interface index to send on. |
| `-no-firewall` | off | Linux, TCP mode: do **not** install the temporary firewall rule that drops the kernel's automatic RST. The kernel does not know about the injected connection and would reset it; pktreplay normally adds an `nftables`/`iptables` rule for the duration and removes it afterwards. Use this flag only if you manage that rule yourself. On Windows the equivalent guard is part of the WinDivert filter. |

Requirements: **Linux** needs root or `CAP_NET_RAW` (plus `CAP_NET_ADMIN` for the firewall rule). **Windows** needs
an elevated (Administrator) prompt and `WinDivert.dll` + `WinDivert64.sys` (from [basil00/WinDivert](https://github.com/basil00/WinDivert/releases)) next to `pktreplay.exe` (the installer
includes them when available); **loopback targets (127.0.0.1) are not supported on Windows**. On Linux, loopback
works. `-backend null` needs nothing.

### Recording what is sent

| Flag | Default | Explanation |
|---|---|---|
| `-record FILE` | none | Save every packet **as actually transmitted** (after rewrites and checksum fixes) to FILE. `.pcapng` writes PCAPNG with a direction flag on each packet; any other extension writes classic PCAP. |
| `-record-rx` | true | With `-record` in TCP mode, also record the replies received from the target (marked inbound in PCAPNG). Use `-record-rx=false` to record only what you sent. |

The recorded file contains raw IP packets (nanosecond timestamps), openable in Wireshark/tshark. After the run
the tool prints how many packets and bytes were written.

### Tuning and diagnostics

| Flag | Default | Explanation |
|---|---|---|
| `-queue N` | 4096 | Depth of the reader-to-sender queue. Larger absorbs disk hiccups; memory use grows by N packets. |
| `-batch N` | 64 | Maximum packets handed to the kernel in one call in `-burst` mode (`sendmmsg` / WinDivertSendEx). |
| `-v` `-vv` `-vvv` `-log-level` `-log-file` | quiet | Diagnostic logging, see [Logging](#logging-and-verbosity). |

### Reading the result

```
mode=udp backend=null capture=samples/sample-mixed.pcap
read 23, matched 5, sent 5 pkts / 465 bytes, skipped 18, send errors 0 in 1ms (8619 pps, 6.41 Mbit/s)
```

`read` = packets read from the file; `matched` = passed the filter (and selection); `sent` = injected;
`skipped` = not sent (filtered out, wrong protocol for the mode, or unselected conversation); `send errors` =
failed sends. In TCP mode an extra line reports the flow, the local address used, handshake round-trip time,
retransmissions, bytes/segments the server sent back, and the final connection state. Press **Ctrl-C** to stop
cleanly: the queue is drained, the firewall rule removed and any recording flushed.

---

## gui

```
pktreplay gui [flags]
```

Starts the local web interface (see [README.md](README.md#gui)) and opens it in your browser.

| Flag | Default | Explanation |
|---|---|---|
| `-no-open` | off | Do not launch a browser; just print the URL (it contains the private access token). |
| `-addr HOST:PORT` | `127.0.0.1:0` | Listen address. **Loopback only**: any other address is refused. Port `0` picks a free port. |
| `-data-dir DIR` | per-user folder | Where run history and the pcap library are stored. Default `%LOCALAPPDATA%\pktreplay\history` (Windows) or `~/.local/share/pktreplay/history` (Linux); override globally with the `PKTREPLAY_DATA` environment variable. |
| `-no-history` | off | Do not record or show any history. |

Run with no flags, a second launch for the same user reopens the already-running interface instead of starting
another process (a record of the running instance is kept in `gui-instance.json` next to the history folder).
`pktreplay-gui.exe` (the windowless Windows build) is the same program and opens the GUI when started without
arguments; its log is `%LOCALAPPDATA%\pktreplay\pktreplay-gui.log`.

---

## Logging and verbosity

`stats`, `conversations`, `index` and `replay` accept the same diagnostics flags. By default only the normal
command output is printed. Diagnostics go to **stderr** (so they never mix with results on stdout), one line each:

```
12:43:42.918 DEBUG replay: new conversation at pkt 2: UDP 192.168.1.50:40000 > 192.168.1.1:53; rewrite dst-ip=10.50.0.9
```

(time, level, component, message).

| Flag | Level | Meaning |
|---|---|---|
| *(none)* | quiet | No diagnostics. |
| `-v` | info | **What is being done:** settings in effect, filter and rewrite summary, conversation rules, the flow chosen for TCP, route/target, backend opened, firewall/RST guard installed and released, index used or built, pass start (`-loop`), TCP protocol milestones (SYN, SYN-ACK and RTT, established, RST/FIN, retransmits, stream anchoring), failed send batches, a progress line every 2 s during `replay`, and timings. |
| `-vv` | debug | Everything above, plus **why:** the first packet of every conversation with the rewrite that will apply to it, every send batch (size, bytes, queue depth), and per-segment TCP detail (each segment sent with its live seq/ack and each ACK received with window and segments in flight). |
| `-vvv` | trace | Everything above, plus **one line for every packet read**: its number, addressing, and the decision (queued with before/after sizes and rewrite, rejected by the filter, skipped because of protocol, flow or missing `-conv` rule). Extremely verbose and slow on large captures; combine with `-start`/`-count` or a filter. `stats` traces every packet as counted or filtered out. |
| `-log-level LEVEL` | | The same as the shortcuts: `quiet`, `info`, `debug` or `trace` (also `0`-`3`). If both are given the higher level wins. |
| `-log-file FILE` | | Also append the diagnostic lines to FILE (still shown on stderr). Handy for sharing a trace. |

```bash
pktreplay replay -mode udp -backend null -v capture.pcap                  # what will happen
pktreplay replay -mode tcp -dst-ip 10.20.0.5 -vv capture.pcap             # TCP handshake and per-segment detail
pktreplay replay -mode udp -backend null -vvv -count 20 capture.pcap      # decision for each of the first packets
pktreplay stats -log-level debug -log-file stats.log huge.pcap            # keep a log file
```

Logging costs nothing when off, and the per-packet levels are checked once outside the packet loop, so quiet
runs keep their full speed. The old `-v` of `replay` (TCP trace) is now part of `-v`; `-vv` adds the finer detail.

---

## Recipes

```bash
# What is in this capture?
pktreplay stats capture.pcap
pktreplay conversations -sort packets -top 20 capture.pcap

# Dry run first: what would be sent, and how fast could this machine do it?
pktreplay replay -mode udp -backend null -burst -dst-ip 10.9.9.9 capture.pcap

# UDP, original timing, to another host/port
sudo pktreplay replay -mode udp -filter "proto == udp AND dst_port == 5060" \
     -dst-ip 10.20.0.5 -dst-port 5060 capture.pcap

# UDP at 100 Mbit/s, repeated 10 times, with a payload substitution
sudo pktreplay replay -mode udp -mbps 100 -loop 10 -replace "tenant-a=>tenant-b" capture.pcap

# Twice the original speed but never wait more than 100 ms for a gap
sudo pktreplay replay -mode udp -speed 2 -max-gap 100ms capture.pcap

# A real TCP connection (the capture contains the handshake)
sudo pktreplay replay -mode tcp -filter "dst_port == 8080" -dst-ip 10.20.0.5 -v capture.pcap

# Capture starts mid-connection; begin 1500 bytes into the client stream
sudo pktreplay replay -mode tcp -dst-ip 10.20.0.5 -dst-port 8080 -tcp-skip-bytes 1500 midstream.pcap

# Change one conversation only; leave everything else as captured
sudo pktreplay replay -mode udp \
     -conv "udp/192.168.1.50:40000/192.168.1.1:53,server-ip=10.50.0.9" capture.pcap

# Save exactly what went on the wire (and the replies) for later comparison in Wireshark
sudo pktreplay replay -mode tcp -dst-ip 10.20.0.5 -record sent.pcapng capture.pcap

# Windows (elevated PowerShell)
.\pktreplay.exe replay -mode tcp -dst-ip 10.20.0.5 -dst-port 8080 capture.pcap
```

---

## Troubleshooting

| Message / symptom | Meaning and fix |
|---|---|
| `select the transmission mode explicitly: -mode tcp or -mode udp` | `-mode` is mandatory. |
| `a capture file is required` | Exactly one capture path, **after** all flags. |
| `choose only one of -delay, -pps, -mbps, -burst` | Pick a single pacing mode. |
| `no TCP packet in the capture matches the filter` / `no UDP ...` | Nothing selected; loosen `-filter`/`-conv`, or you are in the wrong `-mode`. |
| `-tcp-seq-offset / -tcp-skip-bytes only apply to -mode tcp` | Remove those flags for UDP. |
| `-only-conv needs at least one -conv rule` | Add a `-conv`. |
| `tcp handshake timed out: no SYN-ACK from server` | Target unreachable, wrong IP/port, a firewall dropping the SYN, or (Linux) wrong `-iface`. Try `-handshake-timeout 15s -vv`. |
| `connection refused by server (RST in reply to SYN)` | Nothing listens on that port. |
| `server stopped acknowledging data` | The server stopped ACKing (window closed or it hung). Check the server; try `-tcp-skip-bytes` or a slower pacing. |
| Windows: access denied / driver not found | Run elevated and make sure `WinDivert.dll` and `WinDivert64.sys` sit next to `pktreplay.exe`. Antivirus products sometimes block WinDivert. |
| Linux: operation not permitted | Run with `sudo` or grant `CAP_NET_RAW`/`CAP_NET_ADMIN`. |
| Windows: nothing arrives at `127.0.0.1` | Loopback injection is not supported by WinDivert; use a real interface address of the machine. |
| Double-clicking the exe shows a window that vanishes | Starting with no arguments opens the GUI; errors are written to `%LOCALAPPDATA%\pktreplay\pktreplay-gui.log`. |
