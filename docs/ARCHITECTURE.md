# Architecture

## Language and library choice: Go, standard library only

| Requirement | Why Go fits |
|---|---|
| Multi-GB captures in <100 MB RAM | Streaming reader with a single reused buffer; the garbage collector has almost nothing to collect because the hot path allocates nothing. |
| High throughput | Goroutines + a bounded channel give a producer/consumer split without hand-written threading; the compiler produces tight code for the header-parsing loops (5.8 Mpps scan, see below). |
| Windows **and** Linux from one tree | Pure Go (`CGO_ENABLED=0`): `syscall` talks to `AF_PACKET`/`sendmmsg` on Linux and loads `WinDivert.dll` lazily on Windows. No C toolchain, trivial cross-compilation. |
| Stateful TCP | Plain structs and serial-number arithmetic; a single-goroutine state machine owns all session state, so there are no locks in the TCP logic. |
| Memory safety | Bounds-checked slices; every offset taken from packet bytes is validated before use. The only `unsafe` is the ABI glue for `sendmmsg` / WinDivert structs. |

Rust (`pnet` + `windivert-rs`) would be an equally valid choice; Go was picked because the dependency-free
cross-platform build matters more here than the last few percent of throughput. There are **no third-party
dependencies** (`go.mod` has none), which also removes supply-chain surface.

## Data flow

```
 capture file
     |  1 MiB read-ahead (bufio), one reused []byte per record
     v
 pcapio.Reader â”€â”€> decode.Decode â”€â”€> filter.Match â”€â”€> mutate.Buf (pooled) â”€â”€â”
   (pcap/pcapng)     (offsets only,     (headers first,   Load/Rewrite/        â”‚ bounded
                      0 allocs)          payload last)    Finalize             â”‚ channel
                                                                               v (4096 items)
              backend.SendBatch  <â”€â”€  pace.Wait  <â”€â”€  consumer goroutine â”€â”€â”€â”€â”€â”€â”˜
              (sendmmsg / WinDivertSendEx)
```

* **Producer goroutine** (`replay.feed`): reads, decodes, filters, rewrites. Never touches the network.
* **Consumer goroutine** (`replay.send` or the TCP session): paces and injects. Never touches the disk.
* The channel is the ring buffer. When it is full the reader blocks (memory stays flat); when it is empty the sender
  waits (a slow disk cannot make timing *earlier*, only later).

### Memory model
* `pcapio.Reader.Next` returns a `*Packet` whose `Data` aliases the reader's buffer: **no per-packet allocation**.
* `decode.Info` is a value type filled in place (`netip.Addr` is a value type too).
* `mutate.Buf` objects come from a `sync.Pool`; `Load` copies the frame once, every rewrite/checksum is in place,
  and the buffer returns to the pool after transmission (TCP: after the peer acknowledges it).
* Statistics use fixed structures: 2 x 64 Ki port tables and a Space-Saving heavy-hitter sketch
  (16 384 keys) for top talkers. Measured peak working set on a 1.24 GB capture: **11.5 MB**.
* Random access: `pcapio.Index` stores one file offset per 4096 packets (16 B each; ~400 KB for 100 M packets).
  `SeekPacket(n)` seeks to the nearest entry and skips forward at most 4095 packets.

### Why `bufio` and not `mmap`
`mmap` in pure Go needs per-OS syscalls (`mmap` vs `CreateFileMapping`), maps the whole file into the address
space (counted by some memory limiters), and gives no speed-up for strictly sequential scans that the OS
read-ahead already serves. A 1 MiB `bufio.Reader` reaches 748 MB/s here and keeps the RSS flat.

## Fast-path filtering
`filter.Parse` compiles the expression into closures. `combine` sorts the terms of every AND/OR by cost, so header
comparisons (IP/CIDR via `netip.Prefix`, port ranges, protocol, TCP flags) always run before payload terms
(`bytes.Contains`, pre-compiled `regexp`), whatever order the user typed them in. Payload bytes are therefore only
looked at for packets whose headers already matched. A header-only evaluation costs ~28 ns with 0 allocations.

## Transport modes

### UDP (stateless)
Matching UDP datagrams are rewritten (IP/port/payload) and every length and checksum is recomputed
(`mutate.Buf.Finalize`: IPv4 header checksum, UDP length + pseudo-header checksum, IPv6 payload length). They are
injected as IP datagrams; the backend adds the link layer.

### TCP (stateful)
1. `ProbeFlow` selects the stream: the first packet that passes the filter defines the client (its sender) and
   server (its receiver). Only that tuple's **client -> server** packets are replayed; server packets are never
   injected, the live server produces its own.
2. The backend is opened towards the target (rewritten `-dst-ip/-dst-port`, else the captured destination),
   `Guard` installs the RST suppression, then a **real handshake** is performed: SYN (MSS only, retransmitted
   with back-off) -> SYN-ACK -> ACK. RST in reply gives `connection refused`; silence gives a timeout error.
3. Captured `SYN`, `SYN-ACK` and `RST` segments are dropped (never re-injected into the live session), pure ACKs
   are skipped (acknowledgments are generated live), TCP options are stripped (they describe a different
   connection), and a captured `FIN` ends the replay and triggers our own orderly close.

#### Sequence / acknowledgment mapping

```
capture_base_seq  = seq of the first data byte in the capture      (automatic anchoring)
                    + --tcp-skip-bytes
capture_srv_base  = ACK carried by the first replayed packet        (what the client had received by then)

live_seq(pkt) = live_isn + 1 + (pkt_seq - capture_base_seq) + --tcp-seq-offset + delta
live_ack(pkt) = live_server_isn + 1 + (pkt_ack - capture_srv_base)     [--tcp-ack-mode capture]
              = rcv_nxt                                                [--tcp-ack-mode live, default]
```

* All differences are computed as `int32(a - b)`, so **sequence wraparound** (streams crossing 2^32) is handled;
  the test suite replays a stream that wraps.
* `delta` is the accumulated change in payload length caused by `-payload` / `-replace` rewrites, so the stream
  stays contiguous when replacement text is longer or shorter than the original.
* `--tcp-skip-bytes N` starts `N` payload bytes into the stream: packets entirely before the point are dropped, a
  straddling packet is trimmed, and the first replayed byte maps to `live_isn + 1`. A mid-stream capture
  without a SYN needs no flag: the first data packet anchors the base automatically.
* `--tcp-seq-offset N` is the raw shift from the formula. A positive value leaves a hole that the server can
  never acknowledge (the engine reports `server stopped acknowledging data`); a negative value re-sends
  already-acknowledged bytes.
* `rcv_nxt` advances only on in-order server data (and FIN), so replayed segments never acknowledge bytes the
  live server has not sent. `capture` mode uses `min(rebased capture ACK, rcv_nxt)` instead.

#### Reliability
The replay engine is a small but real TCP sender: it honours the peer's advertised window, keeps unacknowledged
segments in pooled buffers, retransmits on RTO (300 ms doubling to 3 s) and on 3 duplicate ACKs, gives up after
`MaxRetries` consecutive timeouts, acknowledges every inbound data segment and FIN, and closes with FIN/ACK after
flushing. Window scaling and SACK are not negotiated (the SYN carries only MSS), so the peer's window is used as is.

## Platform backends (`internal/backend`)

```go
type Backend interface {
    Open(Options) error
    SendBatch(pkts [][]byte) (int, error)   // IP datagrams, no link header
    Guard(Flow) (release func() error, err error)
    Recv(buf []byte, timeout time.Duration) (int, error)
    Close() error
}
```

| | Linux (`linux.go`) | Windows (`windows.go`) |
|---|---|---|
| Injection | `AF_PACKET` + `SOCK_RAW`, batched `sendmmsg(2)` (<=256 frames/syscall) | `WinDivertSendEx`, up to 128 packets per call, network layer, outbound |
| L2 addressing | Interface and source MAC from the routing choice; next hop via `/proc/net/arp`, default gateway, or an ARP probe; `-dst-mac` override | Not needed (stack routes) |
| Capture | second `AF_PACKET` socket, filtered to the guarded 4-tuple, own frames (`PACKET_OUTGOING`) ignored | `WinDivertRecv` handle with a flow filter |
| Stops the OS killing the session | `nft` table (`pktreplay_<pid>`) dropping outbound RSTs of the 4-tuple, falling back to `iptables`/`ip6tables`; removed on exit | The flow's inbound segments are **diverted** to us so the stack never sees them (no RST is generated); any outbound RST of the flow is captured and discarded |
| Privileges | root, or `CAP_NET_RAW` (+ `CAP_NET_ADMIN` for the firewall rule) | Administrator; `WinDivert.dll` + `WinDivert64.sys` next to the exe |

A `null` backend discards packets, for benchmarking the pipeline without privileges.

## Recording (`internal/record`)
`record.Recorder` wraps any `Backend`: `SendBatch` records the datagrams the backend accepted (a partially failed batch records only what was sent) and `Recv` records replies. Records are raw IP (LINKTYPE_RAW) with nanosecond timestamps taken when the packet crosses the backend; PCAPNG output adds an `epb_flags` direction option. The file is flushed when the backend closes, and the CLI/GUI close the writer again on every exit path (idempotent). Because it is a wrapper it adds no cost when unused and works unchanged with the Linux, Windows and null backends.

## Pacing (`internal/pace`)
Absolute schedule (`start + due`), so a late packet never delays later ones; a stall longer than 250 ms re-bases
the clock instead of producing a catch-up burst. Waiting is hybrid: `time.Sleep` until 2 ms before the
deadline, then spin on the monotonic clock. On Windows the spin reads `QueryPerformanceCounter` directly
because Go's monotonic clock there only advances at the system timer tick (measured median lateness fell from
~600 us to ~3 us). Modes: original timing (`-speed`, `-max-gap`), fixed delay, packets/s, Mbit/s, burst.

## Measured results (AMD Ryzen 7 6800HS, Windows 11, NVMe)

| Test | Result |
|---|---|
| `stats` on a 1.24 GB / 10 M-packet pcap | 5.76 Mpps, 748 MB/s, **11.5 MB peak working set** |
| `stats` on a 2 M-packet pcapng | 3.0 Mpps, 443 MB/s |
| Header filter evaluation | 28 ns/packet, 0 allocs |
| Checksum (1500 B) | 5.3 GB/s |
| UDP pipeline, null backend, with IP/port/payload rewrite, 1.24 GB capture | ~0.9 Mpps (665 Mbit/s of 1.24 GB-capture bytes) |
| Real Linux kernel (WSL2, veth + netns): UDP | 33 226 / 33 226 datagrams delivered, ARP-resolved, 20 k pps paced |
| Real Linux kernel: TCP with handshake / mid-stream / `--tcp-skip-bytes 1000` | stream delivered byte-for-byte, FIN/ACK close, nft rule removed |

## Known limitations
* The WinDivert backend compiles, is unit-tested for ABI layout and filter generation, but **was not run against
  the driver** during development (no driver was installed on the build machine). Treat it as untested on
  hardware until you run it elevated with the official WinDivert 2.2 files.
* WinDivert network-layer injection does not support loopback targets; the Windows backend rejects them.
* Frames larger than the path MTU are injected as-is (no fragmentation).
* The TCP engine replays one flow's client->server stream; the first matching packet decides which side is
  the client, so use `-filter` (e.g. `src_ip == ...`) when a capture starts with a server packet.
* PCAPNG seeking assumes a single section (interface table from the file start).
