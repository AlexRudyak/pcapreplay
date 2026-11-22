# internal/pcapio

Streaming reader for classic **PCAP** and **PCAPNG** capture files, plus a sparse seek index.

This is the entry point of every analysis and replay: nothing else in the project opens a capture file.

## What it provides

| API | Purpose |
|---|---|
| `Open(path)` / `NewReader(io.Reader)` | Detects the format (pcap micro/nanosecond, either byte order, or pcapng) from the first bytes. |
| `(*Reader).Next() (*Packet, error)` | Returns the next packet. **`Packet.Data` aliases an internal buffer and is only valid until the next call**, which is what makes reading allocation-free. Copy it if you need to keep it. |
| `Packet` | `Data`, `TsNanos` (always nanoseconds since the Unix epoch), `OrigLen`, `LinkType`, `Offset`, `Index`, `Dir`. |
| `Skip(n)`, `SeekOffset(off, idx)`, `Offset()`, `Count()` | Positioning and progress. |
| `BuildIndex(path, stride)`, `LoadIndex`, `(*Index).Save`, `(*Index).SeekPacket` | A sparse index: one file offset per `stride` packets (default 4096, 16 bytes per entry, about 400 KB per 100 M packets). `SeekPacket(n)` jumps to the nearest entry and skips at most `stride-1` packets. |
| Link-type constants (`LinkEthernet`, `LinkRaw`, `LinkLinuxSLL`, ...) | Shared with `decode` and `mutate`. |
| `Dir*` constants | PCAPNG direction (`epb_flags`): `DirUnknown`, `DirIn`, `DirOut`. |

## How it works

* A 1 MiB `bufio.Reader` feeds a single reusable record buffer; there is no per-packet allocation.
  The choice of `bufio` over `mmap` is deliberate: pure-Go `mmap` needs per-OS syscalls and gives no benefit for strictly
  sequential scans (measured 748 MB/s with flat memory).
* Timestamps are normalised to nanoseconds, honouring the pcap magic (µs/ns) and, for pcapng, each interface's
  `if_tsresol` option.
* PCAPNG: Section Header, Interface Description, Enhanced/Simple Packet and other blocks are handled; unknown blocks are
  skipped by length. The packet direction comes from the `epb_flags` option.
* Truncated files return `io.ErrUnexpectedEOF` after the last complete packet so callers can report what was read.

## Invariants and limits

* Capture files are **untrusted input**: every length is validated against sane maxima before it is used to size a read.
* PCAPNG seeking (`SeekOffset`) assumes a single section, so the interface table is the one read from the file start.
* The index must be rebuilt if the capture changes (it records `Total` and offsets only).

## Tests

`reader_test.go` covers both formats, byte orders, nanosecond timestamps, truncation, malformed headers and the index.

Used by: `decode`, `stats`, `replay`, `history`, `mutate` (link types), `cmd/pcapreplay`.
