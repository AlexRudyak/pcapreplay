# internal/stats

Capture statistics in **one streaming pass with strictly bounded memory**.

```go
st, rd, err := stats.ScanWith(ctx, path, flt, position, count, &progress, true /* conversations */)
st.Report(os.Stdout, 10)           // the text the CLI prints
sum := st.Summary(10)              // the JSON form the GUI uses
rows := st.ConvRows(50, conv.ByBytes)
```

## What is tracked

* Counters: packets, captured and wire bytes, truncated packets, TCP/UDP/ICMP/ICMPv6/ARP/other/non-IP, IPv4 vs IPv6,
  first/last timestamp.
* **Port tables**: two 64 Ki arrays (512 KiB) counting TCP and UDP destination ports.
* **Top talkers**: a Space-Saving (Metwally et al.) heavy-hitter sketch of 16 384 keys
  (`SpaceSaving[K]`, a generic min-heap structure). Each reported talker carries its error bound (`+a..b`).
* **Conversations** (opt-in, one map lookup per IP packet): a bounded `conv.Table`, up to 100 000 flows.

## Why bounded structures

Hosts and conversations in a capture are unbounded. A hash map per host would let a 10 GB capture consume gigabytes;
the sketch and capped table guarantee a constant footprint (measured **11.5 MB** peak on a 1.24 GB capture), and
report honestly when they approximate (`Untracked`, error bounds).

## API notes

* `Scan` / `ScanWith` read the file, apply the filter, honour a `position` callback (for `-start` and index seeks) and a
  packet `count` limit, and publish live progress through `Progress` atomics so a GUI can poll while the scan runs.
* `Summary` is the JSON-friendly structure; `Report` renders the human text.

## Tests

`stats_test.go` and the sketch tests check counters, ordering, error bounds and the conversation rows.

Used by: `cmd/pktreplay` (stats, conversations), `gui` (analysis jobs).
