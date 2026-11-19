# internal/history

A persistent, searchable **history of every replay run** and a **library of the pcap files that were sent**, built on
the standard library only (no database dependency).

## Storage

```
<data dir>/
  history.jsonl     append-only log of put/del operations (runs and library entries)
  settings.json     retention settings
  pcaps/<sha256>.pcap   stored copies of sent captures (library)
  packets/<run>.pcapng  optional copy of the packets that were transmitted
```

Default folder: `%LOCALAPPDATA%\pktreplay\history` (Windows), `~/.local/share/pktreplay/history` (Linux) or the macOS
equivalent; override with `PKTREPLAY_DATA` or `pktreplay gui -data-dir`. Files are private to the user (0600/0700).

## The log

* Each change is one JSON line, written with one `write` and an `fsync`. On open the log is **replayed into memory**.
* A torn last line after a crash is skipped; a run still marked `running` at startup becomes `interrupted`.
* When dead lines pile up the log is **compacted atomically** (temp file + rename).
* Two processes writing the same folder is not supported.

## Runs

`Run` records when, which capture, TCP/UDP, dry-run or network, pacing, loop, target, the conversations sent and how
each was changed, the `Result` counters, TCP details, or the error. It stores the **exact request** and opaque UI state
so *Send again* can restore the screen. A run is written *before* sending and finalised afterwards. `Query` supports
search, state/mode/pinned filters and paging; `ExportCSV`/`ExportJSON` export them (CSV cells starting with `= + - @`
are prefixed so a spreadsheet cannot execute them).

## The pcap library

* Files are identified by the **SHA-256 of their content**, computed during the single copy pass, so identical
  captures are stored once. `(path, size, mtime)` of every location is remembered so an unchanged file is not re-read.
* `RegisterPcap` is meant to run in the background so a large capture never delays a send.
* Files over `MaxPcapFileMB`, or with copies switched off, become **reference** entries (id = hash of the file's
  state) that are folded into the content-hashed entry if the file is copied later.
* `PcapOpenPath` returns the path "send again" should open: the original if it still exists, else the library copy
  (the run stays labelled with the original path).
* The total size cap evicts the least recently used **unpinned** copies, keeping the entry as `removed`.

States: `CopyStored`, `CopyRef`, `CopyTooLarge`, `CopyRemoved`, `CopyFailed`.

## Retention (`Settings`)

`SaveHistory`, `MaxRuns` (1000), `MaxAgeDays`, `KeepPcaps`, `MaxPcapFileMB` (512), `MaxPcapsMB` (4096), `SavePackets`
(off by default), `MaxPacketsMB` (1024). Pinned runs and library entries are exempt; running runs are never removed.

## Packet preview

`Preview(path, offset, limit)` decodes a page of a packet copy (up to `MaxPreview` rows) for the run details view.

## Safety

Identifiers are validated (`ValidID`, `ValidPcapID`) before any file path is built, so a crafted id cannot escape the
data folder.

## Tests

`store_test.go` and `library_test.go` cover the log, crash recovery, compaction, retention, search, export, hashing,
deduplication, references, LRU pruning and id validation.

Used by: `gui`, `cmd/pktreplay`.
