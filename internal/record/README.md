# internal/record

Writes **the traffic a replay actually transmitted** (and, in TCP mode, the replies it received) to a PCAP or PCAPNG
file.

```go
w, _ := record.Create("sent.pcapng")             // .pcapng -> PCAPNG with direction, anything else -> PCAP
be := record.Wrap(realBackend, w, true /* also record replies */)
// use `be` wherever a backend.Backend is expected; be.Close() flushes the file
```

## Design

`Recorder` **wraps any `backend.Backend`** and embeds it:

* `SendBatch` records the datagrams the underlying backend *accepted* (a partially failed batch records only what was
  sent), then returns the backend's result.
* `Recv` records replies when `inbound` is true.
* `Also(w)` adds more writers (the GUI records both a user-chosen file and the history's packet copy).

Because it is a wrapper it adds no cost when unused and works unchanged with the Linux, Windows and null backends; a
**dry run can produce the exact traffic a real run would have sent**.

## File format

* Records are raw IP (`LINKTYPE_RAW`) with **nanosecond** timestamps taken when the packet crosses the backend.
* PCAPNG output adds an `epb_flags` option so Wireshark shows direction (outbound for sent packets, inbound for
  replies). The reader in `pcapio` understands it again.
* The writer is buffered, flushed on `Close`, and `Close` is idempotent, so the CLI and GUI can close it on every exit
  path.

## Tests

`record_test.go` records through the null backend, checks counts, directions and timestamps, and re-reads the files
with `pcapio`.

Used by: `cmd/pcapreplay` (`-record`), `gui`.
