# internal/replay

The replay engine: a bounded **producer/consumer pipeline** with a stateless **UDP** engine and a stateful **TCP
session** engine on top.

```go
res, err := replay.RunUDP(ctx, replay.Config{Capture: path, Filter: flt, Backend: be, Pace: pc, ...})
res, err := replay.RunTCP(ctx, cfg)        // res.TCP has handshake RTT, retransmits, final state
```

`Config` is shared by both engines: capture, positioning, `Filter`, global `Rewrite`, per-conversation `Conversations`
and `OnlyConversations`, `Pace`, `Backend` + `Opts`, queue and batch sizes, `Loop`, live `Progress` counters, a `Log`
(`logx`), and `TCP` options (`SeqOffset`, `SkipBytes`, `AckMode`, timeouts, `Trace`/`Debug` hooks).

## The pipeline (`pipeline.go`)

```
feed (producer goroutine)                     send / session (consumer goroutine)
 pcapio -> decode -> filter -> pick(rule) -> mutate.Buf -> [bounded chan] -> pace.Wait -> backend.SendBatch
```

* `feed` streams the capture, keeps packets of the wanted protocol that pass `accept` (flow tuple, TCP mode) and the
  filter, asks `pick` which rewrite applies (conversation rule → global → drop), applies it, and finalises checksums.
* The channel is the ring buffer: when it is full the reader blocks (flat memory); when it is empty the sender waits.
* `send` batches opportunistically when pacing is `Burst`.
* `Loop` reseeks the capture and shifts timestamps by the capture's duration so pacing continues seamlessly.
* `Counters` (atomic) are readable while a run is active.

## UDP engine

`RunUDP`: probe the first packet that will actually be replayed to learn the route, open the backend, run the
pipeline. Only UDP packets are sent; everything else counts as skipped. Many conversations per run.

## TCP engine (`tcp.go`)

`RunTCP` plays the client of **one** flow against a live server:

1. `ProbeFlow` selects the flow (first packet passing filter/selection; a `-conv` rule names the client explicitly).
2. Backend opened towards the (rewritten) target; `Guard` installs the RST protection.
3. **Real handshake**: SYN (MSS option only, retransmitted with back-off) → SYN-ACK → ACK. RST gives
   `ErrConnRefused`; silence gives `ErrHandshakeTimeout`.
4. **Stream replay** (`replayOne`): captured SYN/SYN-ACK/RST are dropped, pure ACKs are skipped (ACKs are generated
   live), TCP options are stripped, payload rewrites applied, and each client segment is mapped onto the live
   connection:

   ```
   live_seq = live_isn + 1 + (pkt_seq - capture_base) + SeqOffset + delta
   live_ack = rcv_nxt                                  (AckLive, default)
            = srv_isn + 1 + (pkt_ack - capture_srv_base), capped at rcv_nxt   (AckCapture)
   ```

   Differences use `int32(a-b)`, so wraparound across 2^32 works. `delta` accumulates payload-length changes from
   rewrites so the stream stays contiguous. `SkipBytes` starts N payload bytes in (packets before are dropped, a
   straddling packet is trimmed).
5. **Reliability**: the sender honours the peer's advertised window, keeps unacknowledged segments in pooled buffers,
   retransmits on RTO (300 ms, doubling to 3 s) and on 3 duplicate ACKs, gives up after `MaxRetries` consecutive
   timeouts (`ErrStalled`), ACKs inbound data and FIN, and closes with FIN/ACK after flushing.
6. `Result.TCP` (`TCPStats`) reports the flow, local address, handshake RTT, retransmits, bytes/segments received and
   final state.

A single goroutine owns all session state (`rxLoop` feeds it through a channel), so there are no locks in the TCP logic.
Window scaling and SACK are not negotiated.

## Diagnostics

With `Config.Log` set, the engine logs at three levels: info (settings, selected flow, backend, guard), debug (first
packet of each conversation and its rewrite, send batches, per-segment TCP detail) and trace (every packet and the
decision taken). The per-packet checks happen once outside the loop, so a quiet run pays nothing.

## Tests

`pipeline_test.go`, `conv_test.go` and `tcp_test.go`. The TCP tests run the engine against an in-process fake server
implementing `backend.Backend` (a minimal TCP peer), covering handshake, mid-stream anchoring, skip bytes, offsets,
payload length changes, mid-stream sequence wraparound, a lost segment and its retransmission, acknowledgement of server data, handshake failures (refused, timed out), recording of the whole conversation, and flow selection.

Used by: `gui`, `cmd/pktreplay`.
