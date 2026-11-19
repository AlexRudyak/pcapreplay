# internal/mutate

Rewrites captured frames in **pooled buffers** and repairs every length and checksum afterwards.

## Concepts

* `Buf` is a working copy of one frame: `B` always ends exactly at the end of the IP datagram, `In` is the decoded
  view of `B` and is **kept consistent by every method**. Buffers come from a `sync.Pool` (`Get`, `Put`), so a steady
  replay allocates nothing.
* `Rewrite` describes a transformation: `SrcIP`/`DstIP`, `SrcPort`/`DstPort`, `SrcMAC`/`DstMAC`, `SetPayload`
  (replace the whole payload) and `Replace []Subst` (in-payload search and replace). `Active()` tells whether it
  changes anything; `Apply(buf)` performs it.

| API | Purpose |
|---|---|
| `Get()`, `Put(b)` | Pool management. |
| `(*Buf).Load(link, frame)` | Copies the frame once (strips the link header; returns `ErrTruncated` when the capture snaplen cut the packet). |
| `Rewrite.Apply`, `SetIPs`, `ReplacePayload` | In-place edits. |
| `SetSeqAck`, `SetFlags`, `SetWindow`, `StripTCPOptions`, `TrimPayloadFront` | TCP-specific edits used by the session engine. |
| `Finalize()` | Recomputes the IPv4 header checksum, IP/UDP lengths, IPv6 payload length and the TCP/UDP checksum (pseudo-header included). Call **once**, after all edits. |
| `IPPacket()` | The bytes to inject. |
| `ParseBytes`, `ParseSubst` | CLI value parsing: text, `hex:de ad be ef`, `0xdead`, `old=>new`. |

## Design decisions

* **Edit in place, finalise once.** Changing payload length shifts offsets; `substitute` resizes the payload and length
  fields, and the checksum is computed a single time at the end instead of after each edit.
* **No hidden allocation.** Substitutions grow within the pooled buffer (`MaxFrame` bounds it); a result that would not
  fit is an error (`ErrTooLarge`), not a reallocation.
* UDP checksums that compute to 0 are sent as `0xFFFF` (handled by `checksum.Transport`).

## Tests

`mutate_test.go` rewrites IPv4/IPv6 TCP and UDP frames, substitutes payloads of different lengths, and verifies the
result against independently computed checksums.

Used by: `replay`, `conv` (rule rewrites), `gui`.
