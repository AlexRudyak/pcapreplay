# internal/decode

Zero-allocation header decoder. Given a raw frame and its link type it fills a caller-supplied `Info` with **offsets and
values**, never copies, never allocates.

## API

```go
var in decode.Info
ok := decode.Decode(pcapio.LinkEthernet, frame, &in)   // false: not decodable
payload := in.Payload(frame)                           // sub-slice, no copy
```

`Info` carries: `ARP`, `IPv6`, `HasIP`; offsets `L3Off`, `L4Off`, `PayOff`, `PayEnd`; `Proto`, `Src`, `Dst`
(`netip.Addr`, a value type); `HasPorts`, `SrcPort`, `DstPort`; for TCP `Flags`, `Seq`, `Ack`, `Window`, `TCPHdr`;
`ICMPType`; and `Frag` (the packet is an IP fragment). Constants: `ProtoTCP/UDP/ICMP/ICMPv6`, TCP flag bits
(`FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`).

## What is understood

* Link layers: Ethernet (with 802.1Q and QinQ VLAN tags skipped), Linux cooked (SLL, SLL2), BSD null/loop, raw IP
  (v4/v6).
* IPv4 including options and fragmentation (only the first fragment has ports); IPv6 including the extension-header
  chain.
* TCP, UDP, ICMP, ICMPv6 and ARP (no IP header: `ARP` is set).

## Design decisions

* **Offsets, not copies.** Everything downstream (filter, mutate, replay) indexes into the original frame, so a packet
  is decoded once and read many times without allocating.
* **`Info` is a plain value** that callers keep on the stack and reuse for every packet.
* **Defensive by construction.** Every offset taken from packet bytes is checked against the frame length before use;
  truncated captures (snaplen) yield partial information rather than a panic: `HasPorts` is only true when the whole
  TCP/UDP header is present.

## Tests

`decode_test.go` builds frames for every combination (VLAN, v4/v6, options, extension headers, fragments, truncations).

Used by: `filter`, `stats`, `conv`, `mutate`, `replay`, `history`.
