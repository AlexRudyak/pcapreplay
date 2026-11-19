# internal/craft

Builds complete Ethernet/IPv4/IPv6 + TCP/UDP frames into **caller-supplied buffers** (no allocation), with every
length and checksum filled in.

```go
buf := make([]byte, 2048)
frame := craft.TCP(buf, &craft.Spec{
    NoEth: true,                         // raw IP datagram (what the backends inject)
    Src: src, Dst: dst, SrcPort: 49152, DstPort: 80,
    Seq: isn, Flags: decode.SYN, Window: 65535,
    Options: mssOption,                  // multiple of 4 bytes
})
```

`Spec` describes the frame (MACs, IPs, ports, TTL, ID, TCP seq/ack/flags/window/options, payload). `craft.TCP` and
`craft.UDP` return the slice of `buf` that holds the frame.

## Why it exists

* The TCP session engine (`replay`) must create its own SYN, handshake ACK, plain ACKs, retransmitted FINs and so on:
  segments that are not copies of captured packets.
* `cmd/pcapgen` uses it to synthesise captures for tests and benchmarks, and the unit tests use it to build frames
  with known contents.

## Notes

* With `NoEth` the output is a bare IP datagram, matching WinDivert's network layer and the Linux backend, which adds
  its own Ethernet header.
* IPv4 and IPv6 are chosen from the address family of `Src`/`Dst`.

Used by: `replay` (TCP handshake and control segments), `cmd/pcapgen`, tests.
