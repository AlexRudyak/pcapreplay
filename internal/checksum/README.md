# internal/checksum

RFC 1071 Internet checksums, fast and allocation-free.

| Function | Purpose |
|---|---|
| `Checksum(b)` | One-shot checksum of a byte slice. |
| `Sum(b, acc)` / `Fold(acc)` | Incremental form: accumulate 64-bit partial sums over several slices, then fold to 16 bits. |
| `IPv4Header(hdr)` | Recomputes the header checksum in place (clears the field first). |
| `Pseudo(src, dst, proto, l4Len)` | Partial sum of the IPv4/IPv6 pseudo-header. |
| `Transport(src, dst, proto, seg)` | Complete TCP/UDP/ICMPv6 checksum over pseudo-header plus segment. |

## Notes

* Words are accumulated into a 64-bit register eight bytes at a time with deferred carry folding, which reaches
  about **5.3 GB/s** on 1500-byte frames.
* An odd trailing byte is padded with zero as the RFC requires; `Transport` maps a computed UDP checksum of 0 to `0xFFFF` as RFC 768 requires.
* The package has no dependencies, so it is trivially reusable and testable.

## Tests

`checksum_test.go` verifies known vectors, odd lengths, the incremental path against the one-shot path, and
benchmarks throughput.

Used by: `mutate` (checksum repair), `craft` (building frames).
