// Package checksum implements RFC 1071 Internet checksums for IPv4 headers and
// TCP/UDP/ICMPv6 segments including their pseudo-headers.
package checksum

import (
	"encoding/binary"
	"net/netip"
)

// Sum accumulates the 16-bit big-endian words of b onto acc without folding.
// Processing 4 bytes per iteration in a 64-bit accumulator cannot overflow for
// any packet that fits in an IP datagram.
func Sum(b []byte, acc uint64) uint64 {
	for len(b) >= 8 {
		acc += uint64(binary.BigEndian.Uint32(b)) + uint64(binary.BigEndian.Uint32(b[4:]))
		b = b[8:]
	}
	if len(b) >= 4 {
		acc += uint64(binary.BigEndian.Uint32(b))
		b = b[4:]
	}
	if len(b) >= 2 {
		acc += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint64(b[0]) << 8
	}
	return acc
}

// Fold reduces an accumulator to the final one's-complement 16-bit checksum.
func Fold(acc uint64) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// Checksum returns the Internet checksum of b.
func Checksum(b []byte) uint16 { return Fold(Sum(b, 0)) }

// Pseudo returns the pseudo-header accumulator for a transport segment of
// length l4Len carried over the given addresses.
func Pseudo(src, dst netip.Addr, proto uint8, l4Len int) uint64 {
	var acc uint64
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		acc = Sum(s[:], 0)
		acc = Sum(d[:], acc)
	} else {
		s, d := src.As16(), dst.As16()
		acc = Sum(s[:], 0)
		acc = Sum(d[:], acc)
	}
	return acc + uint64(proto) + uint64(l4Len)
}

// Transport computes the TCP/UDP/ICMPv6 checksum over seg (header + payload)
// whose checksum field MUST already be zeroed. A computed UDP checksum of 0 is
// transmitted as 0xffff, per RFC 768.
func Transport(src, dst netip.Addr, proto uint8, seg []byte) uint16 {
	c := Fold(Sum(seg, Pseudo(src, dst, proto, len(seg))))
	if c == 0 && proto == 17 {
		return 0xffff
	}
	return c
}

// IPv4Header recomputes the checksum of the IPv4 header at hdr (its length
// taken from the IHL field) and stores it in place.
func IPv4Header(hdr []byte) {
	ihl := int(hdr[0]&0x0f) * 4
	hdr[10], hdr[11] = 0, 0
	binary.BigEndian.PutUint16(hdr[10:], Checksum(hdr[:ihl]))
}
