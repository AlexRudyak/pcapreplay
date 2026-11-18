package checksum

import (
	"math/rand"
	"net/netip"
	"testing"
)

// naive is a byte-at-a-time reference implementation of RFC 1071.
func naive(b []byte, init uint32) uint16 {
	s := init
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func TestMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 2000; n++ {
		b := make([]byte, n)
		rng.Read(b)
		if got, want := Checksum(b), naive(b, 0); got != want {
			t.Fatalf("len %d: got %04x want %04x", n, got, want)
		}
	}
}

func TestKnownIPv4Header(t *testing.T) {
	// Example header from RFC 1071 style references; checksum 0xb861.
	h := []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
		0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7}
	IPv4Header(h)
	if h[10] != 0xb8 || h[11] != 0x61 {
		t.Fatalf("got %02x%02x", h[10], h[11])
	}
	// A header including its own checksum must sum to zero.
	if Checksum(h) != 0 {
		t.Fatal("verification failed")
	}
}

func TestTransportVerifies(t *testing.T) {
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	seg := []byte{0x30, 0x39, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0, 'h', 'i', '!'}
	c := Transport(src, dst, 6, seg)
	seg[16], seg[17] = byte(c>>8), byte(c)
	if Fold(Sum(seg, Pseudo(src, dst, 6, len(seg)))) != 0 {
		t.Fatal("tcp checksum does not verify")
	}
	s6, d6 := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2")
	seg[16], seg[17] = 0, 0
	c = Transport(s6, d6, 6, seg)
	seg[16], seg[17] = byte(c>>8), byte(c)
	if Fold(Sum(seg, Pseudo(s6, d6, 6, len(seg)))) != 0 {
		t.Fatal("tcp/ipv6 checksum does not verify")
	}
}

func BenchmarkChecksum1500(b *testing.B) {
	buf := make([]byte, 1500)
	b.SetBytes(1500)
	for i := 0; i < b.N; i++ {
		Checksum(buf)
	}
}
