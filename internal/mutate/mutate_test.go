package mutate

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/sasha/pktreplay/internal/checksum"
	"github.com/sasha/pktreplay/internal/craft"
	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/pcapio"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// verify checks that every length and checksum in b is internally consistent.
func verify(t *testing.T, b *Buf) {
	t.Helper()
	var in decode.Info
	if !decode.Decode(pcapio.LinkEthernet, b.B, &in) {
		t.Fatal("result does not decode")
	}
	if checksum.Checksum(b.B[in.L3Off:in.L3Off+20]) != 0 && !in.IPv6 {
		t.Fatal("bad IPv4 header checksum")
	}
	seg := b.B[in.L4Off:]
	if in.Proto == decode.ProtoUDP && uint16(seg[4])<<8|uint16(seg[5]) != uint16(len(seg)) {
		t.Fatal("bad UDP length")
	}
	if checksum.Fold(checksum.Sum(seg, checksum.Pseudo(in.Src, in.Dst, in.Proto, len(seg)))) != 0 {
		t.Fatal("bad transport checksum")
	}
}

func TestRewriteIPsPortsPayload(t *testing.T) {
	cases := map[string][]byte{
		"tcp4": craft.TCP(nil, &craft.Spec{Src: ip("1.1.1.1"), Dst: ip("2.2.2.2"), SrcPort: 1, DstPort: 2, Payload: []byte("hello world")}),
		"udp4": craft.UDP(nil, &craft.Spec{Src: ip("1.1.1.1"), Dst: ip("2.2.2.2"), SrcPort: 1, DstPort: 2, Payload: []byte("hello world")}),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			b := Get()
			defer Put(b)
			if err := b.Load(pcapio.LinkEthernet, frame); err != nil {
				t.Fatal(err)
			}
			rw := Rewrite{SrcIP: ip("10.9.8.7"), DstIP: ip("10.1.1.1"), SrcPort: 5555, DstPort: 80,
				Replace: []Subst{{[]byte("world"), []byte("brave new world")}}}
			if err := rw.Apply(b); err != nil {
				t.Fatal(err)
			}
			b.Finalize()
			verify(t, b)
			var in decode.Info
			decode.Decode(pcapio.LinkEthernet, b.B, &in)
			if in.Src != ip("10.9.8.7") || in.Dst != ip("10.1.1.1") || in.SrcPort != 5555 || in.DstPort != 80 ||
				string(in.Payload(b.B)) != "hello brave new world" {
				t.Fatalf("unexpected result %+v %q", in, in.Payload(b.B))
			}
		})
	}
}

func TestSetPayloadHexAndShrink(t *testing.T) {
	frame := craft.TCP(nil, &craft.Spec{Src: ip("fe80::1"), Dst: ip("fe80::2"), SrcPort: 1, DstPort: 2, Payload: bytes.Repeat([]byte{'a'}, 500)})
	raw, err := ParseBytes("hex:de ad be ef")
	if err != nil || !bytes.Equal(raw, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatal("hex parse", err)
	}
	b := Get()
	defer Put(b)
	if err := b.Load(pcapio.LinkEthernet, frame); err != nil {
		t.Fatal(err)
	}
	if err := (&Rewrite{SetPayload: raw}).Apply(b); err != nil {
		t.Fatal(err)
	}
	b.Finalize()
	verify(t, b)
	if !bytes.HasSuffix(b.B, raw) {
		t.Fatal("payload not set")
	}
}

func TestLoadTrimsPaddingAndRejectsTruncated(t *testing.T) {
	frame := craft.UDP(nil, &craft.Spec{Src: ip("1.1.1.1"), Dst: ip("2.2.2.2"), SrcPort: 1, DstPort: 2, Payload: []byte("x")})
	padded := append(append([]byte{}, frame...), 0, 0, 0, 0, 0)
	b := Get()
	defer Put(b)
	if err := b.Load(pcapio.LinkEthernet, padded); err != nil || len(b.B) != len(frame) {
		t.Fatalf("padding not trimmed: %v %d vs %d", err, len(b.B), len(frame))
	}
	if err := b.Load(pcapio.LinkEthernet, frame[:len(frame)-1]); err != ErrTruncated {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
}

func TestStripOptionsAndTrim(t *testing.T) {
	opts := []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2} // NOP NOP timestamps
	frame := craft.TCP(nil, &craft.Spec{Src: ip("1.1.1.1"), Dst: ip("2.2.2.2"), SrcPort: 1, DstPort: 2,
		Seq: 1000, Flags: decode.ACK, Options: opts, Payload: []byte("0123456789")})
	b := Get()
	defer Put(b)
	if err := b.Load(pcapio.LinkEthernet, frame); err != nil || b.In.TCPHdr != 32 {
		t.Fatalf("load: %v hdr=%d", err, b.In.TCPHdr)
	}
	b.StripTCPOptions()
	b.TrimPayloadFront(4)
	b.SetWindow(4242)
	b.Finalize()
	verify(t, b)
	var in decode.Info
	decode.Decode(pcapio.LinkEthernet, b.B, &in)
	if in.TCPHdr != 20 || string(in.Payload(b.B)) != "456789" || in.Seq != 1004 || in.Window != 4242 {
		t.Fatalf("unexpected: hdr=%d payload=%q seq=%d win=%d", in.TCPHdr, in.Payload(b.B), in.Seq, in.Window)
	}
}

func TestFamilyMismatch(t *testing.T) {
	frame := craft.UDP(nil, &craft.Spec{Src: ip("1.1.1.1"), Dst: ip("2.2.2.2"), SrcPort: 1, DstPort: 2})
	b := Get()
	defer Put(b)
	b.Load(pcapio.LinkEthernet, frame)
	if err := (&Rewrite{DstIP: ip("::1")}).Apply(b); err == nil {
		t.Fatal("expected family mismatch error")
	}
}

func TestNoAllocsSteadyState(t *testing.T) {
	frame := craft.TCP(nil, &craft.Spec{Src: ip("1.1.1.1"), Dst: ip("2.2.2.2"), SrcPort: 1, DstPort: 2, Payload: make([]byte, 1000)})
	rw := Rewrite{SrcIP: ip("3.3.3.3"), DstPort: 99, SetPayload: bytes.Repeat([]byte{7}, 800)}
	allocs := testing.AllocsPerRun(200, func() {
		b := Get()
		b.Load(pcapio.LinkEthernet, frame)
		rw.Apply(b)
		b.Finalize()
		Put(b)
	})
	if allocs > 0.1 {
		t.Fatalf("steady state allocates: %v/op", allocs)
	}
}
