package decode

import (
	"net/netip"
	"testing"

	"github.com/AlexRudyak/pktreplay/internal/craft"
	"github.com/AlexRudyak/pktreplay/internal/pcapio"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestTCPv4(t *testing.T) {
	f := craft.TCP(nil, &craft.Spec{Src: ip("10.1.2.3"), Dst: ip("192.168.0.9"), SrcPort: 4444,
		DstPort: 80, Seq: 1000, Ack: 77, Flags: ACK | PSH, Window: 512, Payload: []byte("GET /")})
	var in Info
	if !Decode(pcapio.LinkEthernet, f, &in) {
		t.Fatal("decode failed")
	}
	if in.Proto != ProtoTCP || in.Src != ip("10.1.2.3") || in.Dst != ip("192.168.0.9") ||
		in.SrcPort != 4444 || in.DstPort != 80 || in.Seq != 1000 || in.Ack != 77 ||
		in.Flags != ACK|PSH || string(in.Payload(f)) != "GET /" {
		t.Fatalf("bad decode: %+v", in)
	}
}

func TestUDPv6AndRaw(t *testing.T) {
	spec := &craft.Spec{Src: ip("fe80::1"), Dst: ip("ff02::fb"), SrcPort: 5353, DstPort: 5353, Payload: []byte{1, 2, 3}}
	f := craft.UDP(nil, spec)
	var in Info
	if !Decode(pcapio.LinkEthernet, f, &in) || !in.IPv6 || in.Proto != ProtoUDP || in.DstPort != 5353 ||
		len(in.Payload(f)) != 3 {
		t.Fatalf("bad v6 decode: %+v", in)
	}
	spec.NoEth, spec.Src, spec.Dst = true, ip("1.1.1.1"), ip("2.2.2.2")
	raw := craft.UDP(nil, spec)
	if !Decode(pcapio.LinkRaw, raw, &in) || in.Src != ip("1.1.1.1") || len(in.Payload(raw)) != 3 {
		t.Fatalf("bad raw decode: %+v", in)
	}
}

func TestVLANAndARP(t *testing.T) {
	f := craft.TCP(nil, &craft.Spec{Src: ip("1.1.1.1"), Dst: ip("2.2.2.2"), SrcPort: 1, DstPort: 2, Flags: SYN})
	// Insert an 802.1Q tag after the MACs.
	v := append(append(append([]byte{}, f[:12]...), 0x81, 0x00, 0x00, 0x05), f[12:]...)
	var in Info
	if !Decode(pcapio.LinkEthernet, v, &in) || in.DstPort != 2 || in.Flags != SYN {
		t.Fatalf("vlan decode: %+v", in)
	}
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	if !Decode(pcapio.LinkEthernet, arp, &in) || !in.ARP {
		t.Fatal("arp not detected")
	}
}

func TestGarbageDoesNotPanic(t *testing.T) {
	var in Info
	for n := 0; n < 80; n++ {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*31 + n)
		}
		for _, link := range []uint32{0, 1, 101, 113, 276} {
			Decode(link, b, &in)
		}
	}
	allocs := testing.AllocsPerRun(100, func() {
		f := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 0, 81, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 2, 0, 0, 0, 0, 0, 0}
		Decode(pcapio.LinkRaw, f, &in)
	})
	if allocs != 0 {
		t.Fatalf("Decode allocates: %v", allocs)
	}
}
