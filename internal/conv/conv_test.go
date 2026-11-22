package conv

import (
	"net/netip"
	"testing"

	"github.com/AlexRudyak/pcapreplay/internal/craft"
	"github.com/AlexRudyak/pcapreplay/internal/decode"
	"github.com/AlexRudyak/pcapreplay/internal/pcapio"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func pkt(t *testing.T, proto, src, dst string, flags uint8, pay string) decode.Info {
	t.Helper()
	s, d := ap(src), ap(dst)
	spec := &craft.Spec{Src: s.Addr(), Dst: d.Addr(), SrcPort: s.Port(), DstPort: d.Port(), Flags: flags, Payload: []byte(pay)}
	var f []byte
	if proto == "udp" {
		f = craft.UDP(nil, spec)
	} else {
		f = craft.TCP(nil, spec)
	}
	var in decode.Info
	if !decode.Decode(pcapio.LinkEthernet, f, &in) {
		t.Fatal("decode")
	}
	return in
}

func TestBothDirectionsShareOneConversation(t *testing.T) {
	tb := NewTable(0)
	a := pkt(t, "tcp", "10.0.0.1:5000", "10.0.0.2:80", decode.SYN, "")
	b := pkt(t, "tcp", "10.0.0.2:80", "10.0.0.1:5000", decode.SYN|decode.ACK, "")
	c := pkt(t, "tcp", "10.0.0.1:5000", "10.0.0.2:80", decode.ACK|decode.PSH, "hello")
	tb.Add(&a, 60, 1)
	tb.Add(&b, 60, 2)
	tb.Add(&c, 100, 3)
	if tb.Len() != 1 {
		t.Fatalf("expected one conversation, got %d", tb.Len())
	}
	cv := tb.Top(0, ByBytes)[0]
	if cv.Client != ap("10.0.0.1:5000") || cv.Server != ap("10.0.0.2:80") || cv.Packets != 3 ||
		cv.C2SPackets != 2 || cv.S2CPackets != 1 || cv.Bytes != 220 || cv.State() != "established" {
		t.Fatalf("%+v state=%s", cv, cv.State())
	}
	if cv.FirstTs != 1 || cv.LastTs != 3 {
		t.Fatalf("timestamps %d..%d", cv.FirstTs, cv.LastTs)
	}
}

func TestClientDetection(t *testing.T) {
	// Capture begins with the SYN-ACK: the sender must be recognised as the server.
	tb := NewTable(0)
	sa := pkt(t, "tcp", "10.0.0.2:80", "10.0.0.1:5000", decode.SYN|decode.ACK, "")
	tb.Add(&sa, 60, 1)
	if c := tb.Top(0, ByTime)[0]; c.Server != ap("10.0.0.2:80") {
		t.Fatalf("SYN-ACK sender must be the server: %+v", c)
	}
	// A late SYN from the other side corrects a mid-stream guess (both high ports).
	tb = NewTable(0)
	mid := pkt(t, "tcp", "10.0.0.2:40000", "10.0.0.1:50000", decode.ACK, "x")
	syn := pkt(t, "tcp", "10.0.0.1:50000", "10.0.0.2:40000", decode.SYN, "")
	tb.Add(&mid, 60, 1)
	tb.Add(&syn, 60, 2)
	c := tb.Top(0, ByTime)[0]
	if c.Client != ap("10.0.0.1:50000") || c.C2SPackets != 1 || c.S2CPackets != 1 {
		t.Fatalf("roles not corrected by SYN: %+v", c)
	}
	// Mid-stream: the well-known port is the server even when the first packet is from it.
	tb = NewTable(0)
	reply := pkt(t, "tcp", "10.0.0.2:443", "10.0.0.1:50000", decode.ACK, "data")
	tb.Add(&reply, 60, 1)
	if c := tb.Top(0, ByTime)[0]; c.Server != ap("10.0.0.2:443") || c.Client != ap("10.0.0.1:50000") {
		t.Fatalf("port heuristic failed: %+v", c)
	}
}

func TestBoundedTable(t *testing.T) {
	tb := NewTable(3)
	for i := 0; i < 10; i++ {
		in := pkt(t, "udp", netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), uint16(2000+i)).String(), "10.0.0.2:53", 0, "q")
		tb.Add(&in, 60, int64(i))
	}
	if tb.Len() != 3 || tb.Untracked != 7 {
		t.Fatalf("len=%d untracked=%d", tb.Len(), tb.Untracked)
	}
	// packets of an already tracked conversation are still counted after the cap
	in := pkt(t, "udp", "10.0.0.1:2000", "10.0.0.2:53", 0, "again")
	tb.Add(&in, 60, 99)
	if c := tb.Top(0, ByTime)[0]; c.Packets != 2 {
		t.Fatalf("tracked flow ignored after cap: %+v", c)
	}
}

func TestSelectorRoundTrip(t *testing.T) {
	for _, s := range []string{
		"tcp/192.168.1.50:51234/192.168.1.10:80",
		"udp/[fd00::1]:5353/[fd00::2]:53",
		"icmp/10.0.0.1/10.0.0.2",
	} {
		k, client, err := ParseSelector(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		server := k.A
		if client == k.A {
			server = k.B
		}
		if got := Selector(k.Proto, client, server); got != s {
			t.Fatalf("round trip %q -> %q", s, got)
		}
	}
	// order of the two endpoints does not change the key, only the client role
	k1, _, _ := ParseSelector("tcp/10.0.0.1:1/10.0.0.2:2")
	k2, _, _ := ParseSelector("tcp/10.0.0.2:2/10.0.0.1:1")
	if k1 != k2 {
		t.Fatal("keys must be direction independent")
	}
	for _, bad := range []string{"", "tcp/10.0.0.1/10.0.0.2", "xyz/1.1.1.1:1/2.2.2.2:2", "tcp/1.1.1.1:1", "icmp/10.0.0.1:5/10.0.0.2"} {
		if _, _, err := ParseSelector(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRuleRewritesBothDirections(t *testing.T) {
	r, err := ParseRule("udp/10.0.0.1:5000/10.0.0.2:53,server-ip=172.16.0.9,server-port=5353,replace=a=>b")
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSet([]Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	c2s := pkt(t, "udp", "10.0.0.1:5000", "10.0.0.2:53", 0, "q")
	s2c := pkt(t, "udp", "10.0.0.2:53", "10.0.0.1:5000", 0, "a")
	other := pkt(t, "udp", "10.0.0.7:5000", "10.0.0.2:53", 0, "q")

	_, rw := set.Lookup(&c2s)
	if rw == nil || rw.DstIP != netip.MustParseAddr("172.16.0.9") || rw.DstPort != 5353 || rw.SrcIP.IsValid() || len(rw.Replace) != 1 {
		t.Fatalf("c2s rewrite wrong: %+v", rw)
	}
	_, rw = set.Lookup(&s2c)
	if rw == nil || rw.SrcIP != netip.MustParseAddr("172.16.0.9") || rw.SrcPort != 5353 || rw.DstIP.IsValid() {
		t.Fatalf("s2c rewrite wrong (reply must come FROM the new server): %+v", rw)
	}
	if rule, rw := set.Lookup(&other); rule != nil || rw != nil {
		t.Fatal("unrelated conversation matched a rule")
	}
}

func TestRuleValidation(t *testing.T) {
	r1, _ := ParseRule("udp/10.0.0.1:5000/10.0.0.2:53,server-ip=1.1.1.1")
	if _, err := NewSet([]Rule{r1, r1}); err == nil {
		t.Fatal("duplicate conversation accepted")
	}
	v6, _ := ParseRule("udp/10.0.0.1:5000/10.0.0.2:53,server-ip=fd00::1")
	if _, err := NewSet([]Rule{v6}); err == nil {
		t.Fatal("IPv4 conversation rewritten to IPv6 accepted")
	}
	icmp, _ := ParseRule("icmp/10.0.0.1/10.0.0.2,server-port=80")
	if _, err := NewSet([]Rule{icmp}); err == nil {
		t.Fatal("port rewrite on ICMP accepted")
	}
	for _, bad := range []string{"udp/10.0.0.1:5000/10.0.0.2:53,server-ip=nope", "udp/10.0.0.1:5000/10.0.0.2:53,foo=1",
		"udp/10.0.0.1:5000/10.0.0.2:53,server-port=99999", "udp/10.0.0.1:5000/10.0.0.2:53,justtext"} {
		if _, err := ParseRule(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
