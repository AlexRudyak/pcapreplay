package filter

import (
	"net/netip"
	"testing"

	"github.com/sasha/pktreplay/internal/craft"
	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/pcapio"
)

func frame(proto string, src, dst string, sp, dp uint16, flags uint8, payload string) []byte {
	s := &craft.Spec{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
		SrcPort: sp, DstPort: dp, Flags: flags, Payload: []byte(payload)}
	if proto == "udp" {
		return craft.UDP(nil, s)
	}
	return craft.TCP(nil, s)
}

func run(t *testing.T, expr string, f []byte) bool {
	t.Helper()
	flt, err := Parse(expr)
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	var in decode.Info
	decode.Decode(pcapio.LinkEthernet, f, &in)
	return flt.Match(f, &in)
}

func TestExpressions(t *testing.T) {
	tcp := frame("tcp", "192.168.1.10", "10.0.0.5", 40000, 8080, decode.ACK|decode.PSH, "GET /index.html HTTP/1.1")
	udp := frame("udp", "172.16.0.9", "8.8.8.8", 5000, 53, 0, "\x00\x01hello")
	cases := []struct {
		expr string
		f    []byte
		want bool
	}{
		{"", tcp, true},
		{"src_ip == 192.168.1.10 AND dst_port == 8080", tcp, true},
		{"src_ip == 192.168.1.11 AND dst_port == 8080", tcp, false},
		{"src_ip == 192.168.1.0/24", tcp, true},
		{"dst_ip == 10.1.0.0/16", tcp, false},
		{"dst_ip == 10.0.0.0/16", tcp, true},
		{"ip == 10.0.0.5", tcp, true},
		{"src_ip != 192.168.1.0/24", tcp, false},
		{"proto == tcp", tcp, true},
		{"proto == udp", tcp, false},
		{"proto == udp and port == 53", udp, true},
		{"dst_port in 8000-8100", tcp, true},
		{"dst_port in 9000-9100", tcp, false},
		{"payload contains \"index.html\"", tcp, true},
		{"payload contains 0x68656c6c6f", udp, true},
		{"payload ~ \"GET /\\w+\\.html\"", tcp, true},
		{"payload ~ \"^POST\"", tcp, false},
		{"NOT proto == udp", tcp, true},
		{"!(proto == udp)", tcp, true},
		{"(proto == tcp OR proto == udp) AND dst_port == 53", udp, true},
		{"proto == tcp || proto == icmp", udp, false},
		{"tcp_flags == ack+psh", tcp, true},
		{"tcp_flags == syn", tcp, false},
		{"payload contains \"hello\" and proto == udp", udp, true}, // payload written first
	}
	for _, c := range cases {
		if got := run(t, c.expr, c.f); got != c.want {
			t.Errorf("%q = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestHeaderTermsRunBeforePayload(t *testing.T) {
	flt, err := Parse(`payload ~ "x" AND dst_port == 1`)
	if err != nil {
		t.Fatal(err)
	}
	if !flt.NeedsPayload() {
		t.Fatal("expected payload need")
	}
	// With a mismatching port the payload term must never be evaluated; a nil
	// frame would panic inside Payload() if it were.
	var in decode.Info
	in.HasPorts, in.DstPort = true, 2
	if flt.Match(nil, &in) {
		t.Fatal("should not match")
	}
}

func TestParseErrors(t *testing.T) {
	for _, e := range []string{"src_ip ==", "bogus == 1", "src_ip == 999.1.1.1", "dst_port == 70000",
		"(proto == tcp", "proto == tcp)", "payload ~ \"(\"", "proto == tcp AND", "src_ip = 1.1.1.1x", "\"abc"} {
		if _, err := Parse(e); err == nil {
			t.Errorf("%q: expected error", e)
		}
	}
}

func BenchmarkMatchHeaderOnly(b *testing.B) {
	f := frame("tcp", "192.168.1.10", "10.0.0.5", 40000, 8080, decode.ACK, "x")
	flt, _ := Parse("src_ip == 192.168.1.0/24 AND dst_port == 8080 AND payload contains \"zzz\"")
	var in decode.Info
	decode.Decode(pcapio.LinkEthernet, f, &in)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		flt.Match(f, &in)
	}
}
