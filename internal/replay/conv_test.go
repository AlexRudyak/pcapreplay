package replay

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AlexRudyak/pktreplay/internal/conv"
	"github.com/AlexRudyak/pktreplay/internal/craft"
	"github.com/AlexRudyak/pktreplay/internal/decode"
	"github.com/AlexRudyak/pktreplay/internal/mutate"
	"github.com/AlexRudyak/pktreplay/internal/pace"
	"github.com/AlexRudyak/pktreplay/internal/pcapio"
)

func udpFrame(src, dst string, pay string) []byte {
	s, d := netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst)
	return craft.UDP(nil, &craft.Spec{Src: s.Addr(), Dst: d.Addr(), SrcPort: s.Port(), DstPort: d.Port(), Payload: []byte(pay)})
}

// two UDP conversations, both directions each:
//
//	A: 10.0.0.1:1000 <-> 10.0.0.2:53      B: 10.0.0.3:2000 <-> 10.0.0.2:53
func twoConversations(t *testing.T) string {
	return writePCAP(t, [][]byte{
		udpFrame("10.0.0.1:1000", "10.0.0.2:53", "A-query"),
		udpFrame("10.0.0.2:53", "10.0.0.1:1000", "A-reply"),
		udpFrame("10.0.0.3:2000", "10.0.0.2:53", "B-query"),
		udpFrame("10.0.0.2:53", "10.0.0.3:2000", "B-reply"),
	})
}

type pktView struct {
	src, dst netip.AddrPort
	payload  string
}

func decodeAll(t *testing.T, pkts [][]byte) []pktView {
	t.Helper()
	var out []pktView
	var in decode.Info
	for _, p := range pkts {
		if !decode.Decode(pcapio.LinkRaw, p, &in) {
			t.Fatal("undecodable packet")
		}
		out = append(out, pktView{netip.AddrPortFrom(in.Src, in.SrcPort), netip.AddrPortFrom(in.Dst, in.DstPort), string(in.Payload(p))})
	}
	return out
}

func mustRule(t *testing.T, s string) conv.Rule {
	t.Helper()
	r, err := conv.ParseRule(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ap2(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestRuleChangesOnlyItsConversationAndBothDirections(t *testing.T) {
	be := &capture{}
	_, err := RunUDP(context.Background(), Config{Capture: twoConversations(t), Backend: be, Pace: pace.Config{Mode: pace.Burst},
		Conversations: []conv.Rule{mustRule(t, "udp/10.0.0.1:1000/10.0.0.2:53,server-ip=172.16.0.9,server-port=5353")}})
	if err != nil {
		t.Fatal(err)
	}
	got := decodeAll(t, be.pkts)
	want := []pktView{
		{ap2("10.0.0.1:1000"), ap2("172.16.0.9:5353"), "A-query"}, // client -> new server
		{ap2("172.16.0.9:5353"), ap2("10.0.0.1:1000"), "A-reply"}, // reply now comes FROM the new server
		{ap2("10.0.0.3:2000"), ap2("10.0.0.2:53"), "B-query"},     // untouched
		{ap2("10.0.0.2:53"), ap2("10.0.0.3:2000"), "B-reply"},     // untouched
	}
	if len(got) != len(want) {
		t.Fatalf("got %d packets", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("packet %d:\n got  %+v\n want %+v", i, got[i], want[i])
		}
	}
}

func TestGlobalRewriteIsExplicitAndSupersededByRule(t *testing.T) {
	be := &capture{}
	_, err := RunUDP(context.Background(), Config{Capture: twoConversations(t), Backend: be, Pace: pace.Config{Mode: pace.Burst},
		Rewrite:       mutate.Rewrite{DstIP: netip.MustParseAddr("192.0.2.77")}, // old behaviour: every packet
		Conversations: []conv.Rule{mustRule(t, "udp/10.0.0.1:1000/10.0.0.2:53,client-ip=10.9.9.9")}})
	if err != nil {
		t.Fatal(err)
	}
	got := decodeAll(t, be.pkts)
	// conversation A: only the rule applies (global dst is NOT applied to it)
	if got[0].src.Addr() != netip.MustParseAddr("10.9.9.9") || got[0].dst != ap2("10.0.0.2:53") {
		t.Errorf("A c2s: %+v", got[0])
	}
	if got[1].src != ap2("10.0.0.2:53") || got[1].dst.Addr() != netip.MustParseAddr("10.9.9.9") {
		t.Errorf("A s2c: %+v", got[1])
	}
	// conversation B keeps the explicit global behaviour
	for _, i := range []int{2, 3} {
		if got[i].dst.Addr() != netip.MustParseAddr("192.0.2.77") {
			t.Errorf("B packet %d should get the global destination: %+v", i, got[i])
		}
	}
}

func TestOnlyConversationsDropsTheRest(t *testing.T) {
	be := &capture{}
	res, err := RunUDP(context.Background(), Config{Capture: twoConversations(t), Backend: be, Pace: pace.Config{Mode: pace.Burst},
		OnlyConversations: true,
		Conversations:     []conv.Rule{mustRule(t, "udp/10.0.0.3:2000/10.0.0.2:53,replace=B-=>X-")}})
	if err != nil {
		t.Fatal(err)
	}
	got := decodeAll(t, be.pkts)
	if len(got) != 2 || got[0].payload != "X-query" || got[1].payload != "X-reply" {
		t.Fatalf("got %+v", got)
	}
	if res.Counters.Skipped.Load() != 2 {
		t.Fatalf("unselected conversation must be counted as skipped: %d", res.Counters.Skipped.Load())
	}
	// payload substitution is per conversation: nothing else was touched
	if got[0].src != ap2("10.0.0.3:2000") || got[0].dst != ap2("10.0.0.2:53") {
		t.Fatalf("addresses changed unexpectedly: %+v", got[0])
	}
}

func TestInvalidRulesRejected(t *testing.T) {
	r := mustRule(t, "udp/10.0.0.1:1000/10.0.0.2:53,server-ip=fd00::1") // family mismatch
	if _, err := RunUDP(context.Background(), Config{Capture: twoConversations(t), Backend: &capture{}, Conversations: []conv.Rule{r}}); err == nil {
		t.Fatal("family mismatch accepted")
	}
}

func TestTCPRuleSelectsTheRightConversationAndRewritesEndpoints(t *testing.T) {
	// an unrelated TCP conversation comes FIRST in the file
	other := craft.TCP(nil, &craft.Spec{Src: netip.MustParseAddr("192.168.1.99"), Dst: srvIP, SrcPort: 6000, DstPort: 80,
		Seq: 5, Flags: decode.ACK | decode.PSH, Payload: []byte("UNRELATED")})
	frames := append([][]byte{other}, withHandshake()...)

	fs := newFake()
	cfg := baseCfg(t, frames, fs)
	cfg.Rewrite = mutate.Rewrite{} // no global rewrite at all
	cfg.Conversations = []conv.Rule{mustRule(t, "tcp/192.168.1.10:5555/10.0.0.9:80,server-port=8081,client-ip=192.0.2.5,client-port=41000")}
	cfg.TCP.CloseTimeout = 2e9
	if _, err := RunTCP(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if string(fs.data) != full {
		t.Fatalf("replayed the wrong conversation: %q", fs.data)
	}
	if fs.synSrc != ap2("192.0.2.5:41000") || fs.synDst != ap2("10.0.0.9:8081") {
		t.Fatalf("live endpoints: %v -> %v", fs.synSrc, fs.synDst)
	}
}
