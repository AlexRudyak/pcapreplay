package stats

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/sasha/pktreplay/internal/craft"
	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/pcapio"
)

func TestSpaceSavingFindsHeavyHitters(t *testing.T) {
	ss := NewSpaceSaving[int](64)
	rng := rand.New(rand.NewSource(7))
	truth := map[int]uint64{}
	// 3 heavy keys + a long tail of 100k distinct keys.
	for i := 0; i < 300000; i++ {
		var k int
		switch r := rng.Intn(10); {
		case r < 3:
			k = rng.Intn(3)
		default:
			k = 1000 + rng.Intn(100000)
		}
		truth[k]++
		ss.Add(k, 1)
	}
	if ss.Len() > 64 {
		t.Fatalf("exceeded capacity: %d", ss.Len())
	}
	top := ss.Top(3)
	seen := map[int]bool{}
	for _, e := range top {
		seen[e.Key] = true
		if e.Count < truth[e.Key] || e.Count-e.Err > truth[e.Key] {
			t.Fatalf("bounds violated for %d: est=%d err=%d true=%d", e.Key, e.Count, e.Err, truth[e.Key])
		}
	}
	for k := 0; k < 3; k++ {
		if !seen[k] {
			t.Fatalf("heavy key %d missing from top: %+v", k, top)
		}
	}
}

func TestStatsCounts(t *testing.T) {
	s := New()
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	var in decode.Info
	feed := func(f []byte) {
		ok := decode.Decode(pcapio.LinkEthernet, f, &in)
		s.Add(&in, ok, len(f), len(f), 1_000_000_000)
	}
	for i := 0; i < 5; i++ {
		feed(craft.TCP(nil, &craft.Spec{Src: a, Dst: b, SrcPort: 1000, DstPort: 443, Payload: make([]byte, 100)}))
	}
	feed(craft.UDP(nil, &craft.Spec{Src: b, Dst: a, SrcPort: 53, DstPort: 5353}))
	feed(make([]byte, 60)) // not IP
	if s.Packets != 7 || s.TCP != 5 || s.UDP != 1 || s.NonIP != 1 {
		t.Fatalf("%+v", s)
	}
	if p := s.TopPorts(decode.ProtoTCP, 1); len(p) != 1 || p[0].Port != 443 || p[0].Packets != 5 {
		t.Fatalf("ports %+v", p)
	}
	if tk := s.TopTalkers(1); len(tk) != 1 || (tk[0].Addr != a && tk[0].Addr != b) {
		t.Fatalf("talkers %+v", tk)
	}
}
