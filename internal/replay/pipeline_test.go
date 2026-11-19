package replay

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AlexRudyak/pktreplay/internal/backend"
	"github.com/AlexRudyak/pktreplay/internal/craft"
	"github.com/AlexRudyak/pktreplay/internal/decode"
	"github.com/AlexRudyak/pktreplay/internal/filter"
	"github.com/AlexRudyak/pktreplay/internal/mutate"
	"github.com/AlexRudyak/pktreplay/internal/pace"
	"github.com/AlexRudyak/pktreplay/internal/pcapio"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// writePCAP creates a classic pcap holding the given frames 1 ms apart.
func writePCAP(t *testing.T, frames [][]byte) string {
	t.Helper()
	var b []byte
	le := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
	b = append(b, le(0xa1b2c3d4)...)
	b = append(b, 2, 0, 4, 0)
	b = append(b, le(0)...)
	b = append(b, le(0)...)
	b = append(b, le(65535)...)
	b = append(b, le(1)...)
	for i, f := range frames {
		b = append(b, le(uint32(100+i/1000))...)
		b = append(b, le(uint32(i%1000*1000))...)
		b = append(b, le(uint32(len(f)))...)
		b = append(b, le(uint32(len(f)))...)
		b = append(b, f...)
	}
	p := filepath.Join(t.TempDir(), "t.pcap")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// capture is a backend that records everything sent to it.
type capture struct {
	backend.Null
	mu   sync.Mutex
	pkts [][]byte
}

func (c *capture) SendBatch(p [][]byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range p {
		c.pkts = append(c.pkts, append([]byte(nil), b...))
	}
	return len(p), nil
}

func mixedCapture(t *testing.T, n int) string {
	var fs [][]byte
	for i := 0; i < n; i++ {
		s := &craft.Spec{Src: ip("192.168.1.10"), Dst: ip("10.0.0.5"), SrcPort: uint16(1000 + i), DstPort: 53,
			Payload: []byte("query")}
		switch i % 3 {
		case 0:
			fs = append(fs, craft.UDP(nil, s))
		case 1:
			s.DstPort = 5353
			fs = append(fs, craft.UDP(nil, s))
		default:
			fs = append(fs, craft.TCP(nil, s))
		}
	}
	return writePCAP(t, fs)
}

func TestUDPFilterRewriteAndOrder(t *testing.T) {
	path := mixedCapture(t, 300)
	flt, err := filter.Parse("dst_port == 53")
	if err != nil {
		t.Fatal(err)
	}
	be := &capture{}
	res, err := RunUDP(context.Background(), Config{
		Capture: path, Filter: flt, Backend: be,
		Rewrite: mutate.Rewrite{DstIP: ip("172.16.0.1"), DstPort: 9000, SetPayload: []byte("replayed")},
		Pace:    pace.Config{Mode: pace.Burst},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Counters.Sent.Load(); got != 100 || len(be.pkts) != 100 {
		t.Fatalf("sent %d / recorded %d, want 100: %s", got, len(be.pkts), res)
	}
	var in decode.Info
	for i, p := range be.pkts {
		if !decode.Decode(pcapio.LinkRaw, p, &in) || in.Dst != ip("172.16.0.1") || in.DstPort != 9000 ||
			string(in.Payload(p)) != "replayed" || in.Proto != decode.ProtoUDP {
			t.Fatalf("pkt %d wrong: %+v", i, in)
		}
		if in.SrcPort != uint16(1000+i*3) {
			t.Fatalf("order violated at %d: srcport %d", i, in.SrcPort)
		}
	}
}

func TestLoopCountAndPositionSkip(t *testing.T) {
	path := mixedCapture(t, 30) // 10 UDP/53 packets
	be := &capture{}
	cfg := Config{Capture: path, Backend: be, Loop: 3, Pace: pace.Config{Mode: pace.Burst},
		Position: func(r *pcapio.Reader) error { return r.Skip(3) }} // skips first pkt of each type group
	if _, err := RunUDP(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	// 27 packets/pass after skipping 3; 2/3 are UDP => 18 per pass.
	if len(be.pkts) != 54 {
		t.Fatalf("got %d packets, want 54", len(be.pkts))
	}
}

func TestCountLimitAndOriginalPacing(t *testing.T) {
	path := mixedCapture(t, 60)
	be := &capture{}
	start := time.Now()
	res, err := RunUDP(context.Background(), Config{Capture: path, Backend: be, Count: 10,
		Pace: pace.Config{Mode: pace.Original, Speed: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Counters.Sent.Load() != 10 {
		t.Fatalf("sent %d", res.Counters.Sent.Load())
	}
	// Matched UDP packets sit 1 ms apart in the file index space: 10 of them
	// span indexes 0..14 => ~14 ms of capture time.
	if el := time.Since(start); el < 12*time.Millisecond || el > 80*time.Millisecond {
		t.Fatalf("original pacing took %v", el)
	}
}

func TestCancel(t *testing.T) {
	path := mixedCapture(t, 3000)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	be := &capture{}
	res, err := RunUDP(ctx, Config{Capture: path, Backend: be, Pace: pace.Config{Mode: pace.Fixed, Delay: 5 * time.Millisecond}})
	if err != nil {
		t.Fatalf("cancellation should be clean: %v", err)
	}
	if n := res.Counters.Sent.Load(); n == 0 || n > 20 {
		t.Fatalf("sent %d packets before cancel", n)
	}
}
