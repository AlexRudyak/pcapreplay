package replay

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sasha/pktreplay/internal/backend"
	"github.com/sasha/pktreplay/internal/craft"
	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/mutate"
	"github.com/sasha/pktreplay/internal/pace"
	"github.com/sasha/pktreplay/internal/pcapio"
	"github.com/sasha/pktreplay/internal/record"
)

// fakeServer is an in-process TCP peer implementing backend.Backend: packets
// the engine "sends" are interpreted by a minimal TCP server whose replies are
// queued for Recv.
type fakeServer struct {
	mu sync.Mutex
	rx chan []byte

	refuse, silent bool
	dropData       map[int]bool // 0-based data-packet indexes to drop once
	replyBytes     int          // server payload sent after the first data segment

	srvISN, expect, srvNxt uint32
	cliISN                 uint32
	syns, dataSeen         int
	data                   []byte
	seqs                   []uint32
	lastAck, lastDataAck   uint32
	synSrc, synDst         netip.AddrPort
	finSeen                bool
}

func newFake() *fakeServer {
	return &fakeServer{rx: make(chan []byte, 1024), srvISN: 7_000_000, dropData: map[int]bool{}}
}

func (f *fakeServer) Name() string               { return "fake" }
func (f *fakeServer) Open(backend.Options) error { return nil }
func (f *fakeServer) Close() error               { return nil }
func (f *fakeServer) Guard(backend.Flow) (func() error, error) {
	return func() error { return nil }, nil
}

func (f *fakeServer) Recv(buf []byte, d time.Duration) (int, error) {
	select {
	case p := <-f.rx:
		return copy(buf, p), nil
	case <-time.After(d):
		return 0, backend.ErrTimeout
	}
}

func (f *fakeServer) reply(in *decode.Info, seq, ack uint32, flags uint8, payload []byte) {
	p := craft.TCP(nil, &craft.Spec{NoEth: true, Src: in.Dst, Dst: in.Src, SrcPort: in.DstPort, DstPort: in.SrcPort,
		Seq: seq, Ack: ack, Flags: flags, Window: 65535, Payload: payload})
	f.rx <- p
}

func (f *fakeServer) SendBatch(pkts [][]byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range pkts {
		var in decode.Info
		if !decode.Decode(pcapio.LinkRaw, p, &in) || in.Proto != decode.ProtoTCP {
			continue
		}
		pay := in.Payload(p)
		switch {
		case in.Flags&decode.SYN != 0:
			f.syns++
			f.synSrc, f.synDst = netip.AddrPortFrom(in.Src, in.SrcPort), netip.AddrPortFrom(in.Dst, in.DstPort)
			if f.silent {
				continue
			}
			if f.refuse {
				f.reply(&in, 0, in.Seq+1, decode.RST|decode.ACK, nil)
				continue
			}
			f.cliISN, f.expect = in.Seq, in.Seq+1
			f.srvNxt = f.srvISN + 1
			f.reply(&in, f.srvISN, in.Seq+1, decode.SYN|decode.ACK, nil)
		case len(pay) > 0:
			f.lastAck, f.lastDataAck = in.Ack, in.Ack
			idx := f.dataSeen
			f.dataSeen++
			if f.dropData[idx] {
				delete(f.dropData, idx) // lose it once; the retransmission passes
				f.dataSeen--
				continue
			}
			f.seqs = append(f.seqs, in.Seq)
			if in.Seq == f.expect {
				f.data = append(f.data, pay...)
				f.expect += uint32(len(pay))
				if len(f.seqs) == 1 && f.replyBytes > 0 {
					f.reply(&in, f.srvNxt, f.expect, decode.ACK|decode.PSH, bytes.Repeat([]byte("s"), f.replyBytes))
					f.srvNxt += uint32(f.replyBytes)
				} else {
					f.reply(&in, f.srvNxt, f.expect, decode.ACK, nil)
				}
			} else {
				f.reply(&in, f.srvNxt, f.expect, decode.ACK, nil) // duplicate ACK
			}
		case in.Flags&decode.FIN != 0:
			f.finSeen = true
			f.expect++
			f.reply(&in, f.srvNxt, f.expect, decode.FIN|decode.ACK, nil)
			f.srvNxt++
		default:
			f.lastAck = in.Ack
		}
	}
	return len(pkts), nil
}

var (
	cliIP = netip.MustParseAddr("192.168.1.10")
	srvIP = netip.MustParseAddr("10.0.0.9")
)

func cliPkt(seq, ack uint32, flags uint8, pay string) []byte {
	return craft.TCP(nil, &craft.Spec{Src: cliIP, Dst: srvIP, SrcPort: 5555, DstPort: 80, Seq: seq, Ack: ack,
		Flags: flags, Window: 1000, Payload: []byte(pay),
		Options: []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2}}) // NOP NOP timestamps
}

func srvPkt(seq, ack uint32, flags uint8, pay string) []byte {
	return craft.TCP(nil, &craft.Spec{Src: srvIP, Dst: cliIP, SrcPort: 80, DstPort: 5555, Seq: seq, Ack: ack,
		Flags: flags, Window: 1000, Payload: []byte(pay)})
}

// withHandshake: a complete capture including SYN / SYN-ACK / data / FIN.
func withHandshake() [][]byte {
	return [][]byte{
		cliPkt(1000, 0, decode.SYN, ""),
		srvPkt(9000, 1001, decode.SYN|decode.ACK, ""),
		cliPkt(1001, 9001, decode.ACK, ""),
		cliPkt(1001, 9001, decode.ACK|decode.PSH, "HELLO "),
		srvPkt(9001, 1007, decode.ACK, ""),
		cliPkt(1007, 9001, decode.ACK|decode.PSH, "WORLD, "),
		cliPkt(1014, 9001, decode.ACK|decode.PSH, "this is a replay"),
		cliPkt(1030, 9001, decode.FIN|decode.ACK, ""),
	}
}

// midStream: no SYN, sequence numbers far from zero and near wraparound.
func midStream() [][]byte {
	const b = 0xfffffff0 // wraps within the stream
	return [][]byte{
		cliPkt(b, 777777, decode.ACK|decode.PSH, "HELLO "),
		srvPkt(777777, b+6, decode.ACK, ""),
		cliPkt(b+6, 777777, decode.ACK|decode.PSH, "WORLD, "),
		cliPkt(b+13, 777777, decode.ACK|decode.PSH, "this is a replay"),
	}
}

func baseCfg(t *testing.T, frames [][]byte, fs *fakeServer) Config {
	return Config{
		Capture: writePCAP(t, frames), Backend: fs,
		Pace:    pace.Config{Mode: pace.Burst},
		Rewrite: mutate.Rewrite{SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 40000},
		TCP:     TCPConfig{HandshakeTimeout: time.Second, CloseTimeout: 2 * time.Second, MaxRetries: 3},
	}
}

const full = "HELLO WORLD, this is a replay"

func TestFullSessionReplay(t *testing.T) {
	fs := newFake()
	res, err := RunTCP(context.Background(), baseCfg(t, withHandshake(), fs))
	if err != nil {
		t.Fatal(err)
	}
	if fs.syns != 1 {
		t.Fatalf("server saw %d SYNs: captured SYN must not be re-injected", fs.syns)
	}
	if string(fs.data) != full {
		t.Fatalf("server received %q", fs.data)
	}
	want := fs.cliISN + 1
	if fs.seqs[0] != want || fs.seqs[1] != want+6 || fs.seqs[2] != want+13 {
		t.Fatalf("seqs not rebased onto live ISN: %v (isn+1=%d)", fs.seqs, want)
	}
	if !fs.finSeen || res.TCP.FinalState == "" || !res.TCP.PeerClosed {
		t.Fatalf("session not closed cleanly: %+v finSeen=%v", res.TCP, fs.finSeen)
	}
	if res.Counters.Sent.Load() != 3 {
		t.Fatalf("sent %d data packets", res.Counters.Sent.Load())
	}
}

func TestMidStreamAutoBaseWithWraparound(t *testing.T) {
	fs := newFake()
	if _, err := RunTCP(context.Background(), baseCfg(t, midStream(), fs)); err != nil {
		t.Fatal(err)
	}
	if string(fs.data) != full {
		t.Fatalf("server received %q", fs.data)
	}
	if fs.seqs[0] != fs.cliISN+1 {
		t.Fatalf("first data seq %d, want live isn+1 = %d", fs.seqs[0], fs.cliISN+1)
	}
}

func TestSkipBytesTrimsStraddlingPacket(t *testing.T) {
	fs := newFake()
	cfg := baseCfg(t, midStream(), fs)
	cfg.TCP.SkipBytes = 9 // drops "HELLO " and "WOR"
	if _, err := RunTCP(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if string(fs.data) != "LD, this is a replay" {
		t.Fatalf("server received %q", fs.data)
	}
	if fs.seqs[0] != fs.cliISN+1 {
		t.Fatalf("first replayed byte must map to isn+1: %d vs %d", fs.seqs[0], fs.cliISN+1)
	}
}

func TestSeqOffsetShiftsSequenceNumbers(t *testing.T) {
	fs := newFake()
	cfg := baseCfg(t, midStream(), fs)
	cfg.TCP.SeqOffset = 100 // leaves a 100-byte hole: the server cannot ack it
	cfg.TCP.MaxRetries = 1
	cfg.TCP.CloseTimeout = 500 * time.Millisecond
	_, err := RunTCP(context.Background(), cfg)
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("want ErrStalled for a stream with a hole, got %v", err)
	}
	if len(fs.seqs) == 0 || fs.seqs[0] != fs.cliISN+1+100 {
		t.Fatalf("offset not applied: %v (isn+1+100 = %d)", fs.seqs, fs.cliISN+101)
	}
}

func TestHandshakeFailures(t *testing.T) {
	fs := newFake()
	fs.refuse = true
	if _, err := RunTCP(context.Background(), baseCfg(t, withHandshake(), fs)); !errors.Is(err, ErrConnRefused) {
		t.Fatalf("refused: got %v", err)
	}
	fs = newFake()
	fs.silent = true
	cfg := baseCfg(t, withHandshake(), fs)
	cfg.TCP.HandshakeTimeout = 700 * time.Millisecond
	start := time.Now()
	if _, err := RunTCP(context.Background(), cfg); !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("silent: got %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("timeout took %v", el)
	}
	if fs.syns < 2 {
		t.Fatalf("SYN was not retransmitted (%d)", fs.syns)
	}
}

func TestRetransmitsLostSegment(t *testing.T) {
	fs := newFake()
	fs.dropData[1] = true
	cfg := baseCfg(t, withHandshake(), fs)
	// A tiny peer window forces the engine to wait for ACKs, so the loss is
	// noticed via RTO rather than the stream silently ending.
	res, err := RunTCP(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(fs.data) != full {
		t.Fatalf("data after loss: %q", fs.data)
	}
	if res.TCP.Retransmits == 0 {
		t.Fatal("expected at least one retransmission")
	}
}

func TestPayloadRewriteKeepsStreamContiguous(t *testing.T) {
	fs := newFake()
	cfg := baseCfg(t, withHandshake(), fs)
	sub, _ := mutate.ParseSubst("WORLD=>BRAVE NEW WORLD")
	cfg.Rewrite.Replace = []mutate.Subst{sub}
	if _, err := RunTCP(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if string(fs.data) != "HELLO BRAVE NEW WORLD, this is a replay" {
		t.Fatalf("server received %q", fs.data)
	}
}

func TestServerDataIsAcknowledged(t *testing.T) {
	fs := newFake()
	fs.replyBytes = 100
	cfg := baseCfg(t, withHandshake(), fs)
	// Pace the segments so the reply is processed before the later ones leave;
	// in burst mode they could all be sent before the reply is read.
	cfg.Pace = pace.Config{Mode: pace.Fixed, Delay: 20 * time.Millisecond}
	res, err := RunTCP(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.TCP.RxBytes != 100 {
		t.Fatalf("rx bytes %d", res.TCP.RxBytes)
	}
	// The last data packet must acknowledge the server's 100 bytes.
	if fs.lastDataAck != fs.srvISN+1+100 {
		t.Fatalf("last data ack %d, want %d", fs.lastDataAck, fs.srvISN+101)
	}
}

func TestRecordingCapturesWholeConversation(t *testing.T) {
	fs := newFake()
	fs.replyBytes = 50
	cfg := baseCfg(t, withHandshake(), fs)
	out := filepath.Join(t.TempDir(), "conv.pcap")
	w, err := record.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Backend = record.Wrap(fs, w, true)
	if _, err := RunTCP(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	// the backend closed the recorder: file must be complete already
	rd, err := pcapio.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	var in decode.Info
	var syn, synack, data, fin, fromServer, toServer int
	var payload []byte
	for {
		p, err := rd.Next()
		if err != nil {
			break
		}
		if !decode.Decode(p.LinkType, p.Data, &in) {
			t.Fatal("recorded packet does not decode")
		}
		if in.DstPort == 80 {
			toServer++
		} else {
			fromServer++
		}
		switch {
		case in.Flags&decode.SYN != 0 && in.Flags&decode.ACK == 0:
			syn++
		case in.Flags&decode.SYN != 0:
			synack++
		case in.Flags&decode.FIN != 0 && in.DstPort == 80:
			fin++
		}
		if in.DstPort == 80 && in.PayEnd > in.PayOff {
			data++
			payload = append(payload, in.Payload(p.Data)...)
		}
	}
	if syn != 1 || synack != 1 || fin != 1 || data != 3 || string(payload) != full {
		t.Fatalf("syn=%d synack=%d data=%d fin=%d payload=%q", syn, synack, data, fin, payload)
	}
	if toServer == 0 || fromServer < 3 {
		t.Fatalf("direction split wrong: to=%d from=%d", toServer, fromServer)
	}
}

func TestProbeFlowPicksFirstMatch(t *testing.T) {
	cfg := baseCfg(t, withHandshake(), newFake())
	k, err := ProbeFlow(&cfg)
	if err != nil || k.Client != cliIP || k.Server != srvIP || k.ServerPort != 80 {
		t.Fatalf("%+v %v", k, err)
	}
}
