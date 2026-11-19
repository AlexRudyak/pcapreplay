package record

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sasha/pktreplay/internal/backend"
	"github.com/sasha/pktreplay/internal/craft"
	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/pcapio"
)

func datagram(i int) []byte {
	return craft.UDP(nil, &craft.Spec{NoEth: true, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"),
		SrcPort: uint16(1000 + i), DstPort: 53, Payload: bytes.Repeat([]byte{byte(i)}, 1+i%9)})
}

func TestRoundTripBothFormats(t *testing.T) {
	for _, name := range []string{"out.pcap", "out.pcapng", "OUT.PCAPNG"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			w, err := Create(path)
			if err != nil {
				t.Fatal(err)
			}
			base := time.Unix(1_700_000_000, 123_456_789)
			for i := 0; i < 100; i++ {
				w.Write(base.Add(time.Duration(i)*time.Millisecond), datagram(i), i%2 == 0)
			}
			if n, _ := w.Stats(); n != 100 {
				t.Fatalf("stats: %d", n)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil { // idempotent
				t.Fatal(err)
			}
			rd, err := pcapio.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer rd.Close()
			if rd.LinkType() != pcapio.LinkRaw {
				t.Fatalf("link type %d", rd.LinkType())
			}
			var in decode.Info
			for i := 0; i < 100; i++ {
				p, err := rd.Next()
				if err != nil {
					t.Fatalf("pkt %d: %v", i, err)
				}
				if !bytes.Equal(p.Data, datagram(i)) {
					t.Fatalf("pkt %d data differs", i)
				}
				if want := base.Add(time.Duration(i) * time.Millisecond).UnixNano(); p.TsNanos != want {
					t.Fatalf("pkt %d ts %d want %d (nanosecond precision lost)", i, p.TsNanos, want)
				}
				if !decode.Decode(p.LinkType, p.Data, &in) || in.SrcPort != uint16(1000+i) {
					t.Fatalf("pkt %d does not decode", i)
				}
			}
			if _, err := rd.Next(); err != io.EOF {
				t.Fatalf("want EOF, got %v", err)
			}
		})
	}
}

// fake backend with a scripted Recv.
type fake struct {
	backend.Null
	reply []byte
	fail  bool
}

func (f *fake) SendBatch(p [][]byte) (int, error) {
	if f.fail {
		return len(p) - 1, errors.New("boom") // last packet not sent
	}
	return f.Null.SendBatch(p)
}
func (f *fake) Recv(buf []byte, _ time.Duration) (int, error) { return copy(buf, f.reply), nil }

func TestRecorderCapturesOnlyAcceptedPacketsAndReplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.pcapng")
	w, _ := Create(path)
	f := &fake{reply: datagram(99)}
	r := Wrap(f, w, true)
	if r.Name() != "null+record" {
		t.Fatal(r.Name())
	}
	r.SendBatch([][]byte{datagram(1), datagram(2)})
	buf := make([]byte, 2000)
	r.Recv(buf, time.Second)
	f.fail = true
	r.SendBatch([][]byte{datagram(3), datagram(4)}) // only datagram(3) was accepted
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	rd, _ := pcapio.Open(path)
	defer rd.Close()
	var got [][]byte
	for {
		p, err := rd.Next()
		if err != nil {
			break
		}
		got = append(got, append([]byte(nil), p.Data...))
	}
	want := [][]byte{datagram(1), datagram(2), datagram(99), datagram(3)}
	if len(got) != len(want) {
		t.Fatalf("recorded %d packets, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d differs", i)
		}
	}
}

func TestPcapngDirectionAndMultipleWriters(t *testing.T) {
	dir := t.TempDir()
	p1, p2 := filepath.Join(dir, "a.pcapng"), filepath.Join(dir, "b.pcapng")
	w1, _ := Create(p1)
	w2, _ := Create(p2)
	r := Wrap(&fake{reply: datagram(50)}, w1, true)
	r.Also(w2)
	r.SendBatch([][]byte{datagram(1), datagram(2)})
	r.Recv(make([]byte, 2000), time.Second)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{p1, p2} {
		rd, err := pcapio.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		var dirs []uint8
		for {
			pk, err := rd.Next()
			if err != nil {
				break
			}
			dirs = append(dirs, pk.Dir)
		}
		rd.Close()
		if len(dirs) != 3 || dirs[0] != pcapio.DirOut || dirs[1] != pcapio.DirOut || dirs[2] != pcapio.DirIn {
			t.Fatalf("%s: directions %v, want [out out in]", filepath.Base(p), dirs)
		}
	}
}

func TestInboundCanBeExcluded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.pcap")
	w, _ := Create(path)
	r := Wrap(&fake{reply: datagram(7)}, w, false)
	r.Recv(make([]byte, 2000), time.Second)
	r.SendBatch([][]byte{datagram(1)})
	r.Close()
	if n, _ := w.Stats(); n != 1 {
		t.Fatalf("recorded %d packets; inbound must be excluded", n)
	}
}

func TestCreateErrors(t *testing.T) {
	if _, err := Create(""); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := Create(filepath.Join(t.TempDir(), "no", "such", "dir", "x.pcap")); err == nil {
		t.Fatal("missing directory accepted")
	}
}
