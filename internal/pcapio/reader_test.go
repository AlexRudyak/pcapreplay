package pcapio

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func buildPCAP(bo binary.ByteOrder, nano bool, frames [][]byte) []byte {
	var b bytes.Buffer
	magic := uint32(pcapMagicMicro)
	if nano {
		magic = pcapMagicNano
	}
	binary.Write(&b, bo, magic)
	binary.Write(&b, bo, []uint16{2, 4})
	binary.Write(&b, bo, []uint32{0, 0, 65535, LinkEthernet})
	for i, f := range frames {
		binary.Write(&b, bo, []uint32{uint32(100 + i), uint32(7), uint32(len(f)), uint32(len(f))})
		b.Write(f)
	}
	return b.Bytes()
}

func ngBlock(bo binary.ByteOrder, typ uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	var b bytes.Buffer
	total := uint32(len(body) + 12)
	binary.Write(&b, bo, typ)
	binary.Write(&b, bo, total)
	b.Write(body)
	binary.Write(&b, bo, total)
	return b.Bytes()
}

func buildPCAPNG(bo binary.ByteOrder, frames [][]byte) []byte {
	var out bytes.Buffer
	var shb bytes.Buffer
	binary.Write(&shb, bo, uint32(ngBOM))
	binary.Write(&shb, bo, []uint16{1, 0})
	binary.Write(&shb, bo, int64(-1))
	out.Write(ngBlock(bo, ngSHB, shb.Bytes()))

	var idb bytes.Buffer
	binary.Write(&idb, bo, []uint16{LinkEthernet, 0})
	binary.Write(&idb, bo, uint32(65535))
	// if_tsresol = 9 (nanoseconds)
	binary.Write(&idb, bo, []uint16{9, 1})
	idb.Write([]byte{9, 0, 0, 0})
	binary.Write(&idb, bo, []uint16{0, 0})
	out.Write(ngBlock(bo, ngIDB, idb.Bytes()))

	for i, f := range frames {
		var epb bytes.Buffer
		ts := uint64(100+i)*1_000_000_000 + 7
		binary.Write(&epb, bo, uint32(0))
		binary.Write(&epb, bo, uint32(ts>>32))
		binary.Write(&epb, bo, uint32(ts))
		binary.Write(&epb, bo, uint32(len(f)))
		binary.Write(&epb, bo, uint32(len(f)))
		epb.Write(f)
		out.Write(ngBlock(bo, ngEPB, epb.Bytes()))
	}
	return out.Bytes()
}

func frames(n int) [][]byte {
	var fs [][]byte
	for i := 0; i < n; i++ {
		fs = append(fs, bytes.Repeat([]byte{byte(i)}, 14+i%7))
	}
	return fs
}

func checkAll(t *testing.T, r *Reader, want [][]byte, nanoFrac int64) {
	t.Helper()
	for i, w := range want {
		p, err := r.Next()
		if err != nil {
			t.Fatalf("pkt %d: %v", i, err)
		}
		if !bytes.Equal(p.Data, w) || p.Index != uint64(i) {
			t.Fatalf("pkt %d mismatch (idx %d)", i, p.Index)
		}
		if p.TsNanos != int64(100+i)*1_000_000_000+nanoFrac {
			t.Fatalf("pkt %d ts=%d", i, p.TsNanos)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("want EOF got %v", err)
	}
}

func TestFormats(t *testing.T) {
	fs := frames(25)
	cases := []struct {
		name string
		data []byte
		frac int64
	}{
		{"pcap-le-micro", buildPCAP(binary.LittleEndian, false, fs), 7000},
		{"pcap-be-micro", buildPCAP(binary.BigEndian, false, fs), 7000},
		{"pcap-le-nano", buildPCAP(binary.LittleEndian, true, fs), 7},
		{"pcapng-le", buildPCAPNG(binary.LittleEndian, fs), 7},
		{"pcapng-be", buildPCAPNG(binary.BigEndian, fs), 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := NewReader(bytes.NewReader(c.data))
			if err != nil {
				t.Fatal(err)
			}
			checkAll(t, r, fs, c.frac)
		})
	}
}

func TestTruncated(t *testing.T) {
	d := buildPCAP(binary.LittleEndian, false, frames(3))
	r, err := NewReader(bytes.NewReader(d[:len(d)-3]))
	if err != nil {
		t.Fatal(err)
	}
	r.Next()
	r.Next()
	if _, err := r.Next(); err != io.ErrUnexpectedEOF {
		t.Fatalf("got %v", err)
	}
}

func TestBadMagic(t *testing.T) {
	if _, err := NewReader(bytes.NewReader([]byte("not a capture file at all"))); err != ErrFormat {
		t.Fatalf("got %v", err)
	}
}

func TestIndexSeek(t *testing.T) {
	fs := frames(1000)
	for name, data := range map[string][]byte{
		"pcap":   buildPCAP(binary.LittleEndian, false, fs),
		"pcapng": buildPCAPNG(binary.LittleEndian, fs),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.cap")
			os.WriteFile(path, data, 0o644)
			ix, err := BuildIndex(path, 64)
			if err != nil {
				t.Fatal(err)
			}
			if ix.Total != 1000 {
				t.Fatalf("total=%d", ix.Total)
			}
			ixPath := path + ".idx"
			if err := ix.Save(ixPath); err != nil {
				t.Fatal(err)
			}
			ix2, err := LoadIndex(ixPath)
			if err != nil {
				t.Fatal(err)
			}
			r, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			for _, n := range []uint64{0, 63, 64, 500, 999, 7} {
				if err := ix2.SeekPacket(r, n); err != nil {
					t.Fatal(err)
				}
				p, err := r.Next()
				if err != nil || p.Index != n || !bytes.Equal(p.Data, fs[n]) {
					t.Fatalf("seek %d: %v idx=%d", n, err, p.Index)
				}
			}
			if err := ix2.SeekPacket(r, 1000); err != io.EOF {
				t.Fatalf("want EOF, got %v", err)
			}
		})
	}
}
