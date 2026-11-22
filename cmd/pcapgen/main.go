// Command pcapgen writes synthetic PCAP/PCAPNG files for tests and benchmarks.
// It streams to disk, so arbitrarily large captures cost constant memory.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net/netip"
	"os"

	"github.com/AlexRudyak/pcapreplay/internal/craft"
)

// main parses the flags and writes the requested synthetic capture.
func main() {
	out := flag.String("o", "synthetic.pcap", "output file")
	n := flag.Int("n", 1_000_000, "number of packets")
	ng := flag.Bool("ng", false, "write PCAPNG instead of classic PCAP")
	payload := flag.Int("payload", 64, "payload bytes per packet")
	hosts := flag.Int("hosts", 5000, "distinct client hosts")
	stream := flag.Int("stream", 0, "instead write ONE TCP conversation with this many client data segments")
	nosyn := flag.Bool("nosyn", false, "with -stream: omit the handshake (capture starts mid-stream)")
	sample := flag.Bool("sample", false, "write a small realistic mixed capture (ARP, DNS, HTTP/TCP, ICMP, syslog)")
	flag.Parse()

	if *sample {
		if err := genSample(*out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *stream > 0 {
		if err := genStream(*out, *stream, !*nosyn); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	le := binary.LittleEndian
	if *ng {
		shb := make([]byte, 28)
		le.PutUint32(shb[0:], 0x0a0d0d0a)
		le.PutUint32(shb[4:], 28)
		le.PutUint32(shb[8:], 0x1a2b3c4d)
		le.PutUint16(shb[12:], 1)
		le.PutUint64(shb[16:], ^uint64(0))
		le.PutUint32(shb[24:], 28)
		w.Write(shb)
		idb := make([]byte, 20)
		le.PutUint32(idb[0:], 1)
		le.PutUint32(idb[4:], 20)
		le.PutUint16(idb[8:], 1)
		le.PutUint32(idb[12:], 65535)
		le.PutUint32(idb[16:], 20)
		w.Write(idb)
	} else {
		hdr := make([]byte, 24)
		le.PutUint32(hdr[0:], 0xa1b2c3d4)
		le.PutUint16(hdr[4:], 2)
		le.PutUint16(hdr[6:], 4)
		le.PutUint32(hdr[16:], 65535)
		le.PutUint32(hdr[20:], 1)
		w.Write(hdr)
	}

	rng := rand.New(rand.NewSource(42))
	server := netip.MustParseAddr("10.200.0.1")
	body := make([]byte, *payload)
	copy(body, "GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n")
	var frame []byte
	ports := []uint16{80, 443, 8080, 53, 123, 5060}
	ts := int64(1_700_000_000) * 1_000_000_000
	for i := 0; i < *n; i++ {
		h := rng.Intn(*hosts)
		spec := &craft.Spec{
			Src:     netip.AddrFrom4([4]byte{192, 168, byte(h >> 8), byte(h)}),
			Dst:     server,
			SrcPort: uint16(1024 + rng.Intn(60000)),
			DstPort: ports[rng.Intn(len(ports))],
			Seq:     uint32(i), Flags: 0x18, Window: 65535, Payload: body, ID: uint16(i),
		}
		if spec.DstPort == 53 || spec.DstPort == 123 {
			frame = craft.UDP(frame, spec)
		} else {
			frame = craft.TCP(frame, spec)
		}
		ts += int64(10_000 + rng.Intn(90_000)) // 10-100 µs apart
		if *ng {
			pad := (4 - len(frame)%4) % 4
			total := uint32(32 + len(frame) + pad)
			blk := make([]byte, 28, total)
			le.PutUint32(blk[0:], 6)
			le.PutUint32(blk[4:], total)
			le.PutUint64(blk[8:], 0)
			le.PutUint32(blk[12:], uint32(uint64(ts/1000)>>32))
			le.PutUint32(blk[16:], uint32(ts/1000))
			le.PutUint32(blk[20:], uint32(len(frame)))
			le.PutUint32(blk[24:], uint32(len(frame)))
			w.Write(blk)
			w.Write(frame)
			w.Write(make([]byte, pad))
			var tail [4]byte
			le.PutUint32(tail[:], total)
			w.Write(tail[:])
		} else {
			var rec [16]byte
			le.PutUint32(rec[0:], uint32(ts/1_000_000_000))
			le.PutUint32(rec[4:], uint32(ts%1_000_000_000/1000))
			le.PutUint32(rec[8:], uint32(len(frame)))
			le.PutUint32(rec[12:], uint32(len(frame)))
			w.Write(rec[:])
			w.Write(frame)
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f.Close()
}
