package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"

	"github.com/sasha/pktreplay/internal/craft"
)

// genStream writes one TCP conversation: optionally a SYN/SYN-ACK/ACK
// handshake, n client->server data segments ("line %d\n") with a few server
// ACKs interleaved, and a closing FIN. With syn=false the capture starts
// mid-stream at an arbitrary sequence number, as real captures often do.
func genStream(path string, n int, syn bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	le := binary.LittleEndian
	hdr := make([]byte, 24)
	le.PutUint32(hdr[0:], 0xa1b2c3d4)
	le.PutUint16(hdr[4:], 2)
	le.PutUint16(hdr[6:], 4)
	le.PutUint32(hdr[16:], 65535)
	le.PutUint32(hdr[20:], 1)
	w.Write(hdr)

	cli, srv := netip.MustParseAddr("192.168.50.5"), netip.MustParseAddr("10.200.0.1")
	ts := int64(1_700_000_000) * 1_000_000_000
	var frame []byte
	emit := func(s *craft.Spec) {
		frame = craft.TCP(frame, s)
		ts += 2_000_000 // 2 ms between packets
		var rec [16]byte
		le.PutUint32(rec[0:], uint32(ts/1_000_000_000))
		le.PutUint32(rec[4:], uint32(ts%1_000_000_000/1000))
		le.PutUint32(rec[8:], uint32(len(frame)))
		le.PutUint32(rec[12:], uint32(len(frame)))
		w.Write(rec[:])
		w.Write(frame)
	}
	c := func(seq, ack uint32, fl uint8, p []byte) *craft.Spec {
		return &craft.Spec{Src: cli, Dst: srv, SrcPort: 40001, DstPort: 8080, Seq: seq, Ack: ack, Flags: fl, Window: 502, Payload: p,
			Options: []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2}}
	}
	s := func(seq, ack uint32, fl uint8) *craft.Spec {
		return &craft.Spec{Src: srv, Dst: cli, SrcPort: 8080, DstPort: 40001, Seq: seq, Ack: ack, Flags: fl, Window: 502}
	}
	cseq, sseq := uint32(0x11223344), uint32(0x55667788)
	if syn {
		emit(c(cseq, 0, 0x02, nil))
		emit(s(sseq, cseq+1, 0x12))
		cseq++
		sseq++
		emit(c(cseq, sseq, 0x10, nil))
	} else {
		cseq, sseq = 3_000_000_000, 4_100_000_000 // mid-stream, no SYN
	}
	for i := 0; i < n; i++ {
		p := []byte(fmt.Sprintf("line %d\n", i))
		emit(c(cseq, sseq, 0x18, p))
		cseq += uint32(len(p))
		if i%4 == 3 {
			emit(s(sseq, cseq, 0x10))
		}
	}
	emit(c(cseq, sseq, 0x11, nil))
	return w.Flush()
}
