// Package record writes the traffic a replay actually transmitted (and, in TCP
// mode, the replies it received) to a PCAP or PCAPNG file.
//
// Packets are stored as raw IP datagrams (LINKTYPE_RAW, 101) with nanosecond
// timestamps taken when the packet was handed to / received from the backend,
// so the recording opens in tshark and Wireshark and can be fed straight back
// into pcapreplay. PCAPNG output (chosen by a .pcapng extension) additionally
// tags every packet with its direction (inbound / outbound).
package record

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	linkTypeRaw = 101
	snapLen     = 262144
)

// Writer is safe for concurrent use: sends and receives are recorded from
// different goroutines.
type Writer struct {
	mu      sync.Mutex
	f       *os.File
	bw      *bufio.Writer
	ng      bool
	err     error
	packets uint64
	bytes   uint64
	hdr     [64]byte
	path    string
}

// Create opens path for writing. The extension picks the format: .pcapng gives
// PCAPNG, anything else classic PCAP.
func Create(path string) (*Writer, error) {
	if path == "" {
		return nil, fmt.Errorf("record: empty path")
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f, bw: bufio.NewWriterSize(f, 1<<20), path: path,
		ng: strings.EqualFold(filepath.Ext(path), ".pcapng")}
	if w.ng {
		w.writeNGHeaders()
	} else {
		var h [24]byte
		le := binary.LittleEndian
		le.PutUint32(h[0:], 0xa1b23c4d) // nanosecond-resolution pcap
		le.PutUint16(h[4:], 2)
		le.PutUint16(h[6:], 4)
		le.PutUint32(h[16:], snapLen)
		le.PutUint32(h[20:], linkTypeRaw)
		w.bw.Write(h[:])
	}
	return w, nil
}

// writeNGHeaders writes the PCAPNG section header and the interface description block.
func (w *Writer) writeNGHeaders() {
	le := binary.LittleEndian
	// Section header block (28 bytes, unknown section length).
	shb := make([]byte, 28)
	le.PutUint32(shb[0:], 0x0a0d0d0a)
	le.PutUint32(shb[4:], 28)
	le.PutUint32(shb[8:], 0x1a2b3c4d)
	le.PutUint16(shb[12:], 1)
	le.PutUint64(shb[16:], ^uint64(0))
	le.PutUint32(shb[24:], 28)
	w.bw.Write(shb)
	// Interface description block with if_tsresol = 9 (nanoseconds).
	idb := make([]byte, 32)
	le.PutUint32(idb[0:], 1)
	le.PutUint32(idb[4:], 32)
	le.PutUint16(idb[8:], linkTypeRaw)
	le.PutUint32(idb[12:], snapLen)
	le.PutUint16(idb[16:], 9) // option code if_tsresol
	le.PutUint16(idb[18:], 1)
	idb[20] = 9
	// idb[21:24] padding, idb[24:28] opt_endofopt
	le.PutUint32(idb[28:], 32)
	w.bw.Write(idb)
}

// Write records one IP datagram. outbound marks packets we sent.
func (w *Writer) Write(t time.Time, ip []byte, outbound bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return
	}
	le := binary.LittleEndian
	n := len(ip)
	if n > snapLen {
		n = snapLen
	}
	ns := t.UnixNano()
	if w.ng {
		pad := (4 - n%4) % 4
		total := uint32(32 + n + pad + 12) // fixed part + data + epb_flags(8) + end(4)
		h := w.hdr[:28]
		le.PutUint32(h[0:], 6)
		le.PutUint32(h[4:], total)
		le.PutUint32(h[8:], 0)
		le.PutUint32(h[12:], uint32(uint64(ns)>>32))
		le.PutUint32(h[16:], uint32(ns))
		le.PutUint32(h[20:], uint32(n))
		le.PutUint32(h[24:], uint32(len(ip)))
		w.bw.Write(h)
		w.bw.Write(ip[:n])
		w.bw.Write(w.hdr[32 : 32+pad]) // zero padding (hdr[32:] is never written)
		var tail [12]byte
		le.PutUint16(tail[0:], 2) // epb_flags
		le.PutUint16(tail[2:], 4)
		flags := uint32(1) // inbound
		if outbound {
			flags = 2
		}
		le.PutUint32(tail[4:], flags)
		// tail[8:12] = opt_endofopt
		w.bw.Write(tail[:])
		var tl [4]byte
		le.PutUint32(tl[:], total)
		_, w.err = w.bw.Write(tl[:])
	} else {
		h := w.hdr[:16]
		le.PutUint32(h[0:], uint32(ns/1_000_000_000))
		le.PutUint32(h[4:], uint32(ns%1_000_000_000))
		le.PutUint32(h[8:], uint32(n))
		le.PutUint32(h[12:], uint32(len(ip)))
		w.bw.Write(h)
		_, w.err = w.bw.Write(ip[:n])
	}
	w.packets++
	w.bytes += uint64(n)
}

// Stats returns the number of packets and captured bytes written so far.
func (w *Writer) Stats() (packets, bytes uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.packets, w.bytes
}

// Path returns the output file path.
func (w *Writer) Path() string { return w.path }

// Close flushes and closes the file. It is safe to call more than once.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return w.err
	}
	err := w.bw.Flush()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	w.f = nil
	if w.err == nil {
		w.err = err
	}
	return w.err
}
