// Package pcapio implements a streaming, allocation-free reader for classic
// PCAP and PCAPNG capture files.
//
// The reader never holds more than one packet in memory. Packet.Data aliases an
// internal buffer that is overwritten by the next call to Next, so callers must
// copy anything they need to keep.
package pcapio

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Common link-layer types (LINKTYPE_*).
const (
	LinkNull      = 0
	LinkEthernet  = 1
	LinkRaw       = 101
	LinkLoop      = 108
	LinkLinuxSLL  = 113
	LinkRawIPv4   = 228
	LinkRawIPv6   = 229
	LinkLinuxSLL2 = 276
)

const (
	readBufSize   = 1 << 20  // 1 MiB read-ahead keeps syscalls rare.
	maxRecordSize = 64 << 20 // sanity cap for a single record / block.

	pcapMagicMicro = 0xa1b2c3d4
	pcapMagicNano  = 0xa1b23c4d

	ngSHB = 0x0a0d0d0a
	ngIDB = 0x00000001
	ngSPB = 0x00000003
	ngEPB = 0x00000006
	ngBOM = 0x1a2b3c4d
)

// ErrFormat is returned for files that are not valid PCAP/PCAPNG.
var ErrFormat = errors.New("pcapio: unrecognised or corrupt capture format")

// Format identifies the container format.
type Format int

const (
	FormatPCAP Format = iota + 1
	FormatPCAPNG
)

func (f Format) String() string {
	if f == FormatPCAPNG {
		return "pcapng"
	}
	return "pcap"
}

// Packet is one captured frame. Data is only valid until the next Next call.
type Packet struct {
	Data     []byte
	TsNanos  int64  // nanoseconds since the Unix epoch
	OrigLen  uint32 // length on the wire
	LinkType uint32
	Offset   int64  // file offset of the record/block that held this packet
	Index    uint64 // zero-based ordinal among packets returned by this reader
}

type iface struct {
	linkType uint32
	// tsUnit converts a raw timestamp tick to nanoseconds: ns = ticks*mul/div.
	mul, div uint64
}

// Reader streams packets from a PCAP or PCAPNG source.
type Reader struct {
	f   *os.File // non-nil when seekable
	br  *bufio.Reader
	bo  binary.ByteOrder
	fmt Format

	pos   int64 // file offset of the next unread byte
	count uint64

	// classic pcap
	nano     bool
	linkType uint32
	snaplen  uint32

	// pcapng
	ifaces []iface

	buf  []byte
	hdr  [32]byte
	pkt  Packet
	data int64 // offset of first record after the file/section headers
}

// Open opens a capture file for streaming.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := newReader(f, f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

// NewReader reads from an arbitrary stream (for example stdin). Seeking is not
// available on such readers.
func NewReader(src io.Reader) (*Reader, error) { return newReader(src, nil) }

func newReader(src io.Reader, f *os.File) (*Reader, error) {
	r := &Reader{f: f, br: bufio.NewReaderSize(src, readBufSize), buf: make([]byte, 64*1024)}
	if err := r.readFileHeader(); err != nil {
		return nil, err
	}
	return r, nil
}

// Close releases the underlying file.
func (r *Reader) Close() error {
	if r.f != nil {
		return r.f.Close()
	}
	return nil
}

// Format reports whether the source is PCAP or PCAPNG.
func (r *Reader) Format() Format { return r.fmt }

// LinkType returns the link type of the first interface seen so far.
func (r *Reader) LinkType() uint32 {
	if r.fmt == FormatPCAP {
		return r.linkType
	}
	if len(r.ifaces) > 0 {
		return r.ifaces[0].linkType
	}
	return LinkEthernet
}

// Offset returns the file offset of the next unread byte.
func (r *Reader) Offset() int64 { return r.pos }

// Count returns how many packets Next has returned.
func (r *Reader) Count() uint64 { return r.count }

func (r *Reader) readFull(p []byte) error {
	n, err := io.ReadFull(r.br, p)
	r.pos += int64(n)
	return err
}

func (r *Reader) readFileHeader() error {
	var magic [4]byte
	if err := r.readFull(magic[:]); err != nil {
		return ErrFormat
	}
	le := binary.LittleEndian.Uint32(magic[:])
	be := binary.BigEndian.Uint32(magic[:])
	switch {
	case le == ngSHB:
		r.fmt = FormatPCAPNG
		return r.readSectionHeader(true)
	case le == pcapMagicMicro:
		r.bo, r.nano = binary.LittleEndian, false
	case le == pcapMagicNano:
		r.bo, r.nano = binary.LittleEndian, true
	case be == pcapMagicMicro:
		r.bo, r.nano = binary.BigEndian, false
	case be == pcapMagicNano:
		r.bo, r.nano = binary.BigEndian, true
	default:
		return ErrFormat
	}
	r.fmt = FormatPCAP
	if err := r.readFull(r.hdr[:20]); err != nil {
		return ErrFormat
	}
	r.snaplen = r.bo.Uint32(r.hdr[12:16])
	r.linkType = r.bo.Uint32(r.hdr[16:20]) & 0x0fffffff
	r.data = r.pos
	return nil
}

// readSectionHeader parses a PCAPNG SHB whose 4-byte block type is already
// consumed, then eagerly consumes the IDBs that follow so LinkType is known.
func (r *Reader) readSectionHeader(first bool) error {
	if err := r.readFull(r.hdr[:8]); err != nil { // total length + byte-order magic
		return ErrFormat
	}
	switch binary.LittleEndian.Uint32(r.hdr[4:8]) {
	case ngBOM:
		r.bo = binary.LittleEndian
	default:
		if binary.BigEndian.Uint32(r.hdr[4:8]) != ngBOM {
			return ErrFormat
		}
		r.bo = binary.BigEndian
	}
	total := r.bo.Uint32(r.hdr[0:4])
	if total < 28 || total > maxRecordSize || total%4 != 0 {
		return ErrFormat
	}
	if err := r.discard(int64(total) - 12); err != nil {
		return ErrFormat
	}
	r.ifaces = r.ifaces[:0]
	if !first {
		return nil
	}
	// Eagerly read leading IDBs so seeking and LinkType() work immediately.
	for {
		peek, err := r.br.Peek(4)
		if err != nil || r.bo.Uint32(peek) != ngIDB {
			break
		}
		if _, err := r.nextBlockType(); err != nil {
			return ErrFormat
		}
		if err := r.readIDB(); err != nil {
			return ErrFormat
		}
	}
	r.data = r.pos
	return nil
}

func (r *Reader) discard(n int64) error {
	d, err := r.br.Discard(int(n))
	r.pos += int64(d)
	return err
}

func (r *Reader) nextBlockType() (uint32, error) {
	if err := r.readFull(r.hdr[:4]); err != nil {
		return 0, err
	}
	// SHB type is palindromic, so it is safe before byte order is known.
	return r.bo.Uint32(r.hdr[:4]), nil
}

// readBlockBody reads total-length and the body (without trailing length).
func (r *Reader) readBlockBody() ([]byte, error) {
	if err := r.readFull(r.hdr[:4]); err != nil {
		return nil, noEOF(err)
	}
	total := r.bo.Uint32(r.hdr[:4])
	if total < 12 || total > maxRecordSize || total%4 != 0 {
		return nil, ErrFormat
	}
	body := int(total) - 12
	r.grow(body)
	if err := r.readFull(r.buf[:body]); err != nil {
		return nil, noEOF(err)
	}
	if err := r.readFull(r.hdr[:4]); err != nil { // trailing total length
		return nil, noEOF(err)
	}
	return r.buf[:body], nil
}

func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func (r *Reader) grow(n int) {
	if n > cap(r.buf) {
		r.buf = make([]byte, n+n/2)
	}
}

func (r *Reader) readIDB() error {
	body, err := r.readBlockBody()
	if err != nil || len(body) < 8 {
		return ErrFormat
	}
	ifc := iface{linkType: uint32(r.bo.Uint16(body[0:2])), mul: 1000, div: 1} // default 1 µs
	for opts := body[8:]; len(opts) >= 4; {
		code, olen := r.bo.Uint16(opts[0:2]), int(r.bo.Uint16(opts[2:4]))
		pad := (olen + 3) &^ 3
		if code == 0 || 4+pad > len(opts) {
			break
		}
		if code == 9 && olen >= 1 { // if_tsresol
			v := opts[4]
			if v&0x80 == 0 { // 10^-v seconds per tick
				if v <= 9 {
					p := uint64(1)
					for i := byte(0); i < 9-v; i++ {
						p *= 10
					}
					ifc.mul, ifc.div = p, 1
				} else {
					p := uint64(1)
					for i := byte(9); i < v; i++ {
						p *= 10
					}
					ifc.mul, ifc.div = 1, p
				}
			} else { // 2^-v seconds per tick
				ifc.mul, ifc.div = 1_000_000_000, uint64(1)<<(v&0x7f)
			}
		}
		opts = opts[4+pad:]
	}
	r.ifaces = append(r.ifaces, ifc)
	return nil
}

// Next returns the next packet, or io.EOF at a clean end of file. A truncated
// final record yields io.ErrUnexpectedEOF.
func (r *Reader) Next() (*Packet, error) {
	if r.fmt == FormatPCAP {
		return r.nextPCAP()
	}
	return r.nextPCAPNG()
}

func (r *Reader) nextPCAP() (*Packet, error) {
	start := r.pos
	if err := r.readFull(r.hdr[:16]); err != nil {
		return nil, err // io.EOF when clean, ErrUnexpectedEOF when partial
	}
	sec := int64(r.bo.Uint32(r.hdr[0:4]))
	frac := int64(r.bo.Uint32(r.hdr[4:8]))
	incl := r.bo.Uint32(r.hdr[8:12])
	orig := r.bo.Uint32(r.hdr[12:16])
	if incl > maxRecordSize {
		return nil, ErrFormat
	}
	r.grow(int(incl))
	if err := r.readFull(r.buf[:incl]); err != nil {
		return nil, noEOF(err)
	}
	if !r.nano {
		frac *= 1000
	}
	r.pkt = Packet{Data: r.buf[:incl], TsNanos: sec*1_000_000_000 + frac, OrigLen: orig,
		LinkType: r.linkType, Offset: start, Index: r.count}
	r.count++
	return &r.pkt, nil
}

func (r *Reader) nextPCAPNG() (*Packet, error) {
	for {
		start := r.pos
		typ, err := r.nextBlockType()
		if err != nil {
			return nil, err
		}
		switch typ {
		case ngSHB:
			if err := r.readSectionHeader(false); err != nil {
				return nil, err
			}
		case ngIDB:
			if err := r.readIDB(); err != nil {
				return nil, err
			}
		case ngEPB:
			body, err := r.readBlockBody()
			if err != nil {
				return nil, err
			}
			if len(body) < 20 {
				return nil, ErrFormat
			}
			id := r.bo.Uint32(body[0:4])
			ts := uint64(r.bo.Uint32(body[4:8]))<<32 | uint64(r.bo.Uint32(body[8:12]))
			capLen, orig := r.bo.Uint32(body[12:16]), r.bo.Uint32(body[16:20])
			if int(capLen) > len(body)-20 || int(id) >= len(r.ifaces) {
				return nil, ErrFormat
			}
			ifc := r.ifaces[id]
			r.pkt = Packet{Data: body[20 : 20+capLen], TsNanos: int64(ts * ifc.mul / ifc.div),
				OrigLen: orig, LinkType: ifc.linkType, Offset: start, Index: r.count}
			r.count++
			return &r.pkt, nil
		case ngSPB:
			body, err := r.readBlockBody()
			if err != nil {
				return nil, err
			}
			if len(body) < 4 || len(r.ifaces) == 0 {
				return nil, ErrFormat
			}
			orig := r.bo.Uint32(body[0:4])
			n := int(orig)
			if n > len(body)-4 {
				n = len(body) - 4
			}
			r.pkt = Packet{Data: body[4 : 4+n], OrigLen: orig, LinkType: r.ifaces[0].linkType,
				Offset: start, Index: r.count}
			r.count++
			return &r.pkt, nil
		default: // NRB, ISB, DSB, custom blocks, obsolete packet block: skip.
			if _, err := r.readBlockBody(); err != nil {
				return nil, err
			}
		}
	}
}

// SeekOffset repositions the reader at a record boundary previously reported
// in Packet.Offset (or an Index entry). packetIndex becomes the ordinal of the
// next packet returned. Only available for file-backed readers.
//
// For PCAPNG the interface table accumulated so far is retained; this is exact
// for single-section files, which is what virtually all tools write.
func (r *Reader) SeekOffset(off int64, packetIndex uint64) error {
	if r.f == nil {
		return errors.New("pcapio: source is not seekable")
	}
	if off < r.data {
		off = r.data
	}
	if _, err := r.f.Seek(off, io.SeekStart); err != nil {
		return err
	}
	r.br.Reset(r.f)
	r.pos = off
	r.count = packetIndex
	return nil
}

// Skip discards n packets from the current position.
func (r *Reader) Skip(n uint64) error {
	for ; n > 0; n-- {
		if _, err := r.Next(); err != nil {
			return err
		}
	}
	return nil
}

// String describes the reader for diagnostics.
func (r *Reader) String() string {
	return fmt.Sprintf("%s link=%d off=%d pkts=%d", r.fmt, r.LinkType(), r.pos, r.count)
}
