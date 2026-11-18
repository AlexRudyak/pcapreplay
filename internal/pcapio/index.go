package pcapio

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// IndexStride is the default number of packets between index entries. With
// 16 bytes per entry a 100M-packet capture needs only ~400 KB of index.
const IndexStride = 4096

// Index is a sparse packet-number -> file-offset map enabling random access
// without keeping decoded packets in memory.
type Index struct {
	Stride  uint64
	Total   uint64
	Offsets []int64 // Offsets[i] is the record offset of packet i*Stride
}

// BuildIndex scans the whole file once, sequentially, using constant memory.
func BuildIndex(path string, stride uint64) (*Index, error) {
	if stride == 0 {
		stride = IndexStride
	}
	r, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	ix := &Index{Stride: stride}
	for {
		p, err := r.Next()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if p.Index%stride == 0 {
			ix.Offsets = append(ix.Offsets, p.Offset)
		}
		ix.Total = p.Index + 1
	}
	return ix, nil
}

// SeekPacket positions r so the next call to Next returns packet n.
func (ix *Index) SeekPacket(r *Reader, n uint64) error {
	if n >= ix.Total {
		return io.EOF
	}
	slot := n / ix.Stride
	if err := r.SeekOffset(ix.Offsets[slot], slot*ix.Stride); err != nil {
		return err
	}
	return r.Skip(n - slot*ix.Stride)
}

const indexMagic = 0x50494458 // "PIDX"

// Save writes the index to path.
func (ix *Index) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	hdr := []uint64{indexMagic, ix.Stride, ix.Total, uint64(len(ix.Offsets))}
	for _, v := range hdr {
		if err := binary.Write(w, binary.LittleEndian, v); err != nil {
			f.Close()
			return err
		}
	}
	if err := binary.Write(w, binary.LittleEndian, ix.Offsets); err != nil {
		f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadIndex reads an index written by Save.
func LoadIndex(path string) (*Index, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var hdr [4]uint64
	if err := binary.Read(br, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	if hdr[0] != indexMagic || hdr[1] == 0 || hdr[3] > 1<<32 {
		return nil, errors.New("pcapio: bad index file")
	}
	ix := &Index{Stride: hdr[1], Total: hdr[2], Offsets: make([]int64, hdr[3])}
	if err := binary.Read(br, binary.LittleEndian, ix.Offsets); err != nil {
		return nil, err
	}
	return ix, nil
}
