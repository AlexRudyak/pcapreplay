// Package craft builds Ethernet/IP/TCP/UDP frames into caller-supplied buffers.
// It is used for the synthetic packets of the TCP handshake and in tests.
package craft

import (
	"encoding/binary"
	"net/netip"

	"github.com/AlexRudyak/pcapreplay/internal/checksum"
)

// Spec describes a frame to build. A zero MAC pair with NoEth set emits a raw
// IP datagram (no link header), as used by WinDivert's network layer.
type Spec struct {
	NoEth            bool
	SrcMAC, DstMAC   [6]byte
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	TTL              uint8
	ID               uint16

	// TCP only.
	Seq, Ack uint32
	Flags    uint8
	Window   uint16
	Options  []byte // must be a multiple of 4 bytes

	Payload []byte
}

// TCP appends a complete TCP frame to buf[:0] and returns it. The returned
// slice reuses buf's backing array when it has enough capacity.
func TCP(buf []byte, s *Spec) []byte {
	if len(s.Options)%4 != 0 {
		panic("craft: TCP options must be 4-byte aligned")
	}
	hl := 20 + len(s.Options)
	buf, l3, l4 := prefix(buf, s, hl+len(s.Payload), 6)
	t := buf[l4:]
	binary.BigEndian.PutUint16(t[0:], s.SrcPort)
	binary.BigEndian.PutUint16(t[2:], s.DstPort)
	binary.BigEndian.PutUint32(t[4:], s.Seq)
	binary.BigEndian.PutUint32(t[8:], s.Ack)
	t[12] = byte(hl/4) << 4
	t[13] = s.Flags
	binary.BigEndian.PutUint16(t[14:], s.Window)
	t[16], t[17], t[18], t[19] = 0, 0, 0, 0
	copy(t[20:], s.Options)
	copy(t[hl:], s.Payload)
	binary.BigEndian.PutUint16(t[16:], checksum.Transport(s.Src, s.Dst, 6, t))
	finishIP(buf, l3, s)
	return buf
}

// UDP appends a complete UDP frame to buf[:0] and returns it.
func UDP(buf []byte, s *Spec) []byte {
	buf, l3, l4 := prefix(buf, s, 8+len(s.Payload), 17)
	u := buf[l4:]
	binary.BigEndian.PutUint16(u[0:], s.SrcPort)
	binary.BigEndian.PutUint16(u[2:], s.DstPort)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	u[6], u[7] = 0, 0
	copy(u[8:], s.Payload)
	binary.BigEndian.PutUint16(u[6:], checksum.Transport(s.Src, s.Dst, 17, u))
	finishIP(buf, l3, s)
	return buf
}

// prefix lays out link + IP headers and returns the buffer sized for the whole
// frame together with the L3 and L4 offsets.
func prefix(buf []byte, s *Spec, l4Len int, proto uint8) ([]byte, int, int) {
	l3 := 0
	if !s.NoEth {
		l3 = 14
	}
	ipLen := 20
	etype := uint16(0x0800)
	if s.Src.Is6() {
		ipLen, etype = 40, 0x86dd
	}
	n := l3 + ipLen + l4Len
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if !s.NoEth {
		copy(buf[0:6], s.DstMAC[:])
		copy(buf[6:12], s.SrcMAC[:])
		binary.BigEndian.PutUint16(buf[12:], etype)
	}
	ttl := s.TTL
	if ttl == 0 {
		ttl = 64
	}
	h := buf[l3:]
	if ipLen == 20 {
		h[0], h[1] = 0x45, 0
		binary.BigEndian.PutUint16(h[2:], uint16(20+l4Len))
		binary.BigEndian.PutUint16(h[4:], s.ID)
		binary.BigEndian.PutUint16(h[6:], 0x4000) // DF
		h[8], h[9] = ttl, proto
		h[10], h[11] = 0, 0
		a, b := s.Src.As4(), s.Dst.As4()
		copy(h[12:16], a[:])
		copy(h[16:20], b[:])
	} else {
		h[0], h[1], h[2], h[3] = 0x60, 0, 0, 0
		binary.BigEndian.PutUint16(h[4:], uint16(l4Len))
		h[6], h[7] = proto, ttl
		a, b := s.Src.As16(), s.Dst.As16()
		copy(h[8:24], a[:])
		copy(h[24:40], b[:])
	}
	return buf, l3, l3 + ipLen
}

func finishIP(buf []byte, l3 int, s *Spec) {
	if s.Src.Is4() {
		checksum.IPv4Header(buf[l3:])
	}
}
