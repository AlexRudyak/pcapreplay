// Package mutate rewrites addresses, ports and payloads of captured frames in
// pooled buffers and repairs every length and checksum field afterwards.
package mutate

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/sasha/pktreplay/internal/checksum"
	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/pcapio"
)

// MaxFrame bounds frame size after payload rewriting.
const MaxFrame = 65535 + 14 + 8

// Errors reported by Apply.
var (
	ErrTruncated = errors.New("mutate: frame truncated by capture snaplen")
	ErrNotIP     = errors.New("mutate: not an IP packet")
	ErrTooLarge  = errors.New("mutate: rewritten frame exceeds maximum size")
)

// Buf is a pooled working copy of one frame. B always ends exactly at the end
// of the IP datagram; In describes B and is kept consistent by every method.
type Buf struct {
	B    []byte
	In   decode.Info
	Link uint32
}

var pool = sync.Pool{New: func() any { return &Buf{B: make([]byte, 0, 2048)} }}

// Get returns a pooled buffer; return it with Put.
func Get() *Buf { return pool.Get().(*Buf) }

// Put recycles b. The buffer must not be used afterwards.
func Put(b *Buf) { pool.Put(b) }

// Load copies frame into b, trimming link-layer padding, and decodes it.
func (b *Buf) Load(link uint32, frame []byte) error {
	var probe decode.Info
	if !decode.Decode(link, frame, &probe) || !probe.HasIP {
		return ErrNotIP
	}
	end := len(frame)
	if probe.IPv6 {
		pl := int(binary.BigEndian.Uint16(frame[probe.L3Off+4:]))
		if e := probe.L3Off + 40 + pl; e <= len(frame) {
			end = e
		} else if pl != 0 {
			return ErrTruncated
		}
	} else {
		tl := int(binary.BigEndian.Uint16(frame[probe.L3Off+2:]))
		if e := probe.L3Off + tl; e <= len(frame) {
			end = e
		} else {
			return ErrTruncated
		}
	}
	b.B = append(b.B[:0], frame[:end]...)
	b.Link = link
	decode.Decode(link, b.B, &b.In)
	return nil
}

// Rewrite describes the modifications applied by Mutator.Apply. Zero values
// leave a field untouched.
type Rewrite struct {
	SrcIP, DstIP     netip.Addr
	SrcPort, DstPort uint16
	SrcMAC, DstMAC   *[6]byte

	// SetPayload replaces the whole transport payload when non-nil.
	SetPayload []byte
	// Replace performs in-payload search/replace (applied after SetPayload).
	Replace []Subst
}

// Subst is one literal search/replace pair.
type Subst struct{ Old, New []byte }

// ParseBytes converts a CLI value into bytes: "hex:de ad be ef" or 0xdeadbeef
// is raw hex, anything else is taken as UTF-8 text.
func ParseBytes(s string) ([]byte, error) {
	switch {
	case strings.HasPrefix(s, "hex:"):
		return decodeHex(s[4:])
	case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"):
		return decodeHex(s[2:])
	}
	return []byte(s), nil
}

func decodeHex(s string) ([]byte, error) {
	s = strings.NewReplacer(" ", "", ":", "", "_", "").Replace(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad hex payload: %w", err)
	}
	return b, nil
}

// ParseSubst parses "old=>new" with ParseBytes semantics on each side.
func ParseSubst(s string) (Subst, error) {
	o, n, ok := strings.Cut(s, "=>")
	if !ok || o == "" {
		return Subst{}, fmt.Errorf("replace %q: expected old=>new", s)
	}
	ob, err := ParseBytes(o)
	if err != nil {
		return Subst{}, err
	}
	nb, err := ParseBytes(n)
	if err != nil {
		return Subst{}, err
	}
	return Subst{ob, nb}, nil
}

// Active reports whether the rewrite changes anything.
func (r *Rewrite) Active() bool {
	return r.SrcIP.IsValid() || r.DstIP.IsValid() || r.SrcPort != 0 || r.DstPort != 0 ||
		r.SrcMAC != nil || r.DstMAC != nil || r.SetPayload != nil || len(r.Replace) > 0
}

// Apply performs the rewrite on b in place. Call Finalize afterwards (once all
// edits, including TCP sequence changes, are done) to repair checksums.
func (r *Rewrite) Apply(b *Buf) error {
	in := &b.In
	if r.SrcMAC != nil && b.Link == pcapio.LinkEthernet {
		copy(b.B[6:12], r.SrcMAC[:])
	}
	if r.DstMAC != nil && b.Link == pcapio.LinkEthernet {
		copy(b.B[0:6], r.DstMAC[:])
	}
	if r.SrcIP.IsValid() {
		if err := b.SetIPs(r.SrcIP, netip.Addr{}); err != nil {
			return err
		}
	}
	if r.DstIP.IsValid() {
		if err := b.SetIPs(netip.Addr{}, r.DstIP); err != nil {
			return err
		}
	}
	if in.HasPorts {
		if r.SrcPort != 0 {
			binary.BigEndian.PutUint16(b.B[in.L4Off:], r.SrcPort)
			in.SrcPort = r.SrcPort
		}
		if r.DstPort != 0 {
			binary.BigEndian.PutUint16(b.B[in.L4Off+2:], r.DstPort)
			in.DstPort = r.DstPort
		}
	}
	if r.SetPayload != nil {
		if err := b.ReplacePayload(r.SetPayload); err != nil {
			return err
		}
	}
	for _, s := range r.Replace {
		if err := b.substitute(s); err != nil {
			return err
		}
	}
	return nil
}

// SetIPs overwrites the source and/or destination address (invalid = keep).
// The address family must match the packet's.
func (b *Buf) SetIPs(src, dst netip.Addr) error {
	in := &b.In
	put := func(off int, a netip.Addr) error {
		if !a.IsValid() {
			return nil
		}
		if a.Is4() == in.IPv6 {
			return fmt.Errorf("mutate: cannot rewrite %s address with %s", map[bool]string{false: "IPv4", true: "IPv6"}[in.IPv6], a)
		}
		if a.Is4() {
			v := a.As4()
			copy(b.B[in.L3Off+off:], v[:])
		} else {
			v := a.As16()
			copy(b.B[in.L3Off+off:], v[:])
		}
		return nil
	}
	so, do := 12, 16
	if in.IPv6 {
		so, do = 8, 24
	}
	if err := put(so, src); err != nil {
		return err
	}
	if err := put(do, dst); err != nil {
		return err
	}
	if src.IsValid() {
		in.Src = src
	}
	if dst.IsValid() {
		in.Dst = dst
	}
	return nil
}

// ReplacePayload swaps the transport payload for p and fixes offsets. Lengths
// and checksums are repaired by Finalize.
func (b *Buf) ReplacePayload(p []byte) error {
	in := &b.In
	if in.PayOff == 0 {
		return errors.New("mutate: packet has no transport payload to rewrite")
	}
	if in.PayOff+len(p) > MaxFrame {
		return ErrTooLarge
	}
	b.B = append(b.B[:in.PayOff], p...)
	in.PayEnd = len(b.B)
	return nil
}

func (b *Buf) substitute(s Subst) error {
	in := &b.In
	pay := b.B[in.PayOff:]
	if in.PayOff == 0 || !bytes.Contains(pay, s.Old) {
		return nil
	}
	// Build the result in a second pooled buffer so source and destination
	// never alias; this still avoids heap allocation in steady state.
	tmp := Get()
	defer Put(tmp)
	tmp.B = tmp.B[:0]
	for {
		i := bytes.Index(pay, s.Old)
		if i < 0 {
			break
		}
		tmp.B = append(tmp.B, pay[:i]...)
		tmp.B = append(tmp.B, s.New...)
		pay = pay[i+len(s.Old):]
	}
	tmp.B = append(tmp.B, pay...)
	return b.ReplacePayload(tmp.B)
}

// SetSeqAck overwrites TCP sequence and acknowledgment numbers.
func (b *Buf) SetSeqAck(seq, ack uint32) {
	binary.BigEndian.PutUint32(b.B[b.In.L4Off+4:], seq)
	binary.BigEndian.PutUint32(b.B[b.In.L4Off+8:], ack)
	b.In.Seq, b.In.Ack = seq, ack
}

// SetFlags overwrites the TCP flag byte.
func (b *Buf) SetFlags(f uint8) {
	b.B[b.In.L4Off+13] = f
	b.In.Flags = f
}

// Finalize recomputes IPv4/IPv6 length fields, the IPv4 header checksum and the
// TCP/UDP/ICMP checksum so the frame is valid on the wire.
func (b *Buf) Finalize() {
	in := &b.In
	l3 := in.L3Off
	if in.IPv6 {
		binary.BigEndian.PutUint16(b.B[l3+4:], uint16(len(b.B)-l3-40))
	} else {
		binary.BigEndian.PutUint16(b.B[l3+2:], uint16(len(b.B)-l3))
		checksum.IPv4Header(b.B[l3:])
	}
	if in.Frag || in.L4Off == 0 {
		return // transport checksum of fragments cannot be recomputed per-packet
	}
	seg := b.B[in.L4Off:]
	switch in.Proto {
	case decode.ProtoTCP:
		seg[16], seg[17] = 0, 0
		binary.BigEndian.PutUint16(seg[16:], checksum.Transport(in.Src, in.Dst, decode.ProtoTCP, seg))
	case decode.ProtoUDP:
		binary.BigEndian.PutUint16(seg[4:], uint16(len(seg)))
		seg[6], seg[7] = 0, 0
		binary.BigEndian.PutUint16(seg[6:], checksum.Transport(in.Src, in.Dst, decode.ProtoUDP, seg))
	case decode.ProtoICMP:
		seg[2], seg[3] = 0, 0
		binary.BigEndian.PutUint16(seg[2:], checksum.Checksum(seg))
	case decode.ProtoICMPv6:
		seg[2], seg[3] = 0, 0
		binary.BigEndian.PutUint16(seg[2:], checksum.Transport(in.Src, in.Dst, decode.ProtoICMPv6, seg))
	}
	in.PayEnd = len(b.B)
}

// IPPacket returns the datagram without any link-layer header, for backends
// that inject at the network layer (WinDivert).
func (b *Buf) IPPacket() []byte { return b.B[b.In.L3Off:] }
