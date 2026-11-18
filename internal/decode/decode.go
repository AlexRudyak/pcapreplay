// Package decode extracts just enough header information from raw frames to
// filter, classify and rewrite them. It never allocates: every field is either
// a scalar, a netip.Addr (value type) or an offset into the caller's frame.
package decode

import (
	"encoding/binary"
	"net/netip"

	"github.com/sasha/pktreplay/internal/pcapio"
)

// IP protocol numbers and EtherTypes used by the engine.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58

	EtherIPv4 = 0x0800
	EtherARP  = 0x0806
	EtherIPv6 = 0x86dd
	EtherVLAN = 0x8100
	EtherQinQ = 0x88a8
)

// TCP flag bits.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
)

// Info is the decoded view of one frame. Offsets index the original frame.
type Info struct {
	ARP    bool // frame is ARP (no IP header)
	IPv6   bool
	HasIP  bool
	L3Off  int // start of IP header
	L4Off  int // start of TCP/UDP/ICMP header; 0 when absent
	PayOff int // start of transport payload
	PayEnd int // end of transport payload (exclusive)
	Proto  uint8
	Src    netip.Addr
	Dst    netip.Addr

	HasPorts bool // TCP or UDP header fully present (first fragment)
	SrcPort  uint16
	DstPort  uint16

	// TCP only.
	Flags    uint8
	Seq, Ack uint32
	Window   uint16
	TCPHdr   int // TCP header length in bytes

	ICMPType uint8
	Frag     bool // IP fragment: transport header may be absent
}

// Payload returns the transport payload slice of frame.
func (i *Info) Payload(frame []byte) []byte {
	if i.PayOff == 0 || i.PayEnd < i.PayOff {
		return nil
	}
	return frame[i.PayOff:i.PayEnd]
}

// L3Start returns the IP header offset for a link type, or -1 when the frame
// cannot carry IP. For Ethernet it also reports the ethertype found.
func l3Start(link uint32, f []byte) (off int, ether uint16) {
	switch link {
	case pcapio.LinkEthernet:
		if len(f) < 14 {
			return -1, 0
		}
		off, ether = 14, binary.BigEndian.Uint16(f[12:14])
		for n := 0; (ether == EtherVLAN || ether == EtherQinQ) && n < 4; n++ {
			if len(f) < off+4 {
				return -1, 0
			}
			ether = binary.BigEndian.Uint16(f[off+2 : off+4])
			off += 4
		}
		return off, ether
	case pcapio.LinkLinuxSLL:
		if len(f) < 16 {
			return -1, 0
		}
		return 16, binary.BigEndian.Uint16(f[14:16])
	case pcapio.LinkLinuxSLL2:
		if len(f) < 20 {
			return -1, 0
		}
		return 20, binary.BigEndian.Uint16(f[0:2])
	case pcapio.LinkNull, pcapio.LinkLoop:
		if len(f) < 4 {
			return -1, 0
		}
		return 4, ipEther(f[4:])
	case pcapio.LinkRaw, pcapio.LinkRawIPv4, pcapio.LinkRawIPv6:
		return 0, ipEther(f)
	}
	return -1, 0
}

func ipEther(b []byte) uint16 {
	if len(b) == 0 {
		return 0
	}
	switch b[0] >> 4 {
	case 4:
		return EtherIPv4
	case 6:
		return EtherIPv6
	}
	return 0
}

// Decode fills info from frame. It returns false if the frame is not IP or ARP
// or is too short to trust. info is fully reset on every call.
func Decode(link uint32, frame []byte, info *Info) bool {
	*info = Info{}
	off, ether := l3Start(link, frame)
	if off < 0 {
		return false
	}
	switch ether {
	case EtherARP:
		info.ARP = true
		return true
	case EtherIPv4:
		return decodeV4(frame, off, info)
	case EtherIPv6:
		return decodeV6(frame, off, info)
	}
	return false
}

func decodeV4(f []byte, off int, in *Info) bool {
	if len(f) < off+20 || f[off]>>4 != 4 {
		return false
	}
	ihl := int(f[off]&0x0f) * 4
	if ihl < 20 || len(f) < off+ihl {
		return false
	}
	total := int(binary.BigEndian.Uint16(f[off+2 : off+4]))
	end := off + total
	if total < ihl || end > len(f) {
		end = len(f) // snap-truncated capture: use what we have
	}
	fragField := binary.BigEndian.Uint16(f[off+6 : off+8])
	in.HasIP, in.L3Off = true, off
	in.Proto = f[off+9]
	in.Src = netip.AddrFrom4([4]byte(f[off+12 : off+16]))
	in.Dst = netip.AddrFrom4([4]byte(f[off+16 : off+20]))
	in.Frag = fragField&0x3fff != 0 // MF set or offset != 0
	l4 := off + ihl
	if fragField&0x1fff != 0 { // not the first fragment: no transport header
		return true
	}
	decodeL4(f, l4, end, in)
	return true
}

func decodeV6(f []byte, off int, in *Info) bool {
	if len(f) < off+40 || f[off]>>4 != 6 {
		return false
	}
	in.HasIP, in.IPv6, in.L3Off = true, true, off
	in.Src = netip.AddrFrom16([16]byte(f[off+8 : off+24]))
	in.Dst = netip.AddrFrom16([16]byte(f[off+24 : off+40]))
	end := off + 40 + int(binary.BigEndian.Uint16(f[off+4:off+6]))
	if end > len(f) || end < off+40 {
		end = len(f)
	}
	nh := f[off+6]
	p := off + 40
	for n := 0; n < 8; n++ { // bounded walk over extension headers
		switch nh {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(f) < p+8 {
				return true
			}
			nh, p = f[p], p+(int(f[p+1])+1)*8
		case 51: // AH counts in 4-byte units
			if len(f) < p+8 {
				return true
			}
			nh, p = f[p], p+(int(f[p+1])+2)*4
		case 44: // fragment
			if len(f) < p+8 {
				return true
			}
			in.Frag = true
			if binary.BigEndian.Uint16(f[p+2:p+4])&0xfff8 != 0 {
				in.Proto = f[p]
				return true
			}
			nh, p = f[p], p+8
		default:
			in.Proto = nh
			decodeL4(f, p, end, in)
			return true
		}
	}
	return true
}

func decodeL4(f []byte, l4, end int, in *Info) {
	if l4 > len(f) {
		return
	}
	switch in.Proto {
	case ProtoTCP:
		if len(f) < l4+20 {
			return
		}
		hl := int(f[l4+12]>>4) * 4
		if hl < 20 || l4+hl > len(f) {
			return
		}
		in.L4Off, in.HasPorts, in.TCPHdr = l4, true, hl
		in.SrcPort = binary.BigEndian.Uint16(f[l4:])
		in.DstPort = binary.BigEndian.Uint16(f[l4+2:])
		in.Seq = binary.BigEndian.Uint32(f[l4+4:])
		in.Ack = binary.BigEndian.Uint32(f[l4+8:])
		in.Flags = f[l4+13]
		in.Window = binary.BigEndian.Uint16(f[l4+14:])
		in.PayOff, in.PayEnd = l4+hl, end
	case ProtoUDP:
		if len(f) < l4+8 {
			return
		}
		in.L4Off, in.HasPorts = l4, true
		in.SrcPort = binary.BigEndian.Uint16(f[l4:])
		in.DstPort = binary.BigEndian.Uint16(f[l4+2:])
		in.PayOff, in.PayEnd = l4+8, end
		if ul := l4 + int(binary.BigEndian.Uint16(f[l4+4:])); ul >= in.PayOff && ul < end {
			in.PayEnd = ul
		}
	case ProtoICMP, ProtoICMPv6:
		if len(f) < l4+4 {
			return
		}
		in.L4Off, in.ICMPType = l4, f[l4]
		in.PayOff, in.PayEnd = l4+4, end
	}
	if in.PayEnd < in.PayOff {
		in.PayEnd = in.PayOff
	}
}
