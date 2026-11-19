//go:build linux

package backend

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/AlexRudyak/pktreplay/internal/decode"
	"github.com/AlexRudyak/pktreplay/internal/pcapio"
)

const (
	ethPAll      = 0x0003
	ethPARP      = 0x0806
	packetOutgng = 4 // sockaddr_ll.sll_pkttype for frames we sent ourselves
	maxBatch     = 256
	frameSlot    = 65535 + 14
)

// Linux injects with AF_PACKET raw sockets and batches with sendmmsg(2).
type Linux struct {
	opts    Options
	iface   *net.Interface
	sfd     int // send socket
	rfd     int // receive socket (opened by Guard)
	srcMAC  [6]byte
	dstMAC  [6]byte
	flow    Flow
	release func() error

	slots [][]byte // preallocated frame buffers, one per batch entry
	msgs  []mmsghdr
	iovs  []syscall.Iovec
	rbuf  []byte
}

type mmsghdr struct {
	Hdr syscall.Msghdr
	Len uint32
}

// NewLinux returns an unopened Linux backend.
func NewLinux() *Linux { return &Linux{sfd: -1, rfd: -1} }

// Name implements Backend.
func (l *Linux) Name() string { return "linux-afpacket" }

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func rawSocket(proto uint16, ifindex int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(proto)))
	if err != nil {
		return -1, fmt.Errorf("AF_PACKET socket (needs root or CAP_NET_RAW): %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(proto), Ifindex: ifindex}); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("bind to interface %d: %w", ifindex, err)
	}
	return fd, nil
}

// Open picks the egress interface and next-hop MAC for o.Target and opens the AF_PACKET
// transmit socket (plus a second one for receiving in TCP mode).
func (l *Linux) Open(o Options) error {
	l.opts = o
	if !o.Target.IsValid() {
		return errors.New("linux backend: a target address is required")
	}
	ifc, err := pickInterface(o)
	if err != nil {
		return err
	}
	l.iface = ifc
	copy(l.srcMAC[:], ifc.HardwareAddr)
	if o.SrcMAC != nil {
		l.srcMAC = *o.SrcMAC
	}
	switch {
	case o.DstMAC != nil:
		l.dstMAC = *o.DstMAC
	case ifc.Flags&net.FlagLoopback != 0:
		// loopback needs no real MAC; zeros are accepted by the kernel.
	default:
		if l.dstMAC, err = resolveNextHop(ifc, o.Target); err != nil {
			return fmt.Errorf("cannot resolve next-hop MAC for %s (use --dst-mac): %w", o.Target, err)
		}
	}
	if l.sfd, err = rawSocket(ethPAll, ifc.Index); err != nil {
		return err
	}
	// Large send buffer so bursts do not hit ENOBUFS immediately.
	syscall.SetsockoptInt(l.sfd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8<<20)

	l.slots = make([][]byte, maxBatch)
	for i := range l.slots {
		l.slots[i] = make([]byte, 0, 2048)
	}
	l.msgs = make([]mmsghdr, maxBatch)
	l.iovs = make([]syscall.Iovec, maxBatch)
	for i := range l.msgs {
		l.msgs[i].Hdr.Iov = &l.iovs[i]
		// Iovlen is uint64 on 64-bit and uint32 on 32-bit Linux: always uintptr-sized.
		*(*uintptr)(unsafe.Pointer(&l.msgs[i].Hdr.Iovlen)) = 1
	}
	return nil
}

// SendBatch prepends the Ethernet header to each datagram and transmits them with
// sendmmsg(2), up to 256 frames per system call. It returns how many were accepted.
func (l *Linux) SendBatch(pkts [][]byte) (int, error) {
	sent := 0
	for sent < len(pkts) {
		n := len(pkts) - sent
		if n > maxBatch {
			n = maxBatch
		}
		for i := 0; i < n; i++ {
			ip := pkts[sent+i]
			fr := l.slots[i][:0]
			fr = append(fr, l.dstMAC[:]...)
			fr = append(fr, l.srcMAC[:]...)
			if len(ip) > 0 && ip[0]>>4 == 6 {
				fr = append(fr, 0x86, 0xdd)
			} else {
				fr = append(fr, 0x08, 0x00)
			}
			fr = append(fr, ip...)
			l.slots[i] = fr // keep any growth
			l.iovs[i].Base = &fr[0]
			l.iovs[i].SetLen(len(fr))
		}
		off := 0
		for off < n {
			r, _, errno := syscall.Syscall6(sysSendmmsg, uintptr(l.sfd),
				uintptr(unsafe.Pointer(&l.msgs[off])), uintptr(n-off), 0, 0, 0)
			if errno != 0 {
				if errno == syscall.EAGAIN || errno == syscall.ENOBUFS || errno == syscall.EINTR {
					time.Sleep(50 * time.Microsecond)
					continue
				}
				return sent + off, fmt.Errorf("sendmmsg: %w", errno)
			}
			off += int(r)
		}
		sent += n
	}
	return sent, nil
}

// Guard installs the firewall rule that drops the kernel's own RST for the flow (unless
// Options.NoFirewall is set) and starts filtering received frames to that 4-tuple.
// The returned function removes the rule again.
func (l *Linux) Guard(f Flow) (func() error, error) {
	l.flow = f
	var err error
	if l.rfd, err = rawSocket(ethPAll, l.iface.Index); err != nil {
		return nil, err
	}
	syscall.SetsockoptInt(l.rfd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	l.rbuf = make([]byte, frameSlot)
	if !l.opts.NoFirewall {
		if l.release, err = installRSTDrop(f); err != nil {
			syscall.Close(l.rfd)
			l.rfd = -1
			return nil, err
		}
	}
	return func() error {
		if l.release != nil {
			r := l.release
			l.release = nil
			return r()
		}
		return nil
	}, nil
}

// Recv waits up to timeout for a frame of the guarded flow and copies its IP datagram into
// buf. Frames the kernel transmitted itself (PACKET_OUTGOING) are ignored.
func (l *Linux) Recv(buf []byte, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	var in decode.Info
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			return 0, ErrTimeout
		}
		tv := syscall.NsecToTimeval(int64(rem))
		syscall.SetsockoptTimeval(l.rfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		n, from, err := syscall.Recvfrom(l.rfd, l.rbuf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			return 0, err
		}
		if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == packetOutgng {
			continue // our own injected frames loop back on this socket
		}
		fr := l.rbuf[:n]
		if !decode.Decode(pcapio.LinkEthernet, fr, &in) || !in.HasIP || in.Proto != decode.ProtoTCP || !in.HasPorts {
			continue
		}
		if in.Src != l.flow.RemoteIP || in.Dst != l.flow.LocalIP ||
			in.SrcPort != l.flow.RemotePort || in.DstPort != l.flow.LocalPort {
			continue
		}
		return copy(buf, fr[in.L3Off:]), nil
	}
}

// Close releases the sockets and any firewall rule still installed.
func (l *Linux) Close() error {
	if l.release != nil {
		l.release()
		l.release = nil
	}
	for _, fd := range []*int{&l.sfd, &l.rfd} {
		if *fd >= 0 {
			syscall.Close(*fd)
			*fd = -1
		}
	}
	return nil
}

// ---- interface and next-hop discovery ----

// pickInterface returns the interface named in o, or the one the routing table would use to
// reach o.Target.
func pickInterface(o Options) (*net.Interface, error) {
	if o.Iface != "" {
		return net.InterfaceByName(o.Iface)
	}
	if o.Target.IsLoopback() {
		return net.InterfaceByName("lo")
	}
	src, err := LocalAddrFor(o.Target)
	if err != nil {
		return nil, err
	}
	ifs, _ := net.Interfaces()
	for i := range ifs {
		addrs, _ := ifs[i].Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr() == src {
				return &ifs[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface owns source address %s", src)
}

func onLink(ifc *net.Interface, ip netip.Addr) bool {
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

// gatewayFor reads the IPv4 default gateway of ifc from /proc/net/route.
func gatewayFor(ifc *net.Interface) (netip.Addr, bool) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, false
	}
	for _, line := range splitLines(string(data))[1:] {
		var name, dst, gw string
		var flags int
		if n, _ := fmt.Sscanf(line, "%s %s %s %x", &name, &dst, &gw, &flags); n < 4 {
			continue
		}
		if name == ifc.Name && dst == "00000000" && flags&2 != 0 {
			var v uint32
			fmt.Sscanf(gw, "%x", &v)
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], v)
			return netip.AddrFrom4(b), true
		}
	}
	return netip.Addr{}, false
}

// splitLines splits s into lines, tolerating both LF and CRLF endings.
func splitLines(s string) []string {
	var out []string
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != '\n' {
			i++
		}
		out = append(out, s[:i])
		if i == len(s) {
			break
		}
		s = s[i+1:]
	}
	return out
}

// resolveNextHop finds the MAC address to put on frames for target: the neighbour table
// entry, the default gateway's, or the answer to an ARP probe sent on ifc.
func resolveNextHop(ifc *net.Interface, target netip.Addr) ([6]byte, error) {
	hop := target
	if !onLink(ifc, target) {
		gw, ok := gatewayFor(ifc)
		if !ok {
			return [6]byte{}, errors.New("no default gateway found")
		}
		hop = gw
	}
	if mac, ok := neighborFromProc(hop); ok {
		return mac, nil
	}
	if hop.Is4() {
		return arpResolve(ifc, hop)
	}
	return [6]byte{}, errors.New("IPv6 neighbour not in cache: ping it first or pass --dst-mac")
}

// neighborFromProc looks the hop up in the kernel ARP cache.
func neighborFromProc(ip netip.Addr) ([6]byte, bool) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return [6]byte{}, false
	}
	for _, line := range splitLines(string(data))[1:] {
		var a, hw, flags, mac string
		if n, _ := fmt.Sscanf(line, "%s %s %s %s", &a, &hw, &flags, &mac); n < 4 || a != ip.String() {
			continue
		}
		if hwa, err := net.ParseMAC(mac); err == nil && len(hwa) == 6 && mac != "00:00:00:00:00:00" {
			var out [6]byte
			copy(out[:], hwa)
			return out, true
		}
	}
	return [6]byte{}, false
}

// arpResolve broadcasts an ARP request and waits for the reply.
func arpResolve(ifc *net.Interface, ip netip.Addr) ([6]byte, error) {
	fd, err := rawSocket(ethPARP, ifc.Index)
	if err != nil {
		return [6]byte{}, err
	}
	defer syscall.Close(fd)
	src, err := LocalAddrFor(ip)
	if err != nil || !src.Is4() {
		return [6]byte{}, errors.New("no IPv4 source address for ARP")
	}
	f := make([]byte, 42)
	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	copy(f[6:12], ifc.HardwareAddr)
	binary.BigEndian.PutUint16(f[12:], ethPARP)
	binary.BigEndian.PutUint16(f[14:], 1)      // hw type ethernet
	binary.BigEndian.PutUint16(f[16:], 0x0800) // proto IPv4
	f[18], f[19] = 6, 4
	binary.BigEndian.PutUint16(f[20:], 1) // request
	copy(f[22:28], ifc.HardwareAddr)
	s4, t4 := src.As4(), ip.As4()
	copy(f[28:32], s4[:])
	copy(f[38:42], t4[:])
	buf := make([]byte, 128)
	for try := 0; try < 3; try++ {
		if err := syscall.Sendto(fd, f, 0, &syscall.SockaddrLinklayer{Protocol: htons(ethPARP), Ifindex: ifc.Index}); err != nil {
			return [6]byte{}, err
		}
		tv := syscall.NsecToTimeval(int64(700 * time.Millisecond))
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				break // timeout: retry
			}
			if n >= 42 && binary.BigEndian.Uint16(buf[20:]) == 2 && [4]byte(buf[28:32]) == t4 {
				var mac [6]byte
				copy(mac[:], buf[22:28])
				return mac, nil
			}
		}
	}
	return [6]byte{}, fmt.Errorf("ARP request for %s timed out", ip)
}
