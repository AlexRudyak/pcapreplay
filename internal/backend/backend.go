// Package backend abstracts raw packet injection and capture so the replay
// engine is identical on Linux (AF_PACKET) and Windows (WinDivert).
package backend

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ErrTimeout is returned by Recv when nothing matching arrived in time.
var ErrTimeout = errors.New("backend: receive timeout")

// Flow identifies one TCP/UDP conversation from the local host's perspective.
type Flow struct {
	LocalIP, RemoteIP     netip.Addr
	LocalPort, RemotePort uint16
}

// Options configures a backend.
type Options struct {
	// Iface names the egress interface (Linux) or is empty to auto-select by
	// routing towards Target.
	Iface string
	// Target is the address traffic will be sent to; used for route, source IP
	// and next-hop MAC discovery.
	Target netip.Addr
	// SrcMAC / DstMAC override automatic L2 addressing (Linux only).
	SrcMAC, DstMAC *[6]byte
	// IfIndex overrides the WinDivert interface index (Windows only).
	IfIndex uint32
	// NoFirewall suppresses automatic nftables/iptables changes on Linux; the
	// operator is then responsible for the RST-drop rule.
	NoFirewall bool
}

// Backend injects IP datagrams (no link-layer header) and receives replies.
type Backend interface {
	// Name is a short identifier such as "linux-afpacket".
	Name() string
	// Open acquires OS resources (raw sockets, WinDivert handles).
	Open(Options) error
	// SendBatch injects datagrams in order and returns how many were sent.
	// Implementations use sendmmsg or equivalent batching where available.
	SendBatch(pkts [][]byte) (int, error)
	// Guard prepares the OS to cooperate with a raw TCP flow: it stops the local
	// kernel from resetting it and starts delivering its inbound packets to Recv.
	// The returned release function undoes every change.
	Guard(f Flow) (release func() error, err error)
	// Recv returns the next inbound datagram of the guarded flow, copied into buf.
	Recv(buf []byte, timeout time.Duration) (int, error)
	// Close releases everything.
	Close() error
}

// ByName returns the backend for "auto" (the platform default) or "null".
func ByName(name string) (Backend, error) {
	switch name {
	case "null", "dry-run":
		return &Null{}, nil
	case "", "auto":
		if b := platformDefault(); b != nil {
			return b, nil
		}
		return nil, errors.New("no packet-injection backend for this OS (supported: linux, windows)")
	}
	return nil, fmt.Errorf("unknown backend %q (want auto or null)", name)
}

// LocalAddrFor returns the local source address the OS would use to reach
// remote, without sending any traffic.
func LocalAddrFor(remote netip.Addr) (netip.Addr, error) {
	network := "udp4"
	if remote.Is6() {
		network = "udp6"
	}
	c, err := net.Dial(network, netip.AddrPortFrom(remote, 9).String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no route to %s: %w", remote, err)
	}
	defer c.Close()
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}

// Null discards every packet. It benchmarks the read/filter/mutate/pace
// pipeline without needing privileges or drivers.
type Null struct{ Packets, Bytes uint64 }

func (n *Null) Name() string       { return "null" }
func (n *Null) Open(Options) error { return nil }
func (n *Null) Close() error       { return nil }
func (n *Null) SendBatch(p [][]byte) (int, error) {
	for _, b := range p {
		n.Packets++
		n.Bytes += uint64(len(b))
	}
	return len(p), nil
}
func (n *Null) Guard(Flow) (func() error, error) { return func() error { return nil }, nil }
func (n *Null) Recv([]byte, time.Duration) (int, error) {
	return 0, errors.New("null backend cannot receive")
}
