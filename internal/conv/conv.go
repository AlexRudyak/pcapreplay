// Package conv groups packets into bidirectional conversations (flows) and
// describes per-conversation rewrite rules.
//
// A conversation is identified by its protocol and the unordered pair of
// endpoints, so both directions of a TCP/UDP/ICMP exchange map to one Key. The
// table that tracks them is bounded, so analysing a huge capture keeps a flat
// memory footprint.
package conv

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/AlexRudyak/pktreplay/internal/decode"
)

// DefaultMaxConversations bounds the flow table (~300 B per entry).
const DefaultMaxConversations = 100_000

// Key identifies a conversation independent of packet direction: A is always
// the lexically smaller endpoint.
type Key struct {
	Proto uint8
	A, B  netip.AddrPort
}

// KeyOf computes the canonical key of a decoded IP packet. Protocols without
// ports (ICMP) use port 0. ok is false for packets that are not IP.
func KeyOf(in *decode.Info) (k Key, ok bool) {
	if !in.HasIP {
		return Key{}, false
	}
	src := netip.AddrPortFrom(in.Src, portOf(in, true))
	dst := netip.AddrPortFrom(in.Dst, portOf(in, false))
	k.Proto = in.Proto
	if cmpEndpoint(src, dst) <= 0 {
		k.A, k.B = src, dst
	} else {
		k.A, k.B = dst, src
	}
	return k, true
}

// MakeKey builds the canonical key for two endpoints.
func MakeKey(proto uint8, a, b netip.AddrPort) Key {
	if cmpEndpoint(a, b) > 0 {
		a, b = b, a
	}
	return Key{Proto: proto, A: a, B: b}
}

func portOf(in *decode.Info, src bool) uint16 {
	if !in.HasPorts {
		return 0
	}
	if src {
		return in.SrcPort
	}
	return in.DstPort
}

func cmpEndpoint(a, b netip.AddrPort) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	switch {
	case a.Port() < b.Port():
		return -1
	case a.Port() > b.Port():
		return 1
	}
	return 0
}

// ProtoName returns "tcp", "udp", "icmp", "icmp6" or the protocol number.
func ProtoName(p uint8) string {
	switch p {
	case decode.ProtoTCP:
		return "tcp"
	case decode.ProtoUDP:
		return "udp"
	case decode.ProtoICMP:
		return "icmp"
	case decode.ProtoICMPv6:
		return "icmp6"
	}
	return fmt.Sprint(p)
}

// protoNumber maps a protocol name used in selectors (tcp, udp, icmp, ...) to its IP protocol number.
func protoNumber(s string) (uint8, bool) {
	switch strings.ToLower(s) {
	case "tcp":
		return decode.ProtoTCP, true
	case "udp":
		return decode.ProtoUDP, true
	case "icmp":
		return decode.ProtoICMP, true
	case "icmp6", "icmpv6":
		return decode.ProtoICMPv6, true
	}
	var n uint8
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return n, true
	}
	return 0, false
}

func hasPorts(proto uint8) bool { return proto == decode.ProtoTCP || proto == decode.ProtoUDP }

func fmtEndpoint(proto uint8, e netip.AddrPort) string {
	if !hasPorts(proto) {
		return e.Addr().String()
	}
	return e.String()
}

// Selector renders "proto/client/server", the textual handle used by the CLI
// and the GUI to refer to a conversation. IPv6 endpoints use [addr]:port.
func Selector(proto uint8, client, server netip.AddrPort) string {
	return ProtoName(proto) + "/" + fmtEndpoint(proto, client) + "/" + fmtEndpoint(proto, server)
}

// parseEndpoint parses "ip:port" (or "[v6]:port"); protocols without ports take a bare address.
func parseEndpoint(proto uint8, s string) (netip.AddrPort, error) {
	if hasPorts(proto) {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("endpoint %q: want ip:port ([v6]:port for IPv6)", s)
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: want an IP address", s)
	}
	return netip.AddrPortFrom(a.Unmap(), 0), nil
}

// ParseSelector parses "proto/client/server". It returns the canonical Key and
// which endpoint was named as the client.
func ParseSelector(s string) (Key, netip.AddrPort, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) != 3 {
		return Key{}, netip.AddrPort{}, fmt.Errorf("selector %q: want proto/client/server, e.g. tcp/10.0.0.1:50000/10.0.0.2:80", s)
	}
	proto, ok := protoNumber(parts[0])
	if !ok {
		return Key{}, netip.AddrPort{}, fmt.Errorf("selector %q: unknown protocol %q", s, parts[0])
	}
	c, err := parseEndpoint(proto, parts[1])
	if err != nil {
		return Key{}, netip.AddrPort{}, err
	}
	sv, err := parseEndpoint(proto, parts[2])
	if err != nil {
		return Key{}, netip.AddrPort{}, err
	}
	k := Key{Proto: proto, A: c, B: sv}
	if cmpEndpoint(c, sv) > 0 {
		k.A, k.B = sv, c
	}
	return k, c, nil
}

// Conversation is the accumulated state of one flow.
type Conversation struct {
	Index  int // order of first appearance in the capture
	Key    Key
	Proto  uint8
	Client netip.AddrPort
	Server netip.AddrPort

	Packets, Bytes       uint64
	C2SPackets, C2SBytes uint64
	S2CPackets, S2CBytes uint64
	FirstTs, LastTs      int64 // ns since epoch

	SawSYN, SawSYNACK, SawFIN, SawRST bool
	clientSure                        bool // role known from a SYN / SYN-ACK
}

// Selector returns the conversation's handle.
func (c *Conversation) Selector() string { return Selector(c.Proto, c.Client, c.Server) }

// State describes the TCP lifecycle observed, or "-" for other protocols.
func (c *Conversation) State() string {
	if c.Proto != decode.ProtoTCP {
		return "-"
	}
	switch {
	case c.SawRST:
		return "reset"
	case c.SawSYN && c.SawSYNACK && c.SawFIN:
		return "closed"
	case c.SawSYN && c.SawSYNACK:
		return "established"
	case c.SawSYN:
		return "syn-only"
	case c.SawFIN:
		return "closing (mid-stream)"
	}
	return "mid-stream"
}

// Table tracks conversations with bounded memory: once max conversations are
// tracked, packets of new ones are counted in Untracked instead.
type Table struct {
	max       int
	m         map[Key]*Conversation
	Untracked uint64 // packets that belonged to conversations beyond the cap
}

// NewTable creates a table holding at most max conversations.
func NewTable(max int) *Table {
	if max < 1 {
		max = DefaultMaxConversations
	}
	return &Table{max: max, m: make(map[Key]*Conversation)}
}

// Len returns the number of tracked conversations.
func (t *Table) Len() int { return len(t.m) }

// Add accounts one packet.
func (t *Table) Add(in *decode.Info, wireLen int, ts int64) {
	k, ok := KeyOf(in)
	if !ok {
		return
	}
	c := t.m[k]
	if c == nil {
		if len(t.m) >= t.max {
			t.Untracked++
			return
		}
		c = newConversation(len(t.m), k, in, ts)
		t.m[k] = c
	}
	isTCP := in.Proto == decode.ProtoTCP
	if isTCP {
		syn, ack := in.Flags&decode.SYN != 0, in.Flags&decode.ACK != 0
		src := netip.AddrPortFrom(in.Src, in.SrcPort)
		switch {
		case syn && !ack:
			c.SawSYN = true
			if !c.clientSure && src != c.Client { // a SYN always comes from the client
				c.swap()
			}
			c.clientSure = true
		case syn && ack:
			c.SawSYNACK = true
			if !c.clientSure && src != c.Server { // a SYN-ACK always comes from the server
				c.swap()
			}
			c.clientSure = true
		}
		if in.Flags&decode.FIN != 0 {
			c.SawFIN = true
		}
		if in.Flags&decode.RST != 0 {
			c.SawRST = true
		}
	}
	fromClient := in.Src == c.Client.Addr() && portOf(in, true) == c.Client.Port()
	c.Packets++
	c.Bytes += uint64(wireLen)
	if fromClient {
		c.C2SPackets++
		c.C2SBytes += uint64(wireLen)
	} else {
		c.S2CPackets++
		c.S2CBytes += uint64(wireLen)
	}
	if ts != 0 {
		if c.FirstTs == 0 || ts < c.FirstTs {
			c.FirstTs = ts
		}
		if ts > c.LastTs {
			c.LastTs = ts
		}
	}
}

// newConversation starts tracking a conversation whose first packet is in, guessing the
// client from the TCP flags or the port numbers (a later SYN can correct the guess).
func newConversation(idx int, k Key, in *decode.Info, ts int64) *Conversation {
	c := &Conversation{Index: idx, Key: k, Proto: in.Proto,
		Client: netip.AddrPortFrom(in.Src, portOf(in, true)), Server: netip.AddrPortFrom(in.Dst, portOf(in, false)), FirstTs: ts}
	// Capture started mid-conversation: guess the roles. A well-known (<1024)
	// port against an ephemeral one identifies the server.
	if in.Proto == decode.ProtoTCP && in.Flags&decode.SYN == 0 || in.Proto == decode.ProtoUDP {
		sp, dp := c.Client.Port(), c.Server.Port()
		if sp < 1024 && dp >= 1024 {
			c.swapEndpoints()
		}
	}
	return c
}

func (c *Conversation) swapEndpoints() { c.Client, c.Server = c.Server, c.Client }

// swap reverses the roles after the real client is learned, fixing counters.
func (c *Conversation) swap() {
	c.swapEndpoints()
	c.C2SPackets, c.S2CPackets = c.S2CPackets, c.C2SPackets
	c.C2SBytes, c.S2CBytes = c.S2CBytes, c.C2SBytes
}

// Sort orders for Top.
const (
	ByBytes   = "bytes"
	ByPackets = "packets"
	ByTime    = "time" // first appearance
)

// Top returns up to n conversations sorted by the given order (n <= 0: all).
func (t *Table) Top(n int, by string) []Conversation {
	out := make([]Conversation, 0, len(t.m))
	for _, c := range t.m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		switch by {
		case ByPackets:
			if out[i].Packets != out[j].Packets {
				return out[i].Packets > out[j].Packets
			}
		case ByTime:
			return out[i].Index < out[j].Index
		default:
			if out[i].Bytes != out[j].Bytes {
				return out[i].Bytes > out[j].Bytes
			}
		}
		return out[i].Index < out[j].Index
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
