package stats

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"time"

	"github.com/sasha/pktreplay/internal/decode"
)

// TalkerCapacity bounds the number of distinct IPs tracked for "top talkers".
const TalkerCapacity = 16384

// Stats accumulates capture-wide counters. Memory use is constant: scalar
// counters, two 64K port tables (512 KiB) and one bounded sketch.
type Stats struct {
	Packets   uint64
	CapBytes  uint64 // bytes actually present in the capture
	WireBytes uint64 // original on-the-wire bytes
	Truncated uint64 // packets with caplen < origlen

	TCP, UDP, ICMP, ICMPv6, ARP, OtherIP, NonIP uint64
	IPv4, IPv6                                  uint64

	FirstTs, LastTs int64 // ns since epoch

	tcpPorts [65536]uint32 // packets per destination port
	udpPorts [65536]uint32
	talkers  *SpaceSaving[netip.Addr]
}

// New returns an empty accumulator.
func New() *Stats {
	return &Stats{talkers: NewSpaceSaving[netip.Addr](TalkerCapacity)}
}

// Add folds one decoded packet into the totals.
func (s *Stats) Add(in *decode.Info, ok bool, capLen, origLen int, tsNanos int64) {
	s.Packets++
	s.CapBytes += uint64(capLen)
	s.WireBytes += uint64(origLen)
	if capLen < origLen {
		s.Truncated++
	}
	if tsNanos != 0 {
		if s.FirstTs == 0 || tsNanos < s.FirstTs {
			s.FirstTs = tsNanos
		}
		if tsNanos > s.LastTs {
			s.LastTs = tsNanos
		}
	}
	switch {
	case !ok:
		s.NonIP++
		return
	case in.ARP:
		s.ARP++
		return
	case !in.HasIP:
		s.NonIP++
		return
	}
	if in.IPv6 {
		s.IPv6++
	} else {
		s.IPv4++
	}
	switch in.Proto {
	case decode.ProtoTCP:
		s.TCP++
	case decode.ProtoUDP:
		s.UDP++
	case decode.ProtoICMP:
		s.ICMP++
	case decode.ProtoICMPv6:
		s.ICMPv6++
	default:
		s.OtherIP++
	}
	if in.HasPorts {
		if in.Proto == decode.ProtoTCP {
			s.tcpPorts[in.DstPort]++
		} else {
			s.udpPorts[in.DstPort]++
		}
	}
	w := uint64(origLen)
	s.talkers.Add(in.Src, w)
	s.talkers.Add(in.Dst, w)
}

// Talker is one heavy-hitter IP with its estimated byte volume.
type Talker struct {
	Addr    netip.Addr
	Bytes   uint64
	MaxOver uint64 // estimate may exceed the truth by at most this much
}

// TopTalkers returns the n IPs with the most observed bytes (sent + received).
func (s *Stats) TopTalkers(n int) []Talker {
	var out []Talker
	for _, e := range s.talkers.Top(n) {
		out = append(out, Talker{e.Key, e.Count, e.Err})
	}
	return out
}

// PortCount is a destination port with its packet count.
type PortCount struct {
	Port    uint16
	Packets uint32
}

// TopPorts returns the busiest destination ports for the given IP protocol.
func (s *Stats) TopPorts(proto uint8, n int) []PortCount {
	tbl := &s.tcpPorts
	if proto == decode.ProtoUDP {
		tbl = &s.udpPorts
	}
	var out []PortCount
	for p, c := range tbl {
		if c > 0 {
			out = append(out, PortCount{uint16(p), c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Duration is the capture time span.
func (s *Stats) Duration() time.Duration { return time.Duration(s.LastTs - s.FirstTs) }

// Report writes a human-readable summary.
func (s *Stats) Report(w io.Writer, top int) {
	pct := func(n uint64) float64 {
		if s.Packets == 0 {
			return 0
		}
		return 100 * float64(n) / float64(s.Packets)
	}
	fmt.Fprintf(w, "Packets:      %d\n", s.Packets)
	fmt.Fprintf(w, "Captured:     %s (wire: %s, truncated pkts: %d)\n", human(s.CapBytes), human(s.WireBytes), s.Truncated)
	if s.LastTs > s.FirstTs {
		secs := s.Duration().Seconds()
		fmt.Fprintf(w, "Time span:    %s  (%.0f pkt/s, %.2f Mbit/s avg)\n", s.Duration().Round(time.Millisecond),
			float64(s.Packets)/secs, float64(s.WireBytes)*8/secs/1e6)
		fmt.Fprintf(w, "First packet: %s\n", time.Unix(0, s.FirstTs).UTC().Format(time.RFC3339Nano))
	}
	fmt.Fprintf(w, "\nProtocols:\n")
	for _, r := range []struct {
		n string
		c uint64
	}{{"TCP", s.TCP}, {"UDP", s.UDP}, {"ICMP", s.ICMP}, {"ICMPv6", s.ICMPv6}, {"ARP", s.ARP},
		{"Other IP", s.OtherIP}, {"Non-IP", s.NonIP}} {
		if r.c > 0 {
			fmt.Fprintf(w, "  %-9s %12d  %5.1f%%\n", r.n, r.c, pct(r.c))
		}
	}
	fmt.Fprintf(w, "  (IPv4 %d, IPv6 %d)\n", s.IPv4, s.IPv6)
	fmt.Fprintf(w, "\nTop talkers (bytes, bounded sketch of %d keys):\n", TalkerCapacity)
	for _, t := range s.TopTalkers(top) {
		fmt.Fprintf(w, "  %-40s %12s  (+0..%s)\n", t.Addr, human(t.Bytes), human(t.MaxOver))
	}
	for _, pr := range []struct {
		name  string
		proto uint8
	}{{"TCP", decode.ProtoTCP}, {"UDP", decode.ProtoUDP}} {
		ports := s.TopPorts(pr.proto, top)
		if len(ports) == 0 {
			continue
		}
		fmt.Fprintf(w, "\nActive %s destination ports:\n", pr.name)
		for _, p := range ports {
			fmt.Fprintf(w, "  %-6d %12d pkts\n", p.Port, p.Packets)
		}
	}
}

func human(n uint64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	f, exp := float64(n), 0
	for f >= u && exp < 4 {
		f /= u
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", f, "KMGT"[exp-1])
}
