package stats

import (
	"context"
	"io"
	"os"
	"sync/atomic"

	"github.com/AlexRudyak/pcapreplay/internal/conv"
	"github.com/AlexRudyak/pcapreplay/internal/decode"
	"github.com/AlexRudyak/pcapreplay/internal/filter"
	"github.com/AlexRudyak/pcapreplay/internal/pcapio"
)

// Progress is updated atomically by Scan so another goroutine can poll it.
type Progress struct {
	Packets atomic.Uint64 // packets read so far
	Bytes   atomic.Int64  // file offset reached
	Total   atomic.Int64  // file size (0 if unknown)
}

// NamedCount is a labelled counter.
type NamedCount struct {
	Name    string `json:"name"`
	Packets uint64 `json:"packets"`
}

// TalkerRow is a JSON-friendly Talker.
type TalkerRow struct {
	Addr    string `json:"addr"`
	Bytes   uint64 `json:"bytes"`
	MaxOver uint64 `json:"maxOver"`
}

// PortRow is a JSON-friendly PortCount.
type PortRow struct {
	Port    uint16 `json:"port"`
	Packets uint32 `json:"packets"`
}

// Summary is the JSON form of a finished scan.
type Summary struct {
	Format      string       `json:"format"`
	LinkType    uint32       `json:"linkType"`
	Packets     uint64       `json:"packets"`
	CapBytes    uint64       `json:"capBytes"`
	WireBytes   uint64       `json:"wireBytes"`
	Truncated   uint64       `json:"truncated"`
	FirstTs     int64        `json:"firstTs"`
	LastTs      int64        `json:"lastTs"`
	DurationSec float64      `json:"durationSec"`
	IPv4        uint64       `json:"ipv4"`
	IPv6        uint64       `json:"ipv6"`
	Protocols   []NamedCount `json:"protocols"`
	Talkers     []TalkerRow  `json:"talkers"`
	TCPPorts    []PortRow    `json:"tcpPorts"`
	UDPPorts    []PortRow    `json:"udpPorts"`

	Conversations          []ConvRow `json:"conversations,omitempty"`
	ConversationsTotal     int       `json:"conversationsTotal"`
	ConversationsUntracked uint64    `json:"conversationsUntracked"` // packets beyond the table cap
}

// MaxConvRows limits the conversations returned in a Summary (sorted by bytes).
const MaxConvRows = 1000

// ConvRow is the JSON form of one conversation.
type ConvRow struct {
	ID          int     `json:"id"`
	Selector    string  `json:"selector"`
	Proto       string  `json:"proto"`
	ClientIP    string  `json:"clientIp"`
	ClientPort  uint16  `json:"clientPort"`
	ServerIP    string  `json:"serverIp"`
	ServerPort  uint16  `json:"serverPort"`
	Packets     uint64  `json:"packets"`
	Bytes       uint64  `json:"bytes"`
	C2SPackets  uint64  `json:"c2sPackets"`
	S2CPackets  uint64  `json:"s2cPackets"`
	C2SBytes    uint64  `json:"c2sBytes"`
	S2CBytes    uint64  `json:"s2cBytes"`
	FirstTs     int64   `json:"firstTs"`
	DurationSec float64 `json:"durationSec"`
	State       string  `json:"state"`
}

// ConvRows returns up to n conversations in the requested order.
func (s *Stats) ConvRows(n int, by string) []ConvRow {
	if s.Convs == nil {
		return nil
	}
	var out []ConvRow
	for _, c := range s.Convs.Top(n, by) {
		out = append(out, ConvRow{ID: c.Index, Selector: c.Selector(), Proto: conv.ProtoName(c.Proto),
			ClientIP: c.Client.Addr().String(), ClientPort: c.Client.Port(), ServerIP: c.Server.Addr().String(), ServerPort: c.Server.Port(),
			Packets: c.Packets, Bytes: c.Bytes, C2SPackets: c.C2SPackets, S2CPackets: c.S2CPackets, C2SBytes: c.C2SBytes, S2CBytes: c.S2CBytes,
			FirstTs: c.FirstTs, DurationSec: float64(c.LastTs-c.FirstTs) / 1e9, State: c.State()})
	}
	return out
}

// Summary converts the accumulated statistics into a JSON-friendly value.
func (s *Stats) Summary(top int) Summary {
	out := Summary{Packets: s.Packets, CapBytes: s.CapBytes, WireBytes: s.WireBytes, Truncated: s.Truncated,
		FirstTs: s.FirstTs, LastTs: s.LastTs, IPv4: s.IPv4, IPv6: s.IPv6}
	if s.LastTs > s.FirstTs {
		out.DurationSec = s.Duration().Seconds()
	}
	for _, p := range []NamedCount{{"TCP", s.TCP}, {"UDP", s.UDP}, {"ICMP", s.ICMP}, {"ICMPv6", s.ICMPv6},
		{"ARP", s.ARP}, {"Other IP", s.OtherIP}, {"Non-IP", s.NonIP}} {
		if p.Packets > 0 {
			out.Protocols = append(out.Protocols, p)
		}
	}
	for _, t := range s.TopTalkers(top) {
		out.Talkers = append(out.Talkers, TalkerRow{t.Addr.String(), t.Bytes, t.MaxOver})
	}
	for _, p := range s.TopPorts(decode.ProtoTCP, top) {
		out.TCPPorts = append(out.TCPPorts, PortRow{p.Port, p.Packets})
	}
	for _, p := range s.TopPorts(decode.ProtoUDP, top) {
		out.UDPPorts = append(out.UDPPorts, PortRow{p.Port, p.Packets})
	}
	if s.Convs != nil {
		out.Conversations = s.ConvRows(MaxConvRows, conv.ByBytes)
		out.ConversationsTotal = s.Convs.Len()
		out.ConversationsUntracked = s.Convs.Untracked
	}
	return out
}

// Scan streams path once, accumulating statistics for packets accepted by flt.
// position (optional) seeks before reading; count (0 = all) limits packets read.
// A truncated final record is not an error. Cancelling ctx returns the partial
// statistics together with ctx.Err().
func Scan(ctx context.Context, path string, flt *filter.Filter, position func(*pcapio.Reader) error,
	count uint64, prog *Progress) (*Stats, *pcapio.Reader, error) {
	return ScanWith(ctx, path, flt, position, count, prog, false)
}

// ScanWith is Scan with optional conversation tracking.
func ScanWith(ctx context.Context, path string, flt *filter.Filter, position func(*pcapio.Reader) error,
	count uint64, prog *Progress, conversations bool) (*Stats, *pcapio.Reader, error) {
	rd, err := pcapio.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if prog != nil {
		if fi, err := os.Stat(path); err == nil {
			prog.Total.Store(fi.Size())
		}
	}
	if position != nil {
		if err := position(rd); err != nil {
			rd.Close()
			return nil, nil, err
		}
	}
	st := New()
	if conversations {
		st.TrackConversations(0)
	}
	var in decode.Info
	var seen uint64
	for count == 0 || seen < count {
		if seen&0xfff == 0 {
			if prog != nil {
				prog.Packets.Store(seen)
				prog.Bytes.Store(rd.Offset())
			}
			if err := ctx.Err(); err != nil {
				return st, rd, err
			}
		}
		p, err := rd.Next()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return st, rd, err
		}
		seen++
		ok := decode.Decode(p.LinkType, p.Data, &in)
		if !flt.MatchAll() && !flt.Match(p.Data, &in) {
			continue
		}
		st.Add(&in, ok, len(p.Data), int(p.OrigLen), p.TsNanos)
	}
	if prog != nil {
		prog.Packets.Store(seen)
		prog.Bytes.Store(rd.Offset())
	}
	return st, rd, nil
}
