package history

import (
	"fmt"
	"io"
	"strings"

	"github.com/AlexRudyak/pktreplay/internal/decode"
	"github.com/AlexRudyak/pktreplay/internal/pcapio"
)

// MaxPreview bounds how many packets one preview request returns.
const MaxPreview = 500

// PacketRow describes one packet of a stored copy.
type PacketRow struct {
	N     int     `json:"n"`
	RelMs float64 `json:"relMs"` // milliseconds since the first packet of the copy
	Dir   string  `json:"dir"`   // "out" (sent), "in" (reply) or ""
	Src   string  `json:"src"`
	Dst   string  `json:"dst"`
	Proto string  `json:"proto"`
	Len   int     `json:"len"`
	Info  string  `json:"info"`
}

func flagNames(f uint8) string {
	var parts []string
	for _, p := range []struct {
		bit  uint8
		name string
	}{{decode.SYN, "SYN"}, {decode.FIN, "FIN"}, {decode.RST, "RST"}, {decode.PSH, "PSH"}, {decode.ACK, "ACK"}, {decode.URG, "URG"}} {
		if f&p.bit != 0 {
			parts = append(parts, p.name)
		}
	}
	return strings.Join(parts, " ")
}

// printable renders up to n payload bytes as text, replacing control bytes.
func printable(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 32 && c < 127 {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

// Preview lists limit packets of a stored copy starting at packet offset, and
// the total number of packets in the file.
func Preview(path string, offset, limit int) (rows []PacketRow, total int, err error) {
	if limit <= 0 || limit > MaxPreview {
		limit = MaxPreview
	}
	if offset < 0 {
		offset = 0
	}
	rd, err := pcapio.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer rd.Close()
	var in decode.Info
	var base int64
	for {
		p, err := rd.Next()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return rows, total, err
		}
		if total == 0 {
			base = p.TsNanos
		}
		n := total
		total++
		if n < offset || len(rows) >= limit {
			continue // keep counting for the total, but only describe the requested page
		}
		row := PacketRow{N: n, RelMs: float64(p.TsNanos-base) / 1e6, Len: len(p.Data)}
		switch p.Dir {
		case pcapio.DirOut:
			row.Dir = "out"
		case pcapio.DirIn:
			row.Dir = "in"
		}
		if !decode.Decode(p.LinkType, p.Data, &in) || !in.HasIP {
			row.Proto, row.Info = "?", "not an IP packet"
			rows = append(rows, row)
			continue
		}
		pay := in.Payload(p.Data)
		row.Src, row.Dst = in.Src.String(), in.Dst.String()
		switch in.Proto {
		case decode.ProtoTCP:
			row.Proto = "TCP"
			if in.HasPorts {
				row.Src, row.Dst = fmt.Sprintf("%s:%d", in.Src, in.SrcPort), fmt.Sprintf("%s:%d", in.Dst, in.DstPort)
				row.Info = fmt.Sprintf("%s seq=%d ack=%d len=%d", flagNames(in.Flags), in.Seq, in.Ack, len(pay))
			}
		case decode.ProtoUDP:
			row.Proto = "UDP"
			if in.HasPorts {
				row.Src, row.Dst = fmt.Sprintf("%s:%d", in.Src, in.SrcPort), fmt.Sprintf("%s:%d", in.Dst, in.DstPort)
				row.Info = fmt.Sprintf("len=%d", len(pay))
			}
		case decode.ProtoICMP, decode.ProtoICMPv6:
			row.Proto, row.Info = "ICMP", fmt.Sprintf("type=%d", in.ICMPType)
		default:
			row.Proto = fmt.Sprint(in.Proto)
		}
		if len(pay) > 0 {
			row.Info += "  “" + printable(pay, 48) + "”"
		}
		rows = append(rows, row)
	}
	return rows, total, nil
}
