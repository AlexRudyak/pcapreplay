// Package filter compiles boolean packet filter expressions into closures that
// run directly on raw frames and their pre-decoded header offsets.
//
// Grammar (case-insensitive keywords):
//
//	expr   = or
//	or     = and { ("OR" | "||") and }
//	and    = unary { ("AND" | "&&") unary }
//	unary  = ("NOT" | "!") unary | "(" expr ")" | cmp
//	cmp    = ("src_ip"|"dst_ip"|"ip")     ("=="|"!=") addr-or-cidr
//	       | ("src_port"|"dst_port"|"port") ("=="|"!="|"in") port | lo-hi
//	       | "proto" ("=="|"!=") tcp|udp|icmp|icmp6|arp|ip|ipv6|<number>
//	       | "tcp_flags" ("=="|"!=") syn|ack|fin|rst|psh|urg [ "+" flag ... ]
//	       | "payload" "contains" "text" | 0xHEX
//	       | "payload" "~" "regexp"
//
// Cost-based ordering guarantees cheap header comparisons run before payload
// searches regardless of how the expression is written, so no payload bytes
// are touched for packets rejected by their headers.
package filter

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/AlexRudyak/pcapreplay/internal/decode"
)

type matchFn func(frame []byte, in *decode.Info) bool

type node struct {
	fn   matchFn
	cost int // 0 = header-only, 1 = payload inspection
}

// Filter is a compiled expression. It is immutable and safe for concurrent use
// provided each goroutine uses its own decode.Info.
type Filter struct {
	root *node
	Expr string
}

// Parse compiles expr. An empty expression matches every packet.
func Parse(expr string) (*Filter, error) {
	f := &Filter{Expr: expr}
	if strings.TrimSpace(expr) == "" {
		return f, nil
	}
	toks, err := lex(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("filter: unexpected %q", p.toks[p.pos].text)
	}
	f.root = n
	return f, nil
}

// MatchAll reports whether the filter accepts every packet.
func (f *Filter) MatchAll() bool { return f.root == nil }

// NeedsPayload reports whether any term inspects payload bytes.
func (f *Filter) NeedsPayload() bool { return f.root != nil && f.root.cost > 0 }

// Match evaluates the filter against an already decoded frame.
func (f *Filter) Match(frame []byte, in *decode.Info) bool {
	return f.root == nil || f.root.fn(frame, in)
}

// ---- lexer ----

type token struct {
	text   string
	quoted bool
}

// lex splits a filter expression into tokens: words, operators, quoted strings and parentheses.
func lex(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')':
			out = append(out, token{text: string(c)})
			i++
		case c == '"' || c == '\'':
			j, lit := i+1, []byte{}
			for ; j < len(s) && s[j] != c; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
					switch s[j] {
					case 'n':
						lit = append(lit, '\n')
						continue
					case 'r':
						lit = append(lit, '\r')
						continue
					case 't':
						lit = append(lit, '\t')
						continue
					case '\\', '"', '\'':
					default:
						lit = append(lit, '\\') // keep regexp escapes like \d
					}
				}
				lit = append(lit, s[j])
			}
			if j >= len(s) {
				return nil, fmt.Errorf("filter: unterminated string")
			}
			out = append(out, token{text: string(lit), quoted: true})
			i = j + 1
		case strings.HasPrefix(s[i:], "=="), strings.HasPrefix(s[i:], "!="),
			strings.HasPrefix(s[i:], "&&"), strings.HasPrefix(s[i:], "||"):
			out = append(out, token{text: s[i : i+2]})
			i += 2
		case c == '!' || c == '~':
			out = append(out, token{text: string(c)})
			i++
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\r\n()\"'=!~&|", rune(s[j])) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("filter: unexpected character %q", c)
			}
			out = append(out, token{text: s[i:j]})
			i = j
		}
	}
	return out, nil
}

// ---- parser ----

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

// kw consumes and reports the next token if it is one of words (case-insensitive).
func (p *parser) kw(words ...string) bool {
	t := p.peek()
	if t == nil || t.quoted {
		return false
	}
	for _, w := range words {
		if strings.EqualFold(t.text, w) {
			p.pos++
			return true
		}
	}
	return false
}

func (p *parser) next() (token, error) {
	if p.pos >= len(p.toks) {
		return token{}, fmt.Errorf("filter: unexpected end of expression")
	}
	p.pos++
	return p.toks[p.pos-1], nil
}

// combine joins kids with AND (or OR when and is false) and orders them cheapest first, so
// header tests run before payload scans.
func combine(kids []*node, and bool) *node {
	if len(kids) == 1 {
		return kids[0]
	}
	sort.SliceStable(kids, func(i, j int) bool { return kids[i].cost < kids[j].cost })
	cost := kids[len(kids)-1].cost
	fns := make([]matchFn, len(kids))
	for i, k := range kids {
		fns[i] = k.fn
	}
	if and {
		return &node{cost: cost, fn: func(f []byte, in *decode.Info) bool {
			for _, fn := range fns {
				if !fn(f, in) {
					return false
				}
			}
			return true
		}}
	}
	return &node{cost: cost, fn: func(f []byte, in *decode.Info) bool {
		for _, fn := range fns {
			if fn(f, in) {
				return true
			}
		}
		return false
	}}
}

// or parses  and { (OR | "||") and }.
func (p *parser) or() (*node, error) {
	kids := []*node{}
	for {
		n, err := p.and()
		if err != nil {
			return nil, err
		}
		kids = append(kids, n)
		if !p.kw("or", "||") {
			return combine(kids, false), nil
		}
	}
}

// and parses  unary { (AND | "&&") unary }.
func (p *parser) and() (*node, error) {
	kids := []*node{}
	for {
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		kids = append(kids, n)
		if !p.kw("and", "&&") {
			return combine(kids, true), nil
		}
	}
}

// unary parses  [NOT | "!"] ( "(" or ")" | comparison ).
func (p *parser) unary() (*node, error) {
	if p.kw("not", "!") {
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		inner := n.fn
		return &node{cost: n.cost, fn: func(f []byte, in *decode.Info) bool { return !inner(f, in) }}, nil
	}
	if t := p.peek(); t != nil && !t.quoted && t.text == "(" {
		p.pos++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if t := p.peek(); t == nil || t.text != ")" {
			return nil, fmt.Errorf("filter: missing ')'")
		}
		p.pos++
		return n, nil
	}
	return p.cmp()
}

// cmp parses one comparison "field op value" and dispatches to the node builder for the field.
func (p *parser) cmp() (*node, error) {
	fld, err := p.next()
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(fld.text)
	opTok, err := p.next()
	if err != nil {
		return nil, fmt.Errorf("filter: %q needs an operator", fld.text)
	}
	op := strings.ToLower(opTok.text)
	valTok, err := p.next()
	if err != nil {
		return nil, fmt.Errorf("filter: %q %s needs a value", fld.text, opTok.text)
	}
	neg := false
	switch op {
	case "==", "in", "contains", "~":
	case "!=":
		neg = true
	default:
		return nil, fmt.Errorf("filter: unknown operator %q", opTok.text)
	}
	var n *node
	switch name {
	case "src_ip", "dst_ip", "ip":
		n, err = ipNode(name, valTok.text)
	case "src_port", "dst_port", "port":
		n, err = portNode(name, valTok.text)
	case "proto", "protocol":
		n, err = protoNode(valTok.text)
	case "tcp_flags", "flags":
		n, err = flagsNode(valTok.text)
	case "payload":
		if neg {
			return nil, fmt.Errorf("filter: use NOT payload ... instead of !=")
		}
		n, err = payloadNode(op, valTok)
	default:
		return nil, fmt.Errorf("filter: unknown field %q", fld.text)
	}
	if err != nil {
		return nil, err
	}
	if neg {
		inner := n.fn
		n = &node{cost: n.cost, fn: func(f []byte, in *decode.Info) bool { return !inner(f, in) }}
	}
	return n, nil
}

// ipNode builds a test on the source, destination or either address; val may be a CIDR prefix.
func ipNode(field, val string) (*node, error) {
	var pfx netip.Prefix
	if strings.Contains(val, "/") {
		var err error
		if pfx, err = netip.ParsePrefix(val); err != nil {
			return nil, fmt.Errorf("filter: bad CIDR %q", val)
		}
	} else {
		a, err := netip.ParseAddr(val)
		if err != nil {
			return nil, fmt.Errorf("filter: bad IP %q", val)
		}
		pfx = netip.PrefixFrom(a, a.BitLen())
	}
	pfx = pfx.Masked()
	var fn matchFn
	switch field {
	case "src_ip":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && pfx.Contains(in.Src) }
	case "dst_ip":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && pfx.Contains(in.Dst) }
	default:
		fn = func(_ []byte, in *decode.Info) bool {
			return in.HasIP && (pfx.Contains(in.Src) || pfx.Contains(in.Dst))
		}
	}
	return &node{fn: fn}, nil
}

// portNode builds a test on a port; val is a number or a "lo-hi" range.
func portNode(field, val string) (*node, error) {
	lo, hi := uint64(0), uint64(0)
	var err error
	if a, b, ok := strings.Cut(val, "-"); ok {
		if lo, err = strconv.ParseUint(a, 10, 16); err == nil {
			hi, err = strconv.ParseUint(b, 10, 16)
		}
	} else if lo, err = strconv.ParseUint(val, 10, 16); err == nil {
		hi = lo
	}
	if err != nil || lo > hi {
		return nil, fmt.Errorf("filter: bad port or range %q", val)
	}
	in16 := func(v uint16) bool { return uint64(v) >= lo && uint64(v) <= hi }
	var fn matchFn
	switch field {
	case "src_port":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasPorts && in16(in.SrcPort) }
	case "dst_port":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasPorts && in16(in.DstPort) }
	default:
		fn = func(_ []byte, in *decode.Info) bool {
			return in.HasPorts && (in16(in.SrcPort) || in16(in.DstPort))
		}
	}
	return &node{fn: fn}, nil
}

// protoNode builds a test on the protocol (tcp, udp, icmp, icmp6, arp, ip, ipv6 or a number).
func protoNode(val string) (*node, error) {
	var fn matchFn
	switch strings.ToLower(val) {
	case "tcp":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && in.Proto == decode.ProtoTCP }
	case "udp":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && in.Proto == decode.ProtoUDP }
	case "icmp":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && in.Proto == decode.ProtoICMP }
	case "icmp6", "icmpv6":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && in.Proto == decode.ProtoICMPv6 }
	case "arp":
		fn = func(_ []byte, in *decode.Info) bool { return in.ARP }
	case "ip", "ipv4":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && !in.IPv6 }
	case "ipv6":
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && in.IPv6 }
	default:
		v, err := strconv.ParseUint(val, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("filter: unknown protocol %q", val)
		}
		fn = func(_ []byte, in *decode.Info) bool { return in.HasIP && uint64(in.Proto) == v }
	}
	return &node{fn: fn}, nil
}

// flagsNode builds a test on TCP flags written like "syn+ack".
func flagsNode(val string) (*node, error) {
	var mask uint8
	names := map[string]uint8{"fin": decode.FIN, "syn": decode.SYN, "rst": decode.RST,
		"psh": decode.PSH, "ack": decode.ACK, "urg": decode.URG}
	for _, part := range strings.Split(strings.ToLower(val), "+") {
		b, ok := names[part]
		if !ok {
			return nil, fmt.Errorf("filter: unknown TCP flag %q", part)
		}
		mask |= b
	}
	return &node{fn: func(_ []byte, in *decode.Info) bool {
		return in.HasPorts && in.Proto == decode.ProtoTCP && in.Flags&mask == mask
	}}, nil
}

// payloadNode builds a payload test: "contains" (text or 0x hex), "==" or "~" (regular expression).
// It is always ordered after the header tests.
func payloadNode(op string, v token) (*node, error) {
	switch op {
	case "contains", "==":
		var needle []byte
		if !v.quoted && (strings.HasPrefix(v.text, "0x") || strings.HasPrefix(v.text, "0X")) {
			var err error
			if needle, err = hex.DecodeString(strings.ReplaceAll(v.text[2:], "_", "")); err != nil || len(needle) == 0 {
				return nil, fmt.Errorf("filter: bad hex literal %q", v.text)
			}
		} else {
			needle = []byte(v.text)
		}
		return &node{cost: 1, fn: func(f []byte, in *decode.Info) bool {
			return bytes.Contains(in.Payload(f), needle)
		}}, nil
	case "~":
		re, err := regexp.Compile(v.text)
		if err != nil {
			return nil, fmt.Errorf("filter: bad regexp: %v", err)
		}
		return &node{cost: 1, fn: func(f []byte, in *decode.Info) bool {
			return re.Match(in.Payload(f))
		}}, nil
	}
	return nil, fmt.Errorf("filter: payload supports 'contains' and '~', got %q", op)
}
