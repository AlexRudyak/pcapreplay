package conv

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/AlexRudyak/pcapreplay/internal/decode"
	"github.com/AlexRudyak/pcapreplay/internal/mutate"
)

// Rule rewrites one conversation. Unlike the global packet-level rewrite it is
// expressed in terms of the conversation's endpoints, so a changed server IP is
// applied consistently to both directions: client->server packets get the new
// destination and server->client packets get the new source.
//
// Zero fields keep the captured value. A Rule replaces the global IP/port
// rewrite for its conversation entirely.
type Rule struct {
	Key    Key
	Client netip.AddrPort // the original initiator, as named by the selector

	NewClientIP, NewServerIP     netip.Addr
	NewClientPort, NewServerPort uint16
	Replace                      []mutate.Subst // payload substitutions, this conversation only
}

// Rewrites returns the rewrites for client->server and server->client packets.
func (r *Rule) Rewrites() (c2s, s2c mutate.Rewrite) {
	c2s = mutate.Rewrite{SrcIP: r.NewClientIP, SrcPort: r.NewClientPort, DstIP: r.NewServerIP, DstPort: r.NewServerPort, Replace: r.Replace}
	s2c = mutate.Rewrite{SrcIP: r.NewServerIP, SrcPort: r.NewServerPort, DstIP: r.NewClientIP, DstPort: r.NewClientPort, Replace: r.Replace}
	return
}

// Server returns the original server endpoint.
func (r *Rule) Server() netip.AddrPort {
	if r.Key.A == r.Client {
		return r.Key.B
	}
	return r.Key.A
}

// Set is a lookup structure over rules.
type Set struct {
	rules map[Key]*ruleEntry
	order []*Rule
}

type ruleEntry struct {
	rule     *Rule
	c2s, s2c mutate.Rewrite
}

// NewSet validates and indexes rules. Duplicate conversations are rejected.
func NewSet(rules []Rule) (*Set, error) {
	s := &Set{rules: make(map[Key]*ruleEntry, len(rules))}
	for i := range rules {
		r := &rules[i]
		if _, dup := s.rules[r.Key]; dup {
			return nil, fmt.Errorf("conversation %s listed twice", Selector(r.Key.Proto, r.Client, r.Server()))
		}
		if !hasPorts(r.Key.Proto) && (r.NewClientPort != 0 || r.NewServerPort != 0) {
			return nil, fmt.Errorf("conversation %s has no ports to rewrite", Selector(r.Key.Proto, r.Client, r.Server()))
		}
		for _, p := range []struct {
			name string
			orig netip.Addr
			new  netip.Addr
		}{{"client", r.Client.Addr(), r.NewClientIP}, {"server", r.Server().Addr(), r.NewServerIP}} {
			if p.new.IsValid() && p.new.Is4() != p.orig.Is4() {
				return nil, fmt.Errorf("conversation %s: new %s IP %s must be the same family as %s",
					Selector(r.Key.Proto, r.Client, r.Server()), p.name, p.new, p.orig)
			}
		}
		e := &ruleEntry{rule: r}
		e.c2s, e.s2c = r.Rewrites()
		s.rules[r.Key] = e
		s.order = append(s.order, r)
	}
	return s, nil
}

// Len returns the number of rules.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// Rules returns the rules in the order given.
func (s *Set) Rules() []*Rule {
	if s == nil {
		return nil
	}
	return s.order
}

// ForKey returns the rule for a conversation key, or nil.
func (s *Set) ForKey(k Key) *Rule {
	if s == nil {
		return nil
	}
	if e := s.rules[k]; e != nil {
		return e.rule
	}
	return nil
}

// Lookup finds the rule for a decoded packet and its rewrite for the packet's
// direction. rule is nil when the packet's conversation has no rule.
func (s *Set) Lookup(in *decode.Info) (rule *Rule, rw *mutate.Rewrite) {
	if s == nil || len(s.rules) == 0 {
		return nil, nil
	}
	k, ok := KeyOf(in)
	if !ok {
		return nil, nil
	}
	e := s.rules[k]
	if e == nil {
		return nil, nil
	}
	if in.Src == e.rule.Client.Addr() && portOf(in, true) == e.rule.Client.Port() {
		return e.rule, &e.c2s
	}
	return e.rule, &e.s2c
}

// ParseRule parses the CLI form
//
//	SELECTOR[,client-ip=IP][,client-port=N][,server-ip=IP][,server-port=N][,replace=old=>new]...
//
// where SELECTOR is "proto/client/server" as printed by `pcapreplay conversations`.
func ParseRule(s string) (Rule, error) {
	parts := strings.Split(s, ",")
	k, client, err := ParseSelector(parts[0])
	if err != nil {
		return Rule{}, err
	}
	r := Rule{Key: k, Client: client}
	var errs []error
	for _, kv := range parts[1:] {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			errs = append(errs, fmt.Errorf("%q: expected key=value", kv))
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "client-ip":
			r.NewClientIP, err = parseIP(val)
		case "server-ip":
			r.NewServerIP, err = parseIP(val)
		case "client-port":
			r.NewClientPort, err = parsePort(val)
		case "server-port":
			r.NewServerPort, err = parsePort(val)
		case "replace":
			var sub mutate.Subst
			if sub, err = mutate.ParseSubst(val); err == nil {
				r.Replace = append(r.Replace, sub)
			}
		default:
			err = fmt.Errorf("unknown key %q (client-ip, client-port, server-ip, server-port, replace)", key)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return r, errors.Join(errs...)
}

func parseIP(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("bad IP %q", s)
	}
	return a.Unmap(), nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}
