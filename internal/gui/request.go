package gui

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sasha/pktreplay/internal/backend"
	"github.com/sasha/pktreplay/internal/filter"
	"github.com/sasha/pktreplay/internal/mutate"
	"github.com/sasha/pktreplay/internal/pace"
	"github.com/sasha/pktreplay/internal/pcapio"
	"github.com/sasha/pktreplay/internal/replay"
)

// RangeRequest selects a slice of a capture.
type RangeRequest struct {
	Path   string `json:"path"`
	Filter string `json:"filter"`
	Start  uint64 `json:"start"`
	Count  uint64 `json:"count"`
}

// ReplayRequest is the JSON body of POST /api/replay. All values are strings or
// numbers exactly as a user would type them on the command line.
type ReplayRequest struct {
	RangeRequest
	Mode    string   `json:"mode"` // "tcp" or "udp": must be chosen explicitly
	Loop    int      `json:"loop"`
	SrcIP   string   `json:"srcIp"`
	DstIP   string   `json:"dstIp"`
	SrcPort uint     `json:"srcPort"`
	DstPort uint     `json:"dstPort"`
	Payload string   `json:"payload"`
	Replace []string `json:"replace"`

	PaceMode string  `json:"paceMode"` // original|fixed|pps|mbps|burst
	Speed    float64 `json:"speed"`
	Delay    string  `json:"delay"`
	PPS      float64 `json:"pps"`
	Mbps     float64 `json:"mbps"`
	MaxGap   string  `json:"maxGap"`

	Backend    string `json:"backend"` // auto|null
	Iface      string `json:"iface"`
	SrcMAC     string `json:"srcMac"`
	DstMAC     string `json:"dstMac"`
	IfIndex    uint   `json:"ifIndex"`
	NoFirewall bool   `json:"noFirewall"`

	SeqOffset        int64  `json:"seqOffset"`
	SkipBytes        int64  `json:"skipBytes"`
	AckMode          string `json:"ackMode"`
	HandshakeTimeout string `json:"handshakeTimeout"`
}

func positionFn(start uint64) func(*pcapio.Reader) error {
	if start == 0 {
		return nil
	}
	return func(r *pcapio.Reader) error {
		if err := r.Skip(start); err != nil {
			return fmt.Errorf("start %d is beyond the end of the capture: %w", start, err)
		}
		return nil
	}
}

func addr(name, s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s: %w", name, err)
	}
	return a.Unmap(), nil
}

func mac(name, s string) (*[6]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return nil, fmt.Errorf("%s: invalid MAC %q", name, s)
	}
	var m [6]byte
	copy(m[:], hw)
	return &m, nil
}

func dur(name, s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w (examples: 250us, 5ms, 2s)", name, err)
	}
	return d, nil
}

// buildConfig validates the request and converts it to a replay.Config.
func (r *ReplayRequest) buildConfig() (replay.Config, replay.Transport, error) {
	var zero replay.Config
	var tr replay.Transport
	switch strings.ToLower(r.Mode) {
	case "tcp":
		tr = replay.TCP
	case "udp":
		tr = replay.UDP
	default:
		return zero, 0, errors.New("select the transmission mode explicitly: TCP or UDP")
	}
	if strings.TrimSpace(r.Path) == "" {
		return zero, 0, errors.New("choose a capture file first")
	}
	flt, err := filter.Parse(r.Filter)
	if err != nil {
		return zero, 0, err
	}
	if r.SrcPort > 65535 || r.DstPort > 65535 {
		return zero, 0, errors.New("ports must be in 0-65535")
	}
	cfg := replay.Config{Capture: r.Path, Filter: flt, Loop: r.Loop, Count: r.Count, Position: positionFn(r.Start)}

	var errs []error
	add := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}
	var e error
	cfg.Rewrite.SrcIP, e = addr("source IP", r.SrcIP)
	add(e)
	cfg.Rewrite.DstIP, e = addr("destination IP", r.DstIP)
	add(e)
	cfg.Rewrite.SrcPort, cfg.Rewrite.DstPort = uint16(r.SrcPort), uint16(r.DstPort)
	cfg.Opts.SrcMAC, e = mac("source MAC", r.SrcMAC)
	add(e)
	cfg.Opts.DstMAC, e = mac("destination MAC", r.DstMAC)
	add(e)
	if r.Payload != "" {
		cfg.Rewrite.SetPayload, e = mutate.ParseBytes(r.Payload)
		add(e)
	}
	for _, s := range r.Replace {
		if strings.TrimSpace(s) == "" {
			continue
		}
		sub, e := mutate.ParseSubst(s)
		add(e)
		cfg.Rewrite.Replace = append(cfg.Rewrite.Replace, sub)
	}
	delay, e := dur("delay", r.Delay)
	add(e)
	maxGap, e := dur("max gap", r.MaxGap)
	add(e)
	hs, e := dur("handshake timeout", r.HandshakeTimeout)
	add(e)
	if err := errors.Join(errs...); err != nil {
		return zero, 0, err
	}

	switch r.PaceMode {
	case "burst":
		cfg.Pace = pace.Config{Mode: pace.Burst}
	case "fixed":
		if delay <= 0 {
			return zero, 0, errors.New("fixed pacing needs a delay greater than zero")
		}
		cfg.Pace = pace.Config{Mode: pace.Fixed, Delay: delay}
	case "pps":
		cfg.Pace = pace.Config{Mode: pace.PPS, PPS: r.PPS}
	case "mbps":
		cfg.Pace = pace.Config{Mode: pace.Mbps, Mbps: r.Mbps}
	case "", "original":
		cfg.Pace = pace.Config{Mode: pace.Original, Speed: r.Speed, MaxGap: maxGap}
	default:
		return zero, 0, fmt.Errorf("unknown pacing mode %q", r.PaceMode)
	}
	if _, err := pace.New(cfg.Pace); err != nil {
		return zero, 0, err
	}

	if cfg.Backend, err = backend.ByName(r.Backend); err != nil {
		return zero, 0, err
	}
	cfg.Opts.Iface, cfg.Opts.IfIndex, cfg.Opts.NoFirewall = strings.TrimSpace(r.Iface), uint32(r.IfIndex), r.NoFirewall

	if tr == replay.UDP && (r.SeqOffset != 0 || r.SkipBytes != 0) {
		return zero, 0, errors.New("sequence offset and skip bytes only apply to TCP mode")
	}
	if r.SkipBytes < 0 {
		return zero, 0, errors.New("skip bytes cannot be negative")
	}
	cfg.TCP = replay.TCPConfig{SeqOffset: r.SeqOffset, SkipBytes: r.SkipBytes, AckMode: r.AckMode, HandshakeTimeout: hs}
	return cfg, tr, nil
}
