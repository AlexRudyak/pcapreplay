package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/AlexRudyak/pcapreplay/internal/backend"
	"github.com/AlexRudyak/pcapreplay/internal/conv"
	"github.com/AlexRudyak/pcapreplay/internal/filter"
	"github.com/AlexRudyak/pcapreplay/internal/logx"
	"github.com/AlexRudyak/pcapreplay/internal/mutate"
	"github.com/AlexRudyak/pcapreplay/internal/pace"
	"github.com/AlexRudyak/pcapreplay/internal/pcapio"
	"github.com/AlexRudyak/pcapreplay/internal/record"
	"github.com/AlexRudyak/pcapreplay/internal/replay"
)

type listFlag []string

// String implements flag.Value.
func (l *listFlag) String() string { return strings.Join(*l, ",") }

// Set appends one occurrence of a repeatable flag.
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func parseAddr(name, s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("-%s: %w", name, err)
	}
	return a.Unmap(), nil
}

func parseMAC(name, s string) (*[6]byte, error) {
	if s == "" {
		return nil, nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return nil, fmt.Errorf("-%s: invalid MAC %q", name, s)
	}
	var m [6]byte
	copy(m[:], hw)
	return &m, nil
}

// cmdReplay implements "pcapreplay replay": it parses the flags into a replay.Config, wires up
// recording and logging, runs the UDP or TCP engine and prints the result.
func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: pcapreplay replay -mode tcp|udp [flags] <capture>

Transport (mandatory):
  -mode tcp|udp        udp: stateless injection; tcp: real handshake, then replay of one client stream

Selection:
  -filter EXPR         e.g. 'src_ip == 192.168.1.10 AND dst_port == 8080'
  -start N -count N    packet range (with -index for O(1) seeking); -loop N passes

Per-conversation rewrites (list conversations with 'pcapreplay conversations'):
  -conv RULE           change ONE conversation, consistently in both directions; repeatable
                       RULE = proto/client/server[,client-ip=IP][,client-port=N][,server-ip=IP][,server-port=N][,replace=a=>b]
  -only-conv           replay only the conversations that have a -conv rule (implied in TCP mode)

Rewrites applied to EVERY packet of every conversation without a -conv rule:
  -src-ip -dst-ip -src-port -dst-port
  -payload TEXT|hex:..|0x..     replace whole payload
  -replace 'old=>new'           in-payload substitution (repeatable)

Pacing (default: original capture timing):
  -speed X | -delay D | -pps N | -mbps N | -burst     (-max-gap D caps idle gaps)

TCP mode:
  -tcp-seq-offset N    shift live sequence numbers by N bytes (signed)
  -tcp-skip-bytes N    start N payload bytes into the captured client stream
  -tcp-ack-mode live|capture
  -handshake-timeout D

Backend:
  -backend auto|null   null = dry run without privileges (benchmark the pipeline)
  -iface NAME  -src-mac  -dst-mac  (Linux)   -ifindex N (Windows)   -no-firewall (Linux)

Recording:
  -record FILE         save everything transmitted (and replies, see -record-rx) as pcap/pcapng

Other:
  -queue N  -batch N  -v

Flags:
`)
		fs.PrintDefaults()
	}
	var rf rangeFlags
	rf.register(fs)
	mode := fs.String("mode", "", "transport mode: tcp or udp (required)")
	expr := fs.String("filter", "", "filter expression")
	loop := fs.Int("loop", 1, "number of passes over the selected packets")
	srcIP := fs.String("src-ip", "", "rewrite source IP (TCP mode: must be a local address)")
	dstIP := fs.String("dst-ip", "", "rewrite destination IP")
	srcPort := fs.Uint("src-port", 0, "rewrite source port (TCP mode: local port to use)")
	dstPort := fs.Uint("dst-port", 0, "rewrite destination port")
	payload := fs.String("payload", "", "replace the transport payload (text, hex:de ad.., or 0xdead..)")
	var repl listFlag
	fs.Var(&repl, "replace", "payload substitution 'old=>new' (repeatable; text or hex)")
	var convRules listFlag
	fs.Var(&convRules, "conv", "per-conversation rewrite 'proto/client/server[,client-ip=..][,client-port=..][,server-ip=..][,server-port=..][,replace=a=>b]' (repeatable; see 'conversations')")
	onlyConv := fs.Bool("only-conv", false, "replay only the conversations given with -conv (implied in TCP mode)")
	speed := fs.Float64("speed", 0, "original-timing speed factor (default 1)")
	delay := fs.Duration("delay", 0, "fixed inter-packet delay")
	pps := fs.Float64("pps", 0, "packets-per-second cap")
	mbps := fs.Float64("mbps", 0, "throughput cap in Mbit/s")
	burst := fs.Bool("burst", false, "no pacing: send at line rate")
	maxGap := fs.Duration("max-gap", 0, "cap idle gaps in original-timing mode")
	be := fs.String("backend", "auto", "auto or null")
	iface := fs.String("iface", "", "egress interface (Linux)")
	srcMAC := fs.String("src-mac", "", "source MAC override (Linux)")
	dstMAC := fs.String("dst-mac", "", "next-hop MAC override (Linux)")
	ifIndex := fs.Uint("ifindex", 0, "WinDivert interface index (Windows)")
	noFW := fs.Bool("no-firewall", false, "do not install the RST-drop firewall rule (Linux)")
	seqOff := fs.Int64("tcp-seq-offset", 0, "TCP: shift sequence numbers by N bytes (signed)")
	skipBytes := fs.Int64("tcp-skip-bytes", 0, "TCP: skip the first N bytes of the captured client stream")
	ackMode := fs.String("tcp-ack-mode", replay.AckLive, "TCP: live or capture")
	hsTimeout := fs.Duration("handshake-timeout", 5*time.Second, "TCP: handshake timeout")
	recordPath := fs.String("record", "", "record transmitted traffic to this file (.pcapng = PCAPNG with direction, else PCAP)")
	recordRx := fs.Bool("record-rx", true, "with -record, also record replies received from the target (TCP mode)")
	queue := fs.Int("queue", 4096, "producer/consumer queue depth")
	batch := fs.Int("batch", 64, "max packets per send batch in burst mode")
	var lf logFlags
	lf.register(fs)
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("a capture file is required")
	}
	var transport replay.Transport
	switch strings.ToLower(*mode) {
	case "tcp":
		transport = replay.TCP
	case "udp":
		transport = replay.UDP
	case "":
		return errors.New("select the transmission mode explicitly: -mode tcp or -mode udp")
	default:
		return fmt.Errorf("invalid -mode %q (want tcp or udp)", *mode)
	}
	flt, err := filter.Parse(*expr)
	if err != nil {
		return err
	}

	lg, closeLog, err := lf.build()
	if err != nil {
		return err
	}
	defer closeLog()
	rf.log = lg
	cfg := replay.Config{Capture: fs.Arg(0), Filter: flt, Loop: *loop, Count: rf.count,
		QueueSize: *queue, Batch: *batch, Log: lg}
	cfg.Position = func(r *pcapio.Reader) error { return rf.position(r, cfg.Capture) }

	var errs []error
	collect := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}
	var e error
	cfg.Rewrite.SrcIP, e = parseAddr("src-ip", *srcIP)
	collect(e)
	cfg.Rewrite.DstIP, e = parseAddr("dst-ip", *dstIP)
	collect(e)
	cfg.Rewrite.SrcPort, cfg.Rewrite.DstPort = uint16(*srcPort), uint16(*dstPort)
	cfg.Rewrite.SrcMAC, e = parseMAC("src-mac", *srcMAC)
	collect(e)
	cfg.Rewrite.DstMAC, e = parseMAC("dst-mac", *dstMAC)
	collect(e)
	cfg.Opts.SrcMAC, cfg.Opts.DstMAC = cfg.Rewrite.SrcMAC, cfg.Rewrite.DstMAC
	cfg.Rewrite.SrcMAC, cfg.Rewrite.DstMAC = nil, nil // L2 is the backend's job
	if *payload != "" {
		cfg.Rewrite.SetPayload, e = mutate.ParseBytes(*payload)
		collect(e)
	}
	for _, r := range repl {
		s, e := mutate.ParseSubst(r)
		collect(e)
		cfg.Rewrite.Replace = append(cfg.Rewrite.Replace, s)
	}
	for _, c := range convRules {
		r, e := conv.ParseRule(c)
		collect(e)
		cfg.Conversations = append(cfg.Conversations, r)
	}
	cfg.OnlyConversations = *onlyConv
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if *onlyConv && len(convRules) == 0 {
		return errors.New("-only-conv needs at least one -conv rule")
	}
	if *srcPort > 65535 || *dstPort > 65535 {
		return errors.New("ports must be in 0-65535")
	}

	// Pacing: at most one mode flag; original timing is the default.
	nModes := 0
	for _, set := range []bool{*delay > 0, *pps > 0, *mbps > 0, *burst} {
		if set {
			nModes++
		}
	}
	if nModes > 1 {
		return errors.New("choose only one of -delay, -pps, -mbps, -burst")
	}
	switch {
	case *burst:
		cfg.Pace = pace.Config{Mode: pace.Burst}
	case *delay > 0:
		cfg.Pace = pace.Config{Mode: pace.Fixed, Delay: *delay}
	case *pps > 0:
		cfg.Pace = pace.Config{Mode: pace.PPS, PPS: *pps}
	case *mbps > 0:
		cfg.Pace = pace.Config{Mode: pace.Mbps, Mbps: *mbps}
	default:
		cfg.Pace = pace.Config{Mode: pace.Original, Speed: *speed, MaxGap: *maxGap}
	}

	cfg.Backend, err = backend.ByName(*be)
	if err != nil {
		return err
	}
	var rec *record.Recorder
	if *recordPath != "" {
		w, err := record.Create(*recordPath)
		if err != nil {
			return fmt.Errorf("-record: %w", err)
		}
		rec = record.Wrap(cfg.Backend, w, *recordRx)
		cfg.Backend = rec
		defer w.Close() // idempotent; guarantees a flushed file on every exit path
	}
	cfg.Opts.Iface, cfg.Opts.IfIndex, cfg.Opts.NoFirewall = *iface, uint32(*ifIndex), *noFW
	cfg.TCP = replay.TCPConfig{SeqOffset: *seqOff, SkipBytes: *skipBytes, AckMode: *ackMode,
		HandshakeTimeout: *hsTimeout}
	if lg.Enabled(logx.Info) {
		cfg.TCP.Trace = func(f string, a ...any) { lg.Infof("tcp", f, a...) }
	}
	if lg.Enabled(logx.Debug) {
		cfg.TCP.Debug = func(f string, a ...any) { lg.Debugf("tcp", f, a...) }
	}
	if transport == replay.UDP && (*seqOff != 0 || *skipBytes != 0) {
		return errors.New("-tcp-seq-offset / -tcp-skip-bytes only apply to -mode tcp")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintf(os.Stderr, "mode=%s backend=%s capture=%s\n", transport, cfg.Backend.Name(), cfg.Capture)
	if lg.Enabled(logx.Info) {
		lg.Infof("replay", "filter=%q rewrite: %s", *expr, describeGlobalRewrite(&cfg))
		for _, c := range convRules {
			lg.Infof("replay", "conversation rule: %s", c)
		}
		cfg.Progress = &replay.Counters{}
		stopProg := make(chan struct{})
		defer close(stopProg)
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stopProg:
					return
				case <-t.C:
					c := cfg.Progress
					lg.Infof("progress", "read %d, matched %d, sent %d pkts / %d bytes, skipped %d, send errors %d",
						c.Read.Load(), c.Matched.Load(), c.Sent.Load(), c.Bytes.Load(), c.Skipped.Load(), c.SendErrs.Load())
				}
			}
		}()
	}

	var res *replay.Result
	if transport == replay.TCP {
		res, err = replay.RunTCP(ctx, cfg)
	} else {
		res, err = replay.RunUDP(ctx, cfg)
	}
	if res != nil {
		fmt.Println(res)
		if t := res.TCP; t != nil {
			fmt.Printf("tcp: flow %s as %s; handshake %s; retransmits %d; server sent %d bytes in %d segments; %s\n",
				t.Flow, t.Live.LocalIP, t.HandshakeRTT.Round(time.Microsecond), t.Retransmits, t.RxBytes,
				t.RxSegments, t.FinalState)
		}
	}
	if rec != nil {
		rec.Writer().Close()
		n, b := rec.Writer().Stats()
		fmt.Printf("recorded %d packets (%d bytes) to %s\n", n, b, rec.Writer().Path())
	}
	return err
}

// describeGlobalRewrite summarises the rewrite applied to conversations without a -conv rule.
func describeGlobalRewrite(cfg *replay.Config) string {
	rw := cfg.Rewrite
	s := ""
	add := func(f string, a ...any) { s += fmt.Sprintf(f, a...) + " " }
	if rw.SrcIP.IsValid() {
		add("src-ip=%s", rw.SrcIP)
	}
	if rw.SrcPort != 0 {
		add("src-port=%d", rw.SrcPort)
	}
	if rw.DstIP.IsValid() {
		add("dst-ip=%s", rw.DstIP)
	}
	if rw.DstPort != 0 {
		add("dst-port=%d", rw.DstPort)
	}
	if rw.SetPayload != nil {
		add("payload=%d bytes", len(rw.SetPayload))
	}
	if len(rw.Replace) > 0 {
		add("replace x%d", len(rw.Replace))
	}
	if s == "" {
		return "none (packets are sent as captured)"
	}
	return s
}
