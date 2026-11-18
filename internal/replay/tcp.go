package replay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sasha/pktreplay/internal/backend"
	"github.com/sasha/pktreplay/internal/craft"
	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/mutate"
	"github.com/sasha/pktreplay/internal/pace"
	"github.com/sasha/pktreplay/internal/pcapio"
)

// Errors reported by the TCP engine.
var (
	ErrHandshakeTimeout = errors.New("tcp handshake timed out: no SYN-ACK from server")
	ErrConnRefused      = errors.New("tcp connection refused by server (RST in reply to SYN)")
	ErrReset            = errors.New("tcp connection reset by server")
	ErrStalled          = errors.New("server stopped acknowledging data")
	errStreamEnd        = errors.New("end of captured stream")
)

// AckMode selects how replayed segments acknowledge server data.
const (
	AckLive    = "live"    // acknowledge everything actually received from the live server
	AckCapture = "capture" // rebase the captured ACK, never acknowledging unseen data
)

// TCPConfig holds the TCP-mode options.
type TCPConfig struct {
	HandshakeTimeout time.Duration // default 5s
	CloseTimeout     time.Duration // default 5s
	MaxRetries       int           // consecutive retransmissions before giving up (default 8)

	// SeqOffset shifts every replayed sequence number by this many bytes:
	// seq = live_isn + 1 + (pkt_seq - capture_base_seq + SeqOffset). Positive
	// values leave a hole in the stream, negative values overlap sent data.
	SeqOffset int64
	// SkipBytes starts the replay this many payload bytes into the captured
	// client stream; the first replayed byte is mapped to live_isn + 1.
	SkipBytes int64
	// AckMode is AckLive (default) or AckCapture.
	AckMode string
	// Trace, if non-nil, receives one line per significant protocol event.
	Trace func(format string, args ...any)
}

// FlowKey is the captured 4-tuple selected for replay (client -> server).
type FlowKey struct {
	Client, Server         netip.Addr
	ClientPort, ServerPort uint16
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s -> %s", netip.AddrPortFrom(k.Client, k.ClientPort), netip.AddrPortFrom(k.Server, k.ServerPort))
}

// TCPStats summarises a stateful TCP replay.
type TCPStats struct {
	Flow         FlowKey
	Live         backend.Flow
	HandshakeRTT time.Duration
	Retransmits  uint64
	RxSegments   uint64
	RxBytes      uint64
	AcksSent     uint64
	PeerClosed   bool   // server sent FIN
	FinalState   string // how the session ended
}

// ProbeFlow scans the capture for the first TCP packet accepted by the filter
// and returns its tuple; that packet's sender is treated as the client.
func ProbeFlow(cfg *Config) (FlowKey, error) {
	cfg.defaults()
	rd, err := pcapio.Open(cfg.Capture)
	if err != nil {
		return FlowKey{}, err
	}
	defer rd.Close()
	if cfg.Position != nil {
		if err := cfg.Position(rd); err != nil {
			return FlowKey{}, err
		}
	}
	var in decode.Info
	for {
		p, err := rd.Next()
		if err != nil {
			return FlowKey{}, errors.New("no TCP packet in the capture matches the filter")
		}
		if decode.Decode(p.LinkType, p.Data, &in) && in.HasIP && in.Proto == decode.ProtoTCP && in.HasPorts &&
			cfg.Filter.Match(p.Data, &in) {
			return FlowKey{in.Src, in.Dst, in.SrcPort, in.DstPort}, nil
		}
	}
}

// RunTCP establishes a real TCP session with the target and replays the
// captured client->server stream of one flow into it.
func RunTCP(ctx context.Context, cfg Config) (*Result, error) {
	cfg.defaults()
	tc := &cfg.TCP
	if tc.HandshakeTimeout == 0 {
		tc.HandshakeTimeout = 5 * time.Second
	}
	if tc.CloseTimeout == 0 {
		tc.CloseTimeout = 5 * time.Second
	}
	if tc.MaxRetries == 0 {
		tc.MaxRetries = 8
	}
	if tc.AckMode == "" {
		tc.AckMode = AckLive
	}
	if tc.AckMode != AckLive && tc.AckMode != AckCapture {
		return nil, fmt.Errorf("unknown ack mode %q", tc.AckMode)
	}
	pc, err := pace.New(cfg.Pace)
	if err != nil {
		return nil, err
	}
	key, err := ProbeFlow(&cfg)
	if err != nil {
		return nil, err
	}

	// Resolve the live endpoints: rewritten values win over captured ones.
	target, remotePort := key.Server, key.ServerPort
	if cfg.Rewrite.DstIP.IsValid() {
		target = cfg.Rewrite.DstIP
	}
	if cfg.Rewrite.DstPort != 0 {
		remotePort = cfg.Rewrite.DstPort
	}
	cfg.Opts.Target = target
	if err := cfg.Backend.Open(cfg.Opts); err != nil {
		return nil, err
	}
	defer cfg.Backend.Close()

	live := backend.Flow{LocalIP: cfg.Rewrite.SrcIP, RemoteIP: target, LocalPort: cfg.Rewrite.SrcPort, RemotePort: remotePort}
	if !live.LocalIP.IsValid() {
		if live.LocalIP, err = backend.LocalAddrFor(target); err != nil {
			return nil, err
		}
	}
	if live.LocalPort == 0 {
		var r [2]byte
		rand.Read(r[:])
		live.LocalPort = 49152 + binary.BigEndian.Uint16(r[:])%16000
	}

	release, err := cfg.Backend.Guard(live)
	if err != nil {
		return nil, err
	}
	defer release()

	cnt := &Counters{StartedAt: time.Now()}
	stats := &TCPStats{Flow: key, Live: live}
	res := &Result{Counters: cnt, TCP: stats}
	// The producer gets its own context so it can be stopped after the replay
	// without cancelling the session while it is still flushing and closing.
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s := newSession(ctx, &cfg, live, stats)
	stop := make(chan struct{})
	defer close(stop)
	go s.rxLoop(stop)

	if err := s.connect(); err != nil {
		stats.FinalState = "handshake failed"
		res.Elapsed = time.Since(cnt.StartedAt)
		return res, err
	}
	s.trace("established %s (local isn=%d, server isn=%d)", live.LocalIP, s.isn, s.srvISN)

	q := make(chan item, cfg.QueueSize)
	prodErr := make(chan error, 1)
	go func() {
		accept := func(in *decode.Info) bool {
			return in.Src == key.Client && in.Dst == key.Server && in.SrcPort == key.ClientPort && in.DstPort == key.ServerPort
		}
		err := feed(pctx, &cfg, feedOpts{proto: decode.ProtoTCP, accept: accept}, cnt, q)
		close(q)
		prodErr <- err
	}()

	runErr := s.replay(pc, cnt, q)
	cancel()
	for it := range q { // release anything still queued
		mutate.Put(it.buf)
	}
	perr := <-prodErr

	closeErr := s.shutdown(runErr == nil)
	res.Elapsed = time.Since(cnt.StartedAt)
	switch {
	case runErr != nil:
		stats.FinalState = "aborted: " + runErr.Error()
		return res, runErr
	case perr != nil && !errors.Is(perr, context.Canceled) && !errors.Is(perr, context.DeadlineExceeded):
		return res, perr
	}
	return res, closeErr
}

// ---- session state machine ----

type seg struct {
	seq, end uint32
	b        *mutate.Buf
}

type tcpSession struct {
	ctx   context.Context
	cfg   *Config
	tc    *TCPConfig
	be    backend.Backend
	live  backend.Flow
	stats *TCPStats

	rx    chan *mutate.Buf
	rxErr atomic.Pointer[error]

	isn, srvISN            uint32
	sndUna, sndNxt, rcvNxt uint32
	peerWnd                uint32
	dupAcks                int
	rto                    time.Duration
	ipID                   uint16

	segs []seg

	spec    craft.Spec
	scratch []byte
	one     [1][]byte

	// replay mapping
	started    bool
	haveBase   bool
	baseOrig   uint32 // captured seq of the first data byte seen
	capBase    uint32 // captured seq mapped to live_isn+1
	capSrvBase uint32 // captured ack mapped to server_isn+1
	delta      int64  // accumulated payload-length change from rewrites
}

func newSession(ctx context.Context, cfg *Config, live backend.Flow, st *TCPStats) *tcpSession {
	s := &tcpSession{ctx: ctx, cfg: cfg, tc: &cfg.TCP, be: cfg.Backend, live: live, stats: st,
		rx: make(chan *mutate.Buf, 1024), rto: 300 * time.Millisecond}
	s.spec = craft.Spec{NoEth: true, Src: live.LocalIP, Dst: live.RemoteIP,
		SrcPort: live.LocalPort, DstPort: live.RemotePort, Window: 65535}
	return s
}

func (s *tcpSession) trace(f string, a ...any) {
	if s.tc.Trace != nil {
		s.tc.Trace(f, a...)
	}
}

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }

// rxLoop pumps inbound datagrams of the guarded flow into s.rx.
func (s *tcpSession) rxLoop(stop <-chan struct{}) {
	defer close(s.rx)
	buf := make([]byte, 65536)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := s.be.Recv(buf, 100*time.Millisecond)
		if err == backend.ErrTimeout {
			continue
		}
		if err != nil {
			s.rxErr.Store(&err)
			return
		}
		b := mutate.Get()
		b.B = append(b.B[:0], buf[:n]...)
		select {
		case s.rx <- b:
		case <-stop:
			mutate.Put(b)
			return
		}
	}
}

func (s *tcpSession) rxFailure() error {
	if e := s.rxErr.Load(); e != nil {
		return fmt.Errorf("receive path failed: %w", *e)
	}
	return errors.New("receive path closed")
}

func (s *tcpSession) sendCtl(seq, ack uint32, flags uint8, opts []byte) error {
	s.ipID++
	s.spec.ID, s.spec.Seq, s.spec.Ack, s.spec.Flags, s.spec.Options = s.ipID, seq, ack, flags, opts
	s.scratch = craft.TCP(s.scratch, &s.spec)
	s.one[0] = s.scratch
	_, err := s.be.SendBatch(s.one[:])
	return err
}

func (s *tcpSession) sendAck() error {
	s.stats.AcksSent++
	return s.sendCtl(s.sndNxt, s.rcvNxt, decode.ACK, nil)
}

// connect performs the three-way handshake with SYN retransmission.
func (s *tcpSession) connect() error {
	var r [4]byte
	rand.Read(r[:])
	s.isn = binary.BigEndian.Uint32(r[:])
	mss := []byte{2, 4, 0x05, 0xb4} // MSS 1460
	deadline := time.Now().Add(s.tc.HandshakeTimeout)
	wait := 500 * time.Millisecond
	var in decode.Info
	for time.Now().Before(deadline) {
		t0 := time.Now()
		if err := s.sendCtl(s.isn, 0, decode.SYN, mss); err != nil {
			return fmt.Errorf("sending SYN: %w", err)
		}
		s.trace("SYN seq=%d", s.isn)
		until := time.Now().Add(wait)
		if until.After(deadline) {
			until = deadline
		}
		for {
			rem := time.Until(until)
			if rem <= 0 {
				break
			}
			t := time.NewTimer(rem)
			select {
			case b, ok := <-s.rx:
				t.Stop()
				if !ok {
					return s.rxFailure()
				}
				okPkt := decode.Decode(pcapio.LinkRaw, b.B, &in) && in.Proto == decode.ProtoTCP && in.HasPorts
				flags, ack, seq, win := in.Flags, in.Ack, in.Seq, in.Window
				mutate.Put(b)
				if !okPkt {
					continue
				}
				if flags&decode.RST != 0 && flags&decode.ACK != 0 && ack == s.isn+1 {
					return ErrConnRefused
				}
				if flags&decode.SYN != 0 && flags&decode.ACK != 0 && ack == s.isn+1 {
					s.srvISN = seq
					s.rcvNxt, s.sndNxt, s.sndUna = seq+1, s.isn+1, s.isn+1
					s.peerWnd = uint32(win)
					s.stats.HandshakeRTT = time.Since(t0)
					s.trace("SYN-ACK seq=%d win=%d rtt=%s", seq, win, s.stats.HandshakeRTT)
					return s.sendAck()
				}
			case <-t.C:
			case <-s.ctx.Done():
				t.Stop()
				return s.ctx.Err()
			}
		}
		wait *= 2
	}
	return ErrHandshakeTimeout
}

// pump processes inbound packets. With wait > 0 it blocks up to wait for the
// first one; afterwards it drains whatever is already queued. It reports
// whether the peer acknowledged new data.
func (s *tcpSession) pump(wait time.Duration) (bool, error) {
	progress := false
	for first := true; ; first = false {
		var b *mutate.Buf
		var ok bool
		if first && wait > 0 {
			t := time.NewTimer(wait)
			select {
			case b, ok = <-s.rx:
				t.Stop()
			case <-t.C:
				return progress, nil
			case <-s.ctx.Done():
				t.Stop()
				return progress, s.ctx.Err()
			}
		} else {
			select {
			case b, ok = <-s.rx:
			default:
				return progress, nil
			}
		}
		if !ok {
			return progress, s.rxFailure()
		}
		p, err := s.handle(b)
		mutate.Put(b)
		progress = progress || p
		if err != nil {
			return progress, err
		}
	}
}

func (s *tcpSession) handle(b *mutate.Buf) (bool, error) {
	var in decode.Info
	if !decode.Decode(pcapio.LinkRaw, b.B, &in) || in.Proto != decode.ProtoTCP || !in.HasPorts {
		return false, nil
	}
	if in.Flags&decode.RST != 0 {
		s.trace("RST from server")
		return false, ErrReset
	}
	progress, needAck := false, false
	if in.Flags&decode.SYN != 0 { // retransmitted SYN-ACK: our final ACK was lost
		return false, s.sendAck()
	}
	if in.Flags&decode.ACK != 0 {
		s.peerWnd = uint32(in.Window)
		switch {
		case seqLT(s.sndUna, in.Ack) && seqLE(in.Ack, s.sndNxt):
			s.sndUna, s.dupAcks, s.rto, progress = in.Ack, 0, 300*time.Millisecond, true
			s.popAcked()
		case in.Ack == s.sndUna && in.PayEnd == in.PayOff && in.Flags&decode.FIN == 0 && len(s.segs) > 0:
			if s.dupAcks++; s.dupAcks == 3 {
				s.trace("3 duplicate ACKs for %d: fast retransmit", in.Ack)
				if err := s.retransmit(); err != nil {
					return progress, err
				}
			}
		}
	}
	if n := in.PayEnd - in.PayOff; n > 0 {
		s.stats.RxSegments++
		if in.Seq == s.rcvNxt {
			s.rcvNxt += uint32(n)
			s.stats.RxBytes += uint64(n)
		}
		needAck = true // in-order, duplicate or future: always (re)acknowledge
	}
	if in.Flags&decode.FIN != 0 && in.Seq+uint32(in.PayEnd-in.PayOff) == s.rcvNxt {
		s.rcvNxt++
		s.stats.PeerClosed = true
		needAck = true
		s.trace("FIN from server")
	}
	if needAck {
		return progress, s.sendAck()
	}
	return progress, nil
}

func (s *tcpSession) popAcked() {
	i := 0
	for i < len(s.segs) && seqLE(s.segs[i].end, s.sndUna) {
		mutate.Put(s.segs[i].b)
		i++
	}
	if i > 0 {
		s.segs = append(s.segs[:0], s.segs[i:]...)
	}
}

func (s *tcpSession) retransmit() error {
	if len(s.segs) == 0 {
		return nil
	}
	s.stats.Retransmits++
	s.one[0] = s.segs[0].b.IPPacket()
	_, err := s.be.SendBatch(s.one[:])
	return err
}

// waitWindow blocks until n more bytes fit in the peer's window, retransmitting
// on timeout; it fails if the peer makes no progress for MaxRetries timeouts.
func (s *tcpSession) waitWindow(n uint32) error {
	retries := 0
	for {
		inflight := s.sndNxt - s.sndUna
		if len(s.segs) == 0 || inflight+n <= s.peerWnd {
			// Opportunistic non-blocking drain keeps ACK processing prompt.
			_, err := s.pump(0)
			return err
		}
		progress, err := s.pump(s.rto)
		if err != nil {
			return err
		}
		if progress {
			retries = 0
			continue
		}
		if retries++; retries > s.tc.MaxRetries {
			return fmt.Errorf("%w (window full, %d bytes in flight)", ErrStalled, s.sndNxt-s.sndUna)
		}
		s.rto = min(s.rto*2, 3*time.Second)
		s.trace("RTO: retransmitting seq=%d (try %d)", s.segs[0].seq, retries)
		if err := s.retransmit(); err != nil {
			return err
		}
	}
}

// replay consumes queued client packets and injects them into the session.
func (s *tcpSession) replay(pc *pace.Pacer, cnt *Counters, q <-chan item) error {
	local := mutate.Rewrite{SrcIP: s.live.LocalIP, DstIP: s.live.RemoteIP,
		SrcPort: s.live.LocalPort, DstPort: s.live.RemotePort}
	userRW := mutate.Rewrite{SetPayload: s.cfg.Rewrite.SetPayload, Replace: s.cfg.Rewrite.Replace}
	for it := range q {
		err := s.replayOne(it, pc, cnt, &local, &userRW)
		if err == errStreamEnd {
			s.drain(q)
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.ctx.Err(); err != nil {
			return nil
		}
	}
	return nil
}

func (s *tcpSession) drain(q <-chan item) {
	go func() {
		for it := range q {
			mutate.Put(it.buf)
		}
	}()
}

func (s *tcpSession) replayOne(it item, pc *pace.Pacer, cnt *Counters, local, userRW *mutate.Rewrite) error {
	b := it.buf
	in := &b.In
	keep := false
	defer func() {
		if !keep {
			mutate.Put(b)
		}
	}()
	if in.Flags&(decode.SYN|decode.RST) != 0 {
		cnt.Skipped.Add(1) // handshake and resets of the original session are never re-injected
		return nil
	}
	fin := in.Flags&decode.FIN != 0
	pay := in.PayEnd - in.PayOff
	if pay == 0 {
		cnt.Skipped.Add(1) // pure ACKs: acknowledgments are generated live
		if fin {
			return errStreamEnd
		}
		return nil
	}

	// Anchor the stream at the first data packet, then apply --tcp-skip-bytes.
	if !s.haveBase {
		s.baseOrig, s.haveBase = in.Seq, true // first data byte of the captured stream
	}
	if skip := s.tc.SkipBytes; skip > 0 {
		rel := int64(int32(in.Seq - s.baseOrig))
		if rel+int64(pay) <= skip {
			cnt.Skipped.Add(1)
			return nil
		}
		if rel < skip {
			b.TrimPayloadFront(int(skip - rel))
			pay = in.PayEnd - in.PayOff
		}
	}
	if !s.started {
		s.started = true
		s.capBase = s.baseOrig + uint32(s.tc.SkipBytes)
		s.capSrvBase = in.Ack
		s.trace("stream anchored: capture seq %d -> live seq %d, capture ack %d -> live ack %d",
			s.capBase, s.isn+1, s.capSrvBase, s.srvISN+1)
	}

	// Payload rewrites happen after trimming so skip offsets refer to original bytes.
	if userRW.Active() {
		if err := userRW.Apply(b); err != nil {
			return err
		}
	}
	newLen := in.PayEnd - in.PayOff
	deltaBefore := s.delta
	s.delta += int64(newLen - pay)

	b.StripTCPOptions()
	if err := local.Apply(b); err != nil {
		return err
	}
	flags := decode.ACK | in.Flags&(decode.PSH|decode.URG)
	origSeq, origAck := in.Seq, in.Ack
	b.SetFlags(uint8(flags))
	b.SetWindow(65535)

	pc.Wait(it.ts, len(b.B))

	off := int64(int32(origSeq-s.capBase)) + s.tc.SeqOffset + deltaBefore
	seq := s.isn + 1 + uint32(off)
	end := seq + uint32(newLen)
	if err := s.waitWindow(uint32(newLen)); err != nil {
		return err
	}
	ack := s.rcvNxt
	if s.tc.AckMode == AckCapture {
		reb := s.srvISN + 1 + uint32(int32(origAck-s.capSrvBase))
		if seqLT(reb, ack) {
			ack = reb
		}
	}
	b.SetSeqAck(seq, ack)
	b.Finalize()
	s.one[0] = b.IPPacket()
	if _, err := s.be.SendBatch(s.one[:]); err != nil {
		cnt.SendErrs.Add(1)
		return fmt.Errorf("send: %w", err)
	}
	cnt.Matched.Add(1)
	cnt.Sent.Add(1)
	cnt.Bytes.Add(uint64(len(b.IPPacket())))
	if seqLT(s.sndNxt, end) {
		s.sndNxt = end
	}
	s.segs = append(s.segs, seg{seq, end, b})
	keep = true // held until acknowledged (for retransmission)
	if fin {
		return errStreamEnd
	}
	return nil
}

// shutdown flushes unacknowledged data, then closes with FIN/ACK. When ok is
// false (replay aborted) it only releases buffers.
func (s *tcpSession) shutdown(ok bool) error {
	defer func() {
		for _, sg := range s.segs {
			mutate.Put(sg.b)
		}
		s.segs = nil
	}()
	if !ok {
		return nil
	}
	deadline := time.Now().Add(s.tc.CloseTimeout)
	retries := 0
	for len(s.segs) > 0 && time.Now().Before(deadline) {
		progress, err := s.pump(s.rto)
		if err != nil && !errors.Is(err, ErrReset) {
			return err
		}
		if errors.Is(err, ErrReset) {
			s.stats.FinalState = "reset by server after replay"
			return ErrReset
		}
		if progress {
			retries = 0
			continue
		}
		if retries++; retries > s.tc.MaxRetries {
			return fmt.Errorf("%w while flushing %d unacknowledged segments", ErrStalled, len(s.segs))
		}
		s.retransmit()
	}
	if len(s.segs) > 0 {
		return fmt.Errorf("%w: %d segments unacknowledged after %s", ErrStalled, len(s.segs), s.tc.CloseTimeout)
	}
	if err := s.sendCtl(s.sndNxt, s.rcvNxt, decode.FIN|decode.ACK, nil); err != nil {
		return err
	}
	finEnd := s.sndNxt + 1
	s.sndNxt = finEnd
	s.trace("FIN seq=%d", finEnd-1)
	closeDeadline := time.Now().Add(min(s.tc.CloseTimeout, 3*time.Second))
	for time.Now().Before(closeDeadline) {
		if _, err := s.pump(50 * time.Millisecond); err != nil {
			if errors.Is(err, ErrReset) {
				break
			}
			return err
		}
		if s.sndUna == finEnd && s.stats.PeerClosed {
			s.stats.FinalState = "closed cleanly (FIN/ACK both directions)"
			return nil
		}
	}
	switch {
	case s.sndUna == finEnd:
		s.stats.FinalState = "FIN acknowledged; server did not close its side"
	default:
		s.stats.FinalState = "FIN not acknowledged within timeout"
	}
	return nil
}
