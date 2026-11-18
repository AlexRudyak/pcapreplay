// Package replay wires the streaming reader, filter, mutator, pacer and a
// backend together. Disk reading/filtering/rewriting runs in a producer
// goroutine and transmission in a consumer goroutine, connected by a bounded
// queue of pooled buffers, so slow disk I/O never stalls the wire and fast disks
// can never run away with memory.
package replay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/sasha/pktreplay/internal/backend"
	"github.com/sasha/pktreplay/internal/conv"
	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/filter"
	"github.com/sasha/pktreplay/internal/mutate"
	"github.com/sasha/pktreplay/internal/pace"
	"github.com/sasha/pktreplay/internal/pcapio"
)

// Transport is the user-selected replay mode.
type Transport int

const (
	UDP Transport = iota + 1
	TCP
)

func (t Transport) String() string {
	if t == TCP {
		return "tcp"
	}
	return "udp"
}

// Config is shared by the UDP and TCP engines.
type Config struct {
	Capture  string
	Position func(*pcapio.Reader) error // seeks to the first packet (may be nil)
	Count    uint64                     // stop after this many matched packets (0 = all)
	Loop     int                        // number of passes over the capture (min 1)
	Filter   *filter.Filter
	Rewrite  mutate.Rewrite
	Pace     pace.Config
	Backend  backend.Backend
	Opts     backend.Options
	// Progress, if non-nil, receives the live counters so another goroutine
	// (a GUI) can poll them while the run is active.
	Progress  *Counters
	QueueSize int // bounded queue depth between producer and sender (default 4096)
	Batch     int // max packets per SendBatch in burst mode (default 64)

	// Conversations holds per-conversation rewrite rules. A rule changes the
	// endpoints of exactly one conversation, consistently in both directions,
	// and replaces the global Rewrite IP/port fields for that conversation.
	// Conversations without a rule are replayed unchanged apart from the global
	// Rewrite (which, as before, applies to every packet).
	Conversations []conv.Rule
	// OnlyConversations replays just the conversations that have a rule. In TCP
	// mode (which replays a single conversation) it is implied by having rules.
	OnlyConversations bool
	convSet           *conv.Set

	// TCP mode.
	TCP TCPConfig
}

// prepare compiles the conversation rules.
func (c *Config) prepare() error {
	set, err := conv.NewSet(c.Conversations)
	if err != nil {
		return err
	}
	c.convSet = set
	return nil
}

// onlyRuled reports whether packets of conversations without a rule are dropped.
func (c *Config) onlyRuled(proto uint8) bool {
	return c.convSet.Len() > 0 && (c.OnlyConversations || proto == decode.ProtoTCP)
}

// pick chooses the rewrite for one packet. ok is false when the packet must not
// be replayed (it belongs to a conversation without a rule in only-rules mode).
func (c *Config) pick(in *decode.Info) (rw *mutate.Rewrite, ok bool) {
	if rule, r := c.convSet.Lookup(in); rule != nil {
		return r, true
	}
	if c.onlyRuled(in.Proto) {
		return nil, false
	}
	return &c.Rewrite, true
}

// Counters are updated atomically and may be sampled while a run is active.
type Counters struct {
	Read      atomic.Uint64 // packets read from the capture
	Matched   atomic.Uint64 // accepted by the filter and transport mode
	Sent      atomic.Uint64
	Bytes     atomic.Uint64 // IP bytes injected
	Skipped   atomic.Uint64 // wrong protocol, not IP, or snaplen-truncated
	SendErrs  atomic.Uint64
	StartedAt time.Time
}

// Result summarises a finished run.
type Result struct {
	Counters *Counters
	Elapsed  time.Duration
	TCP      *TCPStats // set in TCP mode
}

func (r *Result) String() string {
	c := r.Counters
	s := r.Elapsed.Seconds()
	if s == 0 {
		s = 1e-9
	}
	return fmt.Sprintf("read %d, matched %d, sent %d pkts / %d bytes, skipped %d, send errors %d in %s "+
		"(%.0f pps, %.2f Mbit/s)", c.Read.Load(), c.Matched.Load(), c.Sent.Load(), c.Bytes.Load(),
		c.Skipped.Load(), c.SendErrs.Load(), r.Elapsed.Round(time.Millisecond),
		float64(c.Sent.Load())/s, float64(c.Bytes.Load())*8/s/1e6)
}

type item struct {
	buf     *mutate.Buf
	ts      int64
	origPay int // transport payload length before any rewrite
}

// feedOpts specialises the producer for a transport.
type feedOpts struct {
	proto    uint8
	accept   func(*decode.Info) bool                    // extra per-packet test (e.g. flow tuple); may be nil
	pick     func(*decode.Info) (*mutate.Rewrite, bool) // rewrite for a packet (nil = none); false = skip it
	finalize bool                                       // repair lengths/checksums before queueing
}

// counters returns the caller-supplied Progress (reset) or a fresh Counters.
func (c *Config) counters() *Counters {
	cnt := c.Progress
	if cnt == nil {
		cnt = &Counters{}
	}
	cnt.StartedAt = time.Now()
	return cnt
}

func (c *Config) defaults() {
	if c.Loop < 1 {
		c.Loop = 1
	}
	if c.QueueSize < 1 {
		c.QueueSize = 4096
	}
	if c.Batch < 1 {
		c.Batch = 64
	}
	if c.Filter == nil {
		c.Filter, _ = filter.Parse("")
	}
}

// feed is the producer: it streams the capture, keeps packets of the wanted
// protocol that pass the filter, applies rewrites and hands them to out.
func feed(ctx context.Context, cfg *Config, o feedOpts, cnt *Counters, out chan<- item) error {
	rd, err := pcapio.Open(cfg.Capture)
	if err != nil {
		return err
	}
	defer rd.Close()

	var in decode.Info
	var loopShift, firstTs, lastTs int64
	var matched uint64
	for pass := 0; pass < cfg.Loop; pass++ {
		if pass > 0 {
			if err := rd.SeekOffset(0, 0); err != nil {
				return fmt.Errorf("loop: %w", err)
			}
			loopShift += lastTs - firstTs + int64(time.Millisecond)
		}
		if cfg.Position != nil {
			if err := cfg.Position(rd); err != nil {
				return err
			}
		}
		firstTs = 0
		for {
			p, err := rd.Next()
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			if err != nil {
				return fmt.Errorf("packet %d: %w", rd.Count(), err)
			}
			cnt.Read.Add(1)
			if !decode.Decode(p.LinkType, p.Data, &in) || !in.HasIP || in.Proto != o.proto || !in.HasPorts ||
				(o.accept != nil && !o.accept(&in)) {
				cnt.Skipped.Add(1)
				continue
			}
			if !cfg.Filter.MatchAll() && !cfg.Filter.Match(p.Data, &in) {
				continue
			}
			var rw *mutate.Rewrite
			if o.pick != nil {
				var ok bool
				if rw, ok = o.pick(&in); !ok {
					cnt.Skipped.Add(1) // conversation not selected for replay
					continue
				}
			}
			b := mutate.Get()
			if err := b.Load(p.LinkType, p.Data); err != nil {
				mutate.Put(b)
				cnt.Skipped.Add(1)
				continue
			}
			origPay := b.In.PayEnd - b.In.PayOff
			if rw != nil && rw.Active() {
				if err := rw.Apply(b); err != nil {
					mutate.Put(b)
					return err
				}
			}
			if o.finalize {
				b.Finalize()
			}
			if firstTs == 0 {
				firstTs = p.TsNanos
			}
			lastTs = p.TsNanos
			cnt.Matched.Add(1)
			select {
			case out <- item{b, p.TsNanos + loopShift, origPay}:
			case <-ctx.Done():
				mutate.Put(b)
				return ctx.Err()
			}
			matched++
			if cfg.Count > 0 && matched >= cfg.Count {
				return nil
			}
		}
	}
	return nil
}

// RunUDP replays matching UDP datagrams statelessly.
func RunUDP(ctx context.Context, cfg Config) (*Result, error) {
	cfg.defaults()
	if err := cfg.prepare(); err != nil {
		return nil, err
	}
	pc, err := pace.New(cfg.Pace)
	if err != nil {
		return nil, err
	}
	if !cfg.Opts.Target.IsValid() {
		// The first packet that will actually be replayed decides the route.
		k, err := ProbeUDP(&cfg)
		if err != nil {
			return nil, err
		}
		cfg.Opts.Target = k.Server
	}
	if err := cfg.Backend.Open(cfg.Opts); err != nil {
		return nil, err
	}
	defer cfg.Backend.Close()

	cnt := cfg.counters()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	q := make(chan item, cfg.QueueSize)
	prodErr := make(chan error, 1)
	go func() {
		err := feed(ctx, &cfg, feedOpts{proto: decode.ProtoUDP, pick: cfg.pick, finalize: true}, cnt, q)
		close(q)
		prodErr <- err
	}()

	sendErr := send(ctx, &cfg, pc, cnt, q)
	cancel() // unblock the producer if the sender bailed out early
	for range q {
	}
	perr := <-prodErr
	res := &Result{Counters: cnt, Elapsed: time.Since(cnt.StartedAt)}
	if sendErr != nil {
		return res, sendErr
	}
	if perr != nil && !errors.Is(perr, context.Canceled) && !errors.Is(perr, context.DeadlineExceeded) {
		return res, perr
	}
	return res, nil
}

// send is the consumer: it paces and injects, batching when unpaced.
func send(ctx context.Context, cfg *Config, pc *pace.Pacer, cnt *Counters, q <-chan item) error {
	batchBufs := make([]*mutate.Buf, 0, cfg.Batch)
	batch := make([][]byte, 0, cfg.Batch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := cfg.Backend.SendBatch(batch)
		var bytes uint64
		for i := 0; i < n; i++ {
			bytes += uint64(len(batch[i]))
		}
		cnt.Sent.Add(uint64(n))
		cnt.Bytes.Add(bytes)
		cnt.SendErrs.Add(uint64(len(batch) - n))
		for _, b := range batchBufs {
			mutate.Put(b)
		}
		batch, batchBufs = batch[:0], batchBufs[:0]
		return err
	}
	for {
		it, ok := <-q
		if !ok {
			return flush()
		}
		pc.Wait(it.ts, len(it.buf.B))
		batchBufs = append(batchBufs, it.buf)
		batch = append(batch, it.buf.IPPacket())
		if pc.Unpaced() {
			// Opportunistically drain whatever the producer already queued.
		fill:
			for len(batch) < cfg.Batch {
				select {
				case it, ok = <-q:
					if !ok {
						return flush()
					}
					batchBufs = append(batchBufs, it.buf)
					batch = append(batch, it.buf.IPPacket())
				default:
					break fill
				}
			}
		}
		if err := flush(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return nil
		}
	}
}
