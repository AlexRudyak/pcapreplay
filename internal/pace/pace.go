// Package pace schedules packet transmission times with microsecond accuracy
// using a monotonic clock and a hybrid sleep/spin wait.
package pace

import (
	"fmt"
	"runtime"
	"time"
)

// Mode selects the pacing policy.
type Mode int

const (
	Burst    Mode = iota // no pacing: line rate
	Original             // follow capture timestamps (scaled by Speed)
	Fixed                // constant inter-packet delay
	PPS                  // packets-per-second cap
	Mbps                 // wire-throughput cap
)

// Config describes a pacing policy.
type Config struct {
	Mode   Mode
	Speed  float64       // Original: 2 = twice as fast, 0.5 = half speed (default 1)
	Delay  time.Duration // Fixed
	PPS    float64       // PPS
	Mbps   float64       // Mbps
	MaxGap time.Duration // Original: cap any single idle gap (0 = unlimited)
}

// spinThreshold is how close to the deadline we stop sleeping and busy-wait.
// OS timers are typically good to ~1 ms (Windows) or ~50-100 Âµs (Linux).
const spinThreshold = 2 * time.Millisecond

// resyncAfter is how far behind schedule we may fall before re-basing the
// clock, so a long stall does not trigger an unbounded catch-up burst.
const resyncAfter = 250 * time.Millisecond

// Pacer is not safe for concurrent use; it belongs to the sending goroutine.
type Pacer struct {
	cfg Config

	start    int64 // ns on the nanotime clock
	started  bool
	firstTs  int64
	prevTs   int64
	compress int64 // ns removed by MaxGap so far
	n        uint64
	bits     float64
}

// New validates cfg and returns a Pacer.
func New(cfg Config) (*Pacer, error) {
	switch cfg.Mode {
	case Original:
		if cfg.Speed == 0 {
			cfg.Speed = 1
		}
		if cfg.Speed < 0 {
			return nil, fmt.Errorf("pace: speed must be positive")
		}
	case Fixed:
		if cfg.Delay < 0 {
			return nil, fmt.Errorf("pace: negative delay")
		}
	case PPS:
		if cfg.PPS <= 0 {
			return nil, fmt.Errorf("pace: pps must be positive")
		}
	case Mbps:
		if cfg.Mbps <= 0 {
			return nil, fmt.Errorf("pace: mbps must be positive")
		}
	}
	return &Pacer{cfg: cfg}, nil
}

// Unpaced reports whether Wait is a no-op, letting callers batch sends.
func (p *Pacer) Unpaced() bool { return p.cfg.Mode == Burst }

// Wait blocks until packet number n (counting calls) is due. tsNanos is the
// capture timestamp and wireBytes the frame size; both are only used by the
// modes that need them.
func (p *Pacer) Wait(tsNanos int64, wireBytes int) {
	if p.cfg.Mode == Burst {
		return
	}
	if !p.started {
		p.started, p.start, p.firstTs, p.prevTs = true, nanotime(), tsNanos, tsNanos
	}
	var due int64
	switch p.cfg.Mode {
	case Original:
		gap := tsNanos - p.prevTs
		if gap < 0 {
			gap = 0 // timestamps went backwards: send immediately
		}
		if p.cfg.MaxGap > 0 && gap > int64(p.cfg.MaxGap) {
			p.compress += gap - int64(p.cfg.MaxGap)
		}
		p.prevTs = tsNanos
		rel := tsNanos - p.firstTs - p.compress
		due = int64(float64(rel) / p.cfg.Speed)
	case Fixed:
		due = int64(p.n) * int64(p.cfg.Delay)
	case PPS:
		due = int64(float64(p.n) / p.cfg.PPS * 1e9)
	case Mbps:
		due = int64(p.bits / (p.cfg.Mbps * 1e6) * 1e9)
		p.bits += float64(wireBytes) * 8
	}
	p.n++
	deadline := p.start + due
	if late := nanotime() - deadline; late > int64(resyncAfter) {
		p.start += late // forget the backlog
		return
	}
	sleepUntil(deadline)
}

// sleepUntil sleeps coarsely, then spins on the high-resolution clock for the tail.
func sleepUntil(deadline int64) {
	for {
		rem := deadline - nanotime()
		if rem <= 0 {
			return
		}
		if rem > int64(spinThreshold) {
			time.Sleep(time.Duration(rem) - spinThreshold)
			continue
		}
		if rem > int64(50*time.Microsecond) {
			runtime.Gosched() // be polite while there is slack
		}
	}
}
