package gui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sasha/pktreplay/internal/filter"
	"github.com/sasha/pktreplay/internal/history"
	"github.com/sasha/pktreplay/internal/record"
	"github.com/sasha/pktreplay/internal/replay"
	"github.com/sasha/pktreplay/internal/stats"
)

const maxLog = 400

// Job states.
const (
	stateIdle      = "idle"
	stateRunning   = "running"
	stateDone      = "done"
	stateFailed    = "failed"
	stateCancelled = "cancelled"
)

// manager runs at most one background job (analysis or replay) at a time and
// exposes its progress to the HTTP handlers.
type manager struct {
	mu sync.Mutex

	kind     string
	state    string
	cancel   context.CancelFunc
	started  time.Time
	finished time.Time
	errMsg   string
	log      []string

	scan     *stats.Progress
	summary  *stats.Summary
	counters *replay.Counters
	result   string
	tcp      *tcpView
	rec      *record.Writer
	runID    string // history entry of the current/last replay

	hist *history.Store // nil: history disabled
}

func newManager(h *history.Store) *manager { return &manager{state: stateIdle, hist: h} }

type tcpView struct {
	Flow        string  `json:"flow"`
	LocalIP     string  `json:"localIp"`
	LocalPort   uint16  `json:"localPort"`
	HandshakeUs float64 `json:"handshakeUs"`
	Retransmits uint64  `json:"retransmits"`
	RxBytes     uint64  `json:"rxBytes"`
	RxSegments  uint64  `json:"rxSegments"`
	PeerClosed  bool    `json:"peerClosed"`
	FinalState  string  `json:"finalState"`
}

// StatusView is the JSON returned by GET /api/status.
type StatusView struct {
	Kind       string         `json:"kind"`
	State      string         `json:"state"`
	Error      string         `json:"error,omitempty"`
	ElapsedSec float64        `json:"elapsedSec"`
	Log        []string       `json:"log"`
	Scan       *scanView      `json:"scan,omitempty"`
	Summary    *stats.Summary `json:"summary,omitempty"`
	Replay     *replayView    `json:"replay,omitempty"`
	TCP        *tcpView       `json:"tcp,omitempty"`
	Recording  *recView       `json:"recording,omitempty"`
	RunID      string         `json:"runId,omitempty"` // history entry of this replay
}

type recView struct {
	Path    string `json:"path"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type scanView struct {
	Packets uint64  `json:"packets"`
	Bytes   int64   `json:"bytes"`
	Total   int64   `json:"total"`
	Percent float64 `json:"percent"`
}

type replayView struct {
	Read     uint64  `json:"read"`
	Matched  uint64  `json:"matched"`
	Sent     uint64  `json:"sent"`
	Bytes    uint64  `json:"bytes"`
	Skipped  uint64  `json:"skipped"`
	SendErrs uint64  `json:"sendErrs"`
	PPS      float64 `json:"pps"`
	Mbps     float64 `json:"mbps"`
	Result   string  `json:"result,omitempty"`
}

func (m *manager) logf(format string, a ...any) {
	line := time.Now().Format("15:04:05.000 ") + fmt.Sprintf(format, a...)
	m.mu.Lock()
	m.log = append(m.log, line)
	if len(m.log) > maxLog {
		m.log = m.log[len(m.log)-maxLog:]
	}
	m.mu.Unlock()
}

var errBusy = errors.New("another job is still running; stop it first")

// begin claims the manager for a new job.
func (m *manager) begin(kind string) (context.Context, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == stateRunning {
		return nil, errBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	// Reset field by field: overwriting the struct would clobber the held mutex.
	m.kind, m.state, m.cancel, m.started, m.finished = kind, stateRunning, cancel, time.Now(), time.Time{}
	m.errMsg, m.log = "", nil
	m.scan, m.summary, m.counters, m.result, m.tcp, m.rec, m.runID = nil, nil, nil, "", nil, nil, ""
	return ctx, nil
}

func (m *manager) finish(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finished = time.Now()
	switch {
	case err == nil:
		m.state = stateDone
	case errors.Is(err, context.Canceled):
		m.state = stateCancelled
	default:
		m.state, m.errMsg = stateFailed, err.Error()
	}
	if m.cancel != nil {
		m.cancel()
	}
}

// Wait blocks until no job is running or the timeout expires.
func (m *manager) Wait(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		running := m.state == stateRunning
		m.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Stop cancels the running job, if any.
func (m *manager) Stop() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != stateRunning || m.cancel == nil {
		return false
	}
	m.cancel()
	return true
}

// StartStats launches an analysis job.
func (m *manager) StartStats(req RangeRequest, top int) error {
	flt, err := filter.Parse(req.Filter)
	if err != nil {
		return err
	}
	if req.Path == "" {
		return errors.New("choose a capture file first")
	}
	ctx, err := m.begin("stats")
	if err != nil {
		return err
	}
	prog := &stats.Progress{}
	m.mu.Lock()
	m.scan = prog
	m.mu.Unlock()
	m.logf("analysing %s", req.Path)
	go func() {
		st, rd, err := stats.ScanWith(ctx, req.Path, flt, positionFn(req.Start), req.Count, prog, true)
		if err == nil || errors.Is(err, context.Canceled) {
			if st != nil {
				sum := st.Summary(top)
				if rd != nil {
					sum.Format, sum.LinkType = rd.Format().String(), rd.LinkType()
				}
				m.mu.Lock()
				m.summary = &sum
				m.mu.Unlock()
			}
		}
		if rd != nil {
			rd.Close()
		}
		if err == nil {
			m.logf("finished: %d packets read", prog.Packets.Load())
		} else {
			m.logf("stopped: %v", err)
		}
		m.finish(err)
	}()
	return nil
}

// StartReplay launches a replay job.
func (m *manager) StartReplay(req *ReplayRequest) error {
	cfg, tr, err := req.buildConfig()
	if err != nil {
		return err
	}
	ctx, err := m.begin("replay")
	if err != nil {
		if r, ok := cfg.Backend.(*record.Recorder); ok {
			r.Writer().Close() // buildConfig already created the user's recording file
		}
		return err
	}
	cnt := &replay.Counters{}
	cfg.Progress = cnt
	cfg.TCP.Trace = func(f string, a ...any) { m.logf("[tcp] "+f, a...) }
	rec, _ := cfg.Backend.(*record.Recorder) // the recording the user asked for, if any
	backendName := cfg.Backend.Name()
	if rec != nil {
		backendName = rec.Backend.Name()
	}

	// History: the entry is written first, so a crash leaves an "interrupted" record.
	var runID string
	var histW *record.Writer
	if m.hist != nil {
		if st := m.hist.Settings(); st.SaveHistory {
			runID = history.NewID()
			if st.SavePackets {
				if w, werr := record.Create(m.hist.PacketsPath(runID)); werr != nil {
					m.logf("history: cannot keep a copy of the packets: %v", werr)
				} else {
					histW = w
					if rec != nil {
						rec.Also(w)
					} else {
						cfg.Backend = record.Wrap(cfg.Backend, w, true)
					}
				}
			}
			if perr := m.hist.Put(newRunRecord(runID, req, tr, backendName)); perr != nil {
				m.logf("history: cannot save this run: %v", perr)
				runID = ""
				if histW != nil {
					histW.Close()
					os.Remove(histW.Path())
					histW = nil
				}
			}
		}
	}
	m.mu.Lock()
	m.counters, m.runID = cnt, runID
	if rec != nil {
		m.rec = rec.Writer()
	}
	m.mu.Unlock()
	m.logf("starting %s replay of %s via %s backend", tr, req.Path, backendName)
	go func() {
		var res *replay.Result
		var err error
		if tr == replay.TCP {
			res, err = replay.RunTCP(ctx, cfg)
		} else {
			res, err = replay.RunUDP(ctx, cfg)
		}
		if rec != nil {
			rec.Writer().Close() // idempotent: flushed even if the backend never opened
			n, b := rec.Writer().Stats()
			m.logf("recorded %d packets (%d bytes) to %s", n, b, rec.Writer().Path())
		}
		// The engines end cleanly when cancelled; the job context tells us the user stopped it.
		if err == nil && ctx.Err() != nil {
			err = context.Canceled
		}
		var tv *tcpView
		m.mu.Lock()
		if res != nil {
			m.result = res.String()
			if t := res.TCP; t != nil {
				tv = &tcpView{Flow: t.Flow.String(), LocalIP: t.Live.LocalIP.String(), LocalPort: t.Live.LocalPort,
					HandshakeUs: float64(t.HandshakeRTT) / float64(time.Microsecond), Retransmits: t.Retransmits,
					RxBytes: t.RxBytes, RxSegments: t.RxSegments, PeerClosed: t.PeerClosed, FinalState: t.FinalState}
				m.tcp = tv
			}
		}
		m.mu.Unlock()
		if histW != nil {
			histW.Close() // idempotent: flushed even if the backend never opened
		}
		if runID != "" {
			m.finishRun(runID, histW, res, err, tv) // before the job is marked finished, so the UI finds it
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			m.logf("error: %v", err)
		} else if err != nil {
			m.logf("stopped by user")
		} else {
			m.logf("finished")
		}
		m.finish(err)
	}()
	return nil
}

// Status snapshots the current job.
func (m *manager) Status() StatusView {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := StatusView{Kind: m.kind, State: m.state, Error: m.errMsg, Log: append([]string{}, m.log...), Summary: m.summary, TCP: m.tcp, RunID: m.runID}
	if v.State == "" {
		v.State = stateIdle
	}
	if !m.started.IsZero() {
		end := m.finished
		if m.state == stateRunning || end.IsZero() {
			end = time.Now()
		}
		v.ElapsedSec = end.Sub(m.started).Seconds()
	}
	if m.scan != nil {
		sv := &scanView{Packets: m.scan.Packets.Load(), Bytes: m.scan.Bytes.Load(), Total: m.scan.Total}
		if sv.Total > 0 {
			sv.Percent = 100 * float64(sv.Bytes) / float64(sv.Total)
		}
		if m.state == stateDone {
			sv.Percent = 100
		}
		v.Scan = sv
	}
	if m.rec != nil {
		p, b := m.rec.Stats()
		v.Recording = &recView{Path: m.rec.Path(), Packets: p, Bytes: b}
	}
	if c := m.counters; c != nil {
		rv := &replayView{Read: c.Read.Load(), Matched: c.Matched.Load(), Sent: c.Sent.Load(), Bytes: c.Bytes.Load(),
			Skipped: c.Skipped.Load(), SendErrs: c.SendErrs.Load(), Result: m.result}
		if v.ElapsedSec > 0 {
			rv.PPS = float64(rv.Sent) / v.ElapsedSec
			rv.Mbps = float64(rv.Bytes) * 8 / v.ElapsedSec / 1e6
		}
		v.Replay = rv
	}
	return v
}
