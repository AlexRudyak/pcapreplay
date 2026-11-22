package gui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlexRudyak/pcapreplay/internal/history"
	"github.com/AlexRudyak/pcapreplay/internal/record"
	"github.com/AlexRudyak/pcapreplay/internal/replay"
)

// describePacing renders the chosen speed in words for the run record.
func describePacing(r *ReplayRequest) string {
	switch r.PaceMode {
	case "burst":
		return "as fast as possible"
	case "fixed":
		return "one packet every " + r.Delay
	case "pps":
		return fmt.Sprintf("%g packets/s", r.PPS)
	case "mbps":
		return fmt.Sprintf("%g Mbit/s", r.Mbps)
	}
	if r.Speed == 0 || r.Speed == 1 {
		return "recorded speed"
	}
	return fmt.Sprintf("%g× recorded speed", r.Speed)
}

// joinEndpoint formats ip and port as "ip:port", bracketing IPv6 addresses and omitting a zero port.
func joinEndpoint(ip string, port uint) string {
	ip = strings.TrimSpace(ip)
	switch {
	case ip != "" && port != 0:
		if strings.Contains(ip, ":") {
			return fmt.Sprintf("[%s]:%d", ip, port)
		}
		return fmt.Sprintf("%s:%d", ip, port)
	case ip != "":
		return ip
	case port != 0:
		return fmt.Sprintf(":%d", port)
	}
	return ""
}

// convEntries converts the selected conversations (and their edits) of a request into the
// entries stored with the run.
func convEntries(r *ReplayRequest) []history.ConvEntry {
	out := make([]history.ConvEntry, 0, len(r.Conversations))
	for _, c := range r.Conversations {
		e := history.ConvEntry{Selector: c.Selector, NewClient: joinEndpoint(c.ClientIP, c.ClientPort), NewServer: joinEndpoint(c.ServerIP, c.ServerPort)}
		for _, s := range c.Replace {
			if strings.TrimSpace(s) != "" {
				e.Replace++
			}
		}
		e.Changed = e.NewClient != "" || e.NewServer != "" || e.Replace > 0
		out = append(out, e)
	}
	return out
}

// targetOf summarises where the conversations were sent: one address when they
// all share a new destination, "several" otherwise, "" when nothing was retargeted.
func targetOf(entries []history.ConvEntry) string {
	seen := map[string]bool{}
	var one string
	for _, e := range entries {
		if e.NewServer != "" {
			seen[e.NewServer] = true
			one = e.NewServer
		}
	}
	switch len(seen) {
	case 0:
		return ""
	case 1:
		return one
	}
	return "several addresses"
}

// newRunRecord builds the history entry written before a send starts, in state "running".
func newRunRecord(id string, req *ReplayRequest, tr replay.Transport, backendName, capture string) history.Run {
	entries := convEntries(req)
	reqJSON, _ := json.Marshal(req)
	loop := req.Loop
	if loop < 1 {
		loop = 1
	}
	meta := req.Meta
	if len(meta) > 8<<10 {
		meta = nil // opaque UI state is capped; "send again" then restores the request only
	}
	return history.Run{ID: id, StartedAt: time.Now(), State: history.StateRunning, Capture: capture, Mode: tr.String(),
		Backend: backendName, DryRun: req.Backend == "null", Pacing: describePacing(req), Loop: loop,
		Target: targetOf(entries), Conversations: entries, Request: reqJSON, Meta: meta}
}

// finishRun stores the outcome of a run and applies the retention limits.
func (m *manager) finishRun(id string, w *record.Writer, res *replay.Result, runErr error, tcp *tcpView) {
	state, msg := history.StateDone, ""
	switch {
	case runErr == nil:
	case errors.Is(runErr, context.Canceled):
		state = history.StateCancelled
	default:
		state, msg = history.StateFailed, runErr.Error()
	}
	var result *history.Result
	if res != nil {
		c, secs := res.Counters, res.Elapsed.Seconds()
		result = &history.Result{Read: c.Read.Load(), Matched: c.Matched.Load(), Sent: c.Sent.Load(), Bytes: c.Bytes.Load(),
			Skipped: c.Skipped.Load(), SendErrs: c.SendErrs.Load(), ElapsedMs: res.Elapsed.Milliseconds()}
		if secs > 0 {
			result.PPS, result.Mbps = float64(result.Sent)/secs, float64(result.Bytes)*8/secs/1e6
		}
	}
	var file string
	var count uint64
	var size int64
	if w != nil {
		count, _ = w.Stats()
		if count > 0 {
			file = filepath.Base(w.Path())
			if fi, err := os.Stat(w.Path()); err == nil {
				size = fi.Size()
			}
		} else {
			os.Remove(w.Path()) // nothing was sent: no point keeping an empty file
		}
	}
	var tcpJSON json.RawMessage
	if tcp != nil {
		tcpJSON, _ = json.Marshal(tcp)
	}
	if err := m.hist.Update(id, func(r *history.Run) {
		r.State, r.Error, r.FinishedAt, r.Result, r.TCP = state, msg, time.Now(), result, tcpJSON
		r.PacketsFile, r.PacketsCount, r.PacketsBytes = file, count, size
	}); err != nil {
		m.logf("history: could not save the result: %v", err)
	}
	m.hist.Prune()
}
