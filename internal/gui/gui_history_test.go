package gui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AlexRudyak/pktreplay/internal/history"
)

func newTCHist(t *testing.T) (*tc, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewWithOptions("127.0.0.1:0", "test", Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	go s.Serve()
	return &tc{t: t, s: s, host: s.listener.Addr().String(), cookie: &http.Cookie{Name: cookieName, Value: s.token}}, dir
}

type listResp struct {
	Enabled bool          `json:"enabled"`
	Runs    []history.Run `json:"runs"`
	Total   int           `json:"total"`
	Stats   history.Stats `json:"stats"`
}

func (c *tc) list(q string) listResp {
	c.t.Helper()
	_, b := c.do("GET", "/api/history"+q, nil, nil)
	var l listResp
	if err := json.Unmarshal(b, &l); err != nil {
		c.t.Fatalf("list: %v %s", err, b)
	}
	return l
}

func (c *tc) sendUDP(p string, extra map[string]any) StatusView {
	c.t.Helper()
	body := map[string]any{"path": p, "mode": "udp", "backend": "null", "paceMode": "burst", "onlyConversations": true,
		"conversations": []map[string]any{{"selector": "udp/10.0.0.1:1000/10.0.0.2:53", "serverIp": "10.9.9.9"}},
		"meta":          map[string]any{"speed": "burst"}}
	for k, v := range extra {
		body[k] = v
	}
	if r, b := c.do("POST", "/api/replay", body, nil); r.StatusCode != 202 {
		c.t.Fatalf("replay: %d %s", r.StatusCode, b)
	}
	return c.waitDone()
}

func TestHistoryRecordsRunWithPacketsAndPreview(t *testing.T) {
	c, dir := newTCHist(t)
	// copies of the transmitted packets are an opt-in extra
	if r, b := c.do("POST", "/api/history/settings", map[string]any{"savePackets": true}, nil); r.StatusCode != 200 {
		t.Fatalf("settings: %d %s", r.StatusCode, b)
	}
	p := makePCAP(t, 20)
	st := c.sendUDP(p, nil)
	if st.State != stateDone || st.RunID == "" {
		t.Fatalf("status: %+v", st)
	}
	l := c.list("")
	if !l.Enabled || l.Total != 1 || len(l.Runs) != 1 {
		t.Fatalf("list: %+v", l)
	}
	run := l.Runs[0]
	if run.ID != st.RunID || run.State != history.StateDone || run.Mode != "udp" || !run.DryRun || run.Target != "10.9.9.9" ||
		run.Capture != p || run.Result == nil || run.Result.Sent != 20 || run.PacketsCount != 20 || run.PacketsFile == "" || run.PacketsBytes == 0 {
		t.Fatalf("run not recorded properly: %+v result=%+v", run, run.Result)
	}
	if len(run.Conversations) != 1 || !run.Conversations[0].Changed || run.Conversations[0].NewServer != "10.9.9.9" || run.Request != nil {
		t.Fatalf("conversations/brief view: %+v", run.Conversations)
	}
	if st := l.Stats; st.Runs != 1 || st.PacketsBytes == 0 || st.Dir != dir {
		t.Fatalf("stats: %+v", st)
	}

	// full record keeps the exact request and UI state for "send again"
	_, b := c.do("GET", "/api/history/"+run.ID, nil, nil)
	var full struct {
		Run        history.Run `json:"run"`
		HasPackets bool        `json:"hasPackets"`
	}
	json.Unmarshal(b, &full)
	if !full.HasPackets || !strings.Contains(string(full.Run.Request), "udp/10.0.0.1:1000/10.0.0.2:53") || !strings.Contains(string(full.Run.Meta), "burst") {
		t.Fatalf("full run: %s", b)
	}

	// the packets that were really sent
	_, b = c.do("GET", "/api/history/"+run.ID+"/preview?limit=5", nil, nil)
	var pv struct {
		Rows  []history.PacketRow `json:"rows"`
		Total int                 `json:"total"`
	}
	json.Unmarshal(b, &pv)
	if pv.Total != 20 || len(pv.Rows) != 5 || pv.Rows[0].Dir != "out" || pv.Rows[0].Proto != "UDP" || pv.Rows[0].Dst != "10.9.9.9:53" {
		t.Fatalf("preview: %s", b)
	}
	r, body := c.do("GET", "/api/history/"+run.ID+"/packets", nil, nil)
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") || len(body) < 100 || body[0] != 0x0a || body[1] != 0x0d {
		t.Fatalf("download: %d %q len=%d", r.StatusCode, r.Header.Get("Content-Disposition"), len(body))
	}

	// notes, pinning and search
	if r, b := c.do("POST", "/api/history/"+run.ID+"/update", map[string]any{"note": "demo for the QA team", "pinned": true}, nil); r.StatusCode != 200 {
		t.Fatalf("update: %d %s", r.StatusCode, b)
	}
	if l := c.list("?q=qa+team&pinned=1"); l.Total != 1 || !l.Runs[0].Pinned {
		t.Fatalf("search by note: %+v", l)
	}
	if l := c.list("?q=nonexistent"); l.Total != 0 {
		t.Fatal("search matched nothing and must say so")
	}

	// export
	r, body = c.do("GET", "/api/history/export?format=csv", nil, nil)
	if r.StatusCode != 200 || !strings.Contains(string(body), run.ID) || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv export: %d %s", r.StatusCode, body)
	}
	r, body = c.do("GET", "/api/history/export?format=json", nil, nil)
	if r.StatusCode != 200 || !strings.Contains(string(body), `"dryRun": true`) {
		t.Fatalf("json export: %d %s", r.StatusCode, body)
	}

	// delete removes the run and its packet file
	pf := filepath.Join(dir, "packets", run.PacketsFile)
	if _, err := os.Stat(pf); err != nil {
		t.Fatalf("packet copy missing on disk: %v", err)
	}
	if r, b := c.do("POST", "/api/history/"+run.ID+"/delete", struct{}{}, nil); r.StatusCode != 200 {
		t.Fatalf("delete: %d %s", r.StatusCode, b)
	}
	if _, err := os.Stat(pf); !os.IsNotExist(err) {
		t.Fatal("packet copy must be deleted with the run")
	}
	if r, _ := c.do("GET", "/api/history/"+run.ID, nil, nil); r.StatusCode != 404 {
		t.Fatalf("deleted run still readable: %d", r.StatusCode)
	}
}

func TestHistoryRecordsFailedAndCancelledRuns(t *testing.T) {
	c, _ := newTCHist(t)
	p := makePCAP(t, 400)
	// TCP over the null backend cannot receive: the run fails and must be on record with the reason
	st := c.sendUDP(p, map[string]any{"mode": "tcp", "conversations": []map[string]any{{"selector": "tcp/10.0.0.1:2000/10.0.0.2:80"}}})
	if st.State != stateFailed {
		t.Fatalf("expected failure: %+v", st)
	}
	l := c.list("?state=failed")
	if l.Total != 1 || !strings.Contains(l.Runs[0].Error, "null backend cannot receive") || l.Runs[0].Mode != "tcp" {
		t.Fatalf("failed run: %+v", l.Runs)
	}

	// a cancelled run is recorded with what was sent before it stopped
	c.do("POST", "/api/replay", map[string]any{"path": p, "mode": "udp", "backend": "null", "paceMode": "fixed", "delay": "20ms", "onlyConversations": true,
		"conversations": []map[string]any{{"selector": "udp/10.0.0.1:1000/10.0.0.2:53"}}}, nil)
	time.Sleep(120 * time.Millisecond)
	c.do("POST", "/api/cancel", struct{}{}, nil)
	c.waitDone()
	l = c.list("?state=cancelled")
	if l.Total != 1 || l.Runs[0].Result == nil || l.Runs[0].Result.Sent == 0 || l.Runs[0].Result.Sent >= 400 {
		t.Fatalf("cancelled run: %+v", l.Runs)
	}
	// ordering: newest first
	if all := c.list(""); all.Total != 2 || all.Runs[0].State != history.StateCancelled {
		t.Fatalf("newest first: %+v", all)
	}
}

func TestHistorySettingsAndRetention(t *testing.T) {
	c, _ := newTCHist(t)
	p := makePCAP(t, 10)

	// keep the history but not the packets
	if r, b := c.do("POST", "/api/history/settings", map[string]any{"saveHistory": true, "savePackets": false, "maxRuns": 1000, "maxPacketsMB": 100, "maxAgeDays": 0}, nil); r.StatusCode != 200 {
		t.Fatalf("settings: %d %s", r.StatusCode, b)
	}
	c.sendUDP(p, nil)
	l := c.list("")
	if l.Total != 1 || l.Runs[0].PacketsFile != "" || l.Runs[0].PacketsCount != 0 {
		t.Fatalf("savePackets=false must keep the run but no packets: %+v", l.Runs)
	}
	if r, _ := c.do("GET", "/api/history/"+l.Runs[0].ID+"/preview", nil, nil); r.StatusCode != 404 {
		t.Fatalf("preview without a copy: %d", r.StatusCode)
	}

	// no history at all
	c.do("POST", "/api/history/settings", map[string]any{"saveHistory": false, "savePackets": true, "maxRuns": 1000, "maxPacketsMB": 100}, nil)
	c.sendUDP(p, nil)
	if l := c.list(""); l.Total != 1 {
		t.Fatalf("saveHistory=false must not record: %d runs", l.Total)
	}

	// invalid limits are refused; a retention limit prunes immediately
	if r, _ := c.do("POST", "/api/history/settings", map[string]any{"saveHistory": true, "maxRuns": -5}, nil); r.StatusCode != 400 {
		t.Fatalf("negative limit: %d", r.StatusCode)
	}
	c.do("POST", "/api/history/settings", map[string]any{"saveHistory": true, "savePackets": false, "maxRuns": 1000, "maxPacketsMB": 100}, nil)
	c.sendUDP(p, nil)
	c.sendUDP(p, nil)
	_, b := c.do("POST", "/api/history/settings", map[string]any{"saveHistory": true, "savePackets": false, "maxRuns": 2, "maxPacketsMB": 100}, nil)
	var res struct {
		RemovedRuns int `json:"removedRuns"`
	}
	json.Unmarshal(b, &res)
	if res.RemovedRuns != 1 || c.list("").Total != 2 {
		t.Fatalf("limit not applied: removed=%d total=%d", res.RemovedRuns, c.list("").Total)
	}

	// clear (keeping pinned)
	id := c.list("").Runs[0].ID
	c.do("POST", "/api/history/"+id+"/update", map[string]any{"pinned": true}, nil)
	_, b = c.do("POST", "/api/history/clear", map[string]any{"keepPinned": true}, nil)
	if l := c.list(""); l.Total != 1 || l.Runs[0].ID != id {
		t.Fatalf("clear keepPinned: %s -> %+v", b, l)
	}
}

func TestHistoryDisabledAndPathSafety(t *testing.T) {
	c := newTC(t) // no data dir
	if l := c.list(""); l.Enabled || l.Total != 0 {
		t.Fatalf("history must report itself disabled: %+v", l)
	}
	if r, _ := c.do("GET", "/api/history/settings", nil, nil); r.StatusCode != 404 {
		t.Fatalf("settings without history: %d", r.StatusCode)
	}
	c2, _ := newTCHist(t)
	for _, id := range []string{"..%2F..%2Fsecret", "ZZZZZZZZZZZZZZZZZZZZ", "0123456789abcdef0123", "../x"} {
		for _, suffix := range []string{"", "/packets", "/preview"} {
			// Go's router normalises ".." and redirects (3xx) to a different, harmless path.
			if r, _ := c2.do("GET", "/api/history/"+id+suffix, nil, nil); r.StatusCode != 404 && (r.StatusCode < 300 || r.StatusCode > 399) {
				t.Errorf("GET /api/history/%s%s -> %d, want 404 or a redirect", id, suffix, r.StatusCode)
			}
		}
	}
	// state-changing history calls still go through the CSRF guard
	if r, _ := c2.do("POST", "/api/history/clear", struct{}{}, func(q *http.Request) { q.Header.Set("Origin", "http://evil.example") }); r.StatusCode != 403 {
		t.Fatalf("foreign origin on clear: %d", r.StatusCode)
	}
	if r, _ := c2.do("POST", "/api/history/clear", nil, func(q *http.Request) { q.Header.Set("Content-Type", "text/plain") }); r.StatusCode != 415 {
		t.Fatalf("non-json clear: %d", r.StatusCode)
	}
}
