package gui

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sasha/pktreplay/internal/craft"
)

// tc is a test client talking to a real Server on a real loopback listener, so
// Host-header checks are exercised for real.
type tc struct {
	t      *testing.T
	s      *Server
	host   string
	cookie *http.Cookie
}

func newTC(t *testing.T) *tc {
	t.Helper()
	s, err := New("127.0.0.1:0", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	go s.Serve()
	return &tc{t: t, s: s, host: s.listener.Addr().String(), cookie: &http.Cookie{Name: cookieName, Value: s.token}}
}

func (c *tc) do(method, path string, body any, mut func(*http.Request)) (*http.Response, []byte) {
	c.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, "http://"+c.host+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if mut != nil {
		mut(req)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

func (c *tc) waitDone() StatusView {
	c.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, b := c.do("GET", "/api/status", nil, nil)
		var st StatusView
		json.Unmarshal(b, &st)
		if st.State != stateRunning {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.t.Fatal("job did not finish")
	return StatusView{}
}

// makePCAP writes n UDP/53 packets interleaved with n TCP/80 packets.
func makePCAP(t *testing.T, n int) string {
	t.Helper()
	var b bytes.Buffer
	le := binary.LittleEndian
	binary.Write(&b, le, uint32(0xa1b2c3d4))
	binary.Write(&b, le, []uint16{2, 4})
	binary.Write(&b, le, []uint32{0, 0, 65535, 1})
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	for i := 0; i < 2*n; i++ {
		var f []byte
		if i%2 == 0 {
			f = craft.UDP(nil, &craft.Spec{Src: src, Dst: dst, SrcPort: 1000, DstPort: 53, Payload: []byte("query")})
		} else {
			f = craft.TCP(nil, &craft.Spec{Src: src, Dst: dst, SrcPort: 2000, DstPort: 80, Flags: 0x18, Payload: []byte("GET /")})
		}
		binary.Write(&b, le, []uint32{100, uint32(i * 1000), uint32(len(f)), uint32(len(f))})
		b.Write(f)
	}
	p := filepath.Join(t.TempDir(), "t.pcap")
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuthAndHostChecks(t *testing.T) {
	c := newTC(t)
	c.cookie = nil
	if r, _ := c.do("GET", "/api/info", nil, nil); r.StatusCode != 401 {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	c.cookie = &http.Cookie{Name: cookieName, Value: "nope"}
	if r, _ := c.do("GET", "/api/info", nil, nil); r.StatusCode != 401 {
		t.Fatalf("bad token: %d", r.StatusCode)
	}
	c.cookie = nil
	r, _ := c.do("GET", "/?t="+c.s.token, nil, nil)
	if r.StatusCode != 303 || len(r.Cookies()) == 0 || !r.Cookies()[0].HttpOnly {
		t.Fatalf("token exchange failed: %d %v", r.StatusCode, r.Cookies())
	}
	c.cookie = &http.Cookie{Name: cookieName, Value: c.s.token}
	if r, _ := c.do("GET", "/api/info", nil, func(q *http.Request) { q.Host = "evil.example:80" }); r.StatusCode != 403 {
		t.Fatalf("foreign host: %d", r.StatusCode)
	}
	if r, b := c.do("GET", "/api/info", nil, nil); r.StatusCode != 200 || !strings.Contains(string(b), `"version":"test"`) {
		t.Fatalf("info: %d %s", r.StatusCode, b)
	}
	if r, b := c.do("GET", "/", nil, nil); r.StatusCode != 200 || !strings.Contains(string(b), "pktreplay") ||
		!strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("index: %d", r.StatusCode)
	}
}

func TestInfoListsSamplesAndElevateIsGuarded(t *testing.T) {
	c := newTC(t)
	_, b := c.do("GET", "/api/info", nil, nil)
	var info struct {
		Samples []sampleFile `json:"samples"`
	}
	if err := json.Unmarshal(b, &info); err != nil || info.Samples == nil {
		t.Fatalf("info must carry a samples list: %s", b)
	}
	// The restart-as-administrator endpoint triggers a UAC prompt on Windows, so it is
	// only probed through the guards that reject a request before it can act.
	if r, _ := c.do("GET", "/api/elevate", nil, nil); r.StatusCode != 405 {
		t.Fatalf("elevate must require POST: %d", r.StatusCode)
	}
	c.cookie = nil
	if r, _ := c.do("POST", "/api/elevate", struct{}{}, nil); r.StatusCode != 401 {
		t.Fatalf("elevate must require the access token: %d", r.StatusCode)
	}
}

func TestCSRFProtections(t *testing.T) {
	c := newTC(t)
	if r, _ := c.do("POST", "/api/cancel", struct{}{}, func(q *http.Request) { q.Header.Set("Origin", "http://evil.example") }); r.StatusCode != 403 {
		t.Fatalf("foreign origin: %d", r.StatusCode)
	}
	if r, _ := c.do("POST", "/api/cancel", nil, func(q *http.Request) { q.Header.Set("Content-Type", "text/plain") }); r.StatusCode != 415 {
		t.Fatalf("non-json content type: %d", r.StatusCode)
	}
	if r, _ := c.do("POST", "/api/cancel", struct{}{}, func(q *http.Request) { q.Header.Set("Origin", "http://"+c.host) }); r.StatusCode != 200 {
		t.Fatalf("same origin: %d", r.StatusCode)
	}
}

func TestRefusesNonLoopback(t *testing.T) {
	if _, err := New("0.0.0.0:0", "x"); err == nil {
		t.Fatal("must refuse to listen on all interfaces")
	}
	if _, err := New("192.168.1.5:0", "x"); err == nil {
		t.Fatal("must refuse a LAN address")
	}
}

func TestBrowseFiltersCaptures(t *testing.T) {
	c := newTC(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.pcap"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, ".hidden.pcap"), []byte("x"), 0o644)
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	_, b := c.do("GET", "/api/fs?path="+dir, nil, nil)
	var got struct {
		Entries []fsEntry `json:"entries"`
	}
	json.Unmarshal(b, &got)
	if len(got.Entries) != 2 || !got.Entries[0].Dir || got.Entries[1].Name != "a.pcap" {
		t.Fatalf("unexpected listing: %s", b)
	}
}

func TestFilterCheck(t *testing.T) {
	c := newTC(t)
	_, b := c.do("POST", "/api/filter/check", map[string]string{"filter": "dst_port == 80"}, nil)
	if !strings.Contains(string(b), `"ok":true`) {
		t.Fatal(string(b))
	}
	_, b = c.do("POST", "/api/filter/check", map[string]string{"filter": "bogus =="}, nil)
	if !strings.Contains(string(b), `"ok":false`) {
		t.Fatal(string(b))
	}
}

func TestStatsJob(t *testing.T) {
	c := newTC(t)
	p := makePCAP(t, 50)
	if r, b := c.do("POST", "/api/stats", map[string]any{"path": p, "filter": "proto == udp"}, nil); r.StatusCode != 202 {
		t.Fatalf("start: %d %s", r.StatusCode, b)
	}
	st := c.waitDone()
	if st.State != stateDone || st.Summary == nil || st.Summary.Packets != 50 || st.Summary.Format != "pcap" {
		t.Fatalf("bad result: %+v summary=%+v", st, st.Summary)
	}
	if len(st.Summary.UDPPorts) != 1 || st.Summary.UDPPorts[0].Port != 53 {
		t.Fatalf("ports: %+v", st.Summary.UDPPorts)
	}
	if r, b := c.do("POST", "/api/stats", map[string]any{"path": p, "filter": "nonsense =="}, nil); r.StatusCode != 400 {
		t.Fatalf("bad filter: %d %s", r.StatusCode, b)
	}
	c.do("POST", "/api/stats", map[string]any{"path": filepath.Join(t.TempDir(), "missing.pcap")}, nil)
	if st := c.waitDone(); st.State != stateFailed || st.Error == "" {
		t.Fatalf("missing file: %+v", st)
	}
}

func TestReplayValidationAndNullRun(t *testing.T) {
	c := newTC(t)
	p := makePCAP(t, 40)
	r, b := c.do("POST", "/api/replay", map[string]any{"path": p, "backend": "null"}, nil)
	if r.StatusCode != 400 || !strings.Contains(string(b), "transmission mode") {
		t.Fatalf("missing mode: %d %s", r.StatusCode, b)
	}
	for _, bad := range []map[string]any{
		{"path": p, "mode": "udp", "backend": "null", "dstIp": "999.1.1.1"},
		{"path": p, "mode": "udp", "backend": "null", "delay": "fast", "paceMode": "fixed"},
		{"path": p, "mode": "udp", "backend": "null", "seqOffset": 5},
		{"path": p, "mode": "udp", "backend": "null", "dstPort": 70000},
		{"path": p, "mode": "udp", "backend": "nope"},
	} {
		if r, b := c.do("POST", "/api/replay", bad, nil); r.StatusCode != 400 {
			t.Fatalf("%v accepted: %d %s", bad, r.StatusCode, b)
		}
	}
	r, b = c.do("POST", "/api/replay", map[string]any{"path": p, "mode": "udp", "backend": "null", "paceMode": "burst",
		"filter": "proto == udp", "dstIp": "10.9.9.9", "loop": 2}, nil)
	if r.StatusCode != 202 {
		t.Fatalf("start: %d %s", r.StatusCode, b)
	}
	st := c.waitDone()
	if st.State != stateDone || st.Replay == nil || st.Replay.Sent != 80 {
		t.Fatalf("replay result: %+v %+v", st, st.Replay)
	}
}

func TestReplayRecordsTraffic(t *testing.T) {
	c := newTC(t)
	p := makePCAP(t, 40)
	out := filepath.Join(t.TempDir(), "sent.pcapng")
	// a bad record path is rejected before anything starts
	if r, b := c.do("POST", "/api/replay", map[string]any{"path": p, "mode": "udp", "backend": "null",
		"record": filepath.Join(t.TempDir(), "no", "dir", "x.pcap")}, nil); r.StatusCode != 400 {
		t.Fatalf("bad record path: %d %s", r.StatusCode, b)
	}
	if r, b := c.do("POST", "/api/replay", map[string]any{"path": p, "mode": "udp", "backend": "null", "paceMode": "burst",
		"filter": "proto == udp", "dstIp": "10.9.9.9", "record": out}, nil); r.StatusCode != 202 {
		t.Fatalf("start: %d %s", r.StatusCode, b)
	}
	st := c.waitDone()
	if st.State != stateDone || st.Recording == nil || st.Recording.Packets != 40 || st.Recording.Path != out {
		t.Fatalf("status: %+v rec=%+v", st, st.Recording)
	}
	// the file is complete, readable, and contains the *rewritten* datagrams
	cs := newTC(t)
	cs.do("POST", "/api/stats", map[string]any{"path": out}, nil)
	sum := cs.waitDone().Summary
	if sum == nil || sum.Packets != 40 || sum.Format != "pcapng" || len(sum.Protocols) != 1 ||
		sum.Protocols[0].Name != "UDP" || sum.Protocols[0].Packets != 40 {
		t.Fatalf("recording summary: %+v", sum)
	}
}

func TestAnalysisListsConversations(t *testing.T) {
	c := newTC(t)
	p := makePCAP(t, 30)
	c.do("POST", "/api/stats", map[string]any{"path": p}, nil)
	sum := c.waitDone().Summary
	if sum == nil || sum.ConversationsTotal != 2 || len(sum.Conversations) != 2 {
		t.Fatalf("conversations: %+v", sum)
	}
	sel := map[string]uint64{}
	for _, cv := range sum.Conversations {
		sel[cv.Selector] = cv.Packets
	}
	if sel["udp/10.0.0.1:1000/10.0.0.2:53"] != 30 || sel["tcp/10.0.0.1:2000/10.0.0.2:80"] != 30 {
		t.Fatalf("selectors: %v", sel)
	}
}

func TestReplayConversationRuleChangesOnlyThatConversation(t *testing.T) {
	c := newTC(t)
	p := makePCAP(t, 20) // 20 UDP/53 + 20 TCP/80 packets, one conversation each
	out := filepath.Join(t.TempDir(), "sent.pcap")
	r, b := c.do("POST", "/api/replay", map[string]any{"path": p, "mode": "udp", "backend": "null", "paceMode": "burst",
		"record": out, "conversations": []map[string]any{{"selector": "udp/10.0.0.1:1000/10.0.0.2:53", "serverIp": "10.9.9.9"}}}, nil)
	if r.StatusCode != 202 {
		t.Fatalf("start: %d %s", r.StatusCode, b)
	}
	if st := c.waitDone(); st.State != stateDone {
		t.Fatalf("state %s %s", st.State, st.Error)
	}
	// UDP mode replays UDP only; the rule moved that one conversation to 10.9.9.9
	cs := newTC(t)
	cs.do("POST", "/api/stats", map[string]any{"path": out}, nil)
	sum := cs.waitDone().Summary
	if sum == nil || len(sum.Conversations) != 1 || sum.Conversations[0].Selector != "udp/10.0.0.1:1000/10.9.9.9:53" ||
		sum.Conversations[0].Packets != 20 {
		t.Fatalf("recorded conversations: %+v", sum)
	}
}

func TestConversationRequestValidation(t *testing.T) {
	c := newTC(t)
	p := makePCAP(t, 5)
	base := func(extra map[string]any) map[string]any {
		m := map[string]any{"path": p, "mode": "udp", "backend": "null"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	rule := func(sel string) map[string]any { return map[string]any{"selector": sel, "serverIp": "10.1.1.1"} }
	for name, body := range map[string]map[string]any{
		"bad selector":      base(map[string]any{"conversations": []any{rule("nonsense")}}),
		"bad new IP":        base(map[string]any{"conversations": []any{map[string]any{"selector": "udp/10.0.0.1:1000/10.0.0.2:53", "serverIp": "x.y"}}}),
		"family mismatch":   base(map[string]any{"conversations": []any{map[string]any{"selector": "udp/10.0.0.1:1000/10.0.0.2:53", "serverIp": "fd00::1"}}}),
		"duplicate":         base(map[string]any{"conversations": []any{rule("udp/10.0.0.1:1000/10.0.0.2:53"), rule("udp/10.0.0.2:53/10.0.0.1:1000")}}),
		"only without list": base(map[string]any{"onlyConversations": true}),
		"tcp with two": base(map[string]any{"mode": "tcp", "conversations": []any{rule("tcp/10.0.0.1:2000/10.0.0.2:80"),
			rule("tcp/10.0.0.1:2001/10.0.0.2:80")}}),
	} {
		if r, b := c.do("POST", "/api/replay", body, nil); r.StatusCode != 400 {
			t.Errorf("%s accepted: %d %s", name, r.StatusCode, b)
		}
	}
}

func TestCancelAndBusy(t *testing.T) {
	c := newTC(t)
	p := makePCAP(t, 400)
	body := map[string]any{"path": p, "mode": "udp", "backend": "null", "paceMode": "fixed", "delay": "20ms"}
	if r, b := c.do("POST", "/api/replay", body, nil); r.StatusCode != 202 {
		t.Fatalf("start: %d %s", r.StatusCode, b)
	}
	if r, _ := c.do("POST", "/api/replay", body, nil); r.StatusCode != 409 {
		t.Fatalf("second job must be rejected while busy: %d", r.StatusCode)
	}
	time.Sleep(80 * time.Millisecond)
	c.do("POST", "/api/cancel", struct{}{}, nil)
	st := c.waitDone()
	if st.State != stateCancelled && st.State != stateDone {
		t.Fatalf("state after cancel: %s (%s)", st.State, st.Error)
	}
	if st.Replay == nil || st.Replay.Sent == 0 || st.Replay.Sent >= 400 {
		t.Fatalf("cancel did not stop mid-run: %+v", st.Replay)
	}
}
