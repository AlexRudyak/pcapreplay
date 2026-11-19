package gui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sasha/pktreplay/internal/history"
)

// waitPcapLinked waits for the background library registration of the newest run.
func (c *tc) waitPcapLinked() history.Run {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if l := c.list(""); len(l.Runs) > 0 && l.Runs[0].PcapID != "" {
			return l.Runs[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.t.Fatal("the sent pcap was not added to the library")
	return history.Run{}
}

type libResp struct {
	Enabled bool       `json:"enabled"`
	Pcaps   []libEntry `json:"pcaps"`
	Stats   history.Stats
}

func (c *tc) lib(q string) libResp {
	c.t.Helper()
	_, b := c.do("GET", "/api/library"+q, nil, nil)
	var l libResp
	if err := json.Unmarshal(b, &l); err != nil {
		c.t.Fatalf("library: %v %s", err, b)
	}
	return l
}

func TestSentPcapGoesIntoTheLibraryAndCanBeManaged(t *testing.T) {
	c, dir := newTCHist(t)
	p := makePCAP(t, 20)
	orig, _ := os.ReadFile(p)

	c.sendUDP(p, nil)
	run := c.waitPcapLinked()
	l := c.lib("")
	if !l.Enabled || len(l.Pcaps) != 1 {
		t.Fatalf("library: %+v", l)
	}
	e := l.Pcaps[0]
	if e.ID != run.PcapID || e.CopyState != history.CopyStored || e.Runs != 1 || e.Uses != 1 || !e.CanOpen || !e.FromCopy ||
		e.Name != filepath.Base(p) || e.Size != int64(len(orig)) || !strings.HasPrefix(e.OpenPath, filepath.Join(dir, "pcaps")) {
		t.Fatalf("entry: %+v", e)
	}
	if l.Stats.Pcaps != 1 || l.Stats.PcapBytes != int64(len(orig)) {
		t.Fatalf("stats: %+v", l.Stats)
	}

	// the stored copy is byte-identical to what was sent
	r, body := c.do("GET", "/api/library/"+e.ID+"/download", nil, nil)
	if r.StatusCode != 200 || !bytes.Equal(body, orig) || !strings.Contains(r.Header.Get("Content-Disposition"), filepath.Base(p)) {
		t.Fatalf("download: %d len=%d", r.StatusCode, len(body))
	}

	// sending it again reuses the entry (no second copy) and counts the use
	c.sendUDP(p, nil)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && c.lib("").Pcaps[0].Uses < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if l := c.lib(""); len(l.Pcaps) != 1 || l.Pcaps[0].Uses != 2 || l.Pcaps[0].Runs != 2 {
		t.Fatalf("second send: %+v", l.Pcaps)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "pcaps", "*")); len(files) != 1 {
		t.Fatalf("identical file stored %d times", len(files))
	}

	// "send again" can open the capture even after the original is gone
	_, b := c.do("GET", "/api/history/"+run.ID, nil, nil)
	var det struct {
		OpenPath string      `json:"openPath"`
		Pcap     *libEntry   `json:"pcap"`
		Run      history.Run `json:"run"`
	}
	json.Unmarshal(b, &det)
	if det.OpenPath != p || det.Pcap == nil {
		t.Fatalf("detail while the original exists: %+v", det)
	}
	os.Remove(p)
	_, b = c.do("GET", "/api/history/"+run.ID, nil, nil)
	det.OpenPath = ""
	json.Unmarshal(b, &det)
	if !strings.HasPrefix(det.OpenPath, filepath.Join(dir, "pcaps")) {
		t.Fatalf("with the original gone the library copy must be offered: %q", det.OpenPath)
	}

	// sending the stored copy (what "send again" does once the original is gone) keeps the
	// run labelled with the original capture and counts as a use of the same entry
	c.sendUDP(det.OpenPath, nil)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && c.lib("").Pcaps[0].Uses < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	lat := c.list("").Runs[0]
	if lat.Capture != p || lat.PcapID != e.ID {
		t.Fatalf("run sent from the library copy must be labelled with the original: capture=%q pcap=%q", lat.Capture, lat.PcapID)
	}
	if l := c.lib(""); len(l.Pcaps) != 1 || l.Pcaps[0].Uses != 3 || len(l.Pcaps[0].Sources) != 1 || l.Pcaps[0].Sources[0].Path != p {
		t.Fatalf("the library copy must not become a source of its own entry: %+v", l.Pcaps)
	}

	// notes, pin, search
	if r, b := c.do("POST", "/api/library/"+e.ID+"/update", map[string]any{"note": "golden DNS trace", "pinned": true}, nil); r.StatusCode != 200 {
		t.Fatalf("update: %d %s", r.StatusCode, b)
	}
	if got := c.lib("?q=golden&pinned=1"); len(got.Pcaps) != 1 || !got.Pcaps[0].Pinned {
		t.Fatalf("search: %+v", got.Pcaps)
	}
	if got := c.lib("?q=zzz"); len(got.Pcaps) != 0 {
		t.Fatal("search must be able to match nothing")
	}

	// remove only the stored copy: the entry stays, as a removed copy
	r, b = c.do("POST", "/api/library/"+e.ID+"/remove-copy", struct{}{}, nil)
	var rc struct{ Pcap libEntry }
	json.Unmarshal(b, &rc)
	if r.StatusCode != 200 || rc.Pcap.CopyState != history.CopyRemoved || rc.Pcap.CanOpen {
		t.Fatalf("remove-copy: %d %s", r.StatusCode, b)
	}
	if r, _ := c.do("GET", "/api/library/"+e.ID+"/download", nil, nil); r.StatusCode != 404 {
		t.Fatalf("download without a copy: %d", r.StatusCode)
	}

	// delete the entry: runs stay in the history
	if r, b := c.do("POST", "/api/library/"+e.ID+"/delete", struct{}{}, nil); r.StatusCode != 200 {
		t.Fatalf("delete: %d %s", r.StatusCode, b)
	}
	if len(c.lib("").Pcaps) != 0 || c.list("").Total != 3 {
		t.Fatal("deleting a library entry must not delete the runs that used it")
	}
}

func TestLibraryAddWithoutSendingAndSwitchingCopiesOff(t *testing.T) {
	c, dir := newTCHist(t)
	p := makePCAP(t, 5)
	r, b := c.do("POST", "/api/library/add", map[string]any{"path": p}, nil)
	var added struct{ Pcap libEntry }
	json.Unmarshal(b, &added)
	if r.StatusCode != 200 || added.Pcap.CopyState != history.CopyStored || added.Pcap.Uses != 0 || added.Pcap.Runs != 0 {
		t.Fatalf("add: %d %s", r.StatusCode, b)
	}
	if r, _ := c.do("POST", "/api/library/add", map[string]any{"path": filepath.Join(dir, "missing.pcap")}, nil); r.StatusCode != 400 {
		t.Fatalf("missing file: %d", r.StatusCode)
	}

	// with copies off, a send is listed as a reference to the original only
	c.do("POST", "/api/history/settings", map[string]any{"keepPcaps": false}, nil)
	p2 := makePCAP(t, 6)
	c.sendUDP(p2, nil)
	run := c.waitPcapLinked()
	var ref *libEntry
	for _, e := range c.lib("").Pcaps {
		if e.ID == run.PcapID {
			e := e
			ref = &e
		}
	}
	if ref == nil || ref.CopyState != history.CopyRef || ref.CopyFile != "" || !ref.CanOpen || ref.FromCopy || ref.OpenPath != p2 {
		t.Fatalf("reference entry: %+v", ref)
	}
}

func TestLibraryIDsAreValidatedAndGuarded(t *testing.T) {
	c, _ := newTCHist(t)
	for _, id := range []string{"..%2Fx", "abc", strings.Repeat("g", 64), strings.Repeat("0", 64)} {
		for _, suffix := range []string{"", "/download"} {
			if r, _ := c.do("GET", "/api/library/"+id+suffix, nil, nil); r.StatusCode != 404 && (r.StatusCode < 300 || r.StatusCode > 399) {
				t.Errorf("GET /api/library/%s%s -> %d", id, suffix, r.StatusCode)
			}
		}
	}
	if r, _ := c.do("POST", "/api/library/add", struct{}{}, func(q *http.Request) { q.Header.Set("Origin", "http://evil.example") }); r.StatusCode != 403 {
		t.Fatalf("foreign origin: %d", r.StatusCode)
	}
	d := newTC(t) // history disabled
	if l := d.lib(""); l.Enabled {
		t.Fatal("library must report itself disabled without history")
	}
	if r, _ := d.do("POST", "/api/library/add", map[string]any{"path": "x"}, nil); r.StatusCode != 404 {
		t.Fatalf("add without history: %d", r.StatusCode)
	}
}
