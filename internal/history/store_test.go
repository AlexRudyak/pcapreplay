package history

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AlexRudyak/pcapreplay/internal/craft"
	"github.com/AlexRudyak/pcapreplay/internal/record"
)

func mkRun(t *testing.T, s *Store, age time.Duration, mut func(*Run)) Run {
	t.Helper()
	r := Run{ID: NewID(), StartedAt: time.Now().Add(-age), State: StateDone, Capture: `C:\caps\trace.pcap`, Mode: "udp",
		Conversations: []ConvEntry{{Selector: "udp/10.0.0.1:1000/10.0.0.2:53"}}, Result: &Result{Sent: 3, Bytes: 300}}
	if mut != nil {
		mut(&r)
	}
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func open(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	a := mkRun(t, s, time.Hour, nil)
	b := mkRun(t, s, time.Minute, func(r *Run) { r.Mode = "tcp"; r.Note = "first try" })
	if err := s.Update(a.ID, func(r *Run) { r.Pinned = true; r.Note = "keep me" }); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(b.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s = open(t, dir)
	defer s.Close()
	if _, ok := s.Get(b.ID); ok {
		t.Fatal("deleted run came back")
	}
	got, ok := s.Get(a.ID)
	if !ok || !got.Pinned || got.Note != "keep me" || got.Result == nil || got.Result.Sent != 3 {
		t.Fatalf("run not persisted correctly: %+v", got)
	}
}

func TestCrashTolerance(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	good := mkRun(t, s, time.Hour, nil)
	run := mkRun(t, s, time.Minute, func(r *Run) { r.State = StateRunning })
	s.Close()
	// simulate a crash that tore the last line in half
	f, _ := os.OpenFile(filepath.Join(dir, "history.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"op":"put","run":{"id":"abcdef01234567890123","state":"do`)
	f.Close()

	s = open(t, dir)
	defer s.Close()
	if _, ok := s.Get(good.ID); !ok {
		t.Fatal("intact run lost")
	}
	if r, _ := s.Get(run.ID); r.State != StateInterrupted || r.FinishedAt.IsZero() {
		t.Fatalf("a run that was running at crash time must be marked interrupted: %+v", r)
	}
	if st := s.Stats(); st.Runs != 2 {
		t.Fatalf("runs=%d", st.Runs)
	}
	// the log was rewritten cleanly: reopening again must not see corruption
	b, _ := os.ReadFile(filepath.Join(dir, "history.jsonl"))
	if bytes.Contains(b, []byte(`"state":"do`+"\n")) || bytes.Contains(b, []byte("abcdef01234567890123")) {
		t.Fatal("torn line survived compaction")
	}
}

func TestListFilterSortPaging(t *testing.T) {
	s := open(t, t.TempDir())
	defer s.Close()
	mkRun(t, s, 3*time.Hour, func(r *Run) {
		r.Capture = "alpha.pcap"
		r.Mode = "tcp"
		r.State = StateFailed
		r.Error = "connection refused"
	})
	mkRun(t, s, 2*time.Hour, func(r *Run) { r.Capture = "beta.pcap"; r.Target = "10.9.9.9:80" })
	mkRun(t, s, time.Hour, func(r *Run) { r.Capture = "gamma.pcap"; r.Pinned = true; r.Note = "demo for Anna" })

	all, total := s.List(Query{})
	if total != 3 || all[0].Capture != "gamma.pcap" || all[2].Capture != "alpha.pcap" {
		t.Fatalf("expected newest first: %v", []string{all[0].Capture, all[1].Capture, all[2].Capture})
	}
	for q, want := range map[string]string{"refused": "alpha.pcap", "10.9.9.9": "beta.pcap", "anna demo": "gamma.pcap", "TCP failed": "alpha.pcap"} {
		got, n := s.List(Query{Text: q})
		if n != 1 || got[0].Capture != want {
			t.Errorf("search %q -> %d results, first %v, want %s", q, n, got, want)
		}
	}
	if _, n := s.List(Query{State: StateFailed}); n != 1 {
		t.Fatal("state filter")
	}
	if _, n := s.List(Query{Pinned: true}); n != 1 {
		t.Fatal("pinned filter")
	}
	page, total := s.List(Query{Offset: 1, Limit: 1})
	if total != 3 || len(page) != 1 || page[0].Capture != "beta.pcap" {
		t.Fatalf("paging: %+v total=%d", page, total)
	}
}

func TestRetentionLimits(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	defer s.Close()
	for i := 0; i < 6; i++ {
		i := i
		mkRun(t, s, time.Duration(10-i)*time.Hour, func(r *Run) { r.Pinned = i == 0; r.Capture = string(rune('a' + i)) })
	}
	st := DefaultSettings()
	st.MaxRuns = 3
	if err := s.SetSettings(st); err != nil {
		t.Fatal(err)
	}
	removed, _ := s.Prune()
	runs, _ := s.List(Query{})
	if removed != 3 || len(runs) != 3 {
		t.Fatalf("removed %d, %d left", removed, len(runs))
	}
	var pinnedLeft bool
	for _, r := range runs {
		pinnedLeft = pinnedLeft || r.Pinned
	}
	if !pinnedLeft {
		t.Fatal("the pinned (oldest) run must survive pruning")
	}

	// age limit
	st = DefaultSettings()
	st.MaxAgeDays = 1
	s.SetSettings(st)
	mkRun(t, s, 72*time.Hour, func(r *Run) { r.Capture = "ancient" })
	s.Prune()
	if _, n := s.List(Query{Text: "ancient"}); n != 0 {
		t.Fatal("run older than the age limit survived")
	}

	// packet-size limit removes the oldest copies but keeps the history entry
	st = DefaultSettings()
	st.MaxPacketsMB = 1
	s.SetSettings(st)
	for i := 0; i < 3; i++ {
		i := i
		r := mkRun(t, s, time.Duration(3-i)*time.Minute, func(r *Run) { r.Capture = "sized" })
		p := s.PacketsPath(r.ID)
		os.WriteFile(p, make([]byte, 600<<10), 0o600)
		s.Update(r.ID, func(x *Run) { x.PacketsFile, x.PacketsBytes = filepath.Base(p), 600<<10 })
	}
	_, pruned := s.Prune()
	runsSized, _ := s.List(Query{Text: "sized"})
	if pruned != 2 || len(runsSized) != 3 {
		t.Fatalf("pruned %d copies, %d runs kept", pruned, len(runsSized))
	}
	withCopy := 0
	for _, r := range runsSized {
		if r.PacketsFile != "" {
			withCopy++
			if r.PacketsPruned {
				t.Fatal("kept copy flagged as pruned")
			}
		} else if !r.PacketsPruned {
			t.Fatal("removed copy must be flagged so the UI can explain it")
		}
	}
	if withCopy != 1 {
		t.Fatalf("expected the newest copy to remain, have %d", withCopy)
	}
}

func TestDeleteRemovesPacketFileAndClear(t *testing.T) {
	s := open(t, t.TempDir())
	defer s.Close()
	r := mkRun(t, s, time.Minute, nil)
	p := s.PacketsPath(r.ID)
	os.WriteFile(p, []byte("x"), 0o600)
	s.Update(r.ID, func(x *Run) { x.PacketsFile = filepath.Base(p) })
	if _, ok := s.PacketsFile(r.ID); !ok {
		t.Fatal("packet copy not found")
	}
	if err := s.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("packet file must be deleted with its run")
	}
	keep := mkRun(t, s, time.Hour, func(r *Run) { r.Pinned = true })
	mkRun(t, s, time.Minute, nil)
	n, err := s.Clear(true)
	if err != nil || n != 1 {
		t.Fatalf("clear removed %d (%v)", n, err)
	}
	if _, ok := s.Get(keep.ID); !ok {
		t.Fatal("pinned run must survive Clear(keepPinned)")
	}
}

func TestIDValidationAndSettings(t *testing.T) {
	for _, bad := range []string{"", "../../etc/passwd", "ABCDEF01234567890123", "abc", strings.Repeat("a", 21)} {
		if ValidID(bad) {
			t.Errorf("%q accepted as an id", bad)
		}
	}
	if !ValidID(NewID()) {
		t.Fatal("NewID must produce a valid id")
	}
	s := open(t, t.TempDir())
	defer s.Close()
	if s.PacketsPath("../x") != "" {
		t.Fatal("path traversal id must not map to a file")
	}
	if err := s.SetSettings(Settings{MaxRuns: -1}); err == nil {
		t.Fatal("negative limit accepted")
	}
	st := DefaultSettings()
	st.SavePackets = true // off by default: flipping it must survive a restart
	if err := s.SetSettings(st); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2 := open(t, s.dir)
	defer s2.Close()
	if !s2.Settings().SavePackets {
		t.Fatal("settings not persisted")
	}
}

func TestExportCSVNeutralisesFormulas(t *testing.T) {
	s := open(t, t.TempDir())
	defer s.Close()
	mkRun(t, s, time.Minute, func(r *Run) { r.Note = `=HYPERLINK("http://evil","x")`; r.Capture = "a,b.pcap" })
	var buf bytes.Buffer
	if err := s.ExportCSV(&buf, Query{}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("csv: %v rows=%d", err, len(rows))
	}
	hdr, row := rows[0], rows[1]
	col := func(name string) string {
		for i, h := range hdr {
			if h == name {
				return row[i]
			}
		}
		return "<missing>"
	}
	if col("note")[0] != '\'' || col("capture") != "a,b.pcap" {
		t.Fatalf("note=%q capture=%q", col("note"), col("capture"))
	}
	var js bytes.Buffer
	s.ExportJSON(&js, Query{})
	var back []Run
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || len(back) != 1 {
		t.Fatalf("json export: %v", err)
	}
}

func TestPreviewDescribesPackets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "run.pcapng")
	w, _ := record.Create(p)
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	t0 := time.Now()
	w.Write(t0, craft.TCP(nil, &craft.Spec{NoEth: true, Src: src, Dst: dst, SrcPort: 5000, DstPort: 80, Flags: 0x02, Seq: 100}), true)
	w.Write(t0.Add(2*time.Millisecond), craft.TCP(nil, &craft.Spec{NoEth: true, Src: dst, Dst: src, SrcPort: 80, DstPort: 5000, Flags: 0x12, Seq: 900, Ack: 101}), false)
	w.Write(t0.Add(5*time.Millisecond), craft.UDP(nil, &craft.Spec{NoEth: true, Src: src, Dst: dst, SrcPort: 1000, DstPort: 53, Payload: []byte("hi\x00there")}), true)
	w.Close()

	rows, total, err := Preview(p, 0, 10)
	if err != nil || total != 3 || len(rows) != 3 {
		t.Fatalf("rows=%d total=%d err=%v", len(rows), total, err)
	}
	if rows[0].Dir != "out" || rows[0].Proto != "TCP" || !strings.Contains(rows[0].Info, "SYN") || rows[0].Src != "10.0.0.1:5000" {
		t.Fatalf("row0: %+v", rows[0])
	}
	if rows[1].Dir != "in" || !strings.Contains(rows[1].Info, "SYN ACK") {
		t.Fatalf("row1: %+v", rows[1])
	}
	if rows[2].Proto != "UDP" || !strings.Contains(rows[2].Info, "hi.there") || rows[2].RelMs < 4.5 || rows[2].RelMs > 5.5 {
		t.Fatalf("row2: %+v", rows[2])
	}
	page, total, _ := Preview(p, 1, 1)
	if total != 3 || len(page) != 1 || page[0].N != 1 {
		t.Fatalf("paging: %+v total=%d", page, total)
	}
}
