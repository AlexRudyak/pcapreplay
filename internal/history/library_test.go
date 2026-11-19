package history

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name string, size int, fill byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, bytes.Repeat([]byte{fill}, size), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRegisterPcapCopiesAndDeduplicates(t *testing.T) {
	src := t.TempDir()
	s := open(t, t.TempDir())
	defer s.Close()
	a := writeFile(t, src, "a.pcap", 4096, 1)
	b := writeFile(t, src, "copy-of-a.pcap", 4096, 1) // identical content, different path
	c := writeFile(t, src, "other.pcapng", 2048, 2)

	pa, err := s.RegisterPcap(a)
	if err != nil || pa.CopyState != CopyStored || !pa.ContentHash || pa.Uses != 1 || pa.Size != 4096 || !ValidPcapID(pa.ID) {
		t.Fatalf("first registration: %+v %v", pa, err)
	}
	if p, copyOK, ok := s.PcapOpenPath(pa.ID); !ok || !copyOK || filepath.Dir(p) != filepath.Join(s.dir, "pcaps") {
		t.Fatalf("stored copy must be what is opened: %s %v", p, copyOK)
	}
	pb, _ := s.RegisterPcap(b)
	if pb.ID != pa.ID || pb.Uses != 2 || len(pb.Sources) != 2 {
		t.Fatalf("identical content must map to one entry: %+v", pb)
	}
	pc, _ := s.RegisterPcap(c)
	if pc.ID == pa.ID || filepath.Ext(pc.CopyFile) != ".pcapng" {
		t.Fatalf("different content / extension kept: %+v", pc)
	}
	if got := s.ListPcaps(PcapQuery{}); len(got) != 2 || got[0].ID != pc.ID {
		t.Fatalf("library listing (most recently used first): %+v", got)
	}
	if n := len(mustGlob(t, filepath.Join(s.dir, "pcaps", "*"))); n != 2 {
		t.Fatalf("expected 2 stored files, found %d", n)
	}

	// an unchanged file is recognised without being copied again
	before := mustStat(t, filepath.Join(s.dir, "pcaps", pa.CopyFile))
	again, _ := s.RegisterPcap(a)
	if again.Uses != 3 || mustStat(t, filepath.Join(s.dir, "pcaps", pa.CopyFile)) != before {
		t.Fatalf("known file re-read or miscounted: %+v", again)
	}

	// the copy still opens after the original disappears
	os.Remove(a)
	os.Remove(b)
	if p, fromCopy, ok := s.PcapOpenPath(pa.ID); !ok || !fromCopy {
		t.Fatalf("copy must survive deletion of the original: %s", p)
	}
}

func mustGlob(t *testing.T, pat string) []string {
	m, err := filepath.Glob(pat)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mustStat(t *testing.T, p string) time.Time {
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

func TestRegisterPcapLimitsAndReferences(t *testing.T) {
	src := t.TempDir()
	s := open(t, t.TempDir())
	defer s.Close()
	big := writeFile(t, src, "big.pcap", 3<<20, 7)
	small := writeFile(t, src, "small.pcap", 1000, 8)

	st := DefaultSettings()
	st.MaxPcapFileMB = 1
	s.SetSettings(st)
	pb, err := s.RegisterPcap(big)
	if err != nil || pb.CopyState != CopyTooLarge || pb.CopyFile != "" || pb.ContentHash {
		t.Fatalf("too large must be a reference only: %+v %v", pb, err)
	}
	if p, fromCopy, ok := s.PcapOpenPath(pb.ID); !ok || fromCopy || p != big {
		t.Fatalf("reference opens the original: %s %v %v", p, fromCopy, ok)
	}

	// copies switched off entirely: still listed, as references
	st = DefaultSettings()
	st.KeepPcaps = false
	s.SetSettings(st)
	ps, _ := s.RegisterPcap(small)
	if ps.CopyState != CopyRef || ps.CopyFile != "" {
		t.Fatalf("keepPcaps=false: %+v", ps)
	}
	// turning copies on later copies the file on the next send and folds the reference into the real entry
	st.KeepPcaps = true
	s.SetSettings(st)
	runID := mkRun(t, s, time.Minute, func(r *Run) { r.PcapID = ps.ID }).ID
	full, _ := s.RegisterPcap(small)
	if full.CopyState != CopyStored || full.ID == ps.ID || full.Uses != 2 {
		t.Fatalf("reference must be upgraded and merged: %+v", full)
	}
	if _, ok := s.GetPcap(ps.ID); ok {
		t.Fatal("the reference-only duplicate must be gone")
	}
	if r, _ := s.Get(runID); r.PcapID != full.ID {
		t.Fatalf("runs must follow the merge: %s != %s", r.PcapID, full.ID)
	}
	if got := s.ListPcaps(PcapQuery{}); len(got) != 2 {
		t.Fatalf("expected 2 entries (big reference + small copy), got %d", len(got))
	}

	// a missing file is an error, not an entry
	if _, err := s.RegisterPcap(filepath.Join(src, "nope.pcap")); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := s.RegisterPcap(src); err == nil {
		t.Fatal("a directory accepted")
	}
}

func TestPcapSizeCapPrunesOldestAndRespectsPins(t *testing.T) {
	src := t.TempDir()
	s := open(t, t.TempDir())
	defer s.Close()
	st := DefaultSettings()
	st.MaxPcapsMB = 1
	s.SetSettings(st)
	reg := func(name string, fill byte) Pcap {
		p, err := s.RegisterPcap(writeFile(t, src, name, 600<<10, fill))
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
		return p
	}
	first := reg("1.pcap", 1)
	s.UpdatePcap(first.ID, func(p *Pcap) { p.Pinned = true })
	second := reg("2.pcap", 2) // 1.2 MB total: over the cap -> the oldest UNPINNED copy goes (not the pinned first)
	third := reg("3.pcap", 3)
	state := func(id string) string { p, _ := s.GetPcap(id); return p.CopyState }
	if state(first.ID) != CopyStored {
		t.Fatal("a pinned pcap must never be pruned")
	}
	if state(second.ID) != CopyRemoved || state(third.ID) != CopyStored && state(third.ID) != CopyRemoved {
		t.Fatalf("pruning order wrong: second=%s third=%s", state(second.ID), state(third.ID))
	}
	// the entry stays listed so the runs that used it remain explainable
	if _, ok := s.GetPcap(second.ID); !ok {
		t.Fatal("pruned copy must keep its entry")
	}
	if st := s.Stats(); st.Pcaps != 3 || st.PcapBytes > 1<<20+700<<10 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestPcapManagementPersistsAndDeletes(t *testing.T) {
	src := t.TempDir()
	dir := t.TempDir()
	s := open(t, dir)
	p, _ := s.RegisterPcap(writeFile(t, src, "keep.pcap", 500, 4))
	s.UpdatePcap(p.ID, func(x *Pcap) { x.Note = "golden trace"; x.Pinned = true })
	q, _ := s.RegisterPcap(writeFile(t, src, "drop.pcap", 500, 5))
	if err := s.DeletePcap(q.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pcaps", q.CopyFile)); !os.IsNotExist(err) {
		t.Fatal("deleting an entry must delete its copy")
	}
	r := mkRun(t, s, time.Minute, func(r *Run) { r.PcapID = p.ID })
	if s.PcapRuns(p.ID) != 1 {
		t.Fatal("run count")
	}
	// removing only the copy keeps the entry
	if err := s.RemovePcapCopy(p.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetPcap(p.ID); got.CopyState != CopyRemoved || got.CopyFile != "" {
		t.Fatalf("remove copy: %+v", got)
	}
	s.Close()
	// a torn temp copy from a crash is cleaned up on open, and everything persists
	os.WriteFile(filepath.Join(dir, "pcaps", "incoming-123"), []byte("partial"), 0o600)
	s = open(t, dir)
	defer s.Close()
	if _, err := os.Stat(filepath.Join(dir, "pcaps", "incoming-123")); !os.IsNotExist(err) {
		t.Fatal("leftover temp copy not cleaned")
	}
	got, ok := s.GetPcap(p.ID)
	if !ok || got.Note != "golden trace" || !got.Pinned || got.CopyState != CopyRemoved {
		t.Fatalf("not persisted: %+v", got)
	}
	if _, ok := s.GetPcap(q.ID); ok {
		t.Fatal("deleted entry came back")
	}
	if rr, _ := s.Get(r.ID); rr.PcapID != p.ID {
		t.Fatal("run link lost")
	}
	if list := s.ListPcaps(PcapQuery{Text: "golden"}); len(list) != 1 {
		t.Fatal("search by note")
	}
}

func TestSettingsDefaultsForMissingFields(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"saveHistory": true, "maxRuns": 5}`), 0o600) // an older file
	s := open(t, dir)
	defer s.Close()
	if got := s.Settings(); got.MaxRuns != 5 || !got.KeepPcaps || got.MaxPcapsMB != 4096 || got.SavePackets {
		t.Fatalf("missing fields must take their defaults (packet copies off by default): %+v", got)
	}
}
