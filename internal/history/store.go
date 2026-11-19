// Package history keeps a persistent, searchable record of every replay run:
// what was sent, with which settings, how it ended, and (optionally) a copy of
// the packets themselves.
//
// It is a small embedded store built on the standard library only: an
// append-only JSON-lines log ("history.jsonl") holding put/delete operations,
// replayed into memory on open, with crash-tolerant reading (a torn last line is
// skipped) and automatic compaction. Packet copies live beside it as PCAPNG
// files under packets/. Everything is private to the user (mode 0600/0700).
package history

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Run states.
const (
	StateRunning     = "running"
	StateDone        = "done"
	StateFailed      = "failed"
	StateCancelled   = "cancelled"
	StateInterrupted = "interrupted" // the program ended while the run was active
)

// ConvEntry describes one conversation that was sent.
type ConvEntry struct {
	Selector  string `json:"selector"`
	Changed   bool   `json:"changed"`
	NewClient string `json:"newClient,omitempty"`
	NewServer string `json:"newServer,omitempty"`
	Replace   int    `json:"replace,omitempty"` // number of payload substitutions
}

// Result holds the final counters of a run.
type Result struct {
	Read      uint64  `json:"read"`
	Matched   uint64  `json:"matched"`
	Sent      uint64  `json:"sent"`
	Bytes     uint64  `json:"bytes"`
	Skipped   uint64  `json:"skipped"`
	SendErrs  uint64  `json:"sendErrs"`
	ElapsedMs int64   `json:"elapsedMs"`
	PPS       float64 `json:"pps"`
	Mbps      float64 `json:"mbps"`
}

// Run is one entry of the history.
type Run struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
	State      string    `json:"state"`
	Error      string    `json:"error,omitempty"`

	Capture       string      `json:"capture"`
	PcapID        string      `json:"pcapId,omitempty"` // entry in the pcap library
	Mode          string      `json:"mode"`
	Backend       string      `json:"backend"`
	DryRun        bool        `json:"dryRun"`
	Pacing        string      `json:"pacing"`
	Loop          int         `json:"loop"`
	Target        string      `json:"target,omitempty"`
	Conversations []ConvEntry `json:"conversations"`

	Result  *Result         `json:"result,omitempty"`
	TCP     json.RawMessage `json:"tcp,omitempty"`
	Request json.RawMessage `json:"request,omitempty"` // exact request, for "send again"
	Meta    json.RawMessage `json:"meta,omitempty"`    // opaque UI state, for "send again"

	PacketsFile   string `json:"packetsFile,omitempty"` // file name under packets/
	PacketsCount  uint64 `json:"packetsCount,omitempty"`
	PacketsBytes  int64  `json:"packetsBytes,omitempty"`
	PacketsPruned bool   `json:"packetsPruned,omitempty"` // copy was removed to stay within the size limit

	Note   string `json:"note,omitempty"`
	Pinned bool   `json:"pinned,omitempty"` // never removed by retention limits
}

// Settings control what is kept.
type Settings struct {
	SaveHistory bool `json:"saveHistory"` // record runs at all
	MaxRuns     int  `json:"maxRuns"`     // oldest unpinned runs are removed beyond this (0 = unlimited)
	MaxAgeDays  int  `json:"maxAgeDays"`  // unpinned runs older than this are removed (0 = keep)

	// Pcap library: the capture files that were sent.
	KeepPcaps     bool `json:"keepPcaps"`     // store a copy of every pcap that is sent (otherwise only a reference)
	MaxPcapFileMB int  `json:"maxPcapFileMB"` // pcaps larger than this are referenced, not copied (0 = no limit)
	MaxPcapsMB    int  `json:"maxPcapsMB"`    // oldest unpinned copies are removed beyond this total (0 = unlimited)

	// Optional: a copy of the packets that were actually transmitted (rewritten, with replies).
	SavePackets  bool `json:"savePackets"`
	MaxPacketsMB int  `json:"maxPacketsMB"` // oldest packet copies are removed beyond this total (0 = unlimited)
}

// DefaultSettings are used until the user changes them. Copies of the sent
// packets are opt-in; copies of the sent pcap files are on, with size limits.
func DefaultSettings() Settings {
	return Settings{SaveHistory: true, MaxRuns: 1000, KeepPcaps: true, MaxPcapFileMB: 512, MaxPcapsMB: 4096, MaxPacketsMB: 1024}
}

func (s Settings) validate() error {
	const maxMB = 10_000_000
	if s.MaxRuns < 0 || s.MaxRuns > 1_000_000 || s.MaxPacketsMB < 0 || s.MaxPacketsMB > maxMB || s.MaxAgeDays < 0 || s.MaxAgeDays > 36500 ||
		s.MaxPcapFileMB < 0 || s.MaxPcapFileMB > maxMB || s.MaxPcapsMB < 0 || s.MaxPcapsMB > maxMB {
		return errors.New("history limits out of range")
	}
	return nil
}

// Stats summarises the store.
type Stats struct {
	Dir          string `json:"dir"`
	Runs         int    `json:"runs"`
	PacketsBytes int64  `json:"packetsBytes"`
	Pcaps        int    `json:"pcaps"`
	PcapBytes    int64  `json:"pcapBytes"` // size of the stored pcap copies
	DBBytes      int64  `json:"dbBytes"`
}

// Query filters List.
type Query struct {
	Text   string // matches capture, target, conversations, note, error
	State  string // exact, "" = any
	Mode   string
	Pinned bool // only pinned runs
	Offset int
	Limit  int // 0 = all
}

var idRe = regexp.MustCompile(`^[0-9a-f]{20}$`)

// ValidID reports whether id has the shape NewID produces (also guards file paths).
func ValidID(id string) bool { return idRe.MatchString(id) }

// Store is the embedded history database. It is safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	dir      string
	logPath  string
	f        *os.File
	runs     map[string]*Run
	pcaps    map[string]*Pcap
	settings Settings
	dead     int // superseded or deleted log lines
}

type logOp struct {
	Op   string `json:"op"`
	Run  *Run   `json:"run,omitempty"`
	Pcap *Pcap  `json:"pcap,omitempty"`
	ID   string `json:"id,omitempty"`
}

// Open opens (creating if needed) the store in dir.
func Open(dir string) (*Store, error) {
	for _, sub := range []string{"packets", "pcaps"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "pcaps", "incoming-*")); len(leftovers) > 0 {
		for _, f := range leftovers { // half-written copies from a crash
			os.Remove(f)
		}
	}
	s := &Store{dir: dir, logPath: filepath.Join(dir, "history.jsonl"), runs: map[string]*Run{}, pcaps: map[string]*Pcap{}, settings: DefaultSettings()}
	if b, err := os.ReadFile(filepath.Join(dir, "settings.json")); err == nil {
		st := DefaultSettings() // fields missing from an older file keep their defaults
		if json.Unmarshal(b, &st) == nil && st.validate() == nil {
			s.settings = st
		}
	}
	corrupt, err := s.load()
	if err != nil {
		return nil, err
	}
	// A run still "running" at startup was cut short by the program ending.
	changed := false
	for _, r := range s.runs {
		if r.State == StateRunning {
			r.State, r.FinishedAt = StateInterrupted, time.Now()
			changed = true
		}
	}
	if corrupt > 0 || changed || s.dead > 100 && s.dead > len(s.runs) {
		if err := s.compactLocked(); err != nil {
			return nil, err
		}
	} else if s.f, err = os.OpenFile(s.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// load replays the log; it returns how many unreadable lines were skipped.
func (s *Store) load() (corrupt int, err error) {
	f, err := os.Open(s.logPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	for {
		line, rerr := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var op logOp
			if json.Unmarshal(line, &op) != nil {
				corrupt++ // e.g. a torn final line after a crash
			} else {
				switch {
				case op.Op == "put" && op.Run != nil && ValidID(op.Run.ID):
					if _, dup := s.runs[op.Run.ID]; dup {
						s.dead++
					}
					r := *op.Run
					s.runs[r.ID] = &r
				case op.Op == "pcap" && op.Pcap != nil && ValidPcapID(op.Pcap.ID):
					if _, dup := s.pcaps[op.Pcap.ID]; dup {
						s.dead++
					}
					p := *op.Pcap
					s.pcaps[p.ID] = &p
				case op.Op == "delpcap":
					if _, ok := s.pcaps[op.ID]; ok {
						delete(s.pcaps, op.ID)
						s.dead++
					}
					s.dead++
				case op.Op == "del":
					if _, ok := s.runs[op.ID]; ok {
						delete(s.runs, op.ID)
						s.dead++
					}
					s.dead++
				default:
					corrupt++
				}
			}
		}
		if rerr != nil {
			return corrupt, nil
		}
	}
}

// compactLocked rewrites the log with only live runs (atomically).
func (s *Store) compactLocked() error {
	if s.f != nil {
		s.f.Close()
		s.f = nil
	}
	tmp := s.logPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, p := range s.pcaps {
		b, _ := json.Marshal(logOp{Op: "pcap", Pcap: p})
		w.Write(b)
		w.WriteByte('\n')
	}
	for _, r := range s.sorted() {
		b, _ := json.Marshal(logOp{Op: "put", Run: r})
		w.Write(b)
		w.WriteByte('\n')
	}
	if err = w.Flush(); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.logPath); err != nil {
		return err
	}
	s.dead = 0
	s.f, err = os.OpenFile(s.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	return err
}

// sorted returns the runs newest first.
func (s *Store) sorted() []*Run {
	out := make([]*Run, 0, len(s.runs))
	for _, r := range s.runs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.Before(out[j].StartedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// appendLocked writes one operation to the log and fsyncs it. The caller holds s.mu.
func (s *Store) appendLocked(op logOp) error {
	b, err := json.Marshal(op)
	if err != nil {
		return err
	}
	if s.f == nil {
		return errors.New("history store is closed")
	}
	if _, err := s.f.Write(append(b, '\n')); err != nil { // one write per record keeps lines whole
		return err
	}
	return s.f.Sync()
}

// Dir returns the data directory.
func (s *Store) Dir() string { return s.dir }

// NewID returns a time-sortable unique run id (20 lowercase hex characters).
func NewID() string {
	var r [4]byte
	crand.Read(r[:])
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(time.Now().UnixMilli()))
	return fmt.Sprintf("%x%x", t[2:], r[:]) // 6 bytes of milliseconds + 4 random bytes
}

// Put adds a run or replaces the run with the same id.
func (s *Store) Put(r Run) error {
	if !ValidID(r.ID) {
		return errors.New("invalid run id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[r.ID]; ok {
		s.dead++
	}
	cp := r
	if err := s.appendLocked(logOp{Op: "put", Run: &cp}); err != nil {
		return err
	}
	s.runs[r.ID] = &cp
	return nil
}

// Update applies fn to the stored run and persists the result.
func (s *Store) Update(id string, fn func(*Run)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return os.ErrNotExist
	}
	cp := *r
	fn(&cp)
	cp.ID = id
	if err := s.appendLocked(logOp{Op: "put", Run: &cp}); err != nil {
		return err
	}
	s.dead++
	s.runs[id] = &cp
	return nil
}

// Get returns a copy of a run.
func (s *Store) Get(id string) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return Run{}, false
	}
	return *r, true
}

// match reports whether run r satisfies every set field of the query.
func (q Query) match(r *Run) bool {
	if q.State != "" && r.State != q.State {
		return false
	}
	if q.Mode != "" && r.Mode != q.Mode {
		return false
	}
	if q.Pinned && !r.Pinned {
		return false
	}
	if t := strings.ToLower(strings.TrimSpace(q.Text)); t != "" {
		hay := strings.ToLower(r.Capture + " " + r.Target + " " + r.Note + " " + r.Error + " " + r.Mode + " " + r.State)
		for _, c := range r.Conversations {
			hay += " " + strings.ToLower(c.Selector+" "+c.NewClient+" "+c.NewServer)
		}
		for _, w := range strings.Fields(t) {
			if !strings.Contains(hay, w) {
				return false
			}
		}
	}
	return true
}

// List returns matching runs, newest first, plus the total number of matches.
func (s *Store) List(q Query) ([]Run, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.sorted()
	var out []Run
	total := 0
	for i := len(all) - 1; i >= 0; i-- {
		if !q.match(all[i]) {
			continue
		}
		total++
		if total > q.Offset && (q.Limit == 0 || len(out) < q.Limit) {
			out = append(out, *all[i])
		}
	}
	return out, total
}

func (s *Store) packetsPath(file string) string { return filepath.Join(s.dir, "packets", file) }

// PacketsPath returns where the packet copy of run id is (to be) written.
func (s *Store) PacketsPath(id string) string {
	if !ValidID(id) {
		return ""
	}
	return s.packetsPath(id + ".pcapng")
}

// PacketsFile returns the existing packet copy of a run, if it has one.
func (s *Store) PacketsFile(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok || r.PacketsFile == "" || filepath.Base(r.PacketsFile) != r.PacketsFile {
		return "", false
	}
	p := s.packetsPath(r.PacketsFile)
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

// deleteLocked removes a run and its packet copy. The caller holds s.mu.
func (s *Store) deleteLocked(id string) error {
	r, ok := s.runs[id]
	if !ok {
		return os.ErrNotExist
	}
	if err := s.appendLocked(logOp{Op: "del", ID: id}); err != nil {
		return err
	}
	if r.PacketsFile != "" && filepath.Base(r.PacketsFile) == r.PacketsFile {
		os.Remove(s.packetsPath(r.PacketsFile))
	}
	delete(s.runs, id)
	s.dead += 2
	return nil
}

// Delete removes a run and its packet copy.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(id)
}

// Clear removes every run (optionally keeping pinned ones) and returns how many.
func (s *Store) Clear(keepPinned bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.sorted() {
		if keepPinned && r.Pinned {
			continue
		}
		if err := s.deleteLocked(r.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, s.maybeCompactLocked()
}

func (s *Store) maybeCompactLocked() error {
	if s.dead > 100 && s.dead > len(s.runs) {
		return s.compactLocked()
	}
	return nil
}

// Settings returns the current retention settings.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

// SetSettings validates and persists new settings.
func (s *Store) SetSettings(st Settings) error {
	if err := st.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := filepath.Join(s.dir, "settings.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, "settings.json")); err != nil {
		return err
	}
	s.settings = st
	return nil
}

// Prune enforces the retention settings and reports what it removed.
func (s *Store) Prune() (removedRuns, prunedPackets int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.settings
	runs := s.sorted() // oldest first
	if st.MaxAgeDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -st.MaxAgeDays)
		for _, r := range runs {
			if !r.Pinned && r.State != StateRunning && r.StartedAt.Before(cutoff) {
				if s.deleteLocked(r.ID) == nil {
					removedRuns++
				}
			}
		}
	}
	if st.MaxRuns > 0 {
		for _, r := range s.sorted() {
			if len(s.runs) <= st.MaxRuns {
				break
			}
			if !r.Pinned && r.State != StateRunning {
				if s.deleteLocked(r.ID) == nil {
					removedRuns++
				}
			}
		}
	}
	if st.MaxPacketsMB > 0 {
		limit := int64(st.MaxPacketsMB) << 20
		var total int64
		for _, r := range s.runs {
			if r.PacketsFile != "" {
				total += r.PacketsBytes
			}
		}
		for _, r := range s.sorted() {
			if total <= limit {
				break
			}
			if r.PacketsFile == "" || r.Pinned || r.State == StateRunning {
				continue
			}
			cp := *r
			os.Remove(s.packetsPath(cp.PacketsFile))
			total -= cp.PacketsBytes
			cp.PacketsFile, cp.PacketsPruned = "", true
			if s.appendLocked(logOp{Op: "put", Run: &cp}) == nil {
				s.runs[cp.ID] = &cp
				s.dead++
				prunedPackets++
			}
		}
	}
	s.prunePcapsLocked()
	s.maybeCompactLocked()
	return
}

// Stats reports the size of the store.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Dir: s.dir, Runs: len(s.runs), Pcaps: len(s.pcaps)}
	for _, r := range s.runs {
		if r.PacketsFile != "" {
			st.PacketsBytes += r.PacketsBytes
		}
	}
	for _, p := range s.pcaps {
		if p.CopyFile != "" {
			st.PcapBytes += p.Size
		}
	}
	if fi, err := os.Stat(s.logPath); err == nil {
		st.DBBytes = fi.Size()
	}
	return st
}

// Close flushes and closes the store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
