package history

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Pcap copy states.
const (
	CopyStored   = "stored"    // a copy of the file is kept in the library
	CopyRef      = "reference" // copies are turned off: only the original location is remembered
	CopyTooLarge = "too-large" // larger than the per-file limit: only a reference is kept
	CopyRemoved  = "removed"   // the copy was deleted (size limit or by the user)
	CopyFailed   = "failed"    // copying failed; see CopyError
)

// PcapSource is one place a library pcap was seen, with the file state used to
// recognise it again without re-reading it.
type PcapSource struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"` // unix nanoseconds
}

// Pcap is an entry of the pcap library: a capture file that was sent.
type Pcap struct {
	ID          string       `json:"id"` // 64 hex characters
	Name        string       `json:"name"`
	Size        int64        `json:"size"`
	Sources     []PcapSource `json:"sources"` // most recent first
	AddedAt     time.Time    `json:"addedAt"`
	LastUsed    time.Time    `json:"lastUsed"`
	Uses        int          `json:"uses"`
	CopyFile    string       `json:"copyFile,omitempty"` // file name under pcaps/
	CopyState   string       `json:"copyState"`
	CopyError   string       `json:"copyError,omitempty"`
	ContentHash bool         `json:"contentHash"` // ID is the SHA-256 of the content (identical files are recognised)
	Note        string       `json:"note,omitempty"`
	Pinned      bool         `json:"pinned,omitempty"` // its copy is never removed automatically
}

var pcapIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidPcapID reports whether id has the shape of a library id.
func ValidPcapID(id string) bool { return pcapIDRe.MatchString(id) }

const maxSources = 5

func (p *Pcap) addSource(src PcapSource) {
	out := []PcapSource{src}
	for _, s := range p.Sources {
		if s.Path != src.Path && len(out) < maxSources {
			out = append(out, s)
		}
	}
	p.Sources = out
}

// findBySource returns the entry that already knows this exact file state.
func (s *Store) findBySourceLocked(src PcapSource) *Pcap {
	for _, p := range s.pcaps {
		for _, o := range p.Sources {
			if o == src {
				return p
			}
		}
	}
	return nil
}

// libraryEntryForPath recognises a path inside the library's own pcaps folder and
// returns the entry whose stored copy it is.
func (s *Store) libraryEntryForPathLocked(abs string) (*Pcap, bool) {
	dir := filepath.Join(s.dir, "pcaps")
	rel, err := filepath.Rel(dir, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || strings.ContainsRune(rel, filepath.Separator) {
		return nil, false
	}
	id := strings.TrimSuffix(rel, filepath.Ext(rel))
	if !ValidPcapID(id) {
		return nil, false
	}
	p, ok := s.pcaps[id]
	return p, ok
}

// OriginalFor maps a path inside the library back to the original capture it
// stands for (so a run sent from a stored copy is still labelled with the name
// and place of the capture the user knows). ok is false for any other path.
func (s *Store) OriginalFor(path string) (original string, ok bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, found := s.libraryEntryForPathLocked(abs)
	if !found {
		return "", false
	}
	if len(p.Sources) > 0 {
		return p.Sources[0].Path, true
	}
	return p.Name, true
}

func copyExt(name string) string {
	switch ext := strings.ToLower(filepath.Ext(name)); ext {
	case ".pcap", ".pcapng", ".cap":
		return ext
	}
	return ".pcap"
}

// RegisterPcap records that the capture at path was sent and, depending on the
// settings, keeps a copy of it. Files are recognised by content (identical
// captures stored once) and by (path, size, modification time) so a file that
// was already seen is not read again. The slow copy runs without holding the
// store lock.
func (s *Store) RegisterPcap(path string) (Pcap, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Pcap{}, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return Pcap{}, err
	}
	if fi.IsDir() {
		return Pcap{}, errors.New("not a file")
	}
	src := PcapSource{Path: abs, Size: fi.Size(), Mtime: fi.ModTime().UnixNano()}
	now := time.Now()

	s.mu.Lock()
	// Sending a stored copy is a use of that entry: no re-reading, and the copy's
	// own path must never become one of the entry's "original" locations.
	if p, ok := s.libraryEntryForPathLocked(abs); ok {
		cp := *p
		cp.Uses++
		cp.LastUsed = now
		err := s.putPcapLocked(&cp)
		s.mu.Unlock()
		return cp, err
	}
	st := s.settings
	if p := s.findBySourceLocked(src); p != nil && (p.CopyState == CopyStored || p.CopyState == CopyRemoved || !st.KeepPcaps || p.CopyState == CopyTooLarge) {
		cp, err := s.touchPcapLocked(p.ID, src, now)
		s.mu.Unlock()
		return cp, err
	}
	s.mu.Unlock()

	limit := int64(st.MaxPcapFileMB) << 20
	switch {
	case !st.KeepPcaps:
		return s.addReference(src, CopyRef, now)
	case limit > 0 && fi.Size() > limit:
		return s.addReference(src, CopyTooLarge, now)
	}

	// Copy while hashing: one pass over the file.
	tmp, err := os.CreateTemp(filepath.Join(s.dir, "pcaps"), "incoming-*")
	if err != nil {
		return s.addReferenceFailed(src, err, now)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	in, err := os.Open(abs)
	if err != nil {
		tmp.Close()
		return Pcap{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), in)
	in.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return s.addReferenceFailed(src, err, now)
	}
	id := hex.EncodeToString(h.Sum(nil))
	src.Size = n

	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pcaps[id]
	file := id + copyExt(abs)
	if p == nil {
		if err := os.Rename(tmp.Name(), filepath.Join(s.dir, "pcaps", file)); err != nil {
			return Pcap{}, err
		}
		p = &Pcap{ID: id, Name: filepath.Base(abs), Size: n, AddedAt: now, ContentHash: true}
	} else if p.CopyFile == "" || p.CopyState != CopyStored {
		// the content is known but its copy was removed: restore it from this file
		if err := os.Rename(tmp.Name(), filepath.Join(s.dir, "pcaps", file)); err != nil {
			return Pcap{}, err
		}
	} // else: identical copy already stored; the temp file is discarded by the deferred Remove
	cp := *p
	cp.CopyFile, cp.CopyState, cp.CopyError, cp.ContentHash, cp.Size = file, CopyStored, "", true, n
	cp.addSource(src)
	cp.Uses++
	cp.LastUsed = now
	s.absorbReferencesLocked(&cp, abs)
	if err := s.putPcapLocked(&cp); err != nil {
		return Pcap{}, err
	}
	s.prunePcapsLocked()
	if cur, ok := s.pcaps[id]; ok {
		return *cur, nil
	}
	return cp, nil
}

// absorbReferencesLocked folds reference-only entries of the same path into the
// content-hashed entry, so one file is never listed twice, and re-points the runs
// that used them.
func (s *Store) absorbReferencesLocked(into *Pcap, path string) {
	for id, old := range s.pcaps {
		if id == into.ID || old.ContentHash {
			continue
		}
		same := false
		for _, o := range old.Sources {
			same = same || o.Path == path
		}
		if !same {
			continue
		}
		into.Uses += old.Uses
		if old.AddedAt.Before(into.AddedAt) {
			into.AddedAt = old.AddedAt
		}
		if into.Note == "" {
			into.Note = old.Note
		}
		into.Pinned = into.Pinned || old.Pinned
		for _, r := range s.runs {
			if r.PcapID == id {
				cp := *r
				cp.PcapID = into.ID
				if s.appendLocked(logOp{Op: "put", Run: &cp}) == nil {
					s.runs[r.ID] = &cp
					s.dead++
				}
			}
		}
		if s.appendLocked(logOp{Op: "delpcap", ID: id}) == nil {
			delete(s.pcaps, id)
			s.dead += 2
		}
	}
}

// touchPcapLocked counts one more use of an existing entry.
func (s *Store) touchPcapLocked(id string, src PcapSource, now time.Time) (Pcap, error) {
	cp := *s.pcaps[id]
	cp.addSource(src)
	cp.Uses++
	cp.LastUsed = now
	if err := s.putPcapLocked(&cp); err != nil {
		return Pcap{}, err
	}
	return cp, nil
}

func refID(src PcapSource) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", src.Path, src.Size, src.Mtime)))
	return hex.EncodeToString(sum[:])
}

// addReference records a capture as a reference entry (no stored copy) with the given state.
func (s *Store) addReference(src PcapSource, state string, now time.Time) (Pcap, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := refID(src)
	cp := Pcap{ID: id, Name: filepath.Base(src.Path), Size: src.Size, AddedAt: now}
	if old, ok := s.pcaps[id]; ok {
		cp = *old
	}
	cp.CopyState = state
	if cp.CopyFile != "" && state != CopyStored {
		cp.CopyFile = ""
	}
	cp.addSource(src)
	cp.Uses++
	cp.LastUsed = now
	if err := s.putPcapLocked(&cp); err != nil {
		return Pcap{}, err
	}
	return cp, nil
}

func (s *Store) addReferenceFailed(src PcapSource, cause error, now time.Time) (Pcap, error) {
	p, err := s.addReference(src, CopyFailed, now)
	if err != nil {
		return p, err
	}
	err = s.UpdatePcap(p.ID, func(x *Pcap) { x.CopyError = cause.Error() })
	p.CopyError = cause.Error()
	return p, err
}

func (s *Store) putPcapLocked(p *Pcap) error {
	cp := *p
	if _, ok := s.pcaps[p.ID]; ok {
		s.dead++
	}
	if err := s.appendLocked(logOp{Op: "pcap", Pcap: &cp}); err != nil {
		return err
	}
	s.pcaps[p.ID] = &cp
	return nil
}

// UpdatePcap applies fn to a library entry and persists it.
func (s *Store) UpdatePcap(id string, fn func(*Pcap)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pcaps[id]
	if !ok {
		return os.ErrNotExist
	}
	cp := *p
	fn(&cp)
	cp.ID = id
	return s.putPcapLocked(&cp)
}

// GetPcap returns a copy of a library entry.
func (s *Store) GetPcap(id string) (Pcap, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pcaps[id]
	if !ok {
		return Pcap{}, false
	}
	return *p, true
}

// PcapQuery filters ListPcaps.
type PcapQuery struct {
	Text   string
	Pinned bool
}

// ListPcaps returns library entries, most recently used first.
func (s *Store) ListPcaps(q PcapQuery) []Pcap {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := strings.ToLower(strings.TrimSpace(q.Text))
	var out []Pcap
	for _, p := range s.pcaps {
		if q.Pinned && !p.Pinned {
			continue
		}
		if t != "" {
			hay := strings.ToLower(p.Name + " " + p.Note + " " + p.CopyState)
			for _, src := range p.Sources {
				hay += " " + strings.ToLower(src.Path)
			}
			ok := true
			for _, w := range strings.Fields(t) {
				ok = ok && strings.Contains(hay, w)
			}
			if !ok {
				continue
			}
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastUsed.Equal(out[j].LastUsed) {
			return out[i].LastUsed.After(out[j].LastUsed)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// PcapOpenPath returns a path from which the capture can be opened: the stored
// copy if there is one, else the most recent original that still exists with the
// size it had.
func (s *Store) PcapOpenPath(id string) (path string, fromCopy bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, found := s.pcaps[id]
	if !found {
		return "", false, false
	}
	if p.CopyFile != "" && filepath.Base(p.CopyFile) == p.CopyFile {
		cp := filepath.Join(s.dir, "pcaps", p.CopyFile)
		if _, err := os.Stat(cp); err == nil {
			return cp, true, true
		}
	}
	for _, src := range p.Sources {
		if fi, err := os.Stat(src.Path); err == nil && !fi.IsDir() {
			return src.Path, false, true
		}
	}
	return "", false, false
}

// PcapCopyPath returns the stored copy only (for downloads).
func (s *Store) PcapCopyPath(id string) (string, bool) {
	p, copyOK, ok := s.PcapOpenPath(id)
	return p, ok && copyOK
}

// DeletePcap removes a library entry and its copy. Runs that used it keep their
// own record but lose the link.
func (s *Store) DeletePcap(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pcaps[id]
	if !ok {
		return os.ErrNotExist
	}
	if err := s.appendLocked(logOp{Op: "delpcap", ID: id}); err != nil {
		return err
	}
	if p.CopyFile != "" && filepath.Base(p.CopyFile) == p.CopyFile {
		os.Remove(filepath.Join(s.dir, "pcaps", p.CopyFile))
	}
	delete(s.pcaps, id)
	s.dead += 2
	return nil
}

// RemovePcapCopy deletes only the stored copy and keeps the entry as a reference.
func (s *Store) RemovePcapCopy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pcaps[id]
	if !ok {
		return os.ErrNotExist
	}
	if p.CopyFile != "" && filepath.Base(p.CopyFile) == p.CopyFile {
		os.Remove(filepath.Join(s.dir, "pcaps", p.CopyFile))
	}
	cp := *p
	cp.CopyFile, cp.CopyState = "", CopyRemoved
	return s.putPcapLocked(&cp)
}

// PcapRuns returns how many runs reference each library entry.
func (s *Store) PcapRuns(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.runs {
		if r.PcapID == id {
			n++
		}
	}
	return n
}

// prunePcapsLocked enforces MaxPcapsMB by removing the least recently used
// unpinned copies (never ones referenced by a pinned run).
func (s *Store) prunePcapsLocked() {
	limit := int64(s.settings.MaxPcapsMB) << 20
	if limit <= 0 {
		return
	}
	var total int64
	for _, p := range s.pcaps {
		if p.CopyFile != "" {
			total += p.Size
		}
	}
	if total <= limit {
		return
	}
	pinnedRun := map[string]bool{}
	for _, r := range s.runs {
		if r.Pinned {
			pinnedRun[r.PcapID] = true
		}
	}
	var cands []*Pcap
	for _, p := range s.pcaps {
		if p.CopyFile != "" && !p.Pinned && !pinnedRun[p.ID] {
			cands = append(cands, p)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].LastUsed.Before(cands[j].LastUsed) })
	for _, p := range cands {
		if total <= limit {
			return
		}
		os.Remove(filepath.Join(s.dir, "pcaps", p.CopyFile))
		total -= p.Size
		cp := *p
		cp.CopyFile, cp.CopyState = "", CopyRemoved
		s.putPcapLocked(&cp)
	}
}

// PrunePcaps applies the library size limit now.
func (s *Store) PrunePcaps() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunePcapsLocked()
}
