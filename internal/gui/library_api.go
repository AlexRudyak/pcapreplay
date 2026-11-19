package gui

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/sasha/pktreplay/internal/history"
)

func (s *Server) libraryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/library", s.libList)
	mux.HandleFunc("POST /api/library/add", s.libAdd)
	mux.HandleFunc("GET /api/library/{id}", s.libGet)
	mux.HandleFunc("POST /api/library/{id}/update", s.libUpdate)
	mux.HandleFunc("POST /api/library/{id}/delete", s.libDelete)
	mux.HandleFunc("POST /api/library/{id}/remove-copy", s.libRemoveCopy)
	mux.HandleFunc("GET /api/library/{id}/download", s.libDownload)
}

type libEntry struct {
	history.Pcap
	Runs     int    `json:"runs"`     // runs that sent this pcap
	CanOpen  bool   `json:"canOpen"`  // a copy or an original is available to open
	OpenPath string `json:"openPath"` // where to open it from
	FromCopy bool   `json:"fromCopy"`
}

func (s *Server) libEntryOf(p history.Pcap) libEntry {
	e := libEntry{Pcap: p, Runs: s.hist.PcapRuns(p.ID)}
	if path, fromCopy, ok := s.hist.PcapOpenPath(p.ID); ok {
		e.CanOpen, e.OpenPath, e.FromCopy = true, path, fromCopy
	}
	return e
}

func (s *Server) needPcap(w http.ResponseWriter, r *http.Request) (history.Pcap, bool) {
	if !s.needHistory(w) {
		return history.Pcap{}, false
	}
	id := r.PathValue("id")
	if history.ValidPcapID(id) {
		if p, ok := s.hist.GetPcap(id); ok {
			return p, true
		}
	}
	fail(w, http.StatusNotFound, errors.New("no such pcap in the library"))
	return history.Pcap{}, false
}

func (s *Server) libList(w http.ResponseWriter, r *http.Request) {
	if s.hist == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "pcaps": []libEntry{}})
		return
	}
	q := history.PcapQuery{Text: r.URL.Query().Get("q"), Pinned: r.URL.Query().Get("pinned") == "1"}
	out := []libEntry{}
	for _, p := range s.hist.ListPcaps(q) {
		out = append(out, s.libEntryOf(p))
	}
	writeJSON(w, 200, map[string]any{"enabled": true, "pcaps": out, "stats": s.hist.Stats(), "settings": s.hist.Settings()})
}

func (s *Server) libGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.needPcap(w, r)
	if !ok {
		return
	}
	runs, _ := s.hist.List(history.Query{Limit: 0})
	var used []history.Run
	for _, run := range runs {
		if run.PcapID == p.ID && len(used) < 20 {
			run.Request, run.Meta = nil, nil
			used = append(used, run)
		}
	}
	if used == nil {
		used = []history.Run{}
	}
	writeJSON(w, 200, map[string]any{"pcap": s.libEntryOf(p), "runs": used})
}

// libAdd puts a capture into the library without sending it.
func (s *Server) libAdd(w http.ResponseWriter, r *http.Request) {
	if !s.needHistory(w) {
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Path == "" {
		fail(w, http.StatusBadRequest, errors.New("choose a capture file first"))
		return
	}
	p, err := s.hist.RegisterPcap(req.Path)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	// registering counts as a use; adding a file is not a send
	s.hist.UpdatePcap(p.ID, func(x *history.Pcap) {
		if x.Uses > 0 {
			x.Uses--
		}
	})
	p, _ = s.hist.GetPcap(p.ID)
	writeJSON(w, 200, map[string]any{"pcap": s.libEntryOf(p)})
}

func (s *Server) libUpdate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.needPcap(w, r)
	if !ok {
		return
	}
	var req struct {
		Note   *string `json:"note"`
		Pinned *bool   `json:"pinned"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Note != nil && len(*req.Note) > 2000 {
		fail(w, http.StatusBadRequest, errors.New("the note is too long (2000 characters at most)"))
		return
	}
	if err := s.hist.UpdatePcap(p.ID, func(x *history.Pcap) {
		if req.Note != nil {
			x.Note = *req.Note
		}
		if req.Pinned != nil {
			x.Pinned = *req.Pinned
		}
	}); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	up, _ := s.hist.GetPcap(p.ID)
	writeJSON(w, 200, map[string]any{"pcap": s.libEntryOf(up)})
}

func (s *Server) libDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.needPcap(w, r)
	if !ok {
		return
	}
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.hist.DeletePcap(p.ID); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"deleted": true})
}

func (s *Server) libRemoveCopy(w http.ResponseWriter, r *http.Request) {
	p, ok := s.needPcap(w, r)
	if !ok {
		return
	}
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.hist.RemovePcapCopy(p.ID); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	up, _ := s.hist.GetPcap(p.ID)
	writeJSON(w, 200, map[string]any{"pcap": s.libEntryOf(up)})
}

func (s *Server) libDownload(w http.ResponseWriter, r *http.Request) {
	p, ok := s.needPcap(w, r)
	if !ok {
		return
	}
	path, has := s.hist.PcapCopyPath(p.ID)
	if !has {
		fail(w, http.StatusNotFound, errors.New("no stored copy of this pcap"))
		return
	}
	name := filepath.Base(p.Name)
	if name == "" || name == "." || name == string(os.PathSeparator) {
		name = p.ID + ".pcap"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(name)+`"`)
	http.ServeFile(w, r, path)
}

// sanitizeFilename keeps a download name safe inside a header.
func sanitizeFilename(n string) string {
	out := make([]rune, 0, len(n))
	for _, c := range n {
		if c < 32 || c == '"' || c == '\\' || c == '/' || c == 127 {
			c = '_'
		}
		out = append(out, c)
	}
	return string(out)
}
