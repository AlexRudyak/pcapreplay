package gui

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/sasha/pktreplay/internal/history"
)

func (s *Server) historyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/history", s.histList)
	mux.HandleFunc("GET /api/history/settings", s.histGetSettings)
	mux.HandleFunc("POST /api/history/settings", s.histSetSettings)
	mux.HandleFunc("GET /api/history/export", s.histExport)
	mux.HandleFunc("POST /api/history/clear", s.histClear)
	mux.HandleFunc("GET /api/history/{id}", s.histGet)
	mux.HandleFunc("POST /api/history/{id}/update", s.histUpdate)
	mux.HandleFunc("POST /api/history/{id}/delete", s.histDelete)
	mux.HandleFunc("GET /api/history/{id}/packets", s.histPackets)
	mux.HandleFunc("GET /api/history/{id}/preview", s.histPreview)
	s.libraryRoutes(mux)
}

var errNoHistory = errors.New("history is not enabled")

func (s *Server) needHistory(w http.ResponseWriter) bool {
	if s.hist == nil {
		fail(w, http.StatusNotFound, errNoHistory)
		return false
	}
	return true
}

// needRun resolves the {id} path value to an existing run.
func (s *Server) needRun(w http.ResponseWriter, r *http.Request) (history.Run, bool) {
	if !s.needHistory(w) {
		return history.Run{}, false
	}
	id := r.PathValue("id")
	run, ok := history.Run{}, false
	if history.ValidID(id) {
		run, ok = s.hist.Get(id)
	}
	if !ok {
		fail(w, http.StatusNotFound, errors.New("no such run"))
		return history.Run{}, false
	}
	return run, true
}

func (s *Server) replayActive(id string) bool {
	st := s.jobs.Status()
	return st.State == stateRunning && st.Kind == "replay" && st.RunID == id
}

func queryOf(r *http.Request) history.Query {
	v := r.URL.Query()
	q := history.Query{Text: v.Get("q"), State: v.Get("state"), Mode: v.Get("mode"), Pinned: v.Get("pinned") == "1"}
	q.Offset, _ = strconv.Atoi(v.Get("offset"))
	q.Limit, _ = strconv.Atoi(v.Get("limit"))
	return q
}

func (s *Server) histList(w http.ResponseWriter, r *http.Request) {
	if s.hist == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "runs": []history.Run{}, "total": 0})
		return
	}
	q := queryOf(r)
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	runs, total := s.hist.List(q)
	for i := range runs { // the list view does not need the bulky replay request / UI state
		runs[i].Request, runs[i].Meta = nil, nil
	}
	if runs == nil {
		runs = []history.Run{}
	}
	writeJSON(w, 200, map[string]any{"enabled": true, "runs": runs, "total": total, "stats": s.hist.Stats(), "settings": s.hist.Settings()})
}

func (s *Server) histGet(w http.ResponseWriter, r *http.Request) {
	run, ok := s.needRun(w, r)
	if !ok {
		return
	}
	_, hasCopy := s.hist.PacketsFile(run.ID)
	resp := map[string]any{"run": run, "hasPackets": hasCopy}
	// Where "send again" can open the capture from: the original if it is still there,
	// otherwise the library copy.
	if fi, err := os.Stat(run.Capture); err == nil && !fi.IsDir() {
		resp["openPath"] = run.Capture
	}
	if run.PcapID != "" {
		if p, found := s.hist.GetPcap(run.PcapID); found {
			e := s.libEntryOf(p)
			resp["pcap"] = e
			if resp["openPath"] == nil && e.CanOpen {
				resp["openPath"] = e.OpenPath
			}
		}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) histUpdate(w http.ResponseWriter, r *http.Request) {
	run, ok := s.needRun(w, r)
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
	if err := s.hist.Update(run.ID, func(x *history.Run) {
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
	updated, _ := s.hist.Get(run.ID)
	writeJSON(w, 200, map[string]any{"run": updated})
}

func (s *Server) histDelete(w http.ResponseWriter, r *http.Request) {
	run, ok := s.needRun(w, r)
	if !ok {
		return
	}
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	if s.replayActive(run.ID) {
		fail(w, http.StatusConflict, errors.New("this run is still sending: stop it first"))
		return
	}
	if err := s.hist.Delete(run.ID); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"deleted": true})
}

func (s *Server) histClear(w http.ResponseWriter, r *http.Request) {
	if !s.needHistory(w) {
		return
	}
	var req struct {
		KeepPinned bool `json:"keepPinned"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if st := s.jobs.Status(); st.State == stateRunning && st.Kind == "replay" {
		fail(w, http.StatusConflict, errors.New("a replay is still sending: stop it first"))
		return
	}
	n, err := s.hist.Clear(req.KeepPinned)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, 200, map[string]int{"removed": n})
}

func (s *Server) histGetSettings(w http.ResponseWriter, r *http.Request) {
	if !s.needHistory(w) {
		return
	}
	writeJSON(w, 200, map[string]any{"settings": s.hist.Settings(), "stats": s.hist.Stats()})
}

func (s *Server) histSetSettings(w http.ResponseWriter, r *http.Request) {
	if !s.needHistory(w) {
		return
	}
	st := s.hist.Settings() // fields left out of the request keep their current value
	if !decodeBody(w, r, &st) {
		return
	}
	if err := s.hist.SetSettings(st); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	removed, pruned := s.hist.Prune()
	writeJSON(w, 200, map[string]any{"settings": s.hist.Settings(), "stats": s.hist.Stats(), "removedRuns": removed, "removedPacketCopies": pruned})
}

func (s *Server) histExport(w http.ResponseWriter, r *http.Request) {
	if !s.needHistory(w) {
		return
	}
	q := queryOf(r)
	stamp := time.Now().Format("20060102-150405")
	var err error
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="pktreplay-history-`+stamp+`.json"`)
		err = s.hist.ExportJSON(w, q)
	} else {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="pktreplay-history-`+stamp+`.csv"`)
		err = s.hist.ExportCSV(w, q)
	}
	if err != nil {
		// headers are already sent; nothing more can be reported to the client
		s.jobs.logf("history export failed: %v", err)
	}
}

func (s *Server) histPackets(w http.ResponseWriter, r *http.Request) {
	run, ok := s.needRun(w, r)
	if !ok {
		return
	}
	p, has := s.hist.PacketsFile(run.ID)
	if !has {
		fail(w, http.StatusNotFound, errors.New("no packet copy is stored for this run"))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="pktreplay-`+run.ID+`.pcapng"`)
	http.ServeFile(w, r, p)
}

func (s *Server) histPreview(w http.ResponseWriter, r *http.Request) {
	run, ok := s.needRun(w, r)
	if !ok {
		return
	}
	p, has := s.hist.PacketsFile(run.ID)
	if !has {
		fail(w, http.StatusNotFound, errors.New("no packet copy is stored for this run"))
		return
	}
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	lim, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if lim <= 0 {
		lim = 100
	}
	rows, total, err := history.Preview(p, off, lim)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if rows == nil {
		rows = []history.PacketRow{}
	}
	writeJSON(w, 200, map[string]any{"rows": rows, "total": total, "offset": off})
}
