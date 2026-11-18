// Package gui serves a local web interface for pktreplay.
//
// The server binds to the loopback interface only and every request must carry
// a random per-launch token (set as an HttpOnly SameSite=Strict cookie by the
// first visit to the printed URL). Host and Origin headers are checked to block
// DNS-rebinding and cross-site requests, and state-changing calls require a JSON
// content type, so a page on another origin cannot drive the tool.
package gui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sasha/pktreplay/internal/filter"
)

//go:embed web/*
var webFS embed.FS

const cookieName = "pktreplay_token"

// Server is the GUI HTTP server.
type Server struct {
	token    string
	hosts    map[string]bool
	jobs     *manager
	listener net.Listener
	Version  string
}

// New binds addr (use "127.0.0.1:0" for a free port) and prepares the server.
func New(addr, version string) (*Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("refusing to listen on %q: the GUI only binds to loopback addresses", host)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	port := fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	return &Server{
		token:    hex.EncodeToString(raw[:]),
		hosts:    map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true},
		jobs:     newManager(),
		listener: ln,
		Version:  version,
	}, nil
}

// URL returns the address to open, including the one-time login token.
func (s *Server) URL() string {
	return fmt.Sprintf("http://%s/?t=%s", s.listener.Addr(), s.token)
}

// Serve blocks serving requests.
func (s *Server) Serve() error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(s.listener)
}

// Close stops listening and cancels any running job.
func (s *Server) Close() error {
	s.jobs.Stop()
	return s.listener.Close()
}

// Handler returns the full HTTP handler (exported for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	static := http.FileServer(http.FS(sub))
	mux.Handle("/", static)
	mux.HandleFunc("/api/info", s.info)
	mux.HandleFunc("/api/fs", s.browse)
	mux.HandleFunc("/api/filter/check", s.checkFilter)
	mux.HandleFunc("/api/stats", s.startStats)
	mux.HandleFunc("/api/replay", s.startReplay)
	mux.HandleFunc("/api/cancel", s.cancel)
	mux.HandleFunc("/api/status", s.status)
	return s.guard(mux)
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hosts[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		// First visit: exchange the URL token for a cookie, then drop it from the address bar.
		if t := r.URL.Query().Get("t"); t != "" && r.Method == http.MethodGet {
			if s.validToken(t) {
				http.SetCookie(w, &http.Cookie{Name: cookieName, Value: t, Path: "/", HttpOnly: true,
					SameSite: http.SameSiteStrictMode})
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			}
		}
		c, err := r.Cookie(cookieName)
		if err != nil || !s.validToken(c.Value) {
			http.Error(w, "unauthorized: open the URL printed by `pktreplay gui` (it contains the access token)", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || !s.hosts[u.Host] {
					http.Error(w, "forbidden origin", http.StatusForbidden)
					return
				}
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) validToken(t string) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, fmt.Errorf("bad request: %w", err))
		return false
	}
	return true
}

// ---- handlers ----

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	writeJSON(w, 200, map[string]any{
		"version": s.Version, "os": runtime.GOOS, "arch": runtime.GOARCH, "elevated": isElevated(),
		"home": home, "cwd": cwd, "roots": roots(),
	})
}

func roots() []string {
	if runtime.GOOS != "windows" {
		return []string{"/"}
	}
	var out []string
	for c := 'A'; c <= 'Z'; c++ {
		if _, err := os.Stat(string(c) + `:\`); err == nil {
			out = append(out, string(c)+`:\`)
		}
	}
	return out
}

type fsEntry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size"`
}

func isCapture(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pcap", ".pcapng", ".cap":
		return true
	}
	return false
}

// browse lists directories and capture files so the user can pick a capture.
func (s *Server) browse(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if p == "" {
		p, _ = os.UserHomeDir()
	}
	p = filepath.Clean(p)
	ents, err := os.ReadDir(p)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	out := []fsEntry{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if e.IsDir() {
			out = append(out, fsEntry{Name: e.Name(), Dir: true})
		} else if isCapture(e.Name()) {
			var sz int64
			if fi, err := e.Info(); err == nil {
				sz = fi.Size()
			}
			out = append(out, fsEntry{Name: e.Name(), Size: sz})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	parent := filepath.Dir(p)
	if parent == p {
		parent = ""
	}
	writeJSON(w, 200, map[string]any{"path": p, "parent": parent, "entries": out})
}

func (s *Server) checkFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filter string `json:"filter"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if _, err := filter.Parse(req.Filter); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) startStats(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RangeRequest
		Top int `json:"top"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Top <= 0 || req.Top > 100 {
		req.Top = 15
	}
	if err := s.jobs.StartStats(req.RangeRequest, req.Top); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errBusy) {
			code = http.StatusConflict
		}
		fail(w, code, err)
		return
	}
	writeJSON(w, 202, map[string]string{"state": "running"})
}

func (s *Server) startReplay(w http.ResponseWriter, r *http.Request) {
	var req ReplayRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.jobs.StartReplay(&req); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errBusy) {
			code = http.StatusConflict
		}
		fail(w, code, err)
		return
	}
	writeJSON(w, 202, map[string]string{"state": "running"})
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	writeJSON(w, 200, map[string]bool{"stopped": s.jobs.Stop()})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobs.Status())
}
