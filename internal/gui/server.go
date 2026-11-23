// Package gui serves a local web interface for pcapreplay.
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
	"sync"
	"time"

	"github.com/AlexRudyak/pcapreplay/internal/filter"
	"github.com/AlexRudyak/pcapreplay/internal/history"
)

//go:embed web/*
var webFS embed.FS

const cookieName = "pcapreplay_token"

// Server is the GUI HTTP server.
type Server struct {
	token    string
	hosts    map[string]bool
	jobs     *manager
	hist     *history.Store // nil when history is disabled
	listener net.Listener
	Version  string

	exitWhenClosed bool
	stopOnce       sync.Once // closes the listener, which makes Serve return
	closeOnce      sync.Once
	grace          time.Duration // pageGrace; shorter in tests
	pageMu         sync.Mutex
	closing        bool          // the last page said it was closing, and none has checked in since
	waited         time.Duration // awake time since then
}

// Options configures optional server features.
type Options struct {
	// DataDir is where the run history (and the packet copies of every run) is
	// stored. Empty disables the history.
	DataDir string
	// ExitWhenClosed makes Serve return once the browser tab has been closed and no
	// other page has been heard from for pageGrace (and no job is running). It is for
	// launches where the tab is the only window of the program.
	ExitWhenClosed bool
}

// pageGrace is how long the server waits after a tab said it was closing before it exits:
// long enough for a reload, and for another (possibly throttled, background) tab of the same
// GUI to check in; its heartbeat runs every 20 s, at most once a minute when hidden.
const pageGrace = 90 * time.Second

// New binds addr (use "127.0.0.1:0" for a free port) and prepares the server
// without a persistent history.
func New(addr, version string) (*Server, error) { return NewWithOptions(addr, version, Options{}) }

// NewWithOptions is New with options.
func NewWithOptions(addr, version string, opts Options) (*Server, error) {
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
	var hist *history.Store
	if opts.DataDir != "" {
		if abs, aerr := filepath.Abs(opts.DataDir); aerr == nil {
			opts.DataDir = abs // library copies are opened by path: keep it independent of the working directory
		}
		if hist, err = history.Open(opts.DataDir); err != nil {
			ln.Close()
			return nil, fmt.Errorf("opening the history in %s: %w", opts.DataDir, err)
		}
	}
	port := fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	return &Server{
		token:    hex.EncodeToString(raw[:]),
		hosts:    map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true},
		jobs:     newManager(hist),
		hist:     hist,
		listener: ln,
		Version:  version,

		exitWhenClosed: opts.ExitWhenClosed,
		grace:          pageGrace,
	}, nil
}

// URL returns the address to open, including the one-time login token.
func (s *Server) URL() string {
	return fmt.Sprintf("http://%s/?t=%s", s.listener.Addr(), s.token)
}

// Serve blocks serving requests.
func (s *Server) Serve() error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if s.exitWhenClosed {
		done := make(chan struct{})
		defer close(done)
		go s.watchPages(done)
	}
	return srv.Serve(s.listener)
}

// stop makes Serve return (with net.ErrClosed), so the caller's normal shutdown runs.
func (s *Server) stop() { s.stopOnce.Do(func() { s.listener.Close() }) }

// watchPages stops the server once the last tab has gone and no job is running.
func (s *Server) watchPages(done <-chan struct{}) {
	tick := min(5*time.Second, s.grace/4)
	t := time.NewTicker(tick)
	defer t.Stop()
	prev := time.Now()
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			// Count awake time only: a gap much longer than the tick means the computer slept
			// (or the process was throttled), and the pages could not check in meanwhile.
			step := min(now.Sub(prev), 2*tick)
			prev = now
			s.pageMu.Lock()
			if s.closing {
				s.waited += step
			}
			gone := s.closing && s.waited >= s.grace
			s.pageMu.Unlock()
			if gone && s.jobs.Status().State != stateRunning {
				s.stop()
				return
			}
		}
	}
}

// pageSeen records that a page of this GUI is open.
func (s *Server) pageSeen() {
	s.pageMu.Lock()
	s.closing, s.waited = false, 0
	s.pageMu.Unlock()
}

// Close stops listening, cancels any running job and closes the history. It is safe to call
// more than once.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.jobs.Stop()
		s.jobs.Wait(3 * time.Second) // let a cancelled run write its final history entry
		s.stop()
		if s.hist != nil {
			s.hist.Close()
		}
	})
	return nil
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
	mux.HandleFunc("/api/elevate", s.elevate)
	mux.HandleFunc("/api/alive", s.alive)
	mux.HandleFunc("/api/bye", s.bye)
	s.historyRoutes(mux)
	return s.guard(mux)
}

// guard wraps every request in the security checks: Host allow-list (DNS-rebinding defence),
// the token-to-cookie exchange, cookie validation, and for state-changing methods the
// Origin and JSON content-type checks. It also sets the security headers.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hosts[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		// First visit: exchange the URL token for a cookie, then drop it from the address bar.
		if t := r.URL.Query().Get("t"); t != "" && r.Method == http.MethodGet {
			if s.validToken(t) {
				w.Header().Set("X-Pcapreplay", "gui") // lets a second launch recognise this instance
				http.SetCookie(w, &http.Cookie{Name: cookieName, Value: t, Path: "/", HttpOnly: true,
					SameSite: http.SameSiteStrictMode})
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			}
		}
		c, err := r.Cookie(cookieName)
		if err != nil || !s.validToken(c.Value) {
			http.Error(w, "unauthorized: open the URL printed by `pcapreplay gui` (it contains the access token)", http.StatusUnauthorized)
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
		if r.URL.Path != "/api/bye" {
			s.pageSeen()
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

// decodeBody reads a JSON request body into v, answering 400 itself on failure.
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
		"home": home, "cwd": cwd, "roots": roots(), "samples": sampleCaptures(),
	})
}

type sampleFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// sampleCaptures lists the example captures shipped next to the executable (or
// in ./samples when running from a source checkout).
func sampleCaptures() []sampleFile {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "samples"))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, "samples"))
	}
	seen := map[string]bool{}
	out := []sampleFile{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			p := filepath.Join(d, e.Name())
			if e.IsDir() || !isCapture(e.Name()) || seen[p] {
				continue
			}
			seen[p] = true
			var sz int64
			if fi, err := e.Info(); err == nil {
				sz = fi.Size()
			}
			out = append(out, sampleFile{Name: e.Name(), Path: p, Size: sz})
		}
	}
	return out
}

// elevate restarts the program with administrator rights (UAC prompt) and then
// exits this instance, whose browser tab is replaced by the new one.
func (s *Server) elevate(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	if isElevated() {
		fail(w, http.StatusBadRequest, errors.New("already running with administrator rights"))
		return
	}
	if st := s.jobs.Status(); st.State == stateRunning {
		fail(w, http.StatusConflict, errBusy)
		return
	}
	// The elevated copy writes its address into this file instead of opening a browser; the
	// file is created here first so it keeps this user's permissions even when the copy runs
	// under another (administrator) account.
	f, err := os.CreateTemp("", "pcapreplay-handoff-*.txt")
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	handoff := f.Name()
	f.Close()
	defer os.Remove(handoff)
	if err := relaunchElevated(handoff); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	next := waitHandoff(handoff, 30*time.Second)
	writeJSON(w, 200, map[string]any{"restarting": true, "url": next})
	// Shut down normally (history closed, instance record cleaned up) once the answer is out.
	time.AfterFunc(800*time.Millisecond, s.stop)
}

// alive is the open pages' heartbeat (every request counts; this one keeps an idle tab counted).
func (s *Server) alive(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if decodeBody(w, r, &req) {
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

// bye is sent by a page that is being closed or reloaded.
func (s *Server) bye(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	s.pageMu.Lock()
	s.closing, s.waited = true, 0
	s.pageMu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// waitHandoff waits for the elevated copy to write its address and returns it, or ""
// when it did not arrive in time or is not a loopback pcapreplay address.
func waitHandoff(path string, timeout time.Duration) string {
	for end := time.Now().Add(timeout); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		b, err := os.ReadFile(path)
		if err != nil || len(b) == 0 {
			continue
		}
		s := strings.TrimSpace(string(b))
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
			return ""
		}
		return s
	}
	return ""
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

// checkFilter answers POST /api/filter/check: whether a filter expression parses.
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

// startStats answers POST /api/stats: starts the analysis job for a capture.
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

// startReplay answers POST /api/replay: validates the request and starts the replay job.
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
