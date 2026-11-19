package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/AlexRudyak/pktreplay/internal/history"
)

// A running GUI records where it listens so that starting pktreplay again (the Start Menu entry, a
// double-click on pktreplay-gui.exe after the browser tab was closed) re-opens that instance instead
// of starting a second process. The file holds the access token, so it lives in the per-user data
// folder, which other accounts cannot read.
type guiInstance struct {
	URL      string `json:"url"`
	PID      int    `json:"pid"`
	Elevated bool   `json:"elevated"`
}

func instanceFile() string {
	d, err := history.DefaultDir()
	if err != nil || d == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(d), "gui-instance.json")
}

// runningInstance returns the URL of a live GUI that can serve this launch: an elevated instance
// serves anyone, a normal one cannot serve a launch that asked for administrator rights.
func runningInstance(needElevated bool) (string, bool) {
	f := instanceFile()
	if f == "" {
		return "", false
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return "", false
	}
	var in guiInstance
	if json.Unmarshal(b, &in) != nil || in.URL == "" {
		return "", false
	}
	if needElevated && !in.Elevated {
		return "", false
	}
	u, err := url.Parse(in.URL)
	if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return "", false
	}
	// Only a pktreplay GUI that accepts this token answers with the marker; a stale file whose port
	// was reused by something else fails here.
	c := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(in.URL)
	if err != nil {
		return "", false
	}
	resp.Body.Close()
	if resp.Header.Get("X-Pktreplay") != "gui" {
		return "", false
	}
	return in.URL, true
}

// registerInstance records this process as the running GUI and returns a function that removes the
// record again (only if it is still ours).
func registerInstance(u string, elevated bool) func() {
	f := instanceFile()
	if f == "" {
		return func() {}
	}
	in := guiInstance{URL: u, PID: os.Getpid(), Elevated: elevated}
	b, _ := json.Marshal(in)
	if err := os.WriteFile(f, b, 0o600); err != nil {
		return func() {}
	}
	return func() {
		if cur, err := os.ReadFile(f); err == nil {
			var c guiInstance
			if json.Unmarshal(cur, &c) == nil && c.PID == in.PID {
				os.Remove(f)
			}
		}
	}
}
