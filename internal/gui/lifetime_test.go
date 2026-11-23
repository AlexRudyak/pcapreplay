package gui

import (
	"net/http"
	"testing"
	"time"
)

// newLifetimeTC starts a server that exits once its last tab is closed, with a short grace
// period, and returns the client and a channel that receives Serve's result.
func newLifetimeTC(t *testing.T, grace time.Duration) (*tc, <-chan error) {
	t.Helper()
	s, err := NewWithOptions("127.0.0.1:0", "test", Options{ExitWhenClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	s.grace = grace
	t.Cleanup(func() { s.Close() })
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	return &tc{t: t, s: s, host: s.listener.Addr().String(), cookie: &http.Cookie{Name: cookieName, Value: s.token}}, done
}

func TestServerExitsAfterLastTabCloses(t *testing.T) {
	c, done := newLifetimeTC(t, 200*time.Millisecond)
	if r, _ := c.do("POST", "/api/alive", struct{}{}, nil); r.StatusCode != 200 {
		t.Fatalf("alive: %d", r.StatusCode)
	}
	select {
	case <-done:
		t.Fatal("exited while the tab was open")
	case <-time.After(500 * time.Millisecond):
	}
	if r, _ := c.do("POST", "/api/bye", struct{}{}, nil); r.StatusCode != 200 {
		t.Fatalf("bye: %d", r.StatusCode)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("still running after the tab was closed")
	}
}

func TestServerStaysWhenAnotherPageChecksIn(t *testing.T) {
	c, done := newLifetimeTC(t, 400*time.Millisecond)
	c.do("POST", "/api/bye", struct{}{}, nil) // a reload: the old page says bye...
	c.do("GET", "/api/info", nil, nil)        // ...and the new one loads
	select {
	case <-done:
		t.Fatal("exited although a page is open")
	case <-time.After(time.Second):
	}
}

func TestServerWithoutExitWhenClosedKeepsRunning(t *testing.T) {
	c := newTC(t)
	c.s.grace = 100 * time.Millisecond
	c.do("POST", "/api/bye", struct{}{}, nil)
	time.Sleep(400 * time.Millisecond)
	if r, _ := c.do("GET", "/api/info", nil, nil); r.StatusCode != 200 {
		t.Fatalf("server stopped: %d", r.StatusCode)
	}
}
