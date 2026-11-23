package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/AlexRudyak/pcapreplay/internal/gui"
	"github.com/AlexRudyak/pcapreplay/internal/history"
)

// cmdGUI implements "pcapreplay gui": it reopens a running instance when there is one, otherwise
// starts the server, registers the instance and opens the browser.
func cmdGUI(args []string) error {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "listen address (loopback only; port 0 picks a free port)")
	noOpen := fs.Bool("no-open", false, "do not open the browser automatically")
	dataDir := fs.String("data-dir", "", "where the run history is stored (default: per-user data folder, or $PCAPREPLAY_DATA)")
	noHistory := fs.Bool("no-history", false, "do not record or show a history of sent packets")
	handoff := fs.String("handoff", "", "internal (Restart as administrator): write the address to this file instead of opening a browser")
	fs.Parse(args)

	// show opens u for the user: through the handoff file when the instance that restarted us
	// is waiting for it (it moves its own tab there), otherwise in the browser.
	show := func(u string) bool {
		if *handoff != "" && writeHandoff(*handoff, u) {
			return true
		}
		return *noOpen || openBrowser(u)
	}
	defer removeURLShortcut()
	removeStaleURLShortcut()

	// Default launch only: if a GUI is already running for this user, show it again instead of
	// starting a second process (this is what happens when the browser tab was closed).
	shared := *addr == "127.0.0.1:0" && *dataDir == "" && !*noHistory
	if shared {
		if u, ok := runningInstance(gui.IsElevated()); ok {
			if !show(u) {
				reportError("pcapreplay is already running.\nOpen this address yourself (it contains a private access token):\n\n" + u)
			}
			fmt.Fprintln(os.Stderr, "pcapreplay GUI is already running; reopened it.")
			return nil
		}
	}

	windowless := defaultCommand != "" // pcapreplay-gui.exe: no console, output goes to the log file
	var opts gui.Options
	// Started from the Start Menu or by double-click, the browser tab is the program's only
	// window: closing it ends the program. From a terminal it runs until Ctrl-C.
	opts.ExitWhenClosed = (windowless || ownConsole) && !*noOpen
	if !*noHistory {
		opts.DataDir = *dataDir
		if opts.DataDir == "" {
			d, err := history.DefaultDir()
			if err != nil {
				fmt.Fprintln(os.Stderr, "history disabled:", err)
			}
			opts.DataDir = d
		}
	}
	srv, err := gui.NewWithOptions(*addr, version, opts)
	if err != nil {
		if opts.DataDir != "" && *dataDir == "" { // the default location is unusable: run without history rather than not at all
			fmt.Fprintln(os.Stderr, "history disabled:", err)
			opts.DataDir = ""
			srv, err = gui.NewWithOptions(*addr, version, opts)
		}
		if err != nil {
			return err
		}
	}
	defer srv.Close()
	url := srv.URL()
	if shared {
		defer registerInstance(url, gui.IsElevated())()
	}
	if windowless {
		// Keep the access token out of the log file.
		fmt.Fprintf(os.Stderr, "GUI listening on loopback only (elevated: %v)\n", gui.IsElevated())
	} else {
		fmt.Fprintf(os.Stderr, "pcapreplay GUI listening on loopback only (administrator: %v).\nOpen: %s\n(the URL contains a private access token; Ctrl-C to quit)\n", gui.IsElevated(), url)
		if ownConsole {
			fmt.Fprintln(os.Stderr, "Leave this window open while you use pcapreplay; closing it stops the program.\nIt also closes by itself shortly after you close the browser tab.")
		}
	}
	if !show(url) {
		msg := "Could not open your browser automatically.\nOpen this address yourself (it contains a private access token):\n\n" + url
		if windowless {
			reportError(msg) // no console to print on: show a dialog
		} else {
			fmt.Fprintln(os.Stderr, msg)
		}
	}
	go func() {
		c := make(chan os.Signal, 1)
		// SIGTERM: on Windows, the console window being closed, sign-out and shutdown.
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		srv.Close()
	}()
	if err := srv.Serve(); err != nil && !isClosed(err) {
		return err
	}
	return nil
}

func isClosed(err error) bool {
	return errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

// openBrowser opens url in the default browser and reports whether it could start one.
func openBrowser(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		if gui.IsElevated() {
			// A browser started by an elevated process runs elevated too, and browsers
			// commonly refuse or exit when run as administrator. Explorer hands the request
			// to the running (non-elevated) shell, which starts the default browser. It
			// cannot be given the URL itself: Explorer splits its command line on "=" and
			// ",", so "...?t=<token>" makes it open the Documents folder instead. It is given
			// an Internet shortcut (.url) file pointing at the URL.
			f, ok := writeURLShortcut(url)
			if !ok {
				return false
			}
			cmd = exec.Command("explorer.exe", f)
			go func() { time.Sleep(time.Minute); removeURLShortcut() }()
		} else {
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		}
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	go cmd.Wait() // explorer.exe exits with status 1 even on success; the result is ignored
	return true
}

// The Internet shortcut handed to Explorer holds the access token, so it lives in the per-user
// temp folder only as long as Explorer needs to read it.
var shortcut struct {
	sync.Mutex
	path    string
	written time.Time
}

const shortcutPrefix = "pcapreplay-open-"

// writeURLShortcut writes an Internet shortcut to url and returns its path.
func writeURLShortcut(url string) (string, bool) {
	f := filepath.Join(os.TempDir(), fmt.Sprintf("%s%d.url", shortcutPrefix, os.Getpid()))
	if err := os.WriteFile(f, []byte("[InternetShortcut]\r\nURL="+url+"\r\n"), 0o600); err != nil {
		return "", false
	}
	shortcut.Lock()
	shortcut.path, shortcut.written = f, time.Now()
	shortcut.Unlock()
	return f, true
}

// removeURLShortcut deletes this process's shortcut, first giving Explorer (which opens it
// asynchronously) a few seconds to read a freshly written one.
func removeURLShortcut() {
	shortcut.Lock()
	defer shortcut.Unlock()
	if shortcut.path == "" {
		return
	}
	if d := 5*time.Second - time.Since(shortcut.written); d > 0 {
		time.Sleep(d)
	}
	os.Remove(shortcut.path)
	shortcut.path = ""
}

// removeStaleURLShortcut deletes shortcuts left by a pcapreplay that was killed before it could
// clean up (sign-out, Task Manager).
func removeStaleURLShortcut() {
	old, _ := filepath.Glob(filepath.Join(os.TempDir(), shortcutPrefix+"*.url"))
	for _, f := range old {
		if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) > 2*time.Minute {
			os.Remove(f)
		}
	}
}

// writeHandoff gives the instance that restarted this one its new address. The file must already
// exist (that instance creates it and deletes it when it stops waiting), so a late write cannot
// leave a new file behind.
func writeHandoff(path, u string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return false
	}
	_, werr := f.WriteString(u)
	return f.Close() == nil && werr == nil
}
