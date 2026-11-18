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
	"runtime"

	"github.com/sasha/pktreplay/internal/gui"
)

func cmdGUI(args []string) error {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "listen address (loopback only; port 0 picks a free port)")
	noOpen := fs.Bool("no-open", false, "do not open the browser automatically")
	fs.Parse(args)

	srv, err := gui.New(*addr, version)
	if err != nil {
		return err
	}
	defer srv.Close()
	url := srv.URL()
	windowless := defaultCommand != "" // pktreplay-gui.exe: no console, output goes to the log file
	if windowless {
		// Keep the access token out of the log file.
		fmt.Fprintf(os.Stderr, "GUI listening on loopback only (elevated: %v)\n", gui.IsElevated())
	} else {
		fmt.Fprintf(os.Stderr, "pktreplay GUI listening on loopback only (administrator: %v).\nOpen: %s\n(the URL contains a private access token; Ctrl-C to quit)\n", gui.IsElevated(), url)
		if ownConsole {
			fmt.Fprintln(os.Stderr, "Leave this window open while you use pktreplay; closing it stops the program.")
		}
	}
	if !*noOpen && !openBrowser(url) {
		msg := "Could not open your browser automatically.\nOpen this address yourself (it contains a private access token):\n\n" + url
		if windowless {
			reportError(msg) // no console to print on: show a dialog
		} else {
			fmt.Fprintln(os.Stderr, msg)
		}
	}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
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
			// commonly refuse or exit when run as administrator. Explorer runs at normal
			// privilege and launches the default browser from there.
			cmd = exec.Command("explorer.exe", url)
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
