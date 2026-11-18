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
	fmt.Fprintf(os.Stderr, "pktreplay GUI listening on loopback only.\nOpen: %s\n(the URL contains a private access token; Ctrl-C to quit)\n", url)
	if !*noOpen {
		openBrowser(url)
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

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "could not open a browser automatically; open the URL above manually")
		return
	}
	go cmd.Wait()
}
