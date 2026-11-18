//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// logPath is set when the windowless GUI build redirects its output to a file.
var logPath string

// initLogging gives the windowless GUI build somewhere to write: without a
// console, errors and Go runtime panics would otherwise vanish. stderr (both the
// os.Stderr file and the process's standard error handle, which the Go runtime
// uses for fatal errors) is pointed at %LOCALAPPDATA%\pktreplay\pktreplay-gui.log.
func initLogging() {
	if defaultCommand != "gui" {
		return
	}
	dir, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return
	}
	dir = filepath.Join(dir, "pktreplay")
	if os.MkdirAll(dir, 0o755) != nil {
		return
	}
	p := filepath.Join(dir, "pktreplay-gui.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 1<<20 {
		os.Remove(p) // keep the log small
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	const stdErrorHandle = ^uintptr(11) // STD_ERROR_HANDLE = (DWORD)-12
	syscall.NewLazyDLL("kernel32.dll").NewProc("SetStdHandle").Call(stdErrorHandle, f.Fd())
	os.Stderr = f
	logPath = p
	fmt.Fprintf(f, "\n=== %s pktreplay %s started (pid %d, args %q) ===\n", time.Now().Format(time.RFC3339), version, os.Getpid(), os.Args[1:])
}
