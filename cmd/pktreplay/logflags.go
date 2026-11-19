package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sasha/pktreplay/internal/logx"
)

// levelFlag is a boolean-style flag that raises the log level to a fixed value
// (-v = info, -vv = debug, -vvv = trace).
type levelFlag struct {
	dst *logx.Level
	lv  logx.Level
}

func (f levelFlag) String() string   { return "" }
func (f levelFlag) IsBoolFlag() bool { return true }
func (f levelFlag) Set(s string) error {
	if s == "true" && f.lv > *f.dst {
		*f.dst = f.lv
	}
	return nil
}

// logFlags are the diagnostics flags shared by every command.
type logFlags struct {
	level   logx.Level
	named   string
	file    string
	closeFn func()
}

func (l *logFlags) register(fs *flag.FlagSet) {
	fs.Var(levelFlag{&l.level, logx.Info}, "v", "log what is being done (same as -log-level info)")
	fs.Var(levelFlag{&l.level, logx.Debug}, "vv", "also log decisions and protocol detail (same as -log-level debug)")
	fs.Var(levelFlag{&l.level, logx.Trace}, "vvv", "also log every packet (same as -log-level trace; very verbose)")
	fs.StringVar(&l.named, "log-level", "", "diagnostic detail on stderr: quiet (default), info, debug or trace")
	fs.StringVar(&l.file, "log-file", "", "also write the diagnostic log to this file (appended)")
}

// build returns the logger. Call the returned close function when the command ends.
// With no level selected the logger is nil, which costs nothing.
func (l *logFlags) build() (*logx.Logger, func(), error) {
	lv := l.level
	if l.named != "" {
		n, err := logx.ParseLevel(l.named)
		if err != nil {
			return nil, func() {}, err
		}
		if n > lv {
			lv = n
		}
	}
	if lv == logx.Quiet {
		return nil, func() {}, nil
	}
	var w io.Writer = os.Stderr
	closeFn := func() {}
	if l.file != "" {
		f, err := os.OpenFile(l.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, closeFn, fmt.Errorf("-log-file: %w", err)
		}
		w = io.MultiWriter(os.Stderr, f)
		closeFn = func() { f.Close() }
	}
	lg := logx.New(lv, w)
	lg.Infof("log", "level=%s", lv)
	return lg, closeFn, nil
}
