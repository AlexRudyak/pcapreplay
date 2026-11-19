// Package logx is a small leveled logger for the command line tools. A nil
// *Logger is valid and logs nothing, so library code can call it unconditionally;
// hot paths should still test Enabled once outside their loop.
package logx

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Level is how much detail is written. Higher levels include the lower ones.
type Level int

const (
	Quiet Level = iota // only the normal command output
	Info               // what is being done: settings, selection, progress, protocol milestones
	Debug              // why: per-conversation decisions, batches, TCP segment and ACK detail
	Trace              // everything: one line for every packet read
)

// String returns the level name used in flags and log lines.
func (l Level) String() string {
	switch l {
	case Info:
		return "info"
	case Debug:
		return "debug"
	case Trace:
		return "trace"
	}
	return "quiet"
}

// ParseLevel accepts quiet|info|debug|trace or 0-3.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "quiet", "off", "none", "0":
		return Quiet, nil
	case "info", "1":
		return Info, nil
	case "debug", "2":
		return Debug, nil
	case "trace", "3":
		return Trace, nil
	}
	return Quiet, fmt.Errorf("unknown log level %q (want quiet, info, debug or trace)", s)
}

// Logger writes timestamped lines to one writer.
type Logger struct {
	level Level
	mu    sync.Mutex
	w     io.Writer
}

// New returns a logger that writes lines at or below level to w.
func New(level Level, w io.Writer) *Logger { return &Logger{level: level, w: w} }

// Level returns the configured level (Quiet for a nil logger).
func (l *Logger) Level() Level {
	if l == nil {
		return Quiet
	}
	return l.level
}

// Enabled reports whether lines of level lv are written.
func (l *Logger) Enabled(lv Level) bool { return l != nil && lv <= l.level && lv > Quiet }

func (l *Logger) logf(lv Level, comp, format string, a ...any) {
	if !l.Enabled(lv) {
		return
	}
	line := fmt.Sprintf("%s %-5s %s: %s\n", time.Now().Format("15:04:05.000"), strings.ToUpper(lv.String()), comp, fmt.Sprintf(format, a...))
	l.mu.Lock()
	io.WriteString(l.w, line)
	l.mu.Unlock()
}

// Infof logs at Info level. comp is a short component name such as "replay" or "tcp".
func (l *Logger) Infof(comp, format string, a ...any) { l.logf(Info, comp, format, a...) }

// Debugf logs at Debug level.
func (l *Logger) Debugf(comp, format string, a ...any) { l.logf(Debug, comp, format, a...) }

// Tracef logs at Trace level (per packet).
func (l *Logger) Tracef(comp, format string, a ...any) { l.logf(Trace, comp, format, a...) }
