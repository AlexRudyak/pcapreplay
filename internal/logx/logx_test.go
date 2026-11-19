package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestLevelsFilterAndNilIsSafe(t *testing.T) {
	var nilLog *Logger
	nilLog.Infof("x", "ignored")
	if nilLog.Enabled(Info) || nilLog.Level() != Quiet {
		t.Fatal("nil logger must be disabled")
	}
	var b bytes.Buffer
	l := New(Debug, &b)
	l.Infof("a", "one %d", 1)
	l.Debugf("b", "two")
	l.Tracef("c", "three")
	out := b.String()
	if !strings.Contains(out, "INFO  a: one 1") || !strings.Contains(out, "DEBUG b: two") || strings.Contains(out, "three") {
		t.Fatalf("output:\n%s", out)
	}
	if New(Quiet, &b).Enabled(Info) {
		t.Fatal("quiet logs nothing")
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"": Quiet, "INFO": Info, "2": Debug, "trace": Trace, "off": Quiet} {
		if got, err := ParseLevel(in); err != nil || got != want {
			t.Errorf("%q -> %v %v", in, got, err)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Fatal("unknown level must fail")
	}
}
