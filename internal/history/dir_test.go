package history

import (
	"os"
	"path/filepath"
	"testing"
)

// isolate points every per-user location at a temporary directory.
func isolate(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, k := range []string{"LOCALAPPDATA", "XDG_DATA_HOME", "HOME", "USERPROFILE"} {
		t.Setenv(k, root)
	}
	t.Setenv("PCAPREPLAY_DATA", "")
	t.Setenv("PKTREPLAY_DATA", "")
	return root
}

func TestDefaultDirMovesAFolderLeftByTheOldName(t *testing.T) {
	isolate(t)
	old, err := dirFor("pktreplay")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "history.jsonl"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := dirFor("pcapreplay")
	if got != want {
		t.Fatalf("DefaultDir = %q, want %q", got, want)
	}
	if b, err := os.ReadFile(filepath.Join(got, "history.jsonl")); err != nil || string(b) != "x\n" {
		t.Fatalf("history was not moved: %v %q", err, b)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the old folder should be gone after the move")
	}
}

func TestDefaultDirFreshInstallAndEnvironmentOverrides(t *testing.T) {
	isolate(t)
	want, _ := dirFor("pcapreplay")
	if got, err := DefaultDir(); err != nil || got != want {
		t.Fatalf("fresh: %q %v", got, err)
	}
	t.Setenv("PKTREPLAY_DATA", "/legacy")
	if got, _ := DefaultDir(); got != "/legacy" {
		t.Fatalf("the legacy variable must still work: %q", got)
	}
	t.Setenv("PCAPREPLAY_DATA", "/new")
	if got, _ := DefaultDir(); got != "/new" {
		t.Fatalf("the new variable must win: %q", got)
	}
}
