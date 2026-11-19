package history

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDir returns the per-user directory for the history database:
//
//	Windows  %LOCALAPPDATA%\pktreplay\history
//	macOS    ~/Library/Application Support/pktreplay/history
//	other    $XDG_DATA_HOME/pktreplay/history  (default ~/.local/share)
//
// The PKTREPLAY_DATA environment variable overrides it.
func DefaultDir() (string, error) {
	if d := os.Getenv("PKTREPLAY_DATA"); d != "" {
		return d, nil
	}
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			var err error
			if base, err = os.UserCacheDir(); err != nil {
				return "", err
			}
		}
		return filepath.Join(base, "pktreplay", "history"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "pktreplay", "history"), nil
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "pktreplay", "history"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot determine a data directory (set PKTREPLAY_DATA)")
	}
	return filepath.Join(home, ".local", "share", "pktreplay", "history"), nil
}
