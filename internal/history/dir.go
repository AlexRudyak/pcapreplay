package history

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDir returns the per-user directory for the history database:
//
//	Windows  %LOCALAPPDATA%\pcapreplay\history
//	macOS    ~/Library/Application Support/pcapreplay/history
//	other    $XDG_DATA_HOME/pcapreplay/history  (default ~/.local/share)
//
// The PCAPREPLAY_DATA environment variable overrides it.
//
// The program used to be called pktreplay. A history folder (and the PKTREPLAY_DATA
// variable) left by that version is still honoured: the folder is moved to the new
// location the first time the new version runs, so nothing is lost.
func DefaultDir() (string, error) {
	if d := os.Getenv("PCAPREPLAY_DATA"); d != "" {
		return d, nil
	}
	if d := os.Getenv("PKTREPLAY_DATA"); d != "" { // legacy name
		return d, nil
	}
	dir, err := dirFor("pcapreplay")
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if old, oerr := dirFor("pktreplay"); oerr == nil {
			if _, serr := os.Stat(old); serr == nil {
				if os.MkdirAll(filepath.Dir(dir), 0o700) == nil && os.Rename(old, dir) != nil {
					return old, nil // could not move it: keep using it where it is
				}
			}
		}
	}
	return dir, nil
}

// dirFor builds the per-user data directory for the application folder name app.
func dirFor(app string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			var err error
			if base, err = os.UserCacheDir(); err != nil {
				return "", err
			}
		}
		return filepath.Join(base, app, "history"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", app, "history"), nil
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, app, "history"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot determine a data directory (set PCAPREPLAY_DATA)")
	}
	return filepath.Join(home, ".local", "share", app, "history"), nil
}
