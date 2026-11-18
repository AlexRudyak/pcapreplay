//go:build !windows

package gui

import "os"

// isElevated reports whether the process is root.
func isElevated() bool { return os.Geteuid() == 0 }

// IsElevated reports whether the process runs with administrator/root rights.
func IsElevated() bool { return isElevated() }
