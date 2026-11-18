//go:build !linux && !windows

package backend

// platformDefault is nil where no raw-injection backend exists.
func platformDefault() Backend { return nil }
