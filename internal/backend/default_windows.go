//go:build windows

package backend

func platformDefault() Backend { return NewWindows() }
