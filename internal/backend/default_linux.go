//go:build linux

package backend

func platformDefault() Backend { return NewLinux() }
