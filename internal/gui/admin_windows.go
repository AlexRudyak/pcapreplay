//go:build windows

package gui

import (
	"syscall"
	"unsafe"
)

// IsElevated reports whether the process runs with administrator rights.
func IsElevated() bool { return isElevated() }

// isElevated reports whether the process runs with an elevated (admin) token.
func isElevated() bool {
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	var elevated, ret uint32
	const tokenElevation = 20
	if err := syscall.GetTokenInformation(tok, tokenElevation, (*byte)(unsafe.Pointer(&elevated)), 4, &ret); err != nil {
		return false
	}
	return elevated != 0
}
