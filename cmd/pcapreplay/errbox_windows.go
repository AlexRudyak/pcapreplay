//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// reportError prints to stderr and, for the windowless GUI build (which has no
// console to show it on), also pops up a message box.
func reportError(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	if defaultCommand == "" {
		return
	}
	title, _ := syscall.UTF16PtrFromString("pcapreplay")
	text, err := syscall.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	const mbOK, mbIconError = 0x0, 0x10
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0,
		uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), mbOK|mbIconError)
}
