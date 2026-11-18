//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var procGetConsoleProcessList = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// consoleSoleOwner reports whether this process is the only one attached to its
// console. That is the case when the exe was double-clicked or started with
// "Run as administrator": Windows creates a fresh console for it, and the window
// disappears the moment the program exits. From a terminal the shell shares the
// console, so the count is at least 2.
func consoleSoleOwner() bool {
	var ids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return n == 1
}

// holdWindow keeps a console we own open so its message can be read.
func holdWindow() {
	if !ownConsole {
		return
	}
	fmt.Fprint(os.Stderr, "\nPress Enter to close this window...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
