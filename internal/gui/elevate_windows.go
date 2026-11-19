//go:build windows

package gui

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// relaunchElevated starts a copy of this program with administrator rights (the
// user sees the normal UAC prompt). The caller exits afterwards, so the new
// instance, which opens its own browser tab, replaces this one.
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var args []string
	for _, a := range os.Args[1:] {
		if a != "-no-open" && a != "--no-open" { // the new instance must open a browser
			args = append(args, syscall.EscapeArg(a))
		}
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))
	const swShowNormal = 1
	r, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, swShowNormal)
	if r <= 32 { // ShellExecute returns a value <= 32 on failure
		if r == 5 { // SE_ERR_ACCESSDENIED: the UAC prompt was declined
			return errors.New("administrator permission was not granted")
		}
		return errors.New("could not restart with administrator rights")
	}
	return nil
}
