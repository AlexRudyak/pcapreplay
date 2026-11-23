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
// user sees the normal UAC prompt). The copy does not open a browser itself: it
// writes its address to handoff, and the caller sends the current tab there.
// (A browser started from the elevated process would run elevated, which browsers
// often refuse, and handing a tokenised URL to explorer.exe does not work.)
func relaunchElevated(handoff string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var args []string
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		switch a {
		case "-no-open", "--no-open":
			continue
		case "-handoff", "--handoff":
			i++ // drop its value too
			continue
		}
		if strings.HasPrefix(a, "-handoff=") || strings.HasPrefix(a, "--handoff=") {
			continue
		}
		args = append(args, syscall.EscapeArg(a))
	}
	args = append(args, "-handoff", syscall.EscapeArg(handoff))
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
