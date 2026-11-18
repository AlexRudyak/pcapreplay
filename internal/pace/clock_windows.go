//go:build windows

package pace

import (
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	procQPC  = kernel32.NewProc("QueryPerformanceCounter")
	procQPF  = kernel32.NewProc("QueryPerformanceFrequency")
	winmm    = syscall.NewLazyDLL("winmm.dll")
	procTBP  = winmm.NewProc("timeBeginPeriod")

	qpcFreq int64
	qpcBase int64
)

func init() {
	procQPF.Call(uintptr(unsafe.Pointer(&qpcFreq)))
	procQPC.Call(uintptr(unsafe.Pointer(&qpcBase)))
	// Ask for 1 ms system timer resolution so coarse time.Sleep calls wake up
	// close to their deadline; the final stretch is spun on the QPC anyway.
	procTBP.Call(1)
}

// nanotime returns monotonic nanoseconds from the QueryPerformanceCounter,
// whose resolution is ~100 ns. Go's own monotonic clock on Windows only
// advances at the system timer tick, which is far too coarse for µs pacing.
func nanotime() int64 {
	var c int64
	procQPC.Call(uintptr(unsafe.Pointer(&c)))
	c -= qpcBase
	// Split to avoid overflowing c*1e9.
	return c/qpcFreq*1_000_000_000 + c%qpcFreq*1_000_000_000/qpcFreq
}
