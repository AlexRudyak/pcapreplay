//go:build windows

package backend

import (
	"testing"
	"unsafe"
)

// The WinDivert ABI is fixed: WINDIVERT_ADDRESS must be exactly 80 bytes.
func TestDivertAddrLayout(t *testing.T) {
	if s := unsafe.Sizeof(divertAddr{}); s != 80 {
		t.Fatalf("divertAddr is %d bytes, want 80", s)
	}
	var a divertAddr
	if off := unsafe.Offsetof(a.IfIdx); off != 16 {
		t.Fatalf("IfIdx offset %d, want 16", off)
	}
}
