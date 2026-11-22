//go:build windows

package backend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// WinDivert constants (WinDivert 2.2 ABI).
const (
	wdLayerNetwork   = 0
	wdFlagSendOnly   = 8
	wdAddrOutbound   = 1 << 17 // WINDIVERT_ADDRESS bit-field positions in Flags
	wdAddrIPv6       = 1 << 20
	wdAddrIPChecksum = 1 << 21
	wdAddrTCPCksum   = 1 << 22
	wdAddrUDPCksum   = 1 << 23
	wdBatchMax       = 128
)

// divertAddr mirrors WINDIVERT_ADDRESS (80 bytes). Layer/Event/flag bit-fields
// are packed into Flags; the union is reduced to the network-layer view.
type divertAddr struct {
	Timestamp int64
	Flags     uint32 // Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1 IPCsum:1 TCPCsum:1 UDPCsum:1 ...
	Reserved2 uint32
	IfIdx     uint32
	SubIfIdx  uint32
	_         [56]byte
}

// Windows injects and captures packets through the WinDivert driver.
type Windows struct {
	opts Options
	dll  *syscall.LazyDLL

	pOpen, pRecv, pSendEx, pClose, pCalc *syscall.LazyProc

	sender uintptr // send-only handle (filter "false")

	mu       sync.Mutex
	guard    uintptr
	rx       chan []byte
	guarding atomic.Bool
	rstDrops atomic.Uint64

	sbuf  []byte
	saddr []divertAddr
}

// NewWindows returns an unopened WinDivert backend.
func NewWindows() *Windows { return &Windows{} }

// Name implements Backend.
func (w *Windows) Name() string { return "windows-windivert" }

// RSTsDropped reports how many outbound RSTs of the guarded flow were swallowed.
func (w *Windows) RSTsDropped() uint64 { return w.rstDrops.Load() }

// Open loads WinDivert.dll and opens the network-layer send handle. It reports a readable
// error when the DLL or driver is missing or the process is not elevated.
func (w *Windows) Open(o Options) error {
	w.opts = o
	if o.Target.IsLoopback() {
		return errors.New("windows backend: loopback targets are not supported by WinDivert network-layer " +
			"injection; use a real interface address or the Linux backend")
	}
	// Prefer the DLL next to the executable so a planted DLL in the working
	// directory is never picked up.
	name := "WinDivert.dll"
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), name); fileExists(p) {
			name = p
		}
	}
	w.dll = syscall.NewLazyDLL(name)
	if err := w.dll.Load(); err != nil {
		return fmt.Errorf("cannot load WinDivert.dll (place WinDivert.dll and WinDivert64.sys next to pcapreplay.exe): %w", err)
	}
	w.pOpen = w.dll.NewProc("WinDivertOpen")
	w.pRecv = w.dll.NewProc("WinDivertRecv")
	w.pSendEx = w.dll.NewProc("WinDivertSendEx")
	w.pClose = w.dll.NewProc("WinDivertClose")
	w.pCalc = w.dll.NewProc("WinDivertHelperCalcChecksums")

	h, err := w.open("false", wdFlagSendOnly)
	if err != nil {
		return err
	}
	w.sender = h
	w.sbuf = make([]byte, 0, wdBatchMax*2048)
	w.saddr = make([]divertAddr, wdBatchMax)
	return nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// open opens one WinDivert handle with the given filter and flags.
func (w *Windows) open(filter string, flags uint64) (uintptr, error) {
	fp, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	h, _, e := w.pOpen.Call(uintptr(unsafe.Pointer(fp)), wdLayerNetwork, 0, uintptr(flags))
	if h == ^uintptr(0) {
		switch e {
		case syscall.Errno(5):
			return 0, errors.New("WinDivertOpen: access denied - run from an elevated (Administrator) prompt")
		case syscall.Errno(2):
			return 0, errors.New("WinDivertOpen: driver file not found - WinDivert64.sys must sit next to WinDivert.dll")
		case syscall.Errno(577):
			return 0, errors.New("WinDivertOpen: driver signature rejected - use an official signed WinDivert 2.2 release")
		case syscall.Errno(87):
			return 0, fmt.Errorf("WinDivertOpen: invalid filter %q", filter)
		}
		return 0, fmt.Errorf("WinDivertOpen(%q): %w", filter, e)
	}
	return h, nil
}

// SendBatch injects IP datagrams on the outbound path using WinDivertSendEx.
func (w *Windows) SendBatch(pkts [][]byte) (int, error) {
	sent := 0
	for sent < len(pkts) {
		n := len(pkts) - sent
		if n > wdBatchMax {
			n = wdBatchMax
		}
		w.sbuf = w.sbuf[:0]
		// Concatenate first: appending may reallocate, so take addresses afterwards.
		var tmp [wdBatchMax + 1]int // stack array: no per-batch allocation
		offs := tmp[:0]
		for i := 0; i < n; i++ {
			offs = append(offs, len(w.sbuf))
			w.sbuf = append(w.sbuf, pkts[sent+i]...)
		}
		offs = append(offs, len(w.sbuf))
		for i := 0; i < n; i++ {
			a := &w.saddr[i]
			*a = divertAddr{IfIdx: w.opts.IfIndex, Flags: wdAddrOutbound}
			p := w.sbuf[offs[i]:offs[i+1]]
			if len(p) > 0 && p[0]>>4 == 6 {
				a.Flags |= wdAddrIPv6
			}
			// Let WinDivert validate/refresh checksums and set the address
			// checksum flags so the stack does not treat them as offloaded.
			w.pCalc.Call(uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), uintptr(unsafe.Pointer(a)), 0)
		}
		var out uint32
		r, _, e := w.pSendEx.Call(w.sender, uintptr(unsafe.Pointer(&w.sbuf[0])), uintptr(len(w.sbuf)),
			uintptr(unsafe.Pointer(&out)), 0, uintptr(unsafe.Pointer(&w.saddr[0])),
			uintptr(n)*unsafe.Sizeof(divertAddr{}), 0)
		if r == 0 {
			return sent, fmt.Errorf("WinDivertSendEx: %w", e)
		}
		sent += n
	}
	return sent, nil
}

// Guard opens the capture handle for the flow and starts the reader that
// delivers inbound packets to Recv and swallows outbound RSTs.
func (w *Windows) Guard(f Flow) (func() error, error) {
	h, err := w.open(WinDivertGuardFilter(f), 0)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	w.guard = h
	w.rx = make(chan []byte, 1024)
	rx := w.rx
	w.mu.Unlock()
	w.guarding.Store(true)
	go w.readLoop(h, rx)
	return func() error {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.guard != 0 {
			w.guarding.Store(false)
			w.pClose.Call(w.guard) // unblocks the reader
			w.guard = 0
		}
		return nil
	}, nil
}

// readLoop receives diverted packets from h and queues them on rx until the handle closes.
func (w *Windows) readLoop(h uintptr, rx chan<- []byte) {
	defer close(rx)
	buf := make([]byte, 65535+64)
	var addr divertAddr
	for {
		var n uint32
		r, _, _ := w.pRecv.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&addr)))
		if r == 0 {
			return // handle closed or fatal error
		}
		if addr.Flags&wdAddrOutbound != 0 {
			w.rstDrops.Add(1) // outbound RST from the OS stack: not reinjected
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case rx <- pkt:
		case <-time.After(time.Second):
			if !w.guarding.Load() {
				return
			}
		}
	}
}

// Recv returns the next diverted inbound packet of the guarded flow, or ErrTimeout.
func (w *Windows) Recv(buf []byte, timeout time.Duration) (int, error) {
	w.mu.Lock()
	rx := w.rx
	w.mu.Unlock()
	if rx == nil {
		return 0, errors.New("windows backend: Recv before Guard")
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case p, ok := <-rx:
		if !ok {
			return 0, errors.New("windows backend: capture handle closed")
		}
		return copy(buf, p), nil
	case <-t.C:
		return 0, ErrTimeout
	}
}

// Close closes every WinDivert handle that is still open.
func (w *Windows) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.guard != 0 {
		w.guarding.Store(false)
		w.pClose.Call(w.guard)
		w.guard = 0
	}
	if w.sender != 0 {
		w.pClose.Call(w.sender)
		w.sender = 0
	}
	return nil
}
