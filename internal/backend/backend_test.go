package backend

import (
	"net/netip"
	"testing"
)

func TestWinDivertGuardFilter(t *testing.T) {
	f := Flow{LocalIP: netip.MustParseAddr("10.0.0.2"), RemoteIP: netip.MustParseAddr("10.0.0.9"),
		LocalPort: 50000, RemotePort: 8080}
	want := "tcp and ((inbound and ip.SrcAddr == 10.0.0.9 and tcp.SrcPort == 8080 and tcp.DstPort == 50000)" +
		" or (outbound and tcp.Rst and ip.DstAddr == 10.0.0.9 and tcp.DstPort == 8080 and tcp.SrcPort == 50000))"
	if got := WinDivertGuardFilter(f); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	f.LocalIP, f.RemoteIP = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::9")
	if got := WinDivertGuardFilter(f); got[:30] != "tcp and ((inbound and ipv6.Src" {
		t.Fatalf("ipv6 filter wrong: %s", got)
	}
}

func TestNullBackendCounts(t *testing.T) {
	var n Null
	n.SendBatch([][]byte{make([]byte, 10), make([]byte, 20)})
	if n.Packets != 2 || n.Bytes != 30 {
		t.Fatalf("%+v", n)
	}
}

func TestLocalAddrFor(t *testing.T) {
	a, err := LocalAddrFor(netip.MustParseAddr("127.0.0.1"))
	if err != nil || !a.IsLoopback() {
		t.Fatalf("got %v %v", a, err)
	}
}
