package backend

import "fmt"

// WinDivertGuardFilter builds the WinDivert filter used for a guarded TCP flow.
// It is platform independent so it can be unit-tested everywhere.
//
//   - inbound packets of the flow are diverted to us and never reach the
//     Windows TCP/IP stack, so the stack can never answer them with a RST;
//   - outbound RST segments of the flow (anything the stack still manages to
//     generate) are captured so they can be dropped instead of reinjected.
func WinDivertGuardFilter(f Flow) string {
	ip := "ip"
	if f.LocalIP.Is6() {
		ip = "ipv6"
	}
	return fmt.Sprintf("tcp and ((inbound and %[1]s.SrcAddr == %[2]s and tcp.SrcPort == %[3]d and tcp.DstPort == %[4]d)"+
		" or (outbound and tcp.Rst and %[1]s.DstAddr == %[2]s and tcp.DstPort == %[3]d and tcp.SrcPort == %[4]d))",
		ip, f.RemoteIP, f.RemotePort, f.LocalPort)
}
