//go:build linux

package backend

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// installRSTDrop stops the local kernel from killing a raw-socket TCP flow.
//
// The kernel knows nothing about connections we build by hand, so when the
// server's SYN-ACK (or any later segment) arrives it answers with a RST. We
// drop those outbound RSTs, matching only this flow's 4-tuple. nftables is
// preferred; iptables is the fallback. The returned function removes the rule.
func installRSTDrop(f Flow) (func() error, error) {
	proto := "ip"
	if f.LocalIP.Is6() {
		proto = "ip6"
	}
	if nft, err := exec.LookPath("nft"); err == nil {
		table := fmt.Sprintf("pcapreplay_%d", os.Getpid())
		script := fmt.Sprintf(`add table inet %[1]s
add chain inet %[1]s out { type filter hook output priority -10; policy accept; }
add rule inet %[1]s out %[2]s saddr %[3]s %[2]s daddr %[4]s tcp sport %[5]d tcp dport %[6]d tcp flags & rst == rst drop
`, table, proto, f.LocalIP, f.RemoteIP, f.LocalPort, f.RemotePort)
		cmd := exec.Command(nft, "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("nft failed (need root?): %v: %s", err, bytes.TrimSpace(out))
		}
		return func() error {
			out, err := exec.Command(nft, "delete", "table", "inet", table).CombinedOutput()
			if err != nil {
				return fmt.Errorf("nft delete table: %v: %s", err, bytes.TrimSpace(out))
			}
			return nil
		}, nil
	}
	ipt := "iptables"
	if f.LocalIP.Is6() {
		ipt = "ip6tables"
	}
	path, err := exec.LookPath(ipt)
	if err != nil {
		return nil, fmt.Errorf("neither nft nor %s found; add this rule manually and rerun with --no-firewall:\n  "+
			"nft add rule inet filter output %s daddr %s tcp sport %d tcp flags rst drop", ipt, proto, f.RemoteIP, f.LocalPort)
	}
	rule := []string{"OUTPUT", "-p", "tcp", "-s", f.LocalIP.String(), "-d", f.RemoteIP.String(),
		"--sport", fmt.Sprint(f.LocalPort), "--dport", fmt.Sprint(f.RemotePort), "--tcp-flags", "RST", "RST", "-j", "DROP"}
	if out, err := exec.Command(path, append([]string{"-I"}, rule...)...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s failed (need root?): %v: %s", ipt, err, bytes.TrimSpace(out))
	}
	return func() error {
		out, err := exec.Command(path, append([]string{"-D"}, rule...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s -D: %v: %s", ipt, err, bytes.TrimSpace(out))
		}
		return nil
	}, nil
}
