# internal/backend

The seam between the platform-independent replay engine and the operating system's raw networking.

```go
type Backend interface {
    Name() string
    Open(Options) error
    SendBatch(pkts [][]byte) (int, error)      // IP datagrams, no link header
    Guard(f Flow) (release func() error, err error)
    Recv(buf []byte, timeout time.Duration) (int, error)
    Close() error
}
```

`ByName("auto" | "null")` returns the platform default or the dry-run backend. `Options` carries the interface,
the target address (for route/MAC discovery), MAC overrides, the WinDivert interface index and `NoFirewall`.

| Backend | File | How it injects |
|---|---|---|
| **Linux** | `linux.go`, `linux_fw.go`, `sendmmsg_*.go` | `AF_PACKET` `SOCK_RAW`; the Ethernet header is added per batch and frames are sent with `sendmmsg(2)` (up to 256 per call; the syscall number differs per architecture: `sendmmsg_amd64.go`, `_386.go`, `_other.go`). The egress interface and source MAC come from the routing choice; the next-hop MAC from `/proc/net/arp`, the default gateway, or an ARP probe (`-dst-mac` overrides). |
| **Windows** | `windows.go`, `windivert_filter.go` | [WinDivert](https://github.com/basil00/WinDivert)'s `WinDivert.dll` loaded lazily with `syscall.LazyDLL` (no cgo). Network-layer, outbound `WinDivertSendEx`, up to 128 packets per call; receive handle with a flow filter. |
| **Null** | `backend.go` | Discards packets and reports them as sent: a dry run with zero privileges, also used to benchmark the pipeline. |

## `Guard`: keeping the OS out of the way

A raw-injected TCP connection is unknown to the host's TCP stack, which answers the server's replies with RST and
kills the session. `Guard(flow)` prevents that and starts delivering the flow's inbound packets to `Recv`:

* **Linux:** a temporary `nft` table (`pktreplay_<pid>`) dropping the *outbound* RSTs of exactly that 4-tuple, falling
  back to `iptables`/`ip6tables`; a second `AF_PACKET` socket filtered to the tuple receives the replies (frames the
  kernel itself sent, `PACKET_OUTGOING`, are ignored). `release()` removes the rule. `-no-firewall` skips the rule.
* **Windows:** the flow's *inbound* segments are **diverted** to pktreplay so the stack never sees them (and never
  resets); any outbound RST of the flow is captured and discarded (`WinDivertGuardFilter`).

## Requirements

Linux: root or `CAP_NET_RAW` (+ `CAP_NET_ADMIN` for the firewall rule). Windows: Administrator and `WinDivert.dll` +
`WinDivert64.sys` beside the executable. WinDivert network-layer injection cannot target loopback; the Windows backend
rejects it. See the top-level README for setup.

## Tests

`backend_test.go` (null backend, selection, interface behaviour) and `windows_test.go` (WinDivert struct layout, the
guard filter text, and the friendly errors) run everywhere they compile. **The WinDivert raw-injection path has not been
exercised against the driver by the author**; the Linux path is verified end to end by `scripts/e2e-*.sh`.

Used by: `replay`, `record`, `gui`, `cmd/pktreplay`.
