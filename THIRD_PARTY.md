# Third-party software

pktreplay itself has **no Go dependencies** (standard library only). The following external component is used at run
time on Windows and is **not part of this repository**.

## WinDivert

| | |
|---|---|
| Project | [WinDivert](https://github.com/basil00/WinDivert) by basil00 (Windows Packet Divert) |
| Source and releases | <https://github.com/basil00/WinDivert> and <https://github.com/basil00/WinDivert/releases> |
| Version used | 2.2.2 (`WinDivert-2.2.2-A.zip`) |
| Project site | <https://reqrypt.org/windivert.html> |
| License | Dual: GNU LGPL v3 or GNU GPL v2 (see the `LICENSE` file in the release) |
| Files | `WinDivert.dll`, `WinDivert64.sys` (x64) |

How it is used: `internal/backend/windows.go` loads `WinDivert.dll` at run time with `syscall.LazyDLL` (no cgo, no
linking) to inject and receive packets at the network layer.

How it is obtained:

* **Not committed here.** `.gitignore` excludes `WinDivert*.dll`, `WinDivert*.sys` and `installer/redist/`.
* `installer/fetch-windivert.ps1` downloads the official release asset from the upstream GitHub repository, verifies
  **pinned SHA-256 hashes**, the driver's Authenticode signature and the license text, and stages the files so the
  Windows installer can include them together with `WinDivert-LICENSE.txt`.
* Or place the two files next to `pktreplay.exe` yourself after downloading them from the official releases.

Licensing note: the binaries must be redistributed **unmodified** together with their license text. Some antivirus
products flag WinDivert because the same technique is abused by malware; only use binaries you downloaded from the
official repository.
