# Security policy

## Supported versions

Security fixes go into the latest release and the `main` branch.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private vulnerability reporting
(*Security* tab -> *Report a vulnerability*) so the details stay private until a fix is available. Include the version,
the operating system, how to reproduce the issue and, if you can, a minimal capture file that triggers it (without
private data).

You can expect an acknowledgement within a few days. Valid reports will be fixed and credited unless you prefer
otherwise.

## What is in scope

* Memory-safety or logic errors when parsing **capture files** (PCAP/PCAPNG) or decoding packets: crashes, hangs,
  out-of-bounds access, unbounded memory growth.
* The **local web interface**: authentication or origin-check bypasses, path traversal through the history/library API,
  DNS-rebinding or cross-site request issues, injection through exported files (CSV, JSON).
* Privilege-related mistakes in the Windows installer or in the Linux firewall-rule handling (for example a rule that is
  not removed, or a rule broader than the replayed 4-tuple).

## Design notes useful to reporters

* The GUI listens on loopback only and requires a random per-launch token (`internal/gui`).
* Capture files are treated as untrusted input throughout (`internal/pcapio`, `internal/decode`).
* pcapreplay is a tool for transmitting traffic. Misuse (replaying onto networks you do not control) is not a
  vulnerability of the software.
