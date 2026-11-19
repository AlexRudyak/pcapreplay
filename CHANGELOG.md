# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0]

First public version.

### Added
- Streaming PCAP/PCAPNG reader with a sparse seek index; zero-allocation header decoder; cost-ordered boolean filters.
- `stats` and `conversations` commands with bounded-memory statistics.
- `replay` in explicit UDP and TCP modes: real TCP handshake, sequence rebasing for mid-stream captures,
  retransmission, FIN close; per-conversation rewrite rules; pooled mutation with checksum repair.
- Precision pacing (original timing, delay, pps, Mbit/s, burst) with a QueryPerformanceCounter clock on Windows.
- Linux `AF_PACKET` + `sendmmsg` backend with nftables/iptables RST suppression, Windows WinDivert backend,
  null (dry-run) backend.
- Recording of transmitted traffic to PCAP/PCAPNG.
- Local web GUI with history of runs and a library of sent pcap files.
- Leveled diagnostic logging (`-v`, `-vv`, `-vvv`, `-log-level`, `-log-file`).
- Single-instance GUI: starting it again reopens the running one.
- Windows installer (Inno Setup) with optional bundled WinDivert.
- Documentation: top-level README, CLI reference, architecture notes and a README for every package.

[Unreleased]: https://github.com/AlexRudyak/pktreplay/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AlexRudyak/pktreplay/releases/tag/v0.1.0
