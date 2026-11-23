# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Started from the Start Menu or by double-click, the GUI now exits by itself about 90 seconds after its last browser tab
  is closed (not while a replay is running), instead of staying in the background until sign-out. Started from a
  terminal (`pcapreplay gui`) it still runs until Ctrl-C.

### Fixed
- "Restart as administrator" and reopening the GUI from **pcapreplay (Administrator)** opened the Documents folder
  instead of the browser. The tab now switches to the restarted program.
- Leftovers on exit: restarting as administrator, closing the console window, sign-out and shutdown now shut down
  cleanly (history closed, `gui-instance.json` removed), and no temporary files are left in the temp folder.

## [0.2.0]

### Changed
- **The project is now called `pcapreplay`** (it was `pktreplay`). The command, executables
  (`pcapreplay.exe`, `pcapreplay-gui.exe`), Go module (`github.com/AlexRudyak/pcapreplay`), installer, documentation and the
  `PCAPREPLAY_DATA` environment variable were renamed. GitHub redirects the old repository address.
- An existing history folder from 0.1.x is moved to the new location automatically the first time the GUI starts, and the
  old `PKTREPLAY_DATA` variable is still honoured. The installer removes the old program files when upgrading.

### Fixed
- A data race between the analysis job and the GUI status poll (found by the race detector).

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

[Unreleased]: https://github.com/AlexRudyak/pcapreplay/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/AlexRudyak/pcapreplay/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/AlexRudyak/pcapreplay/releases/tag/v0.1.0
