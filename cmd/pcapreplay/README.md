# cmd/pcapreplay

The command-line program. One binary, several commands:

| Command | File | What it does |
|---|---|---|
| `stats` | `cmd_stats.go` | One-pass summary; also hosts the shared `-start/-count/-index` flags (`rangeFlags`) and the `index` command. |
| `conversations` (`convs`) | `cmd_conv.go` | Lists bidirectional conversations with copy-paste selectors. |
| `index` | `cmd_stats.go` | Builds a seek index. |
| `replay` | `cmd_replay.go` | Parses flags into a `replay.Config`, wires recording and logging, runs the UDP or TCP engine, prints the result. |
| `gui` | `cmd_gui.go`, `gui_instance.go` | Starts the web interface (or reopens the running one). |
| `version` | `main.go` | Prints the version. |

Complete flags: [README-CLI.md](../../README-CLI.md).

## Structure

* `main.go` dispatches on the first argument, handles crashes (`recoverCrash`: message + log + exit 3) and decides the
  default behaviour when started without arguments: the windowless `pcapreplay-gui.exe` build (`-X main.defaultCommand=gui`)
  and a console started by double-click both open the GUI.
* `logflags.go` registers `-v`, `-vv`, `-vvv`, `-log-level`, `-log-file` on every command and builds a `logx.Logger`.
* `gui_instance.go` implements **single-instance GUI**: a running GUI writes `gui-instance.json` (URL with token,
  pid, elevation) beside the history folder; a second launch with default options probes that URL, checks the
  `X-Pcapreplay` header and merely reopens the browser. An elevated launch does not reuse a non-elevated instance.
* Platform files: `console_*.go` (detects when the console window belongs to this process so errors are not lost on
  double-click), `log_*.go` (the GUI build writes `%LOCALAPPDATA%\pcapreplay\pcapreplay-gui.log`), `errbox_*.go` (a
  message box when there is no console).
* Link-time variables: `main.version`, `main.defaultCommand`.

## Conventions

* Errors are returned up to `main`, which prints `error: ...` (and a log hint) and exits with 1; usage errors exit 2.
* The transport mode is mandatory for `replay` and never guessed.
* Diagnostics go to stderr; results go to stdout, so output can be piped.

Uses: `replay`, `stats`, `conv`, `filter`, `pcapio`, `backend`, `record`, `gui`, `history`, `logx`.
