// Command pktreplay analyses and replays PCAP/PCAPNG captures.
package main

import (
	"fmt"
	"os"
	"strings"
)

// Set at build time with -ldflags "-X main.version=... -X main.defaultCommand=gui".
// defaultCommand is used when no command is given: the windowless pktreplay-gui
// build sets it to "gui" so that double-clicking the exe opens the interface.
var (
	version        = "0.1.0"
	defaultCommand = ""
)

const usage = `pktreplay - streaming PCAP/PCAPNG analysis and replay

Usage:
  pktreplay stats  [flags] <capture>     one-pass summary statistics
  pktreplay conversations [flags] <capture>  list bidirectional conversations
  pktreplay index  [flags] <capture>     build a seek index for large files
  pktreplay replay [flags] <capture>     replay filtered packets (see 'replay -h')
  pktreplay gui    [-no-open]            local web GUI (loopback only, token protected)
  pktreplay version                      print the version

Run 'pktreplay <command> -h' for the flags of each command.
`

func main() {
	args := os.Args
	if defaultCommand != "" && (len(args) < 2 || strings.HasPrefix(args[1], "-")) {
		args = append([]string{args[0], defaultCommand}, args[1:]...)
	}
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch args[1] {
	case "stats":
		err = cmdStats(args[2:])
	case "conversations", "convs":
		err = cmdConversations(args[2:])
	case "gui":
		err = cmdGUI(args[2:])
	case "replay":
		err = cmdReplay(args[2:])
	case "index":
		err = cmdIndex(args[2:])
	case "version", "-v", "--version":
		fmt.Println("pktreplay", version)
		return
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		reportError(fmt.Sprintf("unknown command %q\n\n%s", args[1], usage))
		os.Exit(2)
	}
	if err != nil {
		reportError("error: " + err.Error())
		os.Exit(1)
	}
}
