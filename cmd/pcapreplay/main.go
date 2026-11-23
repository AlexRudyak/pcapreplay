// Command pcapreplay analyses and replays PCAP/PCAPNG captures.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

// Set at build time with -ldflags "-X main.version=... -X main.defaultCommand=gui".
// defaultCommand is used when no command is given: the windowless pcapreplay-gui
// build sets it to "gui" so that double-clicking the exe opens the interface.
var (
	version        = "0.2.0"
	defaultCommand = ""
)

// ownConsole is true when the console window belongs to this process alone
// (exe double-clicked or "Run as administrator"), so it must not vanish before
// the user can read what it printed.
var ownConsole bool

const usage = `pcapreplay - streaming PCAP/PCAPNG analysis and replay

Usage:
  pcapreplay stats  [flags] <capture>     one-pass summary statistics
  pcapreplay conversations [flags] <capture>  list bidirectional conversations
  pcapreplay index  [flags] <capture>     build a seek index for large files
  pcapreplay replay [flags] <capture>     replay filtered packets (see 'replay -h')
  pcapreplay gui    [-no-open]            local web GUI (loopback only, token protected)
  pcapreplay version                      print the version

Run 'pcapreplay <command> -h' for the flags of each command.
Started without arguments from Explorer, pcapreplay opens the GUI.
`

// recoverCrash turns a panic into a visible message and a log entry instead of a
// window that silently disappears.
func recoverCrash() {
	if r := recover(); r != nil {
		msg := fmt.Sprintf("pcapreplay crashed: %v", r)
		fmt.Fprintf(os.Stderr, "%s\n%s\n", msg, debug.Stack())
		if logPath != "" {
			msg += "\n\nDetails: " + logPath
		}
		reportError(msg)
		holdWindow()
		os.Exit(3)
	}
}

// main dispatches to the sub-command; with no arguments from Explorer it opens the GUI.
func main() {
	initLogging()
	defer recoverCrash()
	args := os.Args
	if defaultCommand != "" && (len(args) < 2 || strings.HasPrefix(args[1], "-")) {
		args = append([]string{args[0], defaultCommand}, args[1:]...)
	} else if len(args) < 2 && consoleSoleOwner() {
		// Double-clicked (or "Run as administrator") with no arguments: opening the GUI is
		// far more useful than printing usage into a window that closes at once.
		args = []string{args[0], "gui"}
		ownConsole = true
	} else if len(args) >= 2 && (args[1] == "-handoff" || args[1] == "--handoff") {
		// The GUI's "Restart as administrator" relaunches a double-clicked console exe with only
		// its internal -handoff flag added: treat it like the double-click it replaces.
		args = append([]string{args[0], "gui"}, args[1:]...)
		ownConsole = consoleSoleOwner()
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
		fmt.Println("pcapreplay", version)
		return
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		reportError(fmt.Sprintf("unknown command %q\n\n%s", args[1], usage))
		holdWindow()
		os.Exit(2)
	}
	if err != nil {
		msg := "error: " + err.Error()
		if logPath != "" {
			msg += "\n\nDetails: " + logPath
		}
		reportError(msg)
		holdWindow()
		os.Exit(1)
	}
}
