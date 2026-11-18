// Command pktreplay analyses and replays PCAP/PCAPNG captures.
package main

import (
	"fmt"
	"os"
)

const usage = `pktreplay - streaming PCAP/PCAPNG analysis and replay

Usage:
  pktreplay stats  [flags] <capture>     one-pass summary statistics
  pktreplay index  [flags] <capture>     build a seek index for large files
  pktreplay replay [flags] <capture>     replay filtered packets (see 'replay -h')

Run 'pktreplay <command> -h' for the flags of each command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "stats":
		err = cmdStats(os.Args[2:])
	case "index":
		err = cmdIndex(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
