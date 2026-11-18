package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/sasha/pktreplay/internal/conv"
	"github.com/sasha/pktreplay/internal/filter"
	"github.com/sasha/pktreplay/internal/pcapio"
	"github.com/sasha/pktreplay/internal/stats"
)

func cmdConversations(args []string) error {
	fs := flag.NewFlagSet("conversations", flag.ExitOnError)
	var rf rangeFlags
	rf.register(fs)
	expr := fs.String("filter", "", "only count packets matching this filter expression")
	top := fs.Int("top", 50, "number of conversations to list (0 = all tracked)")
	sortBy := fs.String("sort", conv.ByBytes, "sort order: bytes, packets or time (first appearance)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: pktreplay conversations [flags] <capture>

Lists the bidirectional conversations in a capture in one streaming pass. The
SELECTOR column can be pasted into 'replay -conv', e.g.

  pktreplay replay -mode udp -conv "udp/10.0.0.1:5000/10.0.0.2:53,server-ip=172.16.0.9" capture.pcap

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("a capture file is required")
	}
	switch *sortBy {
	case conv.ByBytes, conv.ByPackets, conv.ByTime:
	default:
		return fmt.Errorf("-sort must be bytes, packets or time")
	}
	flt, err := filter.Parse(*expr)
	if err != nil {
		return err
	}
	path := fs.Arg(0)
	st, rd, err := stats.ScanWith(context.Background(), path, flt,
		func(r *pcapio.Reader) error { return rf.position(r, path) }, rf.count, nil, true)
	if rd != nil {
		defer rd.Close()
	}
	if err != nil {
		return err
	}
	rows := st.ConvRows(*top, *sortBy)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tSELECTOR (proto/client/server)\tPKTS\tC>S\tS>C\tBYTES\tDURATION\tSTATE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n", r.ID, r.Selector, r.Packets, r.C2SPackets, r.S2CPackets, r.Bytes,
			(time.Duration(r.DurationSec * float64(time.Second))).Round(time.Millisecond), r.State)
	}
	tw.Flush()
	fmt.Printf("\n%d conversations tracked, %d shown", st.Convs.Len(), len(rows))
	if u := st.Convs.Untracked; u > 0 {
		fmt.Printf(" (table full: %d packets of further conversations not tracked)", u)
	}
	fmt.Println()
	return nil
}
