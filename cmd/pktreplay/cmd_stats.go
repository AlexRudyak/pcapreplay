package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sasha/pktreplay/internal/decode"
	"github.com/sasha/pktreplay/internal/filter"
	"github.com/sasha/pktreplay/internal/pcapio"
	"github.com/sasha/pktreplay/internal/stats"
)

// rangeFlags are shared by commands that can inspect a slice of a capture.
type rangeFlags struct {
	start, count uint64
	indexPath    string
}

func (r *rangeFlags) register(fs *flag.FlagSet) {
	fs.Uint64Var(&r.start, "start", 0, "first packet number to process (0-based)")
	fs.Uint64Var(&r.count, "count", 0, "maximum packets to process after -start (0 = all)")
	fs.StringVar(&r.indexPath, "index", "", "seek index file; loaded if present, otherwise built and saved there")
}

// position seeks rd to r.start using an index when available.
func (r *rangeFlags) position(rd *pcapio.Reader, capture string) error {
	if r.start == 0 {
		return nil
	}
	if r.indexPath != "" {
		ix, err := pcapio.LoadIndex(r.indexPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "building index %s ...\n", r.indexPath)
			if ix, err = pcapio.BuildIndex(capture, 0); err != nil {
				return err
			}
			if err = ix.Save(r.indexPath); err != nil {
				return err
			}
		}
		if err := ix.SeekPacket(rd, r.start); err != nil {
			return fmt.Errorf("-start %d: %w (capture has %d packets)", r.start, err, ix.Total)
		}
		return nil
	}
	if err := rd.Skip(r.start); err != nil {
		return fmt.Errorf("-start %d: %w", r.start, err)
	}
	return nil
}

func cmdStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	var rf rangeFlags
	rf.register(fs)
	expr := fs.String("filter", "", "filter expression, e.g. 'src_ip == 10.0.0.0/8 AND dst_port == 443'")
	top := fs.Int("top", 10, "rows in the top-talker and port tables")
	progress := fs.Bool("progress", false, "print progress to stderr")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: pktreplay stats [flags] <capture>")
	}
	path := fs.Arg(0)
	flt, err := filter.Parse(*expr)
	if err != nil {
		return err
	}
	rd, err := pcapio.Open(path)
	if err != nil {
		return err
	}
	defer rd.Close()
	if err := rf.position(rd, path); err != nil {
		return err
	}

	st := stats.New()
	var in decode.Info
	begin, lastTick := time.Now(), time.Now()
	var seen uint64
	for rf.count == 0 || seen < rf.count {
		p, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			fmt.Fprintln(os.Stderr, "warning: capture is truncated; reporting packets read so far")
			break
		}
		if err != nil {
			return fmt.Errorf("packet %d: %w", rd.Count(), err)
		}
		seen++
		ok := decode.Decode(p.LinkType, p.Data, &in)
		if !flt.MatchAll() && !flt.Match(p.Data, &in) {
			continue
		}
		st.Add(&in, ok, len(p.Data), int(p.OrigLen), p.TsNanos)
		if *progress && seen&0xfffff == 0 && time.Since(lastTick) > time.Second {
			lastTick = time.Now()
			fmt.Fprintf(os.Stderr, "\r%d packets, %.1f MB read", seen, float64(rd.Offset())/1e6)
		}
	}
	if *progress {
		el := time.Since(begin)
		fmt.Fprintf(os.Stderr, "\rscanned %d packets (%.1f MB) in %s = %.2f Mpps, %.0f MB/s\n", seen,
			float64(rd.Offset())/1e6, el.Round(time.Millisecond), float64(seen)/el.Seconds()/1e6,
			float64(rd.Offset())/1e6/el.Seconds())
	}
	fmt.Printf("File:         %s (%s, link type %d)\n", path, rd.Format(), rd.LinkType())
	if *expr != "" {
		fmt.Printf("Filter:       %s\n", *expr)
	}
	st.Report(os.Stdout, *top)
	return nil
}

func cmdIndex(args []string) error {
	fs := flag.NewFlagSet("index", flag.ExitOnError)
	out := fs.String("o", "", "output index file (default: <capture>.idx)")
	stride := fs.Uint64("stride", pcapio.IndexStride, "packets between index entries")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: pktreplay index [flags] <capture>")
	}
	if *out == "" {
		*out = fs.Arg(0) + ".idx"
	}
	ix, err := pcapio.BuildIndex(fs.Arg(0), *stride)
	if err != nil {
		return err
	}
	if err := ix.Save(*out); err != nil {
		return err
	}
	fmt.Printf("indexed %d packets, %d entries -> %s\n", ix.Total, len(ix.Offsets), *out)
	return nil
}
