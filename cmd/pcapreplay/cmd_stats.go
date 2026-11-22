package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/AlexRudyak/pcapreplay/internal/decode"
	"github.com/AlexRudyak/pcapreplay/internal/filter"
	"github.com/AlexRudyak/pcapreplay/internal/logx"
	"github.com/AlexRudyak/pcapreplay/internal/pcapio"
	"github.com/AlexRudyak/pcapreplay/internal/stats"
)

// rangeFlags are shared by commands that can inspect a slice of a capture.
type rangeFlags struct {
	start, count uint64
	indexPath    string
	log          *logx.Logger // optional diagnostics
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
			r.log.Infof("index", "%s not usable (%v): building it", r.indexPath, err)
			fmt.Fprintf(os.Stderr, "building index %s ...\n", r.indexPath)
			if ix, err = pcapio.BuildIndex(capture, 0); err != nil {
				return err
			}
			if err = ix.Save(r.indexPath); err != nil {
				return err
			}
		}
		r.log.Infof("index", "using %s (%d entries, %d packets): seeking to packet %d", r.indexPath, len(ix.Offsets), ix.Total, r.start)
		if err := ix.SeekPacket(rd, r.start); err != nil {
			return fmt.Errorf("-start %d: %w (capture has %d packets)", r.start, err, ix.Total)
		}
		return nil
	}
	r.log.Infof("index", "no index: skipping %d packets sequentially", r.start)
	if err := rd.Skip(r.start); err != nil {
		return fmt.Errorf("-start %d: %w", r.start, err)
	}
	return nil
}

// cmdStats implements "pcapreplay stats".
func cmdStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	var rf rangeFlags
	rf.register(fs)
	var lf logFlags
	lf.register(fs)
	expr := fs.String("filter", "", "filter expression, e.g. 'src_ip == 10.0.0.0/8 AND dst_port == 443'")
	top := fs.Int("top", 10, "rows in the top-talker and port tables")
	progress := fs.Bool("progress", false, "print progress to stderr")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: pcapreplay stats [flags] <capture>")
	}
	path := fs.Arg(0)
	lg, closeLog, err := lf.build()
	if err != nil {
		return err
	}
	defer closeLog()
	rf.log = lg
	flt, err := filter.Parse(*expr)
	if err != nil {
		return err
	}
	lg.Infof("stats", "filter=%q range start=%d count=%d top=%d", *expr, rf.start, rf.count, *top)
	rd, err := pcapio.Open(path)
	if err != nil {
		return err
	}
	defer rd.Close()
	lg.Infof("stats", "opened %s: %s, link type %d", path, rd.Format(), rd.LinkType())
	if err := rf.position(rd, path); err != nil {
		return err
	}
	traceOn, debugOn := lg.Enabled(logx.Trace), lg.Enabled(logx.Debug)
	var matched uint64

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
			if traceOn {
				lg.Tracef("stats", "pkt %d len=%d %s: filtered out", rd.Count()-1, len(p.Data), describe(&in, ok))
			}
			continue
		}
		st.Add(&in, ok, len(p.Data), int(p.OrigLen), p.TsNanos)
		matched++
		if traceOn {
			lg.Tracef("stats", "pkt %d len=%d %s: counted", rd.Count()-1, len(p.Data), describe(&in, ok))
		}
		if debugOn && matched&0xfffff == 0 {
			lg.Debugf("stats", "%d packets counted so far (%d read, offset %d)", matched, seen, rd.Offset())
		}
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
	lg.Infof("stats", "done: %d read, %d counted in %s", seen, matched, time.Since(begin).Round(time.Millisecond))
	fmt.Printf("File:         %s (%s, link type %d)\n", path, rd.Format(), rd.LinkType())
	if *expr != "" {
		fmt.Printf("Filter:       %s\n", *expr)
	}
	st.Report(os.Stdout, *top)
	return nil
}

// cmdIndex implements "pcapreplay index".
func cmdIndex(args []string) error {
	fs := flag.NewFlagSet("index", flag.ExitOnError)
	var lf logFlags
	lf.register(fs)
	out := fs.String("o", "", "output index file (default: <capture>.idx)")
	stride := fs.Uint64("stride", pcapio.IndexStride, "packets between index entries")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: pcapreplay index [flags] <capture>")
	}
	if *out == "" {
		*out = fs.Arg(0) + ".idx"
	}
	lg, closeLog, err := lf.build()
	if err != nil {
		return err
	}
	defer closeLog()
	lg.Infof("index", "indexing %s every %d packets -> %s", fs.Arg(0), *stride, *out)
	begin := time.Now()
	ix, err := pcapio.BuildIndex(fs.Arg(0), *stride)
	if err != nil {
		return err
	}
	lg.Infof("index", "scanned %d packets in %s", ix.Total, time.Since(begin).Round(time.Millisecond))
	if err := ix.Save(*out); err != nil {
		return err
	}
	fmt.Printf("indexed %d packets, %d entries -> %s\n", ix.Total, len(ix.Offsets), *out)
	return nil
}

// describe renders the decoded headers of one packet for the trace log.
func describe(in *decode.Info, ok bool) string {
	switch {
	case !ok:
		return "undecoded"
	case !in.HasIP:
		return "non-IP"
	case in.HasPorts:
		return fmt.Sprintf("proto=%d %s:%d > %s:%d", in.Proto, in.Src, in.SrcPort, in.Dst, in.DstPort)
	}
	return fmt.Sprintf("proto=%d %s > %s", in.Proto, in.Src, in.Dst)
}
