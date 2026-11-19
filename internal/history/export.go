package history

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// ExportJSON writes the matching runs as a JSON array (newest first).
func (s *Store) ExportJSON(w io.Writer, q Query) error {
	q.Limit, q.Offset = 0, 0
	runs, _ := s.List(q)
	if runs == nil {
		runs = []Run{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(runs)
}

// csvSafe neutralises spreadsheet formula injection: a cell that starts with
// = + - @ (or a tab/CR) would be evaluated by Excel/LibreOffice.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// ExportCSV writes the matching runs as CSV (newest first), one run per row.
func (s *Store) ExportCSV(w io.Writer, q Query) error {
	q.Limit, q.Offset = 0, 0
	runs, _ := s.List(q)
	cw := csv.NewWriter(w)
	cw.Write([]string{"id", "started", "finished", "state", "capture", "mode", "backend", "dry_run", "pacing", "target",
		"conversations", "packets_sent", "bytes_sent", "elapsed_ms", "packets_saved", "error", "note", "pinned"})
	for _, r := range runs {
		var sent, bytes uint64
		var el int64
		if r.Result != nil {
			sent, bytes, el = r.Result.Sent, r.Result.Bytes, r.Result.ElapsedMs
		}
		var convs []string
		for _, c := range r.Conversations {
			convs = append(convs, c.Selector)
		}
		fin := ""
		if !r.FinishedAt.IsZero() {
			fin = r.FinishedAt.Format("2006-01-02T15:04:05Z07:00")
		}
		cw.Write([]string{r.ID, r.StartedAt.Format("2006-01-02T15:04:05Z07:00"), fin, r.State, csvSafe(r.Capture), r.Mode, r.Backend,
			strconv.FormatBool(r.DryRun), r.Pacing, csvSafe(r.Target), csvSafe(strings.Join(convs, " ; ")),
			strconv.FormatUint(sent, 10), strconv.FormatUint(bytes, 10), strconv.FormatInt(el, 10),
			strconv.FormatUint(r.PacketsCount, 10), csvSafe(r.Error), csvSafe(r.Note), strconv.FormatBool(r.Pinned)})
	}
	cw.Flush()
	return cw.Error()
}
