package record

import (
	"time"

	"github.com/sasha/pktreplay/internal/backend"
)

// Recorder wraps a Backend and writes everything that crosses it to one or more
// files. It works with every backend, including the null (dry-run) backend, so a
// dry run can produce the exact traffic a real run would have sent.
type Recorder struct {
	backend.Backend
	w       *Writer   // primary writer (the one Writer() reports on)
	extra   []*Writer // additional copies, e.g. the history store's
	inbound bool
}

// Wrap records the packets sent through b. With inbound set, replies delivered
// by Recv (TCP mode) are recorded too, giving a complete conversation.
func Wrap(b backend.Backend, w *Writer, inbound bool) *Recorder {
	return &Recorder{Backend: b, w: w, inbound: inbound}
}

// Also adds another file that receives the same packets. It is closed with the
// recorder.
func (r *Recorder) Also(w *Writer) { r.extra = append(r.extra, w) }

// Writer exposes the primary writer (for statistics).
func (r *Recorder) Writer() *Writer { return r.w }

// Name reports the wrapped backend with a recording marker.
func (r *Recorder) Name() string { return r.Backend.Name() + "+record" }

func (r *Recorder) write(t time.Time, p []byte, outbound bool) {
	r.w.Write(t, p, outbound)
	for _, w := range r.extra {
		w.Write(t, p, outbound)
	}
}

// SendBatch forwards to the real backend and records the datagrams it accepted.
func (r *Recorder) SendBatch(pkts [][]byte) (int, error) {
	now := time.Now()
	n, err := r.Backend.SendBatch(pkts)
	for i := 0; i < n && i < len(pkts); i++ {
		r.write(now, pkts[i], true)
	}
	return n, err
}

// Recv forwards to the real backend and records what arrives.
func (r *Recorder) Recv(buf []byte, timeout time.Duration) (int, error) {
	n, err := r.Backend.Recv(buf, timeout)
	if err == nil && r.inbound {
		r.write(time.Now(), buf[:n], false)
	}
	return n, err
}

// Close closes the backend, then flushes and closes every recording.
func (r *Recorder) Close() error {
	err := r.Backend.Close()
	if werr := r.w.Close(); err == nil {
		err = werr
	}
	for _, w := range r.extra {
		if werr := w.Close(); err == nil {
			err = werr
		}
	}
	return err
}
