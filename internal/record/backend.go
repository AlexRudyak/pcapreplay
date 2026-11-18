package record

import (
	"time"

	"github.com/sasha/pktreplay/internal/backend"
)

// Recorder wraps a Backend and writes everything that crosses it to a file.
// It works with every backend, including the null (dry-run) backend, so a dry
// run can produce the exact traffic a real run would have sent.
type Recorder struct {
	backend.Backend
	w       *Writer
	inbound bool
}

// Wrap records the packets sent through b. With inbound set, replies delivered
// by Recv (TCP mode) are recorded too, giving a complete conversation.
func Wrap(b backend.Backend, w *Writer, inbound bool) *Recorder {
	return &Recorder{Backend: b, w: w, inbound: inbound}
}

// Writer exposes the underlying writer (for statistics).
func (r *Recorder) Writer() *Writer { return r.w }

// Name reports the wrapped backend with a recording marker.
func (r *Recorder) Name() string { return r.Backend.Name() + "+record" }

// SendBatch forwards to the real backend and records the datagrams it accepted.
func (r *Recorder) SendBatch(pkts [][]byte) (int, error) {
	now := time.Now()
	n, err := r.Backend.SendBatch(pkts)
	for i := 0; i < n && i < len(pkts); i++ {
		r.w.Write(now, pkts[i], true)
	}
	return n, err
}

// Recv forwards to the real backend and records what arrives.
func (r *Recorder) Recv(buf []byte, timeout time.Duration) (int, error) {
	n, err := r.Backend.Recv(buf, timeout)
	if err == nil && r.inbound {
		r.w.Write(time.Now(), buf[:n], false)
	}
	return n, err
}

// Close closes the backend, then flushes and closes the recording.
func (r *Recorder) Close() error {
	err := r.Backend.Close()
	if werr := r.w.Close(); err == nil {
		err = werr
	}
	return err
}
