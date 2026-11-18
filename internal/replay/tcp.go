package replay

import "time"

// TCPConfig holds the TCP-mode options (the session engine lands in a later
// commit; the type exists now so Config is stable).
type TCPConfig struct {
	HandshakeTimeout time.Duration
	SeqOffset        int64
}
