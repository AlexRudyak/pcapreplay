//go:build !windows

package pace

import "time"

var base = time.Now()

// nanotime returns monotonic nanoseconds (CLOCK_MONOTONIC via the Go runtime).
func nanotime() int64 { return int64(time.Since(base)) }
