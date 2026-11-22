# internal/logx

A tiny leveled logger for the command-line tools.

```go
lg := logx.New(logx.Debug, os.Stderr)         // nil is valid and logs nothing
lg.Infof("replay", "selected flow %s", key)
if lg.Enabled(logx.Trace) { ... }             // check once outside a hot loop
```

| Level | Flag | Typical content |
|---|---|---|
| `Quiet` | (none) | nothing extra |
| `Info` | `-v` | what is being done |
| `Debug` | `-vv` | why, and protocol detail |
| `Trace` | `-vvv` | one line per packet |

Format: `15:04:05.000 LEVEL component: message`. `ParseLevel` accepts `quiet|info|debug|trace` or `0`-`3`.

## Design

* A **nil `*Logger` is valid**, so library code can call it unconditionally and callers that want no logging pass nothing.
* Writes are serialised with a mutex so lines from the producer, consumer and TCP goroutines never interleave.
* `Enabled(level)` lets hot paths test once and skip formatting entirely; the engine checks per-packet levels outside
  its loops.

Used by: `replay`, `cmd/pcapreplay` (flags are in `cmd/pcapreplay/logflags.go`).
