# internal/pace

Decides **when** each packet is sent, with microsecond accuracy.

```go
pc, err := pace.New(pace.Config{Mode: pace.PPS, PPS: 5000})
for each packet {
    pc.Wait(captureTimestampNs, frameLen)   // blocks until this packet is due
    send(...)
}
```

## Modes

| `Mode` | Behaviour |
|---|---|
| `Original` | Reproduce the capture's inter-packet gaps, scaled by `Speed` (2 = twice as fast). `MaxGap` caps any single idle gap. |
| `Fixed` | A constant delay between packets. |
| `PPS` | At most N packets per second. |
| `Mbps` | At most N megabits per second, counted on frame size. |
| `Burst` | No waiting; `Unpaced()` returns true so the sender can batch (`sendmmsg` / `WinDivertSendEx`). |

## How it works

* **Absolute schedule.** Each packet gets a deadline `start + due`. A late packet never delays later ones (no drift
  accumulation). A stall longer than 250 ms re-bases the clock instead of producing a catch-up burst.
* **Hybrid wait.** `time.Sleep` until about 2 ms before the deadline, then spin on the monotonic clock for the last
  stretch, so wake-up jitter of the OS scheduler does not reach the wire.
* **Windows.** Go's monotonic clock there only advances at the system timer tick (~0.5-15 ms), which wrecks short
  gaps. `clock_windows.go` reads `QueryPerformanceCounter` directly and raises the timer resolution
  (`timeBeginPeriod`), reducing median lateness from about 600 µs to about 3 µs. Other platforms use the runtime
  clock (`clock_other.go`).

## Tests

`pace_test.go` measures with the same raw clock the pacer uses (using the quantised Go clock made earlier tests
flaky) and checks accuracy, no-drift behaviour, speed scaling, gap capping and the rate caps.

Used by: `replay`.
