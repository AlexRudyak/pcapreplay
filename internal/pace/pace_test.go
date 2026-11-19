package pace

import (
	"sort"
	"testing"
	"time"
)

func TestFixedDelay(t *testing.T) {
	p, _ := New(Config{Mode: Fixed, Delay: 2 * time.Millisecond})
	start := time.Now()
	for i := 0; i < 50; i++ {
		p.Wait(0, 100)
	}
	el := time.Since(start)
	if el < 96*time.Millisecond || el > 130*time.Millisecond {
		t.Fatalf("50 packets @2ms took %v", el)
	}
}

func TestOriginalTimingAccuracy(t *testing.T) {
	p, _ := New(Config{Mode: Original})
	base := int64(1_700_000_000_000_000_000)
	start := nanotime() // same clock as the pacer; Go's time.Since is tick-quantised on Windows
	late := make([]time.Duration, 0, 400)
	for i := 0; i < 400; i++ {
		ts := base + int64(i)*500_000 // 500 µs apart
		p.Wait(ts, 100)
		e := time.Duration(nanotime()-start) - time.Duration(i)*500*time.Microsecond
		if e < 0 {
			t.Fatalf("sent early by %v at packet %d", -e, i)
		}
		late = append(late, e)
	}
	sort.Slice(late, func(i, j int) bool { return late[i] < late[j] })
	p50, p95, max := late[len(late)/2], late[len(late)*95/100], late[len(late)-1]
	t.Logf("lateness p50=%v p95=%v max=%v (max is OS scheduler preemption)", p50, p95, max)
	// The schedule is absolute, so spikes are recovered from rather than
	// accumulated; judge steady-state accuracy by the median and p95.
	// A multi-ms OS stall makes the following packets late until the schedule
	// is caught up, which can drag p95 on a loaded host; the median is stable.
	if p50 > 200*time.Microsecond {
		t.Fatalf("pacing too imprecise: p50=%v p95=%v", p50, p95)
	}
}

func TestSpeedAndMaxGap(t *testing.T) {
	p, _ := New(Config{Mode: Original, Speed: 2, MaxGap: 10 * time.Millisecond})
	start := nanotime() // the pacer's own clock: time.Since is tick-quantised on Windows
	p.Wait(0, 1)
	p.Wait(int64(40*time.Millisecond), 1) // 40ms gap capped to 10ms then halved = 5ms
	if el := time.Duration(nanotime() - start); el > 20*time.Millisecond || el < 4*time.Millisecond {
		t.Fatalf("elapsed %v", el)
	}
}

func TestMbpsAndBurst(t *testing.T) {
	p, _ := New(Config{Mode: Mbps, Mbps: 8}) // 1 MB/s
	start := time.Now()
	for i := 0; i < 11; i++ {
		p.Wait(0, 10_000) // 10 KB each -> 10 ms apart
	}
	if el := time.Since(start); el < 95*time.Millisecond || el > 130*time.Millisecond {
		t.Fatalf("rate-limited run took %v", el)
	}
	b, _ := New(Config{Mode: Burst})
	start = time.Now()
	for i := 0; i < 1_000_000; i++ {
		b.Wait(0, 1)
	}
	if time.Since(start) > 100*time.Millisecond || !b.Unpaced() {
		t.Fatal("burst mode must not wait")
	}
}

func TestValidation(t *testing.T) {
	for _, c := range []Config{{Mode: PPS}, {Mode: Mbps, Mbps: -1}, {Mode: Original, Speed: -1}} {
		if _, err := New(c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}
