package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func discardBridgeWatchdogLog(string, ...any) {}

func waitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("expected %s", what)
	}
}

func assertNoSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("unexpected %s", what)
	case <-time.After(80 * time.Millisecond):
	}
}

// TestBridgeWatchdogProbeEscalates drives the escalation ladder: rx is flat
// (the sidecar is the sole keepalive sender, so quiet inbound is normal), so
// once rx has been quiet past probeAfter the watchdog probes; consecutive
// probe failures rekey, then reconnect.
func TestBridgeWatchdogProbeEscalates(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(3_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time)
	probeCalls := make(chan struct{}, 16)
	probe := func() error { probeCalls <- struct{}{}; return errors.New("no reply") }
	rekeyCalls := make(chan struct{}, 8)
	rekey := func() error { rekeyCalls <- struct{}{}; return nil }
	reconnectCalls := make(chan struct{}, 1)
	reconnect := func() {
		select {
		case reconnectCalls <- struct{}{}:
		default:
		}
	}
	rx := func() uint64 { return 1000 } // flat

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runBridgeWatchdogLoop(ctx, bridgeWatchdogConfig{
			rx: rx, probe: probe, rekey: rekey, reconnect: reconnect,
			logf: discardBridgeWatchdogLog, tick: tick, now: clk.Now,
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 2, reconnectAfterFails: 3,
		})
		close(done)
	}()

	// Tick 1 seeds rx tracking — no probe (rx quiet only just observed).
	tick <- clk.Now()
	assertNoSignal(t, probeCalls, "probe on seed tick")

	// +25s: rx quiet past probeAfter → probe #1, fails (1) — no rekey yet.
	clk.Set(t0.Add(25 * time.Second))
	tick <- clk.Now()
	waitSignal(t, probeCalls, "probe #1")
	assertNoSignal(t, rekeyCalls, "rekey after a single failure")

	// +50s: probe #2, second consecutive failure → in-place rekey.
	clk.Set(t0.Add(50 * time.Second))
	tick <- clk.Now()
	waitSignal(t, probeCalls, "probe #2")
	waitSignal(t, rekeyCalls, "rekey at 2 consecutive failures")

	// +75s: probe #3, third failure → reconnect, loop returns.
	clk.Set(t0.Add(75 * time.Second))
	tick <- clk.Now()
	waitSignal(t, probeCalls, "probe #3")
	waitSignal(t, reconnectCalls, "reconnect at 3 consecutive failures")
	<-done
}

// TestBridgeWatchdogRxHealthyNoProbe confirms advancing rx (real inbound
// traffic) is treated as liveness on its own, without generating a probe.
func TestBridgeWatchdogRxHealthyNoProbe(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(6_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time)
	var rxv atomic.Uint64
	rxv.Store(1000)
	probeCalls := make(chan struct{}, 8)
	probe := func() error { probeCalls <- struct{}{}; return nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runBridgeWatchdogLoop(ctx, bridgeWatchdogConfig{
			rx:        func() uint64 { return rxv.Load() },
			probe:     probe,
			rekey:     func() error { return nil },
			reconnect: func() {},
			logf:      discardBridgeWatchdogLog, tick: tick, now: clk.Now,
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 2, reconnectAfterFails: 3,
		})
		close(done)
	}()

	tick <- clk.Now() // seed
	for i := 1; i <= 4; i++ {
		clk.Set(t0.Add(time.Duration(i) * 40 * time.Second))
		rxv.Add(32)
		tick <- clk.Now()
	}
	assertNoSignal(t, probeCalls, "probe while rx is advancing")
	cancel()
	<-done
}

// TestBridgeWatchdogProbeSuccessIdle confirms that on a healthy-but-idle
// tunnel (rx flat, probe replies) the watchdog probes on cadence but never
// escalates.
func TestBridgeWatchdogProbeSuccessIdle(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(7_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time)
	probeCalls := make(chan struct{}, 16)
	probe := func() error { probeCalls <- struct{}{}; return nil }
	rekeyCalls := make(chan struct{}, 8)
	rekey := func() error { rekeyCalls <- struct{}{}; return nil }
	reconnectCalls := make(chan struct{}, 1)
	reconnect := func() {
		select {
		case reconnectCalls <- struct{}{}:
		default:
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runBridgeWatchdogLoop(ctx, bridgeWatchdogConfig{
			rx: func() uint64 { return 1000 }, probe: probe, rekey: rekey, reconnect: reconnect,
			logf: discardBridgeWatchdogLog, tick: tick, now: clk.Now,
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 2, reconnectAfterFails: 3,
		})
		close(done)
	}()

	tick <- clk.Now() // seed
	for i := 1; i <= 5; i++ {
		clk.Set(t0.Add(time.Duration(i) * 25 * time.Second))
		tick <- clk.Now()
		waitSignal(t, probeCalls, "idle liveness probe")
	}
	assertNoSignal(t, rekeyCalls, "rekey while probes succeed")
	assertNoSignal(t, reconnectCalls, "reconnect while probes succeed")
	cancel()
	<-done
}

// TestBridgeWatchdogInertWhenReapingDisabled confirms the loop returns
// immediately when reaping is disabled server-side.
func TestBridgeWatchdogInertWhenReapingDisabled(t *testing.T) {
	clk := &fakeClock{}
	clk.Set(time.Unix(4_000_000, 0))
	probeCalls := make(chan struct{}, 4)

	done := make(chan struct{})
	go func() {
		runBridgeWatchdogLoop(context.Background(), bridgeWatchdogConfig{
			rx:        func() uint64 { return 1000 },
			probe:     func() error { probeCalls <- struct{}{}; return errors.New("no reply") },
			rekey:     func() error { return nil },
			reconnect: func() {},
			logf:      discardBridgeWatchdogLog, tick: make(chan time.Time), now: clk.Now,
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 0, reconnectAfterFails: 0,
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("inert watchdog should return immediately when reaping is disabled")
	}
	assertNoSignal(t, probeCalls, "probe with reaping disabled")
}

func TestBridgeWatchdogResetMisses(t *testing.T) {
	for _, c := range []struct{ configured, reconnectAfter, want int }{
		{2, 3, 2},
		{2, 5, 2},
		{4, 10, 4},
		{2, 2, 0},
		{5, 3, 0},
		{0, 3, 0},
		{-1, 3, 0},
	} {
		if got := bridgeWatchdogResetMisses(c.configured, c.reconnectAfter); got != c.want {
			t.Errorf("bridgeWatchdogResetMisses(%d, %d) = %d, want %d", c.configured, c.reconnectAfter, got, c.want)
		}
	}
}
