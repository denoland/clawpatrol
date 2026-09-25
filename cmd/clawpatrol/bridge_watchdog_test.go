package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// fallbackWatchdog runs the loop with a flat rx and the given probe and
// handshake source. step advances the clock and waits until the loop has read
// it, so each tick sees the intended time.
type fallbackWatchdog struct {
	clk        *fakeClock
	tick       chan time.Time
	nowRead    chan struct{}
	rekeys     chan struct{}
	reconnects chan struct{}
	stop       func()
}

func runFallbackWatchdog(t *testing.T, t0 time.Time, probe func() error, lastHandshake func() time.Time) *fallbackWatchdog {
	t.Helper()
	w := &fallbackWatchdog{
		clk:        &fakeClock{},
		tick:       make(chan time.Time),
		nowRead:    make(chan struct{}, 1),
		rekeys:     make(chan struct{}, 8),
		reconnects: make(chan struct{}, 1),
	}
	w.clk.Set(t0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runBridgeWatchdogLoop(ctx, bridgeWatchdogConfig{
			rx:                  func() uint64 { return 1000 },
			probe:               probe,
			lastHandshake:       lastHandshake,
			handshakeStaleAfter: bridgeHandshakeStaleAfter(25 * time.Second),
			rekey:               func() error { w.rekeys <- struct{}{}; return nil },
			reconnect: func() {
				select {
				case w.reconnects <- struct{}{}:
				default:
				}
			},
			logf: discardBridgeWatchdogLog, tick: w.tick,
			now: func() time.Time {
				now := w.clk.Now()
				w.nowRead <- struct{}{}
				return now
			},
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 2, reconnectAfterFails: 3,
		})
		close(done)
	}()
	w.stop = func() { cancel(); <-done }
	t.Cleanup(w.stop)
	return w
}

func (w *fallbackWatchdog) step(t *testing.T, at time.Time) {
	t.Helper()
	w.clk.Set(at)
	w.tick <- at
	waitSignal(t, w.nowRead, "watchdog tick")
}

// A missing ICMP permission is not a liveness failure. With a fresh
// handshake the watchdog never escalates.
func TestBridgeWatchdogProbeUnavailableFreshHandshake(t *testing.T) {
	t0 := time.Unix(9_000_000, 0)
	var w *fallbackWatchdog
	probe := func() error { return fmt.Errorf("%w: operation not permitted", errProbeUnavailable) }
	fresh := func() time.Time { return w.clk.Now().Add(-10 * time.Second) }
	w = runFallbackWatchdog(t, t0, probe, fresh)

	for i := 0; i <= 10; i++ {
		w.step(t, t0.Add(time.Duration(i)*25*time.Second))
	}
	assertNoSignal(t, w.rekeys, "rekey with a fresh handshake")
	assertNoSignal(t, w.reconnects, "reconnect with a fresh handshake")
}

// Without a probe, a stale handshake still escalates to rekey and reconnect.
func TestBridgeWatchdogProbeUnavailableStaleHandshake(t *testing.T) {
	for name, probe := range map[string]func() error{
		"unavailable": func() error { return errProbeUnavailable },
		"nil":         nil,
	} {
		t.Run(name, func(t *testing.T) {
			t0 := time.Unix(9_500_000, 0)
			stale := func() time.Time { return t0.Add(-time.Hour) }
			w := runFallbackWatchdog(t, t0, probe, stale)

			w.step(t, t0) // seed
			w.step(t, t0.Add(25*time.Second))
			assertNoSignal(t, w.rekeys, "rekey after one failure")
			w.step(t, t0.Add(50*time.Second))
			waitSignal(t, w.rekeys, "rekey at 2 stale checks")
			w.step(t, t0.Add(75*time.Second))
			waitSignal(t, w.reconnects, "reconnect at 3 stale checks")
		})
	}
}

func TestBridgeHandshakeStaleAfter(t *testing.T) {
	if got := bridgeHandshakeStaleAfter(25 * time.Second); got != 295*time.Second {
		t.Fatalf("bridgeHandshakeStaleAfter(25s) = %s, want 295s", got)
	}
}

func TestWaitForTunnel(t *testing.T) {
	now := time.Now()
	noHandshake := func() time.Time { return time.Time{} }
	handshake := func() time.Time { return now }
	var calls atomic.Int32
	handshakeLater := func() time.Time {
		if calls.Add(1) < 3 {
			return time.Time{}
		}
		return now
	}
	cases := []struct {
		name          string
		lastHandshake func() time.Time
		probe         func() error
		wantErr       string
	}{
		{name: "handshake and reply", lastHandshake: handshake, probe: func() error { return nil }},
		{name: "handshake after a few polls", lastHandshake: handshakeLater},
		{name: "no probe", lastHandshake: handshake},
		{name: "probe unavailable", lastHandshake: handshake, probe: func() error { return errProbeUnavailable }},
		{name: "no handshake", lastHandshake: noHandshake, wantErr: "no WireGuard handshake"},
		{name: "probe fails", lastHandshake: handshake, probe: func() error { return errors.New("timeout") }, wantErr: "no reply from the gateway tunnel address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := waitForTunnel(context.Background(), tc.lastHandshake, tc.probe, time.Millisecond, 50*time.Millisecond)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
