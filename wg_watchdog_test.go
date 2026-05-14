package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func TestParsePeerStats(t *testing.T) {
	uapi := strings.Join([]string{
		"private_key=abcd",
		"listen_port=51820",
		"public_key=deadbeef",
		"endpoint=10.0.0.1:51820",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=123456789",
		"tx_bytes=4096",
		"rx_bytes=8192",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
		"",
	}, "\n")
	got := parsePeerStats(uapi)
	if got == nil {
		t.Fatal("parsePeerStats returned nil")
	}
	wantHS := time.Unix(1700000000, 123456789)
	if !got.lastHandshake.Equal(wantHS) {
		t.Errorf("lastHandshake = %v, want %v", got.lastHandshake, wantHS)
	}
	if got.txBytes != 4096 {
		t.Errorf("txBytes = %d, want 4096", got.txBytes)
	}
	if got.rxBytes != 8192 {
		t.Errorf("rxBytes = %d, want 8192", got.rxBytes)
	}
}

func TestParsePeerStatsNoHandshake(t *testing.T) {
	// last_handshake_time_sec=0 / _nsec=0 means "never" — wireguard-go
	// uses zero for unset, and on the cold path we don't want to
	// interpret that as a 1970 timestamp.
	uapi := "last_handshake_time_sec=0\nlast_handshake_time_nsec=0\ntx_bytes=0\n"
	got := parsePeerStats(uapi)
	if got == nil {
		t.Fatal("parsePeerStats returned nil")
	}
	if !got.lastHandshake.IsZero() {
		t.Errorf("lastHandshake = %v, want zero", got.lastHandshake)
	}
}

// loggerWithLines returns a device.Logger that captures Errorf lines
// into the returned slice pointer. Used to assert log behavior without
// pulling in os.Stdout.
func loggerWithLines() (*device.Logger, *[]string) {
	var lines []string
	l := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, _ ...any) {
			lines = append(lines, format)
		},
	}
	return l, &lines
}

func TestWrapWGLoggerSignalsForceReset(t *testing.T) {
	base, lines := loggerWithLines()
	ch := make(chan struct{}, 1)
	w := wrapWGLogger(base, ch)
	w.Errorf("peer(x) - Failed to derive keypair: %s", "invalid state for keypair derivation: handshakeInitiationCreated")
	w.Errorf("unrelated noise")
	select {
	case <-ch:
	default:
		t.Fatal("expected forceReset signal")
	}
	// Subsequent "Failed to derive keypair" should not block on a full
	// channel — the watchdog coalesces signals.
	w.Errorf("peer(x) - Failed to derive keypair: blah")
	if len(*lines) != 3 {
		t.Errorf("got %d lines, want 3", len(*lines))
	}
}

func TestWrapWGLoggerNilBase(t *testing.T) {
	// A nil base must not panic — defensive guard for the call sites
	// that forget to construct a logger.
	ch := make(chan struct{}, 1)
	w := wrapWGLogger(nil, ch)
	w.Errorf("peer(x) - Failed to derive keypair: nope")
	select {
	case <-ch:
	default:
		t.Fatal("expected forceReset signal")
	}
}

// fakeClock advances synthetic time so the watchdog loop can be tested
// in microseconds.
type fakeClock struct {
	now atomic.Int64 // unix nanos
}

func (c *fakeClock) Now() time.Time {
	return time.Unix(0, c.now.Load())
}

func (c *fakeClock) Set(t time.Time) {
	c.now.Store(t.UnixNano())
}

func TestWatchdogResetsWhenHandshakeStale(t *testing.T) {
	clk := &fakeClock{}
	clk.Set(time.Unix(2_000_000, 0))

	tick := make(chan time.Time, 4)
	forceReset := make(chan struct{}, 1)

	stale := time.Unix(2_000_000-300, 0) // 5min ago, well past stuckTimeout
	var statsHandshake atomic.Value
	statsHandshake.Store(stale)
	var statsTx atomic.Uint64
	statsTx.Store(100)

	stats := func() *wgPeerStats {
		return &wgPeerStats{
			lastHandshake: statsHandshake.Load().(time.Time),
			txBytes:       statsTx.Load(),
		}
	}

	resetCalls := make(chan struct{}, 8)
	reset := func() error {
		resetCalls <- struct{}{}
		// Simulate a successful reset: handshake refreshed to now.
		statsHandshake.Store(clk.Now())
		return nil
	}

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			stats:         stats,
			reset:         reset,
			log:           log,
			forceReset:    forceReset,
			tick:          tick,
			stuckTimeout:  3 * time.Minute,
			resetCooldown: time.Minute,
			now:           clk.Now,
		})
		close(done)
	}()

	// First tick: stale handshake + tx growing → reset.
	statsTx.Store(200)
	tick <- clk.Now()

	select {
	case <-resetCalls:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not call reset for stale handshake")
	}

	// Second tick during cooldown should not reset again.
	clk.Set(clk.Now().Add(10 * time.Second))
	// Make it stale again to be sure the only thing stopping a reset
	// is the cooldown, not "fresh handshake".
	statsHandshake.Store(time.Unix(0, 0).Add(-time.Hour)) // ancient
	statsTx.Store(300)
	tick <- clk.Now()
	select {
	case <-resetCalls:
		t.Fatal("watchdog reset during cooldown window")
	case <-time.After(50 * time.Millisecond):
	}

	// Advance past cooldown — next tick should reset again.
	clk.Set(clk.Now().Add(2 * time.Minute))
	statsTx.Store(400)
	tick <- clk.Now()
	select {
	case <-resetCalls:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not reset after cooldown expired")
	}

	cancel()
	<-done
}

func TestWatchdogResetsOnForceSignal(t *testing.T) {
	clk := &fakeClock{}
	clk.Set(time.Unix(2_000_000, 0))

	tick := make(chan time.Time, 4)
	forceReset := make(chan struct{}, 1)

	// Handshake is fresh — only forceReset should cause a reset.
	stats := func() *wgPeerStats {
		return &wgPeerStats{
			lastHandshake: clk.Now(),
			txBytes:       100,
		}
	}

	resetCalls := make(chan struct{}, 8)
	reset := func() error {
		resetCalls <- struct{}{}
		return nil
	}

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			stats:         stats,
			reset:         reset,
			log:           log,
			forceReset:    forceReset,
			tick:          tick,
			stuckTimeout:  3 * time.Minute,
			resetCooldown: time.Minute,
			now:           clk.Now,
		})
		close(done)
	}()

	forceReset <- struct{}{}
	select {
	case <-resetCalls:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not reset on force signal")
	}
	cancel()
	<-done
}

func TestWatchdogWaitsForInitialHandshake(t *testing.T) {
	clk := &fakeClock{}
	clk.Set(time.Unix(2_000_000, 0))

	tick := make(chan time.Time, 4)
	forceReset := make(chan struct{}, 1)

	// Simulate "no handshake yet" by returning lastHandshake.IsZero().
	stats := func() *wgPeerStats {
		return &wgPeerStats{
			lastHandshake: time.Time{},
			txBytes:       100,
		}
	}

	resetCalls := make(chan struct{}, 8)
	reset := func() error {
		resetCalls <- struct{}{}
		return nil
	}

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			stats:         stats,
			reset:         reset,
			log:           log,
			forceReset:    forceReset,
			tick:          tick,
			stuckTimeout:  3 * time.Minute,
			resetCooldown: time.Minute,
			now:           clk.Now,
		})
		close(done)
	}()

	tick <- clk.Now()
	tick <- clk.Now()
	select {
	case <-resetCalls:
		t.Fatal("watchdog reset before any handshake completed")
	case <-time.After(80 * time.Millisecond):
	}
	cancel()
	<-done
}
