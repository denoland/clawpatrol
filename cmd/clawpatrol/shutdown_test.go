package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGatewayShutdownFlush exercises the small piece of
// installGatewayShutdown we can drive without actually killing the
// test process: that the captured otelShutdown closure is invoked
// inside a bounded context and that a long-running closure is cut off
// at the deadline so a wedged collector cannot hang the exit path.
//
// We extract the body of the signal handler into a helper so this test
// drives it directly — the goroutine in installGatewayShutdown is just
// signal.Notify + this helper + os.Exit. This guards the "telemetry
// flushed before the process exits" promise listed in the boot banner.
func TestGatewayShutdownFlush(t *testing.T) {
	called := make(chan struct{})
	flush := func(_ context.Context) error {
		close(called)
		return nil
	}
	runShutdownFlush(flush, 200*time.Millisecond)
	select {
	case <-called:
	default:
		t.Fatalf("otel shutdown was not invoked")
	}
}

// TestGatewayShutdownFlushHonorsTimeout proves the deadline survives a
// hostile collector: the helper returns once the context expires even
// if the flush closure ignores the signal.
func TestGatewayShutdownFlushHonorsTimeout(t *testing.T) {
	flush := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	start := time.Now()
	runShutdownFlush(flush, 50*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("shutdown waited %s; should have given up at the 50ms deadline", elapsed)
	}
}

// TestGatewayShutdownFlushNoOpWhenNil: nil flush closure is the
// "otel disabled" path and must not panic.
func TestGatewayShutdownFlushNoOpWhenNil(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("runShutdownFlush(nil) panicked: %v", r)
		}
	}()
	runShutdownFlush(nil, time.Second)
}

// TestGatewayShutdownFlushLogsFlushError ensures a flush error is
// surfaced through the function return (instead of being swallowed)
// so the goroutine wrapper can log it. The wrapper itself is just
// glue; this checks the contract.
func TestGatewayShutdownFlushLogsFlushError(t *testing.T) {
	wantErr := errors.New("collector unreachable")
	flush := func(_ context.Context) error { return wantErr }
	if err := runShutdownFlushErr(flush, time.Second); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

// TestSinkCloseDrainsBufferedEvents proves the contract Close adds to
// the gateway shutdown path: every event Emit accepted before Close
// runs lands in the actions table before Close returns. Without this,
// SIGTERM mid-batch silently drops the in-flight 4096-deep sink.
func TestSinkCloseDrainsBufferedEvents(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()
	s, err := NewSink(db, 16)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	const want = 10
	for i := 0; i < want; i++ {
		s.Emit(Event{Mode: "pg", Host: "drain-test", Method: "SELECT"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("sink Close: %v", err)
	}
	var got int
	if err := db.QueryRow("SELECT COUNT(*) FROM actions WHERE host = ?", "drain-test").Scan(&got); err != nil {
		t.Fatalf("count actions: %v", err)
	}
	if got != want {
		t.Fatalf("persisted %d, want %d", got, want)
	}
}

// TestSinkCloseIdempotent: a second Close on an already-closed sink
// returns nil without panicking. runGatewayShutdown only calls Close
// once, but layered shutdown paths (e.g. a test that closes via
// runGatewayShutdown and then triggers another path) need this to be
// safe.
func TestSinkCloseIdempotent(t *testing.T) {
	s, err := NewSink(nil, 4)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	ctx := context.Background()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestSinkEmitAfterCloseIsNoop: callers (request handlers, dispatch
// goroutines) racing with Close must not panic. Emit detects the
// closed state up front; the residual race between closed-check and
// channel-send is caught by the recover in Emit. Either way the
// caller sees no error and drops_counter ticks.
func TestSinkEmitAfterCloseIsNoop(t *testing.T) {
	s, err := NewSink(nil, 4)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dropsBefore := s.Drops()
	// Hammer it from a few goroutines; any send-on-closed-channel
	// panic would crash the test binary instead of being recovered.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				s.Emit(Event{Mode: "pg", Host: "post-close"})
			}
		}()
	}
	wg.Wait()
	if s.Drops() < dropsBefore {
		t.Fatalf("drops shrank from %d to %d", dropsBefore, s.Drops())
	}
}

// TestTunnelManagerCloseAllClosesEntries verifies CloseAll tears down
// every live entry and the manager forgets them all, so a wedged
// shutdown can't leave orphan tsnet / SSH / kubectl subprocesses.
func TestTunnelManagerCloseAllClosesEntries(t *testing.T) {
	m := NewTunnelManager(nil, t.TempDir())
	var closes atomic.Int32
	// Stuff three entries directly into the map; we don't have an
	// in-tree TunnelRuntime stub small enough to drive through
	// Acquire, so simulate "entries opened" by populating the map.
	for i := 0; i < 3; i++ {
		mk := mgrKey{Name: "fake", Key: "k", Fingerprint: "f"}
		mk.Key += string(rune('a' + i))
		m.entries[mk] = &tunnelEntry{
			name:   "fake",
			tunnel: &fakeTunnelHandle{onClose: func() { closes.Add(1) }},
		}
	}
	if err := m.CloseAll(context.Background()); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if got := closes.Load(); got != 3 {
		t.Fatalf("close hits = %d, want 3", got)
	}
	if len(m.entries) != 0 {
		t.Fatalf("entries not cleared: %d remain", len(m.entries))
	}
	if err := m.CloseAll(context.Background()); err != nil {
		t.Fatalf("second CloseAll: %v", err)
	}
}

// fakeTunnelHandle implements just enough of runtime.Tunnel for
// CloseAll's bookkeeping path. Dial is unused — CloseAll doesn't
// dial. Close fires the test hook so we can count tear-downs.
type fakeTunnelHandle struct {
	onClose func()
}

func (f *fakeTunnelHandle) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("fakeTunnelHandle.Dial: not implemented")
}

func (f *fakeTunnelHandle) Close() error {
	if f.onClose != nil {
		f.onClose()
	}
	return nil
}
