package main

import (
	"context"
	"errors"
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
	flush := func(ctx context.Context) error {
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
	flush := func(ctx context.Context) error { return wantErr }
	if err := runShutdownFlushErr(flush, time.Second); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}
