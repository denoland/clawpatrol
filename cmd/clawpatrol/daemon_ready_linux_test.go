//go:build linux

package main

// WaitReady-pathway tests: the bare polling loops behind each
// transport's WaitReady, plus the ATTACHED-or-READYERR wire format
// exchanged with the wrapper. The full daemon.handle integration is
// covered by TestDaemonProtocolRoundTrip in daemon_linux_test.go —
// the unit tests here exist so the ready-check logic is exercisable
// without booting tsnet or wireguard-go.

import (
	"bufio"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWGConfigHasHandshake covers the parser that converts
// wireguard-go's IpcGet blob into a "handshake done?" boolean. The
// daemon's wg WaitReady polls this on every tick, so a regression
// here (handshake never detected, or false positive on the zero
// line) directly translates to either an infinite wait or a wrapper
// that exec's into a tunnel that hasn't actually carried a packet.
func TestWGConfigHasHandshake(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want bool
	}{
		{"empty", "", false},
		{"absent line", "private_key=abc\npublic_key=def\n", false},
		{"explicit zero", "public_key=def\nlast_handshake_time_sec=0\n", false},
		{"non-zero", "public_key=def\nlast_handshake_time_sec=1734200000\nlast_handshake_time_nsec=0\n", true},
		{"trailing junk after value tolerated", "last_handshake_time_sec=42 garbage\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wgConfigHasHandshake(tc.cfg); got != tc.want {
				t.Fatalf("wgConfigHasHandshake(%q) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestPollWGReady_ColdToReady mimics the cold-start case: the first
// few IpcGet returns carry no handshake, then one does. pollWGReady
// must keep polling instead of returning early, and must stop the
// instant the handshake appears.
func TestPollWGReady_ColdToReady(t *testing.T) {
	var calls atomic.Int32
	getCfg := func() (string, error) {
		n := calls.Add(1)
		if n < 3 {
			return "public_key=def\nlast_handshake_time_sec=0\n", nil
		}
		return "public_key=def\nlast_handshake_time_sec=1734200000\n", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := pollWGReady(ctx, getCfg, 5*time.Millisecond); err != nil {
		t.Fatalf("pollWGReady cold→ready: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("pollWGReady cold→ready took %v, want < 1s", d)
	}
	if n := calls.Load(); n < 3 {
		t.Fatalf("calls = %d, want ≥ 3", n)
	}
}

// TestPollWGReady_WarmIsImmediate is the no-measurable-delay
// invariant for the warm path: if IpcGet reports handshake done on
// the very first read, pollWGReady must return without ever
// scheduling its tick.
func TestPollWGReady_WarmIsImmediate(t *testing.T) {
	var calls atomic.Int32
	getCfg := func() (string, error) {
		calls.Add(1)
		return "last_handshake_time_sec=1734200000\n", nil
	}
	// A huge interval would expose a regression where the loop
	// sleeps unconditionally on the first iteration.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pollWGReady(ctx, getCfg, time.Hour); err != nil {
		t.Fatalf("pollWGReady warm: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("warm path: calls = %d, want 1 (no polling required)", n)
	}
}

// TestPollWGReady_Timeout: handshake never lands, ctx expires →
// pollWGReady returns ctx.Err. The caller wraps that into the
// user-visible "wg handshake not established" message.
func TestPollWGReady_Timeout(t *testing.T) {
	getCfg := func() (string, error) {
		return "last_handshake_time_sec=0\n", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := pollWGReady(ctx, getCfg, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

// TestPollTsnetReady_ColdToReady: the dial probe fails until the
// exit-node ACL catches up, then succeeds. pollTsnetReady must keep
// retrying without burning the entire budget on one hung dial.
func TestPollTsnetReady_ColdToReady(t *testing.T) {
	var calls atomic.Int32
	dial := func(ctx context.Context) error {
		n := calls.Add(1)
		if n < 3 {
			return errors.New("no route")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := pollTsnetReady(ctx, dial, 50*time.Millisecond, 5*time.Millisecond); err != nil {
		t.Fatalf("pollTsnetReady cold→ready: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("pollTsnetReady cold→ready took %v, want < 1s", d)
	}
	if n := calls.Load(); n < 3 {
		t.Fatalf("calls = %d, want ≥ 3", n)
	}
}

// TestPollTsnetReady_WarmIsImmediate: a dial that succeeds on the
// first try must not schedule any sleeps. Same no-measurable-delay
// invariant as the wg warm case.
func TestPollTsnetReady_WarmIsImmediate(t *testing.T) {
	var calls atomic.Int32
	dial := func(ctx context.Context) error {
		calls.Add(1)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pollTsnetReady(ctx, dial, time.Hour, time.Hour); err != nil {
		t.Fatalf("pollTsnetReady warm: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("warm path: calls = %d, want 1", n)
	}
}

// TestPollTsnetReady_Timeout: dials never succeed, ctx expires → we
// surface DeadlineExceeded so the wrapper can fail with a useful
// error instead of hanging.
func TestPollTsnetReady_Timeout(t *testing.T) {
	dial := func(ctx context.Context) error {
		// Honor the per-probe ctx so the test runs at the configured
		// pace instead of the kernel's dial timeout.
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	err := pollTsnetReady(ctx, dial, 30*time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

// TestDaemonReadyErr_ClientParses round-trips a READYERR frame
// through the wire format: daemon writes it, the client parser
// surfaces the body as the error text. The wrapper relies on the
// body being preserved verbatim so the operator sees the actual
// failure (e.g. "wg handshake not established: context deadline
// exceeded") instead of a parser-stage error.
func TestDaemonReadyErr_ClientParses(t *testing.T) {
	daemonSide, clientSide := socketpairConns(t)
	defer func() { _ = daemonSide.Close() }()
	defer func() { _ = clientSide.Close() }()

	msg := "wg handshake not established: context deadline exceeded"
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := daemonWriteReadyErr(daemonSide, msg); err != nil {
			t.Errorf("daemonWriteReadyErr: %v", err)
		}
	}()

	br := bufio.NewReader(clientSide)
	err := daemonClientWaitAttached(clientSide, br)
	wg.Wait()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), msg) {
		t.Fatalf("err = %q, want it to contain %q", err.Error(), msg)
	}
}

// TestDaemonReadyErr_EmptyBody covers the n=0 edge: the daemon
// writes the framing but no body. Client must still return an
// error (no ATTACHED arrived) without trying to read zero bytes
// off the conn.
func TestDaemonReadyErr_EmptyBody(t *testing.T) {
	daemonSide, clientSide := socketpairConns(t)
	defer func() { _ = daemonSide.Close() }()
	defer func() { _ = clientSide.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := daemonWriteReadyErr(daemonSide, ""); err != nil {
			t.Errorf("daemonWriteReadyErr: %v", err)
		}
	}()

	br := bufio.NewReader(clientSide)
	err := daemonClientWaitAttached(clientSide, br)
	wg.Wait()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("err = %q, want it to mention 'not ready'", err.Error())
	}
}
