package main

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// fakeBind refuses batched sends the way the kernel refuses a GSO
// segment wider than the route, and accepts single datagrams.
type fakeBind struct {
	conn.Bind
	calls [][]int // lengths per Send call
}

func (f *fakeBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	lens := make([]int, len(bufs))
	for i, b := range bufs {
		lens[i] = len(b)
	}
	f.calls = append(f.calls, lens)
	if len(bufs) > 1 {
		// The real chain from x/net: *net.OpError wrapping the syscall error.
		return &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendmmsg", syscall.EMSGSIZE)}
	}
	return nil
}

func TestGSOFallbackBindDegradesToSingleSends(t *testing.T) {
	inner := &fakeBind{}
	b := &gsoFallbackBind{Bind: inner, describe: "test"}
	batch := [][]byte{make([]byte, 1500), make([]byte, 1500), make([]byte, 700)}

	if err := b.Send(batch, nil); err != nil {
		t.Fatalf("first batch: %v", err)
	}
	// One failed batched attempt, then three single sends.
	if len(inner.calls) != 4 || len(inner.calls[0]) != 3 {
		t.Fatalf("calls after first batch = %v", inner.calls)
	}
	for _, c := range inner.calls[1:] {
		if len(c) != 1 {
			t.Fatalf("expected single sends after fallback, got %v", inner.calls)
		}
	}

	// Sticky: the next batch is never tried as a batch again.
	inner.calls = nil
	if err := b.Send(batch, nil); err != nil {
		t.Fatalf("second batch: %v", err)
	}
	if len(inner.calls) != 3 {
		t.Fatalf("expected 3 single sends, got %v", inner.calls)
	}
}

func TestGSOFallbackBindPassesOtherErrorsThrough(t *testing.T) {
	inner := &errBind{err: &os.SyscallError{Syscall: "sendmmsg", Err: syscall.ENETUNREACH}}
	b := &gsoFallbackBind{Bind: inner, describe: "test"}
	err := b.Send([][]byte{make([]byte, 10), make([]byte, 10)}, nil)
	if !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("err = %v, want ENETUNREACH passed through", err)
	}
	if b.single.Load() {
		t.Fatal("fell back on an unrelated error")
	}
}

type errBind struct {
	conn.Bind
	err error
}

func (e *errBind) Send([][]byte, conn.Endpoint) error { return e.err }

// A single buffer never goes through the batched attempt, and a
// failure while sending singly stops at that buffer.
func TestGSOFallbackBindSingleBufferAndStopOnError(t *testing.T) {
	inner := &fakeBind{}
	b := &gsoFallbackBind{Bind: inner, describe: "test"}
	if err := b.Send([][]byte{make([]byte, 1500)}, nil); err != nil {
		t.Fatal(err)
	}
	if len(inner.calls) != 1 || len(inner.calls[0]) != 1 || b.single.Load() {
		t.Fatalf("single buffer took the batched path: %v single=%v", inner.calls, b.single.Load())
	}

	failing := &errBind{err: &net.OpError{Op: "write", Err: os.NewSyscallError("sendmsg", syscall.ENETUNREACH)}}
	b = &gsoFallbackBind{Bind: failing, describe: "test"}
	b.single.Store(true)
	if err := b.Send([][]byte{{1}, {2}, {3}}, nil); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("err = %v", err)
	}
}
