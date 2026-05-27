//go:build linux

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestParseProcNetIPHex covers the endian-juggling for the local_address
// column in /proc/net/tcp{,6}. The expected outputs are the canonical
// network-order bytes — the host endianness of the running test should
// not affect them.
func TestParseProcNetIPHex(t *testing.T) {
	cases := []struct {
		name string
		// hex string as emitted by the kernel on a little-endian host
		// (the only realistic clawpatrol target); parseProcNetIPHex
		// adapts via NativeEndian and produces the same network-order
		// bytes regardless of host.
		hexLE string
		want  net.IP
	}{
		{"v4 loopback", "0100007F", net.IPv4(127, 0, 0, 1).To4()},
		{"v4 any", "00000000", net.IPv4(0, 0, 0, 0).To4()},
		{"v4 1.2.3.4", "04030201", net.IPv4(1, 2, 3, 4).To4()},
		{"v6 any", "00000000000000000000000000000000", net.ParseIP("::")},
		{"v6 loopback", "00000000000000000000000001000000", net.ParseIP("::1")},
		{"v6 v4-mapped 127.0.0.1", "0000000000000000FFFF00000100007F", net.ParseIP("::ffff:127.0.0.1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The test only matches the canonical LE-host behaviour
			// because that's what the kernel emits on amd64/arm64.
			got, err := parseProcNetIPHex(tc.hexLE)
			if err != nil {
				t.Fatalf("parseProcNetIPHex(%q): %v", tc.hexLE, err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parseProcNetIPHex(%q) = %s, want %s", tc.hexLE, got, tc.want)
			}
		})
	}
}

// TestParseProcNetIPHexBadInput exercises the input validation.
func TestParseProcNetIPHexBadInput(t *testing.T) {
	cases := []string{
		"",
		"010",                                  // wrong length
		"GGGGGGGG",                             // bad hex
		"0100007F0100007F",                     // wrong length (16)
		"000000000000000000000000010000000000", // wrong length (36)
	}
	for _, s := range cases {
		if _, err := parseProcNetIPHex(s); err == nil {
			t.Fatalf("parseProcNetIPHex(%q) accepted bad input", s)
		}
	}
}

// TestScanProcNetTcp synthesises a /proc/net/tcp file and verifies
// scanProcNetTCP finds the row by inode + state.
func TestScanProcNetTcp(t *testing.T) {
	dir := t.TempDir()
	v4 := filepath.Join(dir, "tcp")
	v6 := filepath.Join(dir, "tcp6")

	if err := os.WriteFile(v4, []byte(""+
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99001 1 0000000000000000 100 0 0 10 0\n"+
		"   1: 04030201:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99002 1 0000000000000000 100 0 0 10 0\n"+
		"   2: 0100007F:2710 0100007F:1234 01 00000000:00000000 00:00000000 00000000  1000        0 99003 1 0000000000000000 100 0 0 10 0\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v6, []byte(""+
		"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99100 1 0000000000000000 100 0 0 10 0\n"+
		"   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99101 1 0000000000000000 100 0 0 10 0\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		ipHexLen  int
		inode     uint64
		wantPort  uint16
		wantIP    net.IP
		wantFound bool
	}{
		{"v4 listen on 127.0.0.1:8080", v4, 8, 99001, 8080, net.IPv4(127, 0, 0, 1).To4(), true},
		{"v4 listen on 1.2.3.4:80", v4, 8, 99002, 80, net.IPv4(1, 2, 3, 4).To4(), true},
		{"v4 established skipped", v4, 8, 99003, 0, nil, false},
		{"v4 missing inode", v4, 8, 12345, 0, nil, false},
		{"v6 listen on :::8080", v6, 32, 99100, 8080, net.ParseIP("::"), true},
		{"v6 listen on ::1:80", v6, 32, 99101, 80, net.ParseIP("::1"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port, ip, ok, err := scanProcNetTCP(tc.path, tc.inode, tc.ipHexLen)
			if err != nil {
				t.Fatalf("scanProcNetTCP: %v", err)
			}
			if ok != tc.wantFound {
				t.Fatalf("found=%v, want %v", ok, tc.wantFound)
			}
			if !tc.wantFound {
				return
			}
			if port != tc.wantPort {
				t.Errorf("port=%d, want %d", port, tc.wantPort)
			}
			if !ip.Equal(tc.wantIP) {
				t.Errorf("ip=%s, want %s", ip, tc.wantIP)
			}
		})
	}
}

// TestIsTransientRecvErr pins which errno classes the worker treats as
// retryable interruptions vs fatal. Regression guard for the symptom
// "[clawpatrol relay-worker] recv: resource temporarily unavailable"
// (EAGAIN's canonical strerror text) where the worker previously exited
// on the first EAGAIN instead of looping.
func TestIsTransientRecvErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EAGAIN", syscall.EAGAIN, true},
		{"EWOULDBLOCK", syscall.EWOULDBLOCK, true},
		{"EINTR", syscall.EINTR, true},
		{"wrapped EAGAIN", errors.Join(errors.New("recv"), syscall.EAGAIN), true},
		{"EOF", io.EOF, false},
		{"ECONNRESET", syscall.ECONNRESET, false},
		{"EBADF", syscall.EBADF, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientRecvErr(tc.err); got != tc.want {
				t.Errorf("isTransientRecvErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestRelayWorkerLoopRetriesTransient drives the loop with a fake recv
// that returns EAGAIN/EWOULDBLOCK/EINTR on the first call and io.EOF on
// the second. The loop must consume the transient and then exit cleanly
// on EOF — i.e. exactly two recv calls.
func TestRelayWorkerLoopRetriesTransient(t *testing.T) {
	transients := []struct {
		name string
		err  error
	}{
		{"EAGAIN", syscall.EAGAIN},
		{"EWOULDBLOCK", syscall.EWOULDBLOCK},
		{"EINTR", syscall.EINTR},
	}
	for _, tc := range transients {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			recv := func() (uint16, int, error) {
				calls++
				if calls == 1 {
					return 0, -1, tc.err
				}
				return 0, -1, io.EOF
			}
			relayWorkerLoop(recv, func(uint16, int) {
				t.Errorf("handle should not be called on errored recvs")
			})
			if calls != 2 {
				t.Errorf("recv calls = %d, want 2 (one transient + one EOF)", calls)
			}
		})
	}
}

// TestRelayWorkerLoopExitsOnFatal pins that non-transient, non-EOF errors
// terminate the loop immediately.
func TestRelayWorkerLoopExitsOnFatal(t *testing.T) {
	var calls int
	recv := func() (uint16, int, error) {
		calls++
		return 0, -1, syscall.ECONNRESET
	}
	relayWorkerLoop(recv, func(uint16, int) {
		t.Errorf("handle should not be called on errored recvs")
	})
	if calls != 1 {
		t.Errorf("recv calls = %d, want 1 (fatal exits immediately)", calls)
	}
}

// TestRelayWorkerLoopDispatches verifies a successful recv goes to handle
// before the loop continues. Uses a buffered channel so the goroutine can
// publish independent of test timing.
func TestRelayWorkerLoopDispatches(t *testing.T) {
	var calls int
	handled := make(chan uint16, 1)
	recv := func() (uint16, int, error) {
		calls++
		if calls == 1 {
			return 8080, 42, nil
		}
		return 0, -1, io.EOF
	}
	relayWorkerLoop(recv, func(port uint16, _ int) {
		handled <- port
	})
	select {
	case p := <-handled:
		if p != 8080 {
			t.Errorf("handled port = %d, want 8080", p)
		}
	case <-time.After(time.Second):
		t.Fatal("handle goroutine never ran")
	}
}

// TestRecvJobReturnsEAGAINOnEmptyNonblockingSocket exercises recvJob
// against a real SOCK_SEQPACKET socketpair flipped to nonblocking. With
// no pending frame the kernel returns EAGAIN; recvJob must surface that
// errno (not strip it or wrap it past recognition) so isTransientRecvErr
// can classify it correctly.
func TestRecvJobReturnsEAGAINOnEmptyNonblockingSocket(t *testing.T) {
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer func() { _ = unix.Close(sp[0]) }()
	defer func() { _ = unix.Close(sp[1]) }()

	if err := unix.SetNonblock(sp[1], true); err != nil {
		t.Fatalf("set nonblock: %v", err)
	}

	_, _, err = recvJob(sp[1])
	if err == nil {
		t.Fatal("recvJob on empty nonblocking socket returned nil error")
	}
	if !isTransientRecvErr(err) {
		t.Fatalf("recvJob err = %v, want classified transient (EAGAIN)", err)
	}
}

// TestMirrorBindScope verifies the host bind-address policy mirrors the
// agent's bind scope: loopback → loopback, otherwise unspecified, with
// a family-mismatch fallback to 127.0.0.1.
func TestMirrorBindScope(t *testing.T) {
	cases := []struct {
		family int
		inner  net.IP
		want   string
	}{
		{unix.AF_INET, net.IPv4(127, 0, 0, 1), "127.0.0.1"},
		{unix.AF_INET, net.IPv4(0, 0, 0, 0), "0.0.0.0"},
		{unix.AF_INET, net.IPv4(10, 0, 0, 5), "0.0.0.0"},
		{unix.AF_INET6, net.ParseIP("::1"), "::1"},
		{unix.AF_INET6, net.ParseIP("::"), "::"},
		{unix.AF_INET6, net.ParseIP("fd00::1"), "::"},
		{unix.AF_UNIX, net.IPv4(127, 0, 0, 1), "127.0.0.1"},
	}
	for _, tc := range cases {
		got := mirrorBindScope(tc.family, tc.inner)
		if got != tc.want {
			t.Errorf("mirrorBindScope(%d, %s) = %s, want %s",
				tc.family, tc.inner, got, tc.want)
		}
	}
}
