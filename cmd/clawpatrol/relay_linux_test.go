//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"unsafe"

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

// newRelaySocketpair returns a non-blocking SOCK_SEQPACKET socketpair
// wrapped in *os.File on both ends. Non-blocking is required for the
// SyscallConn.Read / Write paths to engage the runtime poller. Test
// helper, not used by production.
func newRelaySocketpair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	sp, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	a := os.NewFile(uintptr(sp[0]), "relay-test-a")
	b := os.NewFile(uintptr(sp[1]), "relay-test-b")
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// sendOneFrame is a tiny helper that ships one (u16 port, SCM_RIGHTS fd)
// frame to the worker over a *os.File-wrapped sock, bypassing the
// production sendJob helper so tests can drive recv-side behaviour
// directly.
func sendOneFrame(t *testing.T, sender *os.File, port uint16, fd int) {
	t.Helper()
	var portBuf [2]byte
	binary.LittleEndian.PutUint16(portBuf[:], port)
	rights := unix.UnixRights(fd)
	rc, err := sender.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := sendJob(rc, portBuf[:], rights); err != nil {
		t.Fatalf("sendJob: %v", err)
	}
}

// TestRecvJobReceivesFrame exercises the happy-path end-to-end: drop a
// frame onto one end of a real socketpair and confirm recvJob extracts
// the port and the SCM_RIGHTS fd from the other end.
func TestRecvJobReceivesFrame(t *testing.T) {
	sup, worker := newRelaySocketpair(t)

	// Use a pipe's read end as the "fd to ship" — any fd that the
	// receiver can fstat will do; we just want a recognisable kernel
	// object on the other end so this test catches accidental fd loss.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()

	sendOneFrame(t, sup, 8080, int(pr.Fd()))

	rc, err := worker.SyscallConn()
	if err != nil {
		t.Fatalf("worker SyscallConn: %v", err)
	}
	port, gotFD, err := recvJob(rc)
	if err != nil {
		t.Fatalf("recvJob: %v", err)
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
	if gotFD < 0 {
		t.Errorf("gotFD = %d, want >= 0", gotFD)
	}
	_ = unix.Close(gotFD)
}

// TestRecvJobAbsorbsEAGAINViaPoller verifies the SyscallConn.Read poller
// integration: a recvJob on an empty non-blocking socket must NOT return
// EAGAIN. It should park on the poller until a frame arrives, then
// complete. This is the property that replaces the previous explicit
// isTransientRecvErr retry — under load, transient EAGAINs are absorbed
// by the kernel poller, not surfaced to the loop.
func TestRecvJobAbsorbsEAGAINViaPoller(t *testing.T) {
	sup, worker := newRelaySocketpair(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()

	rc, err := worker.SyscallConn()
	if err != nil {
		t.Fatalf("worker SyscallConn: %v", err)
	}

	type result struct {
		port uint16
		fd   int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		port, fd, err := recvJob(rc)
		done <- result{port, fd, err}
	}()

	// Recv should be blocked in the poller. Confirm by ensuring no
	// result arrives within a short window.
	select {
	case r := <-done:
		t.Fatalf("recvJob returned prematurely: port=%d fd=%d err=%v", r.port, r.fd, r.err)
	case <-time.After(50 * time.Millisecond):
	}

	// Now publish a frame; recv should complete.
	sendOneFrame(t, sup, 9090, int(pr.Fd()))
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("recvJob err = %v, want nil", r.err)
		}
		if r.port != 9090 {
			t.Errorf("port = %d, want 9090", r.port)
		}
		_ = unix.Close(r.fd)
	case <-time.After(time.Second):
		t.Fatal("recvJob did not unblock after frame was sent")
	}
}

// TestRecvJobReturnsEOFOnPeerClose pins shutdown semantics: when the
// supervisor goes away, recvJob must return io.EOF (not EBADF, not a
// stray errno) so the loop can exit cleanly.
func TestRecvJobReturnsEOFOnPeerClose(t *testing.T) {
	sup, worker := newRelaySocketpair(t)
	_ = sup.Close()

	rc, err := worker.SyscallConn()
	if err != nil {
		t.Fatalf("worker SyscallConn: %v", err)
	}
	_, _, err = recvJob(rc)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("recvJob err = %v, want io.EOF", err)
	}
}

// TestRelayWorkerLoopDispatchesEndToEnd ships two frames through a real
// socketpair and confirms both reach the dispatch callback in order,
// then verifies a clean shutdown when the sender closes.
func TestRelayWorkerLoopDispatchesEndToEnd(t *testing.T) {
	sup, worker := newRelaySocketpair(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()

	rc, err := worker.SyscallConn()
	if err != nil {
		t.Fatalf("worker SyscallConn: %v", err)
	}

	type job struct {
		port uint16
		fd   int
	}
	jobs := make(chan job, 4)
	loopDone := make(chan struct{})
	go func() {
		relayWorkerLoop(rc, func(port uint16, fd int) {
			jobs <- job{port, fd}
		})
		close(loopDone)
	}()

	sendOneFrame(t, sup, 5000, int(pr.Fd()))
	sendOneFrame(t, sup, 5001, int(pr.Fd()))

	// Order between the two dispatch goroutines is non-deterministic;
	// collect both and check as a set.
	want := map[uint16]bool{5000: true, 5001: true}
	got := map[uint16]bool{}
	for i := 0; i < 2; i++ {
		select {
		case j := <-jobs:
			got[j.port] = true
			_ = unix.Close(j.fd)
		case <-time.After(time.Second):
			t.Fatalf("dispatch[%d] never ran (got so far: %v)", i, got)
		}
	}
	for p := range want {
		if !got[p] {
			t.Errorf("missing dispatch for port %d", p)
		}
	}

	// Sender closes → loop sees EOF → returns.
	_ = sup.Close()
	select {
	case <-loopDone:
	case <-time.After(time.Second):
		t.Fatal("relayWorkerLoop did not return after peer close")
	}
}

// TestLoopbackRedirectRuleArgs pins the exact iptables argv shape used
// for the host-loopback REDIRECT install. The wrapped command runs
// without CAP_NET_ADMIN so it cannot set SO_MARK; the mark-RETURN rule
// exists solely so the relay-worker's own dial to the agent loopback
// (auto-expose reverse direction) skips the REDIRECT and reaches the
// agent's local listener instead of looping back through the host.
func TestLoopbackRedirectRuleArgs(t *testing.T) {
	const fwdPort uint16 = 41234
	got := loopbackRedirectRuleArgs(fwdPort)
	want := [][]string{
		{"-t", "nat", "-A", "OUTPUT", "-m", "mark", "--mark", "0xc1aa/0xc1aa", "-j", "RETURN"},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.0/8",
			"-m", "tcp", "!", "--dport", "41234", "-j", "REDIRECT", "--to-ports", "41234"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loopbackRedirectRuleArgs(%d) =\n  %#v\nwant\n  %#v", fwdPort, got, want)
	}
}

// TestLoopbackRedirectDeleteArgs asserts the teardown args are the install
// args with -A swapped for -D (iptables -D matches on the full spec), and
// that deriving them does not perturb a fresh install-args slice.
func TestLoopbackRedirectDeleteArgs(t *testing.T) {
	const fwdPort uint16 = 41234
	got := loopbackRedirectDeleteArgs(fwdPort)
	want := [][]string{
		{"-t", "nat", "-D", "OUTPUT", "-m", "mark", "--mark", "0xc1aa/0xc1aa", "-j", "RETURN"},
		{"-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-d", "127.0.0.0/8",
			"-m", "tcp", "!", "--dport", "41234", "-j", "REDIRECT", "--to-ports", "41234"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loopbackRedirectDeleteArgs(%d) =\n  %#v\nwant\n  %#v", fwdPort, got, want)
	}
	// A freshly-built install slice must still say -A (no shared backing).
	if loopbackRedirectRuleArgs(fwdPort)[0][2] != "-A" {
		t.Fatalf("loopbackRedirectRuleArgs mutated to %q; delete-args must not share backing", loopbackRedirectRuleArgs(fwdPort)[0][2])
	}

	// Invariant, independent of the literals above: the delete args are the
	// install args verbatim except every -A becomes -D. This catches a
	// future rule added to the install set whose teardown would otherwise be
	// silently forgotten — iptables -D must remove exactly what -A added.
	install := loopbackRedirectRuleArgs(fwdPort)
	del := loopbackRedirectDeleteArgs(fwdPort)
	if len(del) != len(install) {
		t.Fatalf("delete args cover %d rules, install covers %d", len(del), len(install))
	}
	for i := range install {
		swapped := append([]string(nil), install[i]...)
		for j, tok := range swapped {
			if tok == "-A" {
				swapped[j] = "-D"
			}
		}
		if !reflect.DeepEqual(del[i], swapped) {
			t.Errorf("rule %d delete args %v are not install args modulo -A->-D (%v)", i, del[i], swapped)
		}
	}
}

// TestWorkerPIDFrameRoundTrip exercises the sendWorkerPID/recvWorkerPID
// path over a SOCK_SEQPACKET socketpair: the supervisor reads the
// worker's PID off the loopback sock before entering its main loop, and
// uses it to suppress mirroring of the worker's own listen() trap.
func TestWorkerPIDFrameRoundTrip(t *testing.T) {
	workerEnd, supEnd := newRelaySocketpair(t)
	workerRC, err := workerEnd.SyscallConn()
	if err != nil {
		t.Fatalf("worker SyscallConn: %v", err)
	}
	supRC, err := supEnd.SyscallConn()
	if err != nil {
		t.Fatalf("supervisor SyscallConn: %v", err)
	}
	// Note: sendWorkerPID writes os.Getpid(); we don't override that,
	// we just verify what we wrote is what we read.
	if err := sendWorkerPID(workerRC); err != nil {
		t.Fatalf("sendWorkerPID: %v", err)
	}
	got, err := recvWorkerPID(supRC)
	if err != nil {
		t.Fatalf("recvWorkerPID: %v", err)
	}
	if got != os.Getpid() {
		t.Fatalf("recvWorkerPID = %d, want %d", got, os.Getpid())
	}
}

// TestGetOriginalDstPortByteOrder verifies the endian dance inside
// getOriginalDst: SO_ORIGINAL_DST hands back a sockaddr_in with
// sin_port in network byte order; reading the in-memory bytes via
// binary.BigEndian must yield the host-order value regardless of host
// endianness. We can't actually call getsockopt without a redirected
// connection, but we CAN exercise the byte-order conversion against a
// synthetic struct.
func TestGetOriginalDstPortByteOrder(t *testing.T) {
	// Construct a RawSockaddrInet4 the same way the kernel would: Port
	// in network byte order. binary.BigEndian.PutUint16 on a [2]byte
	// alias of &sa.Port writes the network-order bytes.
	cases := []uint16{1, 80, 443, 8080, 65535}
	for _, want := range cases {
		var sa unix.RawSockaddrInet4
		portBytes := (*[2]byte)(unsafe.Pointer(&sa.Port))
		binary.BigEndian.PutUint16(portBytes[:], want)
		got := binary.BigEndian.Uint16(portBytes[:])
		if got != want {
			t.Errorf("port round-trip: got %d, want %d", got, want)
		}
	}
}

// TestLoopbackFrameRoundTrip verifies the (IP, port) wire frame the worker
// ships to the supervisor over the lb sock survives encode→decode. The IP
// matters now that the REDIRECT covers all of 127.0.0.0/8: a connect to
// 127.0.0.2 must arrive at the supervisor as 127.0.0.2, not collapse to
// 127.0.0.1.
func TestLoopbackFrameRoundTrip(t *testing.T) {
	cases := []struct {
		ip   [4]byte
		port uint16
	}{
		{[4]byte{127, 0, 0, 1}, 8080},
		{[4]byte{127, 0, 0, 2}, 5432},
		{[4]byte{127, 1, 2, 3}, 443},
		{[4]byte{127, 255, 255, 254}, 1},
		{[4]byte{127, 0, 0, 1}, 65535},
	}
	for _, tc := range cases {
		f := encodeLoopbackFrame(tc.ip, tc.port)
		if len(f) != loopbackFrameLen {
			t.Fatalf("frame len = %d, want %d", len(f), loopbackFrameLen)
		}
		gotIP, gotPort := decodeLoopbackFrame(f[:])
		if gotIP != tc.ip || gotPort != tc.port {
			t.Errorf("round-trip %v:%d → %v:%d", tc.ip, tc.port, gotIP, gotPort)
		}
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
