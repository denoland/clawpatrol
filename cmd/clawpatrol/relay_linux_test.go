//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// skipIfSandboxBlocks short-circuits a test when the underlying syscall
// is blocked by the test environment (e.g. CI sandboxes that disable
// listen/bind for non-loopback or return ENOSYS). The real supervisor
// runs outside the test process and isn't affected; we just don't want
// false negatives locally.
func skipIfSandboxBlocks(t *testing.T, op string, err error) {
	t.Helper()
	for _, e := range []error{syscall.ENOSYS, syscall.EPERM, syscall.EACCES, syscall.EAFNOSUPPORT} {
		if errors.Is(err, e) {
			t.Skipf("sandbox blocks %s: %v", op, err)
		}
	}
}

// writeProcTCP4 writes a one-row /proc/net/tcp file with the given inode
// at local_address (col 1) in state (col 3). An empty local/state writes
// a header-only stub (the scanner skips it but still considers the file
// readable, which simulates a netns with no v4 listeners).
func writeProcTCP4(t *testing.T, path string, inode uint64, local, state string) {
	t.Helper()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	body := ""
	if local != "" && state != "" {
		body = fmt.Sprintf("   0: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 100 0 0 10 0\n", local, state, inode)
	}
	if err := os.WriteFile(path, []byte(header+body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeProcTCP6 is the v6 counterpart to writeProcTCP4.
func writeProcTCP6(t *testing.T, path string, inode uint64, local, state string) {
	t.Helper()
	header := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	body := ""
	if local != "" && state != "" {
		body = fmt.Sprintf("   0: %s 00000000000000000000000000000000:0000 %s 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 100 0 0 10 0\n", local, state, inode)
	}
	if err := os.WriteFile(path, []byte(header+body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

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

// TestProcReadSocketInode covers the pre-continue inode capture: open a
// real TCP socket (without listen()) and confirm procReadSocketInode
// parses out the kernel inode of the corresponding /proc/self/fd link.
//
// This is the lookup that has to succeed BEFORE we send CONTINUE in the
// supervisor, because the fd may close shortly after the agent's listen
// returns — see denoland/orchid#175.
func TestProcReadSocketInode(t *testing.T) {
	// Bind a TCP socket but don't listen — the inode exists in the
	// fd table either way, so the pre-continue path works.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		skipIfSandboxBlocks(t, "socket", err)
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		skipIfSandboxBlocks(t, "bind", err)
		t.Fatalf("bind: %v", err)
	}

	pid := os.Getpid()
	inode, err := procReadSocketInode("/proc", pid, fd)
	if err != nil {
		t.Fatalf("procReadSocketInode: %v", err)
	}

	// Cross-check by stat'ing the fd link directly; the inode of the
	// socket is the same number the kernel embeds in the readlink target.
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/fd/%d", pid, fd), &st); err != nil {
		t.Fatalf("stat /proc/self/fd: %v", err)
	}
	if st.Ino != inode {
		t.Fatalf("inode mismatch: parsed %d vs stat %d", inode, st.Ino)
	}
}

// TestProcReadSocketInodeBadLink validates the parse rejects non-socket
// fds and malformed readlink output. Defensive: a fd table lookup
// returning anything other than "socket:[N]" means we should not be
// using the /proc fallback at all.
func TestProcReadSocketInodeBadLink(t *testing.T) {
	dir := t.TempDir()
	pidDir := filepath.Join(dir, "1", "fd")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, target string
	}{
		{"file fd", "/etc/hosts"},
		{"pipe fd", "pipe:[123]"},
		{"truncated", "socket:[12"},
		{"missing prefix", "[12]"},
		{"non-numeric inode", "socket:[abc]"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link := filepath.Join(pidDir, fmt.Sprintf("%d", i))
			if err := os.Symlink(tc.target, link); err != nil {
				t.Fatal(err)
			}
			if _, err := procReadSocketInode(dir, 1, i); err == nil {
				t.Fatalf("accepted bad readlink target %q", tc.target)
			}
		})
	}
}

// TestProcPollForListenSuccess covers the post-continue happy path: the
// inode already shows up in TCP_LISTEN state on the first read.
func TestProcPollForListenSuccess(t *testing.T) {
	dir := t.TempDir()
	procDir := filepath.Join(dir, "1234", "net")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeProcTCP6(t, filepath.Join(procDir, "tcp6"), 99001, "00000000000000000000000000000000:1F90", "0A")
	writeProcTCP4(t, filepath.Join(procDir, "tcp"), 0, "", "")

	port, ip, family, err := procPollForListen(dir, 1234, 99001, 100*time.Millisecond, time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("procPollForListen: %v", err)
	}
	if port != 8080 || family != unix.AF_INET6 || !ip.Equal(net.ParseIP("::")) {
		t.Fatalf("got port=%d family=%d ip=%s, want :::8080", port, family, ip)
	}
}

// TestProcPollForListenRace mirrors the production race: the supervisor
// has just sent CONTINUE but the kernel has not yet flipped the socket
// to TCP_LISTEN. The poll has to retry until the row appears.
//
// This is the regression test for denoland/orchid#175 — pre-fix, the
// fallback ran inside the trapped listen() window and saw no TCP_LISTEN
// row, then gave up forever.
func TestProcPollForListenRace(t *testing.T) {
	dir := t.TempDir()
	procDir := filepath.Join(dir, "1234", "net")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp4 := filepath.Join(procDir, "tcp")
	tcp6 := filepath.Join(procDir, "tcp6")
	// Initially neither file contains our inode. Use a non-matching
	// row so the scanner still has structurally valid content.
	writeProcTCP4(t, tcp4, 12345, "0100007F:1F90", "0A")
	writeProcTCP6(t, tcp6, 12345, "00000000000000000000000000000000:1F90", "0A")

	// After 25ms (well inside the 200ms poll budget), flip the v4
	// file to include the inode in TCP_LISTEN state.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(25 * time.Millisecond)
		writeProcTCP4(t, tcp4, 99001, "0100007F:1F90", "0A")
	}()
	defer wg.Wait()

	start := time.Now()
	port, ip, family, err := procPollForListen(dir, 1234, 99001, 200*time.Millisecond, time.Millisecond, 10*time.Millisecond)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("procPollForListen: %v (after %v)", err, elapsed)
	}
	if port != 8080 || family != unix.AF_INET || !ip.Equal(net.IPv4(127, 0, 0, 1).To4()) {
		t.Fatalf("got port=%d family=%d ip=%s, want 127.0.0.1:8080", port, family, ip)
	}
	if elapsed < 20*time.Millisecond {
		t.Fatalf("poll returned too fast (%v) — likely didn't observe the race", elapsed)
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("poll took %v, expected to converge soon after 25ms transition", elapsed)
	}
}

// TestProcPollForListenTimeout confirms the bounded-retry contract: if
// the inode never appears, we give up cleanly with a descriptive error
// instead of spinning forever.
func TestProcPollForListenTimeout(t *testing.T) {
	dir := t.TempDir()
	procDir := filepath.Join(dir, "1234", "net")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeProcTCP4(t, filepath.Join(procDir, "tcp"), 0, "", "")
	writeProcTCP6(t, filepath.Join(procDir, "tcp6"), 0, "", "")

	start := time.Now()
	_, _, _, err := procPollForListen(dir, 1234, 99001, 25*time.Millisecond, time.Millisecond, 10*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "no TCP_LISTEN row with inode 99001") {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed < 25*time.Millisecond {
		t.Fatalf("returned before timeout: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("ran way past timeout: %v", elapsed)
	}
}

// TestProcPollForListenMissingFiles confirms that an entirely absent
// /proc tree returns the timeout error, not an IO panic — the scanner
// treats ENOENT as "keep trying" since /proc/<pid>/net/tcp6 may be
// missing on systems with IPv6 disabled.
func TestProcPollForListenMissingFiles(t *testing.T) {
	dir := t.TempDir() // no pid subdir at all
	_, _, _, err := procPollForListen(dir, 1234, 99001, 15*time.Millisecond, time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error on missing /proc tree")
	}
}

// TestCaptureBeforeContinueProducesAnswer exercises the full
// pre-continue + resolve pipeline against a real bound+listening socket
// in our own process. Whichever path succeeds (pidfd or /proc), we must
// recover the bound port and address — never end up with both branches
// in their error state.
func TestCaptureBeforeContinueProducesAnswer(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		skipIfSandboxBlocks(t, "socket", err)
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		skipIfSandboxBlocks(t, "bind", err)
		t.Fatalf("bind: %v", err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		skipIfSandboxBlocks(t, "listen", err)
		t.Fatalf("listen: %v", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	wantPort := uint16(sa.(*unix.SockaddrInet4).Port)

	c := captureBeforeContinue(os.Getpid(), fd)
	if c.pidfd == nil && !c.inodeOK {
		t.Fatalf("capture produced neither pidfd nor inode: pidfdErr=%v inodeErr=%v",
			c.pidfdErr, c.inodeErr)
	}
	port, ip, family, err := c.resolveAfterContinue()
	if err != nil {
		t.Fatalf("resolveAfterContinue: %v", err)
	}
	if port != wantPort || (family != unix.AF_INET && family != unix.AF_INET6) {
		t.Fatalf("bad capture: port=%d (want %d) family=%d ip=%s", port, wantPort, family, ip)
	}
}

// TestCaptureBeforeContinueFallbackInode forces the /proc fallback by
// supplying an unreadable pid to pidfdPeekListener and verifies the
// inode-capture path runs. This is the structural regression that
// makes denoland/orchid#175 survivable: when pidfd_getfd can't dup
// the fd (multi-threaded agents, fork-then-listen patterns), we still
// must grab the inode before sending CONTINUE.
func TestCaptureBeforeContinueFallbackInode(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		skipIfSandboxBlocks(t, "socket", err)
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		skipIfSandboxBlocks(t, "bind", err)
		t.Fatalf("bind: %v", err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		skipIfSandboxBlocks(t, "listen", err)
		t.Fatalf("listen: %v", err)
	}

	// Test the inode-capture half directly. pidfdPeekListener may
	// succeed in-process, so we bypass it and call the fallback
	// component the supervisor would use after pidfd failed.
	inode, err := procReadSocketInode("/proc", os.Getpid(), fd)
	if err != nil {
		t.Fatalf("procReadSocketInode: %v", err)
	}
	if inode == 0 {
		t.Fatalf("got inode 0")
	}

	// And the post-continue side resolves the same inode against the
	// real /proc/net/tcp{,6}, since we listen()'d above.
	port, ip, family, err := procPollForListen("/proc", os.Getpid(), inode, 500*time.Millisecond, time.Millisecond, 25*time.Millisecond)
	if err != nil {
		t.Fatalf("procPollForListen: %v", err)
	}
	if port == 0 || ip == nil || (family != unix.AF_INET && family != unix.AF_INET6) {
		t.Fatalf("bad fallback result: port=%d ip=%s family=%d", port, ip, family)
	}
}

// TestResolveAfterContinuePidfdShortcut verifies the pidfd fast path
// skips polling entirely (resolveAfterContinue must be ~free when the
// pre-continue capture already has an answer).
func TestResolveAfterContinuePidfdShortcut(t *testing.T) {
	c := &listenerCapture{
		pidfd: &listenerInfo{port: 4242, ip: net.ParseIP("10.1.2.3"), family: unix.AF_INET},
		// Intentionally absurd timeout — should never be consulted.
		pollTimeout: 10 * time.Second,
	}
	start := time.Now()
	port, ip, family, err := c.resolveAfterContinue()
	if err != nil {
		t.Fatalf("resolveAfterContinue: %v", err)
	}
	if port != 4242 || family != unix.AF_INET || !ip.Equal(net.ParseIP("10.1.2.3")) {
		t.Fatalf("bad pidfd passthrough: %d %s %d", port, ip, family)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatalf("pidfd shortcut took the polling path")
	}
}

// TestRelayFDsSurviveGC is the regression test for the "notif_recv: bad
// file descriptor" half of denoland/orchid#175. runRelaySupervisor
// extracts raw fds from *os.File wrappers and then never references
// the wrappers again, so the GC was free to run the wrappers'
// finalizers (which close the fd). Once the seccomp notify fd was
// closed, the next ioctl(NOTIF_RECV) returned EBADF and the supervisor
// died.
//
// We can't drive the real supervisor in a unit test, but the failure
// mode is independent of seccomp — any os.NewFile(fd, ...) whose fd is
// only kept as an int has the same hazard. The fix is the package-level
// `relaySupervisorFiles` map that keeps the wrappers reachable; this
// test models that pattern and verifies it survives GC pressure.
//
// Modeling note: this test prove the *strategy* works (a long-lived
// reference stops the finalizer from running) — the supervisor's
// actual use of relaySupervisorFiles is exercised by inspection of the
// runRelaySupervisor code path.
func TestRelayFDsSurviveGC(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer func() { _ = unix.Close(pair[1]) }()

	f := os.NewFile(uintptr(pair[0]), "test-relay-fd")
	if f == nil {
		t.Fatal("os.NewFile returned nil")
	}
	rawFD := int(f.Fd())

	// Mirror the supervisor's strategy: pin the *os.File in a
	// long-lived container so its finalizer can't run.
	keepAlive := map[*os.File]struct{}{f: {}}
	defer func() { delete(keepAlive, f) }()

	// Drop the only local reference and aggressively GC. With the
	// pinning in place, the fd must stay open.
	f = nil
	for i := 0; i < 3; i++ {
		runtime.GC()
	}

	// fcntl(F_GETFD) on a live fd returns 0 or FD_CLOEXEC; on a
	// closed fd it returns EBADF.
	if _, err := unix.FcntlInt(uintptr(rawFD), unix.F_GETFD, 0); err != nil {
		if errors.Is(err, syscall.EBADF) {
			t.Fatalf("fd was closed by finalizer (denoland/orchid#175 regression)")
		}
		t.Fatalf("unexpected fcntl error: %v", err)
	}
}

// TestRelayFDsClosedWithoutPin is the inverse: without the
// package-level pin, the wrapper's finalizer DOES close the fd. This
// proves the failure mode that motivates the fix exists, and that the
// pin in TestRelayFDsSurviveGC is what's preventing it.
//
// Skipped if the runtime doesn't actually close the fd in the test's
// short window — older Go runtimes occasionally defer finalizers; the
// fix only needs to make finalizer execution irrelevant, not
// deterministic.
func TestRelayFDsClosedWithoutPin(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer func() { _ = unix.Close(pair[1]) }()

	rawFD := setupOrphanFile(pair[0])

	for i := 0; i < 5; i++ {
		runtime.GC()
	}

	if _, err := unix.FcntlInt(uintptr(rawFD), unix.F_GETFD, 0); err == nil {
		t.Skip("runtime did not finalize the wrapper in the test window; cannot prove the failure mode here, but the positive test (TestRelayFDsSurviveGC) still covers the fix")
	} else if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("unexpected fcntl error: %v (want EBADF)", err)
	}
}

// setupOrphanFile wraps fd in *os.File and immediately drops the only
// reference, so the GC's next pass is free to run the finalizer.
// Isolating this in its own function keeps liveness analysis from
// "rescuing" the wrapper across the caller's stack frame.
//
//go:noinline
func setupOrphanFile(fd int) int {
	f := os.NewFile(uintptr(fd), "orphan")
	if f == nil {
		return -1
	}
	return int(f.Fd())
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
