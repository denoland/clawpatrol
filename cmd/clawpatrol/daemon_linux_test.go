//go:build linux

package main

// In-memory round-trip of the daemon's control protocol. Does not
// boot tsnet, does not build a gVisor stack — exercises only the
// wire format and the SCM_RIGHTS fd hand-off. A real Unix
// socketpair is used (not net.Pipe) because the daemon
// type-asserts the conn to *net.UnixConn for the SCM_RIGHTS recv,
// and File() on a non-Unix conn would not return a usable fd.

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// socketpairConns returns two ends of an AF_UNIX SOCK_STREAM
// socketpair as *net.UnixConn. The underlying fds are owned by the
// returned conns; closing them releases the fds.
func socketpairConns(t *testing.T) (a, b *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	fa := os.NewFile(uintptr(fds[0]), "sp-a")
	fb := os.NewFile(uintptr(fds[1]), "sp-b")
	defer func() { _ = fa.Close() }()
	defer func() { _ = fb.Close() }()
	ca, err := net.FileConn(fa)
	if err != nil {
		t.Fatalf("FileConn a: %v", err)
	}
	cb, err := net.FileConn(fb)
	if err != nil {
		_ = ca.Close()
		t.Fatalf("FileConn b: %v", err)
	}
	uc1, ok1 := ca.(*net.UnixConn)
	uc2, ok2 := cb.(*net.UnixConn)
	if !ok1 || !ok2 {
		_ = ca.Close()
		_ = cb.Close()
		t.Fatalf("expected *net.UnixConn, got %T / %T", ca, cb)
	}
	return uc1, uc2
}

// TestDaemonProtocolRoundTrip drives the full session-start protocol
// end-to-end over a real Unix socketpair: hello handshake, START
// command, ADDR/ENV/WARN reply, SCM_RIGHTS TUN-fd hand-off, ATTACHED
// reply. Verifies the client-side parser reconstructs every value
// the daemon-side encoder ships, and that a real fd flows through
// SCM_RIGHTS in both directions.
//
// Covers cases:
//   - non-empty env-pushdown payload
//   - non-empty boot warning (the load-bearing case for the new WARN
//     frame — empty would still pass even with the WARN line missing)
//   - real fd round-trip (writes a sentinel byte through the recv'd
//     fd and reads it back on the original to confirm).
func TestDaemonProtocolRoundTrip(t *testing.T) {
	daemonSide, clientSide := socketpairConns(t)
	defer func() { _ = daemonSide.Close() }()
	defer func() { _ = clientSide.Close() }()

	wantTunAddr := netip.MustParseAddr("100.64.0.7")
	envVarsIn := []pushdownEnvVar{
		{Name: "SSL_CERT_FILE", Value: "/home/u/.clawpatrol/ca.crt"},
		{Name: "GH_TOKEN", Value: "ghp_placeholder", Description: "github"},
	}
	envJSON, err := json.Marshal(envVarsIn)
	if err != nil {
		t.Fatalf("marshal env: %v", err)
	}
	wantWarning := "tsnet probe: gateway unreachable via exit-node routing (i/o timeout). " +
		"Check autoApprovers.exitNode in your tailnet ACL."

	// A pair of socketpair'd fds for the SCM_RIGHTS round-trip
	// payload. The daemon side recvs one end; the client keeps the
	// other to write a sentinel byte we can read on the recv'd end.
	fdPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("fd-payload socketpair: %v", err)
	}
	clientKeeps := os.NewFile(uintptr(fdPair[0]), "payload-a")
	defer func() { _ = clientKeeps.Close() }()
	defer func() { _ = unix.Close(fdPair[1]) }()

	// --- daemon side --------------------------------------------------
	type daemonResult struct {
		recvFd   int
		attached bool
		err      error
	}
	dCh := make(chan daemonResult, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		res := daemonResult{recvFd: -1}
		defer func() { dCh <- res }()

		if err := daemonHandshake(daemonSide); err != nil {
			res.err = err
			return
		}
		br := bufio.NewReader(daemonSide)
		cmd, err := br.ReadString('\n')
		if err != nil {
			res.err = err
			return
		}
		if cmd != "START\n" {
			res.err = io.ErrUnexpectedEOF
			return
		}
		if err := daemonWriteStartReply(daemonSide, wantTunAddr, envJSON, wantWarning); err != nil {
			res.err = err
			return
		}
		recvFd, err := recvFDUnixConn(daemonSide)
		if err != nil {
			res.err = err
			return
		}
		res.recvFd = recvFd
		if _, err := io.WriteString(daemonSide, "ATTACHED\n"); err != nil {
			res.err = err
			return
		}
		res.attached = true
	}()

	// --- client side --------------------------------------------------
	if err := daemonHello(clientSide); err != nil {
		t.Fatalf("client daemonHello: %v", err)
	}
	// daemonClientStartSession writes "START\n" itself — do not write
	// it here too. An extra START would sit in the kernel buffer until
	// some later read; if that read happens to be the recvmsg waiting
	// for SCM_RIGHTS, Linux truncates at the byte-before-ancillary and
	// the FD never gets delivered.
	br, gotTunAddr, gotEnv, gotWarning, err := daemonClientStartSession(clientSide)
	if err != nil {
		t.Fatalf("daemonClientStartSession: %v", err)
	}
	if gotTunAddr != wantTunAddr {
		t.Errorf("tunAddr: got %v, want %v", gotTunAddr, wantTunAddr)
	}
	if gotWarning != wantWarning {
		t.Errorf("warning: got %q\nwant %q", gotWarning, wantWarning)
	}
	if !envVarsEqual(gotEnv, envVarsIn) {
		t.Errorf("env vars: got %+v, want %+v", gotEnv, envVarsIn)
	}
	if err := sendFDUnixConn(clientSide, fdPair[1]); err != nil {
		t.Fatalf("client sendFD: %v", err)
	}
	// Pull the daemon's result FIRST so a daemon-side error surfaces
	// as a clear failure message, instead of the client timing out
	// reading ATTACHED that the daemon never wrote.
	wg.Wait()
	res := <-dCh
	if res.err != nil {
		t.Fatalf("daemon side: %v", res.err)
	}
	if !res.attached {
		t.Fatalf("daemon never wrote ATTACHED")
	}
	if err := daemonClientWaitAttached(clientSide, br); err != nil {
		t.Fatalf("client wait ATTACHED: %v", err)
	}

	// Smoke-verify the SCM_RIGHTS fd actually points at the same
	// socketpair: write a sentinel through the daemon's recv'd fd,
	// read it on the client's retained end.
	defer func() { _ = unix.Close(res.recvFd) }()
	if _, err := unix.Write(res.recvFd, []byte{0xAB}); err != nil {
		t.Fatalf("write to recv'd fd: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := unix.Read(int(clientKeeps.Fd()), buf); err != nil {
		t.Fatalf("read sentinel on client end: %v", err)
	}
	if buf[0] != 0xAB {
		t.Fatalf("sentinel mismatch: got %#x, want 0xAB", buf[0])
	}
}

// TestDaemonProtocol_EmptyWarning covers the n=0 WARN frame: the
// daemon still emits "WARN 0\n" with no body, the client parses it,
// and the empty warning is returned without spurious bytes.
func TestDaemonProtocol_EmptyWarning(t *testing.T) {
	daemonSide, clientSide := socketpairConns(t)
	defer func() { _ = daemonSide.Close() }()
	defer func() { _ = clientSide.Close() }()

	go func() {
		_ = daemonHandshake(daemonSide)
		br := bufio.NewReader(daemonSide)
		_, _ = br.ReadString('\n') // "START\n"
		_ = daemonWriteStartReply(daemonSide, netip.MustParseAddr("100.64.0.1"), []byte("[]"), "")
	}()

	if err := daemonHello(clientSide); err != nil {
		t.Fatalf("client hello: %v", err)
	}
	// START is written by daemonClientStartSession itself.
	_, _, _, gotWarning, err := daemonClientStartSession(clientSide)
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}
	if gotWarning != "" {
		t.Errorf("warning: got %q, want empty", gotWarning)
	}
}

// TestDaemonClientParse_Malformed feeds the client parser
// hand-rolled byte streams that violate the protocol, and checks
// each variant returns a non-nil error rather than a misinterpreted
// value.
func TestDaemonClientParse_Malformed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing ADDR prefix", "WAT 100.64.0.1\nENV 0\nWARN 0\n"},
		{"bad ADDR value", "ADDR not-an-ip\nENV 0\nWARN 0\n"},
		{"missing ENV prefix", "ADDR 100.64.0.1\nVNE 0\nWARN 0\n"},
		{"non-numeric ENV length", "ADDR 100.64.0.1\nENV xyz\nWARN 0\n"},
		{"oversized ENV length", "ADDR 100.64.0.1\nENV 9999999999\nWARN 0\n"},
		{"missing WARN frame", "ADDR 100.64.0.1\nENV 0\n"},
		{"oversized WARN length", "ADDR 100.64.0.1\nENV 0\nWARN 99999\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			daemonSide, clientSide := socketpairConns(t)
			defer func() { _ = daemonSide.Close() }()
			defer func() { _ = clientSide.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = io.WriteString(daemonSide, tc.body)
				_ = daemonSide.Close()
			}()
			_, _, _, _, err := daemonClientStartSession(clientSide)
			<-done // join the writer so we never leak goroutines or fds
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

// TestDaemonEnvCommand_RoundTrip drives daemonWriteEnvReply through
// daemonClientFetchEnv over a socketpair: the daemon's lightweight
// ENV command (no session / TUN / gvisor) reads back as the same
// pushdownEnvVar slice the daemon cached.
func TestDaemonEnvCommand_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		vars []pushdownEnvVar
	}{
		{"empty list", nil},
		{
			"two vars",
			[]pushdownEnvVar{
				{Name: "OPENAI_API_KEY", Value: "<placeholder>", Description: "OpenAI", PluginType: "openai"},
				{Name: "ANTHROPIC_API_KEY", Value: "<placeholder>", Description: "Anthropic"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.vars)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if tc.vars == nil {
				body = nil // exercise the n=0 branch
			}
			daemonSide, clientSide := socketpairConns(t)
			defer func() { _ = daemonSide.Close() }()
			defer func() { _ = clientSide.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				br := bufio.NewReader(daemonSide)
				cmd, err := br.ReadString('\n')
				if err != nil {
					t.Errorf("daemon read cmd: %v", err)
					return
				}
				if cmd != "ENV\n" {
					t.Errorf("daemon got cmd %q, want %q", cmd, "ENV\n")
					return
				}
				if err := daemonWriteEnvReply(daemonSide, body); err != nil {
					t.Errorf("daemonWriteEnvReply: %v", err)
				}
				_ = daemonSide.Close()
			}()
			got, err := daemonClientFetchEnv(clientSide)
			<-done
			if err != nil {
				t.Fatalf("daemonClientFetchEnv: %v", err)
			}
			if !envVarsEqual(got, tc.vars) {
				t.Errorf("env vars: got %+v, want %+v", got, tc.vars)
			}
		})
	}
}

// TestDaemonFreshEnvVarsPicksUpChanges verifies that freshEnvVars
// hits the gateway on every call: a credential change on the gateway
// side (modelled here as the injected fetcher returning a new payload)
// is reflected in the very next freshEnvVars call without restarting
// the daemon — regression check for #546.
//
// Uses an injected fetcher so the test doesn't require a real
// /api/env-pushdown HTTP round-trip; the unit under test is the
// daemon's per-call fetch wiring, not the HTTP plumbing (which
// TestFetchEnvPushdownFromGateway already covers).
func TestDaemonFreshEnvVarsPicksUpChanges(t *testing.T) {
	initial, err := json.Marshal([]pushdownEnvVar{
		{Name: "GH_TOKEN", Value: "ghp_initial", PluginType: "github_oauth"},
	})
	if err != nil {
		t.Fatalf("marshal initial: %v", err)
	}
	updated, err := json.Marshal([]pushdownEnvVar{
		{Name: "GH_TOKEN", Value: "ghp_initial", PluginType: "github_oauth"},
		{Name: "ANTHROPIC_AUTH_TOKEN", Value: "sk-ant-new", PluginType: "anthropic_oauth_subscription"},
	})
	if err != nil {
		t.Fatalf("marshal updated: %v", err)
	}

	var (
		mu      sync.Mutex
		current = initial
		calls   int
	)
	fetch := func() []byte {
		mu.Lock()
		defer mu.Unlock()
		calls++
		out := make([]byte, len(current))
		copy(out, current)
		return out
	}

	d := &daemon{envFetch: fetch}

	if got := string(d.freshEnvVars()); got != string(initial) {
		t.Fatalf("initial freshEnvVars = %q, want %q", got, string(initial))
	}
	if calls != 1 {
		t.Fatalf("after one freshEnvVars: calls = %d, want 1", calls)
	}

	// Simulate the operator connecting a new credential on the
	// gateway: subsequent fetches now return the updated payload. The
	// very next freshEnvVars must reflect it — no cache, no waiting
	// for a background tick.
	mu.Lock()
	current = updated
	mu.Unlock()

	if got := string(d.freshEnvVars()); got != string(updated) {
		t.Fatalf("after gateway update: freshEnvVars = %q, want %q", got, string(updated))
	}
	if calls != 2 {
		t.Fatalf("after two freshEnvVars: calls = %d, want 2 (every call must fetch)", calls)
	}
}

// TestDaemonFreshEnvVarsKeepsLastGoodOnTransientEmpty verifies the
// transient-failure guard in freshEnvVars: a fetch that returns an
// empty list (the sentinel daemonFetchEnvPushdown emits on every kind
// of fetch failure) must NOT clobber a previously-observed non-empty
// list. Without this guard a single gateway blip would silently drop
// every declared env var from the daemon's pushdown for one session.
func TestDaemonFreshEnvVarsKeepsLastGoodOnTransientEmpty(t *testing.T) {
	good, err := json.Marshal([]pushdownEnvVar{
		{Name: "GH_TOKEN", Value: "ghp_good"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var (
		mu    sync.Mutex
		empty bool
	)
	fetch := func() []byte {
		mu.Lock()
		defer mu.Unlock()
		if empty {
			return []byte("[]")
		}
		return good
	}

	d := &daemon{envFetch: fetch}

	// First call: real payload — populates lastGoodEnv.
	if got := string(d.freshEnvVars()); got != string(good) {
		t.Fatalf("initial freshEnvVars = %q, want %q", got, string(good))
	}

	// Gateway "goes down" — fetcher now returns the empty sentinel.
	// freshEnvVars must serve the prior good list.
	mu.Lock()
	empty = true
	mu.Unlock()
	if got := string(d.freshEnvVars()); got != string(good) {
		t.Fatalf("during transient empty: freshEnvVars = %q, want %q (last good preserved)", got, string(good))
	}
}

func envVarsEqual(a, b []pushdownEnvVar) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// silence "imported and not used" if strings happens to drop out.
var _ = strings.HasPrefix
