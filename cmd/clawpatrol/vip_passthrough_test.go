package main

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/denoland/clawpatrol/cmd/clawpatrol/dnsvip"
	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestVIPPassthroughBridgesBytes proves the fallback dials the real
// hostname:port and pipes bytes both ways. Reproduces the SSH case from
// orchid #184: a profile without the SSH endpoint dialed a VIP and got
// a silent RST. Post-fix the upstream banner reaches the agent.
func TestVIPPassthroughBridgesBytes(t *testing.T) {
	// Banner-only listener so we can match the exact bytes the agent
	// sees on accept — the bidi echo path is exercised separately
	// further down via the full handleVIPConn test.
	ln := testTCPBanner(t, "SSH-2.0-clawpatrol-test\r\n")
	host, port := splitHostPort(t, ln.Addr().String())

	g := newPassthroughTestGateway(t)
	agent, c := net.Pipe()
	t.Cleanup(func() { _ = agent.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		g.vipPassthrough(c, host, port)
	}()

	const want = "SSH-2.0-clawpatrol-test\r\n"
	buf := make([]byte, len(want))
	_ = agent.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(agent, buf); err != nil {
		t.Fatalf("agent ReadFull: %v", err)
	}
	if got := string(buf); got != want {
		t.Fatalf("agent banner = %q, want %q", got, want)
	}

	_ = agent.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("vipPassthrough did not return after agent close")
	}
}

// TestVIPPassthroughEmitsRelayEvent verifies the dashboard sink sees an
// allow-mode `relay` event with the resolved host:port — the same shape
// wgRelay emits — so passthrough flows are observable instead of
// silently dropped from analytics.
func TestVIPPassthroughEmitsRelayEvent(t *testing.T) {
	ln := testTCPEcho(t, "ok")
	host, port := splitHostPort(t, ln.Addr().String())

	g := newPassthroughTestGateway(t)
	_, sub, cancel := g.sink.RecentAndSubscribe()
	t.Cleanup(cancel)

	agent, c := net.Pipe()
	t.Cleanup(func() { _ = agent.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.vipPassthrough(c, host, port)
	}()

	if _, err := agent.Write([]byte("x")); err != nil {
		t.Fatalf("agent write: %v", err)
	}
	buf := make([]byte, 4)
	_ = agent.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = agent.Read(buf)
	_ = agent.Close()
	<-done

	wantHost := net.JoinHostPort(host, strconv.Itoa(int(port)))
	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-sub:
			if pkt.ev.Mode == "relay" && pkt.ev.Action == "allow" && pkt.ev.Host == wantHost {
				return
			}
		case <-deadline:
			t.Fatalf("did not observe a relay/allow event for %q within 2s", wantHost)
		}
	}
}

// TestVIPPassthroughDialError emits a deny event when the upstream
// can't be reached. Matches wgRelay's behaviour so the dashboard
// surfaces the failure to the operator instead of silently dropping.
func TestVIPPassthroughDialError(t *testing.T) {
	// Bind a listener, capture its port, then close it. The port is
	// known-unreachable for the rest of the test.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot create TCP listener (sandboxed?): %v", err)
	}
	host, port := splitHostPort(t, ln.Addr().String())
	_ = ln.Close()

	g := newPassthroughTestGateway(t)
	_, sub, cancel := g.sink.RecentAndSubscribe()
	t.Cleanup(cancel)

	agent, c := net.Pipe()
	t.Cleanup(func() { _ = agent.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.vipPassthrough(c, host, port)
	}()
	<-done

	wantHost := net.JoinHostPort(host, strconv.Itoa(int(port)))
	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-sub:
			if pkt.ev.Mode == "relay" && pkt.ev.Action == "deny" && pkt.ev.Host == wantHost {
				if pkt.ev.Reason == "" {
					t.Fatalf("deny event missing Reason for %q", wantHost)
				}
				return
			}
		case <-deadline:
			t.Fatalf("did not observe a relay/deny event for unreachable %q", wantHost)
		}
	}
}

// TestHandleVIPConnPassthroughOnProfileMiss exercises the full
// handleVIPConn dispatch: a VIP exists for a hostname bound to one
// endpoint at the policy root, but the connecting peer's profile
// doesn't grant that endpoint. Pre-fix this path returned a silent
// RST; post-fix the conn flows through vipPassthrough to the real
// upstream.
func TestHandleVIPConnPassthroughOnProfileMiss(t *testing.T) {
	ln := testTCPEcho(t, "ssh-banner")
	host, port := splitHostPort(t, ln.Addr().String())

	g := newPassthroughTestGateway(t)
	// Seed the onboard registry so profileFor("pipe") resolves to a
	// real profile name and handleVIPConn walks the per-profile
	// endpoint filter (rather than falling through the empty-profile
	// shortcut). net.Pipe's RemoteAddr stringifies as "pipe".
	g.onboard = newOnboardRegistry()
	g.onboard.assignProfileMemOnly("pipe", "crowlbot")

	// Policy: one SSH endpoint declared at the root, "crowlbot"
	// profile doesn't grant it. Mirrors orchid#184 — global SSH
	// endpoint, profile with only OAuth credentials.
	policy := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{
			"github_ssh": {
				Name:   "github_ssh",
				Family: "ssh",
				Plugin: &config.Plugin{Type: "ssh"},
				Hosts:  []string{fmt.Sprintf("%s:%d", host, port)},
				Body:   sshBodyForVIP{hosts: []string{fmt.Sprintf("%s:%d", host, port)}},
			},
		},
		Profiles: map[string]*config.CompiledProfile{
			"crowlbot": {
				Endpoints: map[string]*config.CompiledEndpoint{},
			},
		},
	}
	g.policy.Store(policy)

	// Drive dnsvip through the same RebuildFromPolicy path the
	// gateway uses at runtime so the VIP <-> hostname binding the
	// dispatcher reads matches production.
	vipDB := newTestDNSVIPDB(t)
	a, err := dnsvip.New(vipDB, dnsvip.DefaultCIDR4, dnsvip.DefaultCIDR6)
	if err != nil {
		t.Fatalf("dnsvip.New: %v", err)
	}
	if err := a.RebuildFromPolicy(policy); err != nil {
		t.Fatalf("RebuildFromPolicy: %v", err)
	}
	v4, _ := a.VIPsFor(host)
	if !v4.IsValid() {
		t.Fatalf("VIP not allocated for %q", host)
	}
	g.dnsvip = a

	agent, c := net.Pipe()
	t.Cleanup(func() { _ = agent.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleVIPConn(c, v4.String(), port)
	}()

	// Read the banner — if pre-fix RST behavior regressed, this would
	// time out (the conn would be closed before the upstream got a
	// chance to write).
	buf := make([]byte, 32)
	_ = agent.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := agent.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("agent read: %v", err)
	}
	if got := string(buf[:n]); got != "ssh-banner" {
		t.Fatalf("agent banner = %q, want %q (passthrough should reach upstream)", got, "ssh-banner")
	}

	_ = agent.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleVIPConn did not return after agent close")
	}
}

// --- helpers --------------------------------------------------------

// sshBodyForVIP is the minimal endpoint body the dnsvip allocator needs
// to opt the endpoint into a VIP. Mirrors the testBody pattern in
// dnsvip's own tests.
type sshBodyForVIP struct {
	hosts []string
}

func (sshBodyForVIP) RequiresVIP() bool { return true }

// testTCPBanner starts a TCP server that writes a fixed banner on
// accept and then drains+closes the conn. Used when we only need to
// assert that the bytes the upstream produced traversed the passthrough.
//
// Skips the calling test if the sandbox blocks listen(2) — same skip
// shape relay_linux_test.go uses for its AF_INET/AF_UNIX helpers.
func testTCPBanner(t *testing.T, banner string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot create TCP listener (sandboxed?): %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(banner))
				// Drain so the client-side close can flow through.
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln
}

// testTCPEcho starts a TCP server that writes a fixed banner on accept
// and echoes whatever the client sends until EOF. Returns the listener;
// closes it on Cleanup. Skips the test if listen(2) is sandboxed.
func testTCPEcho(t *testing.T, banner string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot create TCP listener (sandboxed?): %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if banner != "" {
					_, _ = c.Write([]byte(banner))
				}
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln
}

func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort %q: %v", addr, err)
	}
	port64, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint %q: %v", p, err)
	}
	return h, uint16(port64)
}

// newPassthroughTestGateway returns a *Gateway with just enough wired
// up for the vipPassthrough path: a dialer, a sink, and a nil onboard
// registry (so the `known` gate trivially passes without seeding fake
// devices).
func newPassthroughTestGateway(t *testing.T) *Gateway {
	t.Helper()
	sink, err := NewSink(nil, 16)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { close(sink.ch) })
	return &Gateway{
		cfg:    &config.Gateway{},
		dialer: &net.Dialer{Timeout: 2 * time.Second},
		sink:   sink,
	}
}

func newTestDNSVIPDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)",
		filepath.Join(t.TempDir(), "vip.db"))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE dnsvip_allocations (
		id        INTEGER PRIMARY KEY,
		hostname  TEXT NOT NULL UNIQUE,
		v4        TEXT NOT NULL UNIQUE,
		v6        TEXT NOT NULL UNIQUE
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
