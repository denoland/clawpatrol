package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/cmd/clawpatrol/dnsvip"
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/miekg/dns"
	_ "modernc.org/sqlite"
)

func TestUDPRelayRejectsUnauthorizedPeer(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	g := &Gateway{onboard: newOnboardRegistry()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleTsnetUDPRelayConn(&addrOverrideConn{
			Conn:  server,
			raddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("100.98.20.53:12345")),
			laddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("100.64.91.47:45353")),
		})
	}()
	if err := writeUDPRelayHello(client, netip.MustParseAddrPort("192.0.2.10:9999"), netip.Addr{}, ""); err != nil {
		t.Fatalf("write relay hello: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unauthorized relay connection did not close")
	}
}

func TestUDPRelayRejectsMalformedHello(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	reg := newOnboardRegistry()
	reg.AssignProfile("100.98.20.53", "default")
	g := &Gateway{onboard: reg}
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleTsnetUDPRelayConn(&addrOverrideConn{
			Conn:  server,
			raddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("100.98.20.53:12345")),
			laddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("100.64.91.47:45353")),
		})
	}()
	_, _ = client.Write([]byte("not-a-valid-udp-relay-hello"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("malformed relay connection did not close")
	}
}

func TestUDPRelayNonDNSRoundTrip(t *testing.T) {
	upstream := startUDPEcho(t)
	client := startAuthorizedUDPRelay(t, &Gateway{onboard: authorizedRegistry()}, upstream)
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if got, want := string(buf[:n]), "echo:ping"; got != want {
		t.Fatalf("relay response = %q, want %q", got, want)
	}
}

func TestUDPRelayRejectsUnregisteredPeerWithoutTokenEvenWithDefaultProfile(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	g := &Gateway{onboard: newOnboardRegistry()}
	storeDefaultProfileConfig(g)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleTsnetUDPRelayConn(&addrOverrideConn{
			Conn:  server,
			raddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("100.98.20.53:12345")),
			laddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("100.64.91.47:45353")),
		})
	}()
	if err := writeUDPRelayHello(client, netip.MustParseAddrPort("192.0.2.10:9999"), netip.Addr{}, ""); err != nil {
		t.Fatalf("write relay hello: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unregistered relay connection without token did not close")
	}
}

func TestUDPRelayNonDNSIdleTimeoutClosesStream(t *testing.T) {
	oldTimeout := udpRelayIdleTimeout
	udpRelayIdleTimeout = 10 * time.Millisecond
	t.Cleanup(func() { udpRelayIdleTimeout = oldTimeout })

	upstream := startUDPEcho(t)
	client := startAuthorizedUDPRelay(t, &Gateway{onboard: authorizedRegistry()}, upstream)
	defer func() { _ = client.Close() }()
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	start := time.Now()
	n, err := client.Read(buf)
	if err == nil {
		t.Fatalf("idle relay read returned n=%d, want close/error", n)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("idle relay closed after %s, want server-side idle timeout", elapsed)
	}
}

func TestUDPRelayRegisteredPeerUsesDefaultProfile(t *testing.T) {
	upstream := startUDPEcho(t)
	reg, db := newTestOnboardRegistryWithDB(t)
	reg.SetHostname("100.98.20.53", "ip-10-0-128-236")
	g := &Gateway{onboard: reg, db: db}
	storeDefaultProfileConfig(g)
	client := startAuthorizedUDPRelay(t, g, upstream)
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if got, want := string(buf[:n]), "echo:ping"; got != want {
		t.Fatalf("relay response = %q, want %q", got, want)
	}
}

func TestUDPRelayAuthorizesUnregisteredPeerWithAPIToken(t *testing.T) {
	upstream := startUDPEcho(t)
	reg := newOnboardRegistry()
	placeholder := tsnetPlaceholderPrefix + "ip-10-0-128-236"
	reg.assignProfileMemOnly(placeholder, "default")
	db, err := OpenDB(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()
	token, err := mintAndPersistPeerAPIToken(db, placeholder)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	client := startUDPRelay(t, &Gateway{onboard: reg, db: db}, upstream, token)
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if got, want := string(buf[:n]), "echo:ping"; got != want {
		t.Fatalf("relay response = %q, want %q", got, want)
	}
	if got := peerIPForAPIToken(db, token); got != "100.98.20.53" {
		t.Fatalf("token peer = %q, want promoted tsnet peer", got)
	}
	if got := reg.ProfileForIP("100.98.20.53"); got != "default" {
		t.Fatalf("promoted peer profile = %q, want default", got)
	}
	if got := reg.HostnameForIP("100.98.20.53"); got != "ip-10-0-128-236" {
		t.Fatalf("promoted peer hostname = %q, want ip-10-0-128-236", got)
	}
}

func TestUDPRelayDoesNotTrustUnverifiedClaimedPeer(t *testing.T) {
	upstream := startUDPEcho(t)
	reg := newOnboardRegistry()
	placeholder := tsnetPlaceholderPrefix + "ip-10-0-128-236"
	reg.assignProfileMemOnly(placeholder, "default")
	db, err := OpenDB(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()
	token, err := mintAndPersistPeerAPIToken(db, placeholder)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	client := startUDPRelayWithPeer(t, &Gateway{onboard: reg, db: db}, upstream, token, "100.98.20.53", netip.MustParseAddr("100.88.88.88"))
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if got := peerIPForAPIToken(db, token); got != "100.98.20.53" {
		t.Fatalf("token peer = %q, want authenticated remote peer", got)
	}
	if reg.HasDevice("100.88.88.88") {
		t.Fatal("unverified claimed peer created a device row")
	}
}

func TestUDPRelayPlaceholderTokenFallsBackToDefaultProfileAfterRestart(t *testing.T) {
	upstream := startUDPEcho(t)
	reg := newOnboardRegistry()
	placeholder := tsnetPlaceholderPrefix + "ip-10-0-128-236"
	db, err := OpenDB(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()
	token, err := mintAndPersistPeerAPIToken(db, placeholder)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	g := &Gateway{onboard: reg, db: db}
	storeDefaultProfileConfig(g)
	client := startUDPRelay(t, g, upstream, token)
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if got, want := string(buf[:n]), "echo:ping"; got != want {
		t.Fatalf("relay response = %q, want %q", got, want)
	}
	if got := reg.ProfileForIP("100.98.20.53"); got != "default" {
		t.Fatalf("promoted peer profile = %q, want default", got)
	}
}

func TestUDPRelayDNSOverUDP(t *testing.T) {
	g := &Gateway{
		onboard:     authorizedRegistry(),
		dnsvip:      newTestDNSVIP(t),
		tailscaleIP: "100.64.91.47",
	}
	client := startAuthorizedUDPRelay(t, g, netip.MustParseAddrPort("100.64.91.47:53"))
	defer func() { _ = client.Close() }()
	q := new(dns.Msg)
	q.SetQuestion("localhost.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatalf("pack DNS query: %v", err)
	}
	if _, err := client.Write(wire); err != nil {
		t.Fatalf("relay DNS write: %v", err)
	}
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("relay DNS read: %v", err)
	}
	var resp dns.Msg
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpack DNS response: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("DNS response rcode=%d answers=%d, want success with answers", resp.Rcode, len(resp.Answer))
	}
}

func TestPeerTsnetRegisterRejectsUnrelatedHostnameOnlyRow(t *testing.T) {
	reg, db := newTestOnboardRegistryWithDB(t)
	reg.AssignProfile("100.98.20.53", "default")
	token, err := mintAndPersistPeerAPIToken(db, "100.98.20.53")
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	w := &webMux{g: &Gateway{db: db, onboard: reg}}
	req := httptest.NewRequest(http.MethodPost, "/api/peer/tsnet/register?ip=100.88.88.88&hostname=unrelated", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	w.apiPeerTsnetRegister(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("register status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if reg.HasDevice("100.88.88.88") {
		t.Fatal("register created a hostname-only row for unrelated tsnet IP")
	}
}

func TestUDPRelayStreamConnPreservesZeroLengthDatagrams(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	conn := newUDPRelayStreamConn(client)
	defer func() { _ = conn.Close() }()

	writeDone := make(chan error, 1)
	go func() {
		n, err := conn.Write(nil)
		if err == nil && n != 0 {
			err = fmt.Errorf("zero-length write returned n=%d, want 0", n)
		}
		writeDone <- err
	}()
	var hdr [2]byte
	if _, err := server.Read(hdr[:]); err != nil {
		t.Fatalf("read zero-length frame header: %v", err)
	}
	if got := binary.BigEndian.Uint16(hdr[:]); got != 0 {
		t.Fatalf("zero-length frame length = %d, want 0", got)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write zero-length frame: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		buf := []byte("unchanged")
		n, err := conn.Read(buf)
		if err == nil && n != 0 {
			err = fmt.Errorf("zero-length read returned n=%d, want 0", n)
		}
		readDone <- err
	}()
	if _, err := server.Write([]byte{0, 0}); err != nil {
		t.Fatalf("write zero-length frame header: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("read zero-length frame: %v", err)
	}
}

func TestDialTsnetUDPRelayBoundsDialContext(t *testing.T) {
	oldLimit := udpRelayHandshakeLimit
	udpRelayHandshakeLimit = 10 * time.Millisecond
	t.Cleanup(func() { udpRelayHandshakeLimit = oldLimit })

	start := time.Now()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	_, err := dialTsnetUDPRelay(context.Background(), dial, netip.MustParseAddr("100.64.91.47"), netip.MustParseAddr("100.98.20.53"), "relay-token", "192.0.2.10:9999")
	if err == nil {
		t.Fatal("dialTsnetUDPRelay unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("relay dial returned after %s, want bounded dial timeout", elapsed)
	}
}

func TestUDPRelayStreamConnWriteRefreshesIdleReadDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	conn := newUDPRelayStreamConnWithIdle(client, 30*time.Millisecond)
	defer func() { _ = conn.Close() }()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		n, err := conn.Read(buf)
		if err != nil {
			readDone <- err
			return
		}
		if got := string(buf[:n]); got != "ok" {
			readDone <- fmt.Errorf("read payload = %q, want ok", got)
			return
		}
		readDone <- nil
	}()

	writeDone := make(chan error, 1)
	go func() {
		n, err := conn.Write([]byte("x"))
		if err == nil && n != 1 {
			err = fmt.Errorf("write returned n=%d, want 1", n)
		}
		writeDone <- err
	}()
	var outbound [3]byte
	if _, err := io.ReadFull(server, outbound[:]); err != nil {
		t.Fatalf("read outbound frame: %v", err)
	}
	if binary.BigEndian.Uint16(outbound[:2]) != 1 || outbound[2] != 'x' {
		t.Fatalf("outbound frame = %v, want len=1 body=x", outbound)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write outbound frame: %v", err)
	}

	// Wait past the original read deadline. Write must refresh the shared idle
	// deadline, otherwise the blocked Read above would time out before this frame.
	time.Sleep(20 * time.Millisecond)
	if _, err := server.Write([]byte{0, 2, 'o', 'k'}); err != nil {
		t.Fatalf("write inbound frame: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("read after write-refresh: %v", err)
	}
}

func TestDialTsnetUDPRelayFramesDestinationAndDatagrams(t *testing.T) {
	server, client := net.Pipe()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	type helloResult struct {
		dst   netip.AddrPort
		peer  netip.Addr
		token string
		err   error
	}
	helloCh := make(chan helloResult, 1)
	go func() {
		dst, peer, token, err := readUDPRelayHello(server)
		helloCh <- helloResult{dst: dst, peer: peer, token: token, err: err}
	}()
	conn, err := dialTsnetUDPRelay(context.Background(), dial, netip.MustParseAddr("100.64.91.47"), netip.MustParseAddr("100.98.20.53"), "relay-token", "192.0.2.10:9999")
	if err != nil {
		t.Fatalf("dialTsnetUDPRelay: %v", err)
	}
	defer func() { _ = conn.Close() }()
	res := <-helloCh
	if res.err != nil {
		t.Fatalf("read hello: %v", res.err)
	}
	if want := netip.MustParseAddrPort("192.0.2.10:9999"); res.dst != want {
		t.Fatalf("hello dst = %v, want %v", res.dst, want)
	}
	if want := netip.MustParseAddr("100.98.20.53"); res.peer != want {
		t.Fatalf("hello peer = %v, want %v", res.peer, want)
	}
	if res.token != "relay-token" {
		t.Fatalf("hello token = %q, want relay-token", res.token)
	}
	frameCh := make(chan error, 1)
	go func() {
		var hdr [2]byte
		if _, err := server.Read(hdr[:]); err != nil {
			frameCh <- fmt.Errorf("read frame header: %w", err)
			return
		}
		if got := binary.BigEndian.Uint16(hdr[:]); got != 3 {
			frameCh <- fmt.Errorf("frame length = %d, want 3", got)
			return
		}
		body := make([]byte, 3)
		if _, err := server.Read(body); err != nil {
			frameCh <- fmt.Errorf("read frame body: %w", err)
			return
		}
		if string(body) != "abc" {
			frameCh <- fmt.Errorf("frame body = %q, want abc", body)
			return
		}
		frameCh <- nil
	}()
	if _, err := conn.Write([]byte("abc")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if err := <-frameCh; err != nil {
		t.Fatal(err)
	}
}

func newTestOnboardRegistryWithDB(t *testing.T) (*onboardRegistry, *sql.DB) {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	reg := newOnboardRegistry()
	if err := reg.Load(db); err != nil {
		t.Fatalf("onboard Load: %v", err)
	}
	return reg, db
}

func storeDefaultProfileConfig(g *Gateway) {
	g.cfg.Store(&config.Gateway{Policy: &config.Policy{
		Profiles: map[string]*config.Profile{"default": {Name: "default"}},
		Order:    []string{"default"},
	}})
}

func authorizedRegistry() *onboardRegistry {
	reg := newOnboardRegistry()
	reg.AssignProfile("100.98.20.53", "default")
	return reg
}

func startAuthorizedUDPRelay(t *testing.T, g *Gateway, dst netip.AddrPort) net.Conn {
	t.Helper()
	return startUDPRelay(t, g, dst, "")
}

func startUDPRelay(t *testing.T, g *Gateway, dst netip.AddrPort, token string) net.Conn {
	t.Helper()
	return startUDPRelayWithPeer(t, g, dst, token, "100.98.20.53", netip.MustParseAddr("100.98.20.53"))
}

func startUDPRelayWithPeer(t *testing.T, g *Gateway, dst netip.AddrPort, token, remotePeer string, claimedPeer netip.Addr) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	go g.handleTsnetUDPRelayConn(&addrOverrideConn{
		Conn:  server,
		raddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remotePeer + ":12345")),
		laddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("100.64.91.47:45353")),
	})
	if err := writeUDPRelayHello(client, dst, claimedPeer, token); err != nil {
		t.Fatalf("write relay hello: %v", err)
	}
	return newUDPRelayStreamConn(client)
}

func startUDPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("parse echo addr: %v", err)
	}
	return addr
}

func newTestDNSVIP(t *testing.T) *dnsvip.Allocator {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dnsvip.db")
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", path))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE dnsvip_allocations (
		id INTEGER PRIMARY KEY,
		hostname TEXT NOT NULL UNIQUE,
		v4 TEXT NOT NULL UNIQUE,
		v6 TEXT NOT NULL UNIQUE
	)`); err != nil {
		t.Fatalf("create dnsvip table: %v", err)
	}
	a, err := dnsvip.New(db, dnsvip.DefaultCIDR4, dnsvip.DefaultCIDR6)
	if err != nil {
		t.Fatalf("dnsvip.New: %v", err)
	}
	return a
}

type addrOverrideConn struct {
	net.Conn
	raddr net.Addr
	laddr net.Addr
}

func (c *addrOverrideConn) RemoteAddr() net.Addr { return c.raddr }
func (c *addrOverrideConn) LocalAddr() net.Addr  { return c.laddr }
