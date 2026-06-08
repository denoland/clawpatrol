package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

const (
	tsnetUDPRelayPort      = 45353
	udpRelayMaxDatagram    = 65507
	udpRelayMaxTokenLength = 4096
)

var (
	udpRelayHandshakeLimit = 2 * time.Second
	udpRelayIdleTimeout    = 30 * time.Second
)

var udpRelayMagic = [8]byte{'C', 'P', 'U', 'D', 'P', 'R', '1', '\n'}

// Linux tsnet clients cannot use tsnet's exit-node path for arbitrary UDP:
// tsnet has RegisterFallbackTCPHandler for TCP, but no UDP equivalent. The
// relay below keeps the child-facing UDP contract intact while carrying each
// child UDP flow over a tailnet TCP stream to the gateway. The gateway accepts
// streams only from peers already known to the onboard registry or peers that
// present the per-peer API token minted during onboarding, then applies the
// same UDP dispatch as WG mode: dnsvip owns UDP/53 and all other UDP is
// transparently relayed to the original destination.
type udpRelayDialer func(context.Context, string, string) (net.Conn, error)

func dialTsnetUDPRelay(ctx context.Context, dial udpRelayDialer, gateway, local netip.Addr, token, dstAddr string) (net.Conn, error) {
	if !gateway.IsValid() {
		return nil, errors.New("tsnet udp relay: gateway address is not set")
	}
	dst, err := netip.ParseAddrPort(dstAddr)
	if err != nil {
		return nil, fmt.Errorf("tsnet udp relay: parse destination %q: %w", dstAddr, err)
	}
	relayAddr := net.JoinHostPort(gateway.String(), strconv.Itoa(tsnetUDPRelayPort))
	dialCtx, dialCancel := context.WithTimeout(ctx, udpRelayHandshakeLimit)
	defer dialCancel()
	c, err := dial(dialCtx, "tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("tsnet udp relay: dial gateway %s: %w", relayAddr, err)
	}
	deadline := time.Now().Add(udpRelayHandshakeLimit)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if err := writeUDPRelayHello(c, dst, local, token); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return newUDPRelayStreamConn(c), nil
}

func (g *Gateway) startTsnetUDPRelay(s *tsnet.Server) {
	if g == nil || s == nil {
		return
	}
	ln, err := s.Listen("tcp", net.JoinHostPort("", strconv.Itoa(tsnetUDPRelayPort)))
	if err != nil {
		log.Printf("tsnet: udp relay listen :%d: %v", tsnetUDPRelayPort, err)
		return
	}
	log.Printf("tsnet: udp relay listening on :%d", tsnetUDPRelayPort)
	go func() {
		defer func() { _ = ln.Close() }()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go g.handleTsnetUDPRelayConn(c)
		}
	}()
}

func (g *Gateway) handleTsnetUDPRelayConn(raw net.Conn) {
	peer := peerIP(raw)
	_ = raw.SetDeadline(time.Now().Add(udpRelayHandshakeLimit))
	dst, claimedPeer, token, err := readUDPRelayHello(raw)
	if err != nil {
		log.Printf("tsnet udp-relay: malformed hello from %s: %v", peer, err)
		_ = raw.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})

	agentIP, profile, ok := g.authorizeTsnetUDPRelayPeer(peer, claimedPeer, token)
	if !ok {
		log.Printf("tsnet udp-relay: reject unauthorized peer %q", peer)
		_ = raw.Close()
		return
	}

	conn := newUDPRelayStreamConnWithIdle(raw, udpRelayIdleTimeout)
	dstIP := dst.Addr().String()
	dstPort := dst.Port()
	log.Printf("tsnet udp-relay: %s profile=%s -> %s", agentIP, profile, dst)
	if dstPort == 53 && g.dnsvip != nil {
		g.dnsvip.ServeUDP(conn, g.udpRelayDNSOrigDst(dstIP, raw.LocalAddr()))
		return
	}
	relayUDP(conn, dstIP, dstPort)
}

func (g *Gateway) authorizeTsnetUDPRelayPeer(peer string, claimedPeer netip.Addr, token string) (agentIP, profile string, ok bool) {
	if g == nil || g.onboard == nil || peer == "" {
		return "", "", false
	}
	if agentIP, profile, ok := g.authorizeTsnetUDPRelayKnownPeer(peer); ok {
		return agentIP, profile, true
	}
	if token == "" || g.db == nil {
		return "", "", false
	}
	parentIP := peerIPForAPIToken(g.db, token)
	if parentIP == "" {
		return "", "", false
	}
	if strings.HasPrefix(parentIP, tsnetPlaceholderPrefix) {
		// daemonRegisterTsnetPeer is intentionally best-effort. If the daemon's
		// first successful contact with the gateway is this UDP relay, the same
		// per-peer bearer can safely promote the tsnet placeholder here. The
		// placeholder's profile is memory-only and can be lost on gateway restart,
		// so fall back to the configured default just like profileFor does.
		profile := g.onboard.ProfileForIP(parentIP)
		if profile == "" {
			profile = g.udpRelayDefaultProfile()
		}
		promotedPeer := peer
		if claimedPeer.IsValid() {
			promotedPeer = g.verifiedUDPRelayClaimedPeer(peer, claimedPeer)
		}
		_, _ = g.db.Exec("UPDATE peer_api_tokens SET peer_ip=? WHERE peer_ip=?", promotedPeer, parentIP)
		g.onboard.ForgetIP(parentIP)
		if g.agents != nil {
			g.agents.Delete(parentIP)
		}
		g.onboard.AssignProfile(promotedPeer, profile)
		if promotedPeer != peer {
			g.onboard.RegisterIPAlias(peer, promotedPeer)
		}
		if hostname := strings.TrimPrefix(parentIP, tsnetPlaceholderPrefix); hostname != "" && hostname != parentIP {
			g.onboard.SetHostname(promotedPeer, hostname)
		}
		if g.agents != nil {
			g.agents.Seed(promotedPeer)
		}
		return promotedPeer, profile, true
	}
	if p, ok := g.udpRelayProfileForRegisteredIP(parentIP); ok {
		return parentIP, p, true
	}
	return "", "", false
}

func (g *Gateway) verifiedUDPRelayClaimedPeer(peer string, claimed netip.Addr) string {
	if g.tsnetLC == nil || !claimed.IsValid() || claimed.String() == peer {
		return peer
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	w, err := g.tsnetLC.WhoIs(ctx, net.JoinHostPort(peer, "0"))
	if err != nil || w == nil || w.Node == nil {
		return peer
	}
	for _, addr := range w.Node.Addresses {
		if addr.Addr() == claimed {
			return claimed.String()
		}
	}
	return peer
}

func (g *Gateway) authorizeTsnetUDPRelayKnownPeer(peer string) (agentIP, profile string, ok bool) {
	if p, ok := g.udpRelayProfileForRegisteredIP(peer); ok {
		return g.onboard.AgentIPFor(peer), p, true
	}
	if g.tsnetLC != nil && g.onboard.ClaimAliasResolve(peer, 5*time.Minute) {
		if canonical := g.resolveTsnetAlias(peer); canonical != "" {
			if p, ok := g.udpRelayProfileForRegisteredIP(canonical); ok {
				return g.onboard.AgentIPFor(canonical), p, true
			}
		}
	}
	if canonical := g.onboard.AgentIPFor(peer); canonical != peer {
		if p, ok := g.udpRelayProfileForRegisteredIP(canonical); ok {
			return canonical, p, true
		}
	}
	return "", "", false
}

func (g *Gateway) udpRelayProfileForRegisteredIP(ip string) (string, bool) {
	if p := g.onboard.ProfileForIP(ip); p != "" {
		return p, true
	}
	if !g.onboard.HasDevice(ip) {
		return "", false
	}
	return g.udpRelayDefaultProfile(), true
}

func (g *Gateway) udpRelayDefaultProfile() string {
	if cfg := g.cfg.Load(); cfg != nil {
		return defaultProfileName(cfg.Policy)
	}
	return ""
}

func (g *Gateway) udpRelayDNSOrigDst(dstIP string, local net.Addr) string {
	if dstIP == g.tailscaleIP {
		return ""
	}
	if local != nil {
		host, _, err := net.SplitHostPort(local.String())
		if err != nil {
			host = local.String()
		}
		if host == dstIP {
			return ""
		}
	}
	return dstIP
}

func writeUDPRelayHello(w io.Writer, dst netip.AddrPort, peer netip.Addr, token string) error {
	dstAddr := dst.Addr()
	if !dstAddr.IsValid() || dst.Port() == 0 {
		return fmt.Errorf("udp relay hello: invalid destination %s", dst)
	}
	dstBytes := dstAddr.AsSlice()
	if len(dstBytes) != 4 && len(dstBytes) != 16 {
		return fmt.Errorf("udp relay hello: unsupported address %s", dstAddr)
	}
	var peerBytes []byte
	if peer.IsValid() {
		peerBytes = peer.AsSlice()
		if len(peerBytes) != 4 && len(peerBytes) != 16 {
			return fmt.Errorf("udp relay hello: unsupported peer address %s", peer)
		}
	}
	if len(token) > udpRelayMaxTokenLength {
		return fmt.Errorf("udp relay hello: token length %d exceeds %d", len(token), udpRelayMaxTokenLength)
	}
	header := make([]byte, 14+len(dstBytes)+len(peerBytes)+len(token))
	copy(header[:8], udpRelayMagic[:])
	header[8] = byte(len(dstBytes))
	header[9] = byte(len(peerBytes))
	binary.BigEndian.PutUint16(header[10:12], dst.Port())
	binary.BigEndian.PutUint16(header[12:14], uint16(len(token)))
	pos := 14
	copy(header[pos:], dstBytes)
	pos += len(dstBytes)
	copy(header[pos:], peerBytes)
	pos += len(peerBytes)
	copy(header[pos:], token)
	return writeUDPRelayFull(w, header)
}

func readUDPRelayHello(r io.Reader) (netip.AddrPort, netip.Addr, string, error) {
	var fixed [14]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return netip.AddrPort{}, netip.Addr{}, "", err
	}
	if string(fixed[:8]) != string(udpRelayMagic[:]) {
		return netip.AddrPort{}, netip.Addr{}, "", errors.New("bad magic")
	}
	dstLen := int(fixed[8])
	peerLen := int(fixed[9])
	if dstLen != 4 && dstLen != 16 {
		return netip.AddrPort{}, netip.Addr{}, "", fmt.Errorf("bad destination address length %d", dstLen)
	}
	if peerLen != 0 && peerLen != 4 && peerLen != 16 {
		return netip.AddrPort{}, netip.Addr{}, "", fmt.Errorf("bad peer address length %d", peerLen)
	}
	port := binary.BigEndian.Uint16(fixed[10:12])
	if port == 0 {
		return netip.AddrPort{}, netip.Addr{}, "", errors.New("zero destination port")
	}
	tokenLen := int(binary.BigEndian.Uint16(fixed[12:14]))
	if tokenLen > udpRelayMaxTokenLength {
		return netip.AddrPort{}, netip.Addr{}, "", fmt.Errorf("token length %d exceeds %d", tokenLen, udpRelayMaxTokenLength)
	}
	dstBytes := make([]byte, dstLen)
	if _, err := io.ReadFull(r, dstBytes); err != nil {
		return netip.AddrPort{}, netip.Addr{}, "", err
	}
	dstAddr, ok := netip.AddrFromSlice(dstBytes)
	if !ok || !dstAddr.IsValid() {
		return netip.AddrPort{}, netip.Addr{}, "", errors.New("invalid destination address")
	}
	peerBytes := make([]byte, peerLen)
	if _, err := io.ReadFull(r, peerBytes); err != nil {
		return netip.AddrPort{}, netip.Addr{}, "", err
	}
	var peer netip.Addr
	if peerLen > 0 {
		var ok bool
		peer, ok = netip.AddrFromSlice(peerBytes)
		if !ok || !peer.IsValid() {
			return netip.AddrPort{}, netip.Addr{}, "", errors.New("invalid peer address")
		}
	}
	tokenBytes := make([]byte, tokenLen)
	if _, err := io.ReadFull(r, tokenBytes); err != nil {
		return netip.AddrPort{}, netip.Addr{}, "", err
	}
	return netip.AddrPortFrom(dstAddr, port), peer, string(tokenBytes), nil
}

func newUDPRelayStreamConn(c net.Conn) net.Conn {
	return newUDPRelayStreamConnWithIdle(c, 0)
}

func newUDPRelayStreamConnWithIdle(c net.Conn, idle time.Duration) net.Conn {
	return &udpRelayStreamConn{Conn: c, idleTimeout: idle}
}

type udpRelayStreamConn struct {
	net.Conn
	writeMu     sync.Mutex
	idleTimeout time.Duration
}

func (c *udpRelayStreamConn) Read(b []byte) (int, error) {
	c.refreshIdleDeadline()
	var hdr [2]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > udpRelayMaxDatagram {
		return 0, fmt.Errorf("udp relay frame: invalid length %d", n)
	}
	if n == 0 {
		return 0, nil
	}
	if n > len(b) {
		if _, err := io.CopyN(io.Discard, c.Conn, int64(n)); err != nil {
			return 0, err
		}
		return 0, io.ErrShortBuffer
	}
	_, err := io.ReadFull(c.Conn, b[:n])
	return n, err
}

func (c *udpRelayStreamConn) Write(b []byte) (int, error) {
	c.refreshIdleDeadline()
	if len(b) > udpRelayMaxDatagram {
		return 0, fmt.Errorf("udp relay frame: invalid length %d", len(b))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	if err := writeUDPRelayFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	if err := writeUDPRelayFull(c.Conn, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpRelayStreamConn) refreshIdleDeadline() {
	if c.idleTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(c.idleTimeout))
	}
}

func writeUDPRelayFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
