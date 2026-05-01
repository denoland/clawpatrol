package main

// Outbound dialing + extra-port serving. Combines the per-rule TCP
// listener loop (handleRaw / spliceTo for ports beyond 443) with the
// upstream TLS dialers (stdlib for normal hosts, uTLS Chrome for
// fingerprint-sensitive endpoints like chatgpt.com WS, mTLS for
// client-cert-authenticated upstreams like the Kubernetes API).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func uniqueExtraPorts(rules []Rule) []int {
	seen := map[int]bool{}
	var out []int
	for _, r := range rules {
		if r.Port == 0 || r.Port == 443 {
			continue
		}
		if seen[r.Port] {
			continue
		}
		seen[r.Port] = true
		out = append(out, r.Port)
	}
	return out
}

func ruleForPort(rules []Rule, port int) *Rule {
	for i := range rules {
		if rules[i].Port == port {
			return &rules[i]
		}
	}
	return nil
}

func (g *Gateway) servePorts() {
	host := splitHost(g.cfg.Listen)
	for _, port := range uniqueExtraPorts(g.rules) {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("listen %s: %v", addr, err)
			continue
		}
		log.Printf("port %d listening (%d-host rule)", port, countRulesOnPort(g.rules, port))
		go g.acceptRaw(ln, port)
	}
}

func (g *Gateway) acceptRaw(ln net.Listener, port int) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept :%d: %v", port, err)
			return
		}
		go g.handleRaw(c, port)
	}
}

func (g *Gateway) handleRaw(c net.Conn, port int) {
	defer c.Close()
	rule := ruleForPort(g.rules, port)
	if rule == nil {
		return
	}
	if rule.Action == "deny" {
		log.Printf("deny port %d host %s: %s", port, rule.Host, rule.Reason)
		return
	}
	upstream := rule.Host
	if rule.Upstream != "" {
		upstream = rule.Upstream
	}
	g.spliceTo(c, upstream, port)
}

func (g *Gateway) spliceTo(c net.Conn, host string, port int) {
	start := time.Now()
	up, err := g.dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		log.Printf("dial %s:%d: %v", host, port, err)
		g.sink.Emit(Event{Mode: "splice", Host: host, Action: "error", Reason: err.Error(), Ms: time.Since(start).Milliseconds()})
		return
	}
	defer up.Close()
	defer func() {
		g.sink.Emit(Event{Mode: "splice", Host: host, Action: "allow", Ms: time.Since(start).Milliseconds()})
	}()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, c)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, up)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func splitHost(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return ""
}

func countRulesOnPort(rules []Rule, port int) int {
	n := 0
	for _, r := range rules {
		if r.Port == port {
			n++
		}
	}
	return n
}

// dialMTLSUpstream dials an upstream that authenticates via client
// certificate (e.g. Kubernetes API server). Loads the cert+key+CA
// from the rule's MTLS config and presents them at TLS handshake.
func dialMTLSUpstream(ctx context.Context, network, addr, serverName string, m *MTLSConfig) (net.Conn, error) {
	cert, err := tls.LoadX509KeyPair(m.Cert, m.Key)
	if err != nil {
		return nil, fmt.Errorf("mtls load cert+key: %w", err)
	}
	cfg := &tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
	if m.CA != "" {
		caPEM, err := os.ReadFile(m.CA)
		if err != nil {
			return nil, fmt.Errorf("mtls read ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("mtls ca: no PEM blocks parsed")
		}
		cfg.RootCAs = pool
	}
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

// dialUpstreamTLS opens a TCP connection and runs stdlib TLS with
// ALPN forced to http/1.1 (our http.Transport is HTTP/1.1 only).
// Used for normal HTTP-mode upstreams.
func dialUpstreamTLS(ctx context.Context, network, addr, serverName string) (net.Conn, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: serverName, NextProtos: []string{"http/1.1"}})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

// dialBrowserTLS opens a TCP connection and performs a uTLS handshake
// using Chrome's TLS fingerprint (HelloChrome_Auto), with ALPN forced
// to http/1.1. Used for WS upgrades to chatgpt.com — Cloudflare WAF
// otherwise rejects the WS handshake with "Attack attempt detected".
//
// Plain Go TLS works fine for chatgpt.com HTTP requests but the WS
// upgrade specifically gets fingerprint-blocked. Mimicking Chrome's
// ClientHello bypasses it.
func dialBrowserTLS(ctx context.Context, network, addr, serverName string) (net.Conn, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	// HelloChrome_Auto bakes ALPN ["h2","http/1.1"] into the ClientHello.
	// We need http/1.1 only (WS upgrade requires HTTP/1.1; raw response
	// reader breaks on h2 SETTINGS frames). Apply preset spec, mutate
	// ALPNExtension, then handshake.
	c := utls.UClient(raw, &utls.Config{ServerName: serverName}, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		raw.Close()
		return nil, err
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	if err := c.ApplyPreset(&spec); err != nil {
		raw.Close()
		return nil, err
	}
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}
