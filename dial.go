package main

// Outbound dialing. Stdlib TLS for normal hosts; uTLS Chrome for
// fingerprint-sensitive endpoints like chatgpt.com WS where
// Cloudflare WAF rejects plain-Go TLS handshakes.
//
// Per-rule extra-port serving is gone in this transition — the v14
// schema doesn't carry per-port listening declarations; postgres /
// clickhouse_native sit behind their endpoint plugins' future
// ConnEndpointRuntime, not a top-level port listener.

import (
	"context"
	"crypto/tls"
	"net"

	utls "github.com/refraction-networking/utls"
)

// servePorts is a no-op until the postgres / clickhouse_native
// endpoint plugins land their wire-protocol runtime hooks.
func (g *Gateway) servePorts() {}

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
