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
	"log"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// browserTLSHosts: hosts whose Cloudflare WAF rejects plain Go TLS
// fingerprints. Match suffix so subdomains (e.g. backend-api.chatgpt.com,
// auth.openai.com) get the uTLS Chrome treatment too. Add new hosts
// here when "Attack detected" 405s show up in the gateway log.
var browserTLSHosts = []string{
	"chatgpt.com",
	"openai.com",
}

func needsBrowserTLS(host string) bool {
	h := strings.ToLower(host)
	for _, suffix := range browserTLSHosts {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return true
		}
	}
	return false
}

// endpointWantsClientCert reports whether ep declares any credential
// implementing TLSCredentialRuntime. Such endpoints (mtls / k8s) need
// the upstream Config to carry a client cert, which dialBrowserTLS
// can't satisfy — fall back to dialUpstream.
func endpointWantsClientCert(ep *config.CompiledEndpoint) bool {
	if ep == nil {
		return false
	}
	for _, cc := range ep.Credentials {
		if _, ok := cc.Credential.Body.(runtime.TLSCredentialRuntime); ok {
			return true
		}
	}
	return false
}

// profileCtxKey is the context key for the peer's profile name.
// mitmHTTPS injects it into each request's context so DialTLSContext
// can fetch per-profile mTLS credentials without the transport needing
// to know about WireGuard peer → profile mapping.
type profileCtxKey struct{}

// servePorts is a no-op until the postgres / clickhouse_native
// endpoint plugins land their wire-protocol runtime hooks.
func (g *Gateway) servePorts() {}

// dialUpstream opens an upstream TLS connection for an HTTPS-family
// endpoint. The default path runs stdlib TLS with ALPN forced to
// http/1.1; endpoints whose credential satisfies TLSCredentialRuntime
// (currently mtls_credential) get the plugin a chance to add client
// certs / replace RootCAs before the handshake.
//
// profile is the peer's profile name (e.g. "avocet2"); it is used to
// fetch per-profile secrets from the dashboard DB. Callers that don't
// have a profile may pass "" — secrets stored under "" or via env-var
// still resolve correctly for non-profiled deployments.
//
// Empty TLS credential (cert/key not configured) logs a hint and
// falls back to plain TLS — the request still flows but the
// upstream rejects it on cert-required endpoints. Operators see
// the misconfiguration in the dashboard event log.
func (g *Gateway) dialUpstream(ctx context.Context, network, addr, serverName string, ep *config.CompiledEndpoint, profile string) (net.Conn, error) {
	cfg := &tls.Config{ServerName: serverName, NextProtos: []string{"http/1.1"}}

	if ep != nil {
		for _, cc := range ep.Credentials {
			// Body is the real decoded HCL instance; Plugin.Runtime
			// is a typed-nil sentinel used only for interface-
			// compliance assertions.
			tlsRT, ok := cc.Credential.Body.(runtime.TLSCredentialRuntime)
			if !ok {
				continue
			}
			sec, err := g.secrets.Get(cc.Credential.Symbol.Name)
			if err != nil {
				log.Printf("tls-secret %s: %v — dialing without client cert", cc.Credential.Symbol.Name, err)
				break
			}
			if err := tlsRT.ConfigureUpstreamTLS(cfg, sec); err != nil {
				log.Printf("tls-configure %s: %v — dialing without client cert", cc.Credential.Symbol.Name, err)
				break
			}
			break
		}
	}

	raw, err := g.dialThrough(ctx, ep, network, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// dialBrowserTLS opens a tunnel-aware TCP connection and performs a uTLS
// handshake using Chrome's TLS fingerprint (HelloChrome_Auto), with ALPN
// forced to http/1.1. Used for WS upgrades to chatgpt.com — Cloudflare WAF
// otherwise rejects the WS handshake with "Attack attempt detected".
//
// Plain Go TLS works fine for chatgpt.com HTTP requests but the WS
// upgrade specifically gets fingerprint-blocked. Mimicking Chrome's
// ClientHello bypasses it.
func (g *Gateway) dialBrowserTLS(ctx context.Context, network, addr, serverName string, ep *config.CompiledEndpoint) (net.Conn, error) {
	raw, err := g.dialThrough(ctx, ep, network, addr)
	if err != nil {
		return nil, err
	}
	return browserTLSOver(ctx, raw, serverName)
}

func browserTLSOver(ctx context.Context, raw net.Conn, serverName string) (net.Conn, error) {
	// HelloChrome_Auto bakes ALPN ["h2","http/1.1"] into the ClientHello.
	// We need http/1.1 only (WS upgrade requires HTTP/1.1; raw response
	// reader breaks on h2 SETTINGS frames). Apply preset spec, mutate
	// ALPNExtension, then handshake.
	c := utls.UClient(raw, &utls.Config{ServerName: serverName}, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	if err := c.ApplyPreset(&spec); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := c.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}
