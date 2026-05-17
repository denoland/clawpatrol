package main

// Shared helpers for tsnet-backed `clawpatrol run` — used by both the
// Linux (gVisor/TUN) and macOS (SOCKS5) implementations.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

// gatewayHTTPClient builds an http.Client that trusts caPath in addition
// to system roots. If caPath doesn't exist the client falls back to system
// roots only (Tailscale mode exposes the gateway over a trusted tailnet).
func gatewayHTTPClient(caPath string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(caPath); err == nil {
		roots.AppendCertsFromPEM(pem)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}, nil
}

// fetchEphemeralTsnetKey calls POST /api/peer/ephemeral/tsnet on the
// gateway to obtain a single-use ephemeral Tailscale auth key and the
// tailnet port the gateway is listening on. gwPort defaults to "443" if
// the gateway omits it (old gateway versions).
func fetchEphemeralTsnetKey(gwURL, token, caPath string) (authKey, gwPort string, err error) {
	client, ferr := gatewayHTTPClient(caPath)
	if ferr != nil {
		return "", "", fmt.Errorf("http client: %w", ferr)
	}
	req, ferr := http.NewRequest(http.MethodPost, gwURL+"/api/peer/ephemeral/tsnet", nil)
	if ferr != nil {
		return "", "", ferr
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, ferr := client.Do(req)
	if ferr != nil {
		return "", "", ferr
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", "", fmt.Errorf("gateway %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result struct {
		AuthKey     string `json:"auth_key"`
		GatewayPort string `json:"gateway_port"`
	}
	if ferr := json.NewDecoder(resp.Body).Decode(&result); ferr != nil {
		return "", "", ferr
	}
	if result.AuthKey == "" {
		return "", "", fmt.Errorf("empty auth_key in response")
	}
	if result.GatewayPort == "" {
		result.GatewayPort = "443"
	}
	return result.AuthKey, result.GatewayPort, nil
}

// waitTsnetUp starts the tsnet.Server and blocks until the node is Running
// and has a 100.x.x.x IP. Returns the IPv4 tailnet address.
func waitTsnetUp(s *tsnet.Server) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	upSt, err := s.Up(ctx)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("tsnet up: %w", err)
	}
	for _, ip := range upSt.Self.TailscaleIPs {
		if ip.Is4() {
			return ip, nil
		}
	}
	lc, err := s.LocalClient()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("local client: %w", err)
	}
	lcSt, err := lc.Status(ctx)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("status: %w", err)
	}
	for _, ip := range lcSt.Self.TailscaleIPs {
		if ip.Is4() {
			return ip, nil
		}
	}
	if len(lcSt.Self.TailscaleIPs) > 0 {
		return lcSt.Self.TailscaleIPs[0], nil
	}
	return netip.Addr{}, fmt.Errorf("no tailnet IPs assigned")
}

// registerEphemeralTsnetIP tells the gateway which 100.x.x.x tailnet IP this
// ephemeral tsnet run session got, so the gateway maps it to the parent
// device's profile for credential dispatch.
func registerEphemeralTsnetIP(gwURL, token, caPath, tsIP string) error {
	client, err := gatewayHTTPClient(caPath)
	if err != nil {
		return fmt.Errorf("http client: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, gwURL+"/api/peer/ephemeral/tsnet/register?ip="+tsIP, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("gateway %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// tsnetBiRelay copies bidirectionally between a and b, half-closing
// each side when the opposite direction finishes.
func tsnetBiRelay(a, b net.Conn) {
	type halfCloser interface {
		CloseWrite() error
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(b, a)
		if hc, ok := b.(halfCloser); ok {
			_ = hc.CloseWrite()
		} else {
			_ = b.Close()
		}
	}()
	_, _ = io.Copy(a, b)
	if hc, ok := a.(halfCloser); ok {
		_ = hc.CloseWrite()
	} else {
		_ = a.Close()
	}
	<-done
}
