//go:build linux

package main

// Shared helpers for tsnet-backed `clawpatrol run` — currently consumed
// by the Linux daemon transport. The historical macOS SOCKS5 client
// used the same helpers and may again; keep them isolated behind a
// build tag rather than splitting per-call sites.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// tsnetHTTPClient builds an http.Client that dials via tsnet so tailnet
// IPs (100.x.x.x) are reachable from the parent process (which otherwise
// has no route — the host network isn't on the tailnet, only the
// in-process tsnet stack is).
func tsnetHTTPClient(ts *tsnet.Server, caPath string) *http.Client {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(caPath); err == nil {
		roots.AppendCertsFromPEM(pem)
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:     ts.Dial,
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
}

// setGatewayExitNode points this tsnet node at the gateway as its exit
// node. Once set, every outbound dial on s (tcp + udp) is routed via
// the gateway, where it lands in the gateway's RegisterFallbackTCPHandler
// / DNS UDP listener — same dispatch as whole-machine clients. The
// gateway-side already auto-advertises 0.0.0.0/0 + ::/0 (see
// advertiseExitRoutes), so this only needs the operator's tailnet
// ACL to auto-approve exit-node usage for the client's tag.
func setGatewayExitNode(s *tsnet.Server, gatewayIP netip.Addr) error {
	if !gatewayIP.IsValid() {
		return fmt.Errorf("setGatewayExitNode: invalid gateway IP")
	}
	lc, err := s.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(context.Background(), &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
		Prefs:         ipn.Prefs{ExitNodeIP: gatewayIP},
	})
	return err
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

// registerTsnetPeer tells the gateway which 100.x.x.x tailnet IP this
// daemon is using, so it can promote the synthetic "tsnet-<host>"
// placeholder bound to the api-token at approve time into a real
// devices row keyed on the tailnet IP. Idempotent: subsequent calls
// (later daemon boots) see the token already pointing at a real IP
// and hit the gateway's no-op branch.
func registerTsnetPeer(client *http.Client, gwURL, token, tsIP string) error {
	// Prefer the operator-supplied --hostname from `clawpatrol join`
	// (persisted to <ca-dir>/hostname). Fall back to os.Hostname() for
	// older joins that didn't write the file.
	hn := strings.TrimSpace(readFileSilent(filepath.Join(defaultClawpatrolDir(), "hostname")))
	if hn == "" {
		hn, _ = os.Hostname()
	}
	u := gwURL + "/api/peer/tsnet/register?ip=" + tsIP
	if hn != "" {
		u += "&hostname=" + hn
	}
	req, err := http.NewRequest(http.MethodPost, u, nil)
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
