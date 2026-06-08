//go:build linux

package main

// tsnetTransport: daemonTransport implementation backed by an embedded
// tsnet.Server with the gateway pinned as its exit node. TCP dials use
// tsnet.Server.Dial and land in the gateway's tsnet
// RegisterFallbackTCPHandler with the original dst intact. UDP dials use
// Claw Patrol's framed tailnet relay because tsnet exposes no arbitrary-UDP
// fallback equivalent to RegisterFallbackTCPHandler.

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

type tsnetTransport struct {
	s           *tsnet.Server
	gatewayAddr netip.Addr
	apiToken    string
	localAddr   netip.Addr
	bootWarning string
}

func (t *tsnetTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if strings.HasPrefix(network, "udp") {
		return dialTsnetUDPRelay(ctx, t.s.Dial, t.gatewayAddr, t.localAddr, t.apiToken, addr)
	}
	return t.s.Dial(ctx, network, addr)
}

func (t *tsnetTransport) LocalAddr() netip.Addr { return t.localAddr }
func (t *tsnetTransport) BootWarning() string   { return t.bootWarning }
func (t *tsnetTransport) Close() error          { return t.s.Close() }

// startTsnetTransport reads persisted join state (auth-key, control-url,
// gateway-ip), starts a tsnet.Server, waits for it to come up, points
// its outbound dials at the gateway as an exit node, and registers
// the resulting tailnet IP with the gateway so the synthetic
// "tsnet-<host>" placeholder gets promoted to a real devices row.
func startTsnetTransport() (daemonTransport, error) {
	caDir := defaultClawpatrolDir()
	stateDir := daemonStateDir()
	authKey := strings.TrimSpace(readFileSilent(filepath.Join(stateDir, "auth-key")))
	controlURL := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "control-url")))
	gwIPStr := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "tailnet-gateway-ip")))
	if authKey == "" {
		return nil, fmt.Errorf("missing auth-key in %s (re-run `clawpatrol join`)", stateDir)
	}
	if gwIPStr == "" {
		return nil, fmt.Errorf("missing tailnet-gateway-ip in %s (re-run `clawpatrol join`)", caDir)
	}
	gwIP, err := netip.ParseAddr(gwIPStr)
	if err != nil {
		return nil, fmt.Errorf("parse tailnet-gateway-ip %q: %w", gwIPStr, err)
	}

	// Persistent state dir so the tsnet node keeps the same identity
	// (and tailnet IP, when the control plane is cooperative) across
	// idle-exit + respawn cycles. Auth keys are minted non-ephemeral,
	// so a single device row shows up on the dashboard per host
	// instead of churning one per daemon lifetime.
	tsnetDir := filepath.Join(stateDir, "tsnet")
	if err := os.MkdirAll(tsnetDir, 0o700); err != nil {
		return nil, fmt.Errorf("tsnet state dir: %w", err)
	}

	hn := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "hostname")))
	if hn == "" {
		hn, _ = os.Hostname()
	}

	s := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Dir:        tsnetDir,
		Ephemeral:  false,
		Logf:       func(string, ...any) {},
	}

	log.Printf("daemon: joining tailnet as %q...", hn)
	tsIP, err := waitTsnetUp(s)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("waitTsnetUp: %w", err)
	}
	log.Printf("daemon: tailnet IP %s", tsIP)

	if err := setGatewayExitNode(s, gwIP); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("set exit-node %s: %w", gwIP, err)
	}

	// Smoke-test exit-node routing. EditPrefs accepts ExitNodeIP
	// unconditionally, but actual routing requires the tailnet ACL to
	// auto-approve the gateway as an exit node for our tag (see
	// doc/tailscale.md → "Required tailnet ACL"). Without that, every
	// dial silently times out instead of returning a useful error.
	// Probe by dialing the gateway's tailnet IP on port 53 — that
	// port is bound by the gateway's tsnet DNS listener so a working
	// path returns "connection established" within hundreds of ms.
	var bootWarning string
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 8*time.Second)
	if c, derr := s.Dial(probeCtx, "tcp", net.JoinHostPort(gwIP.String(), "53")); derr == nil {
		_ = c.Close()
	} else {
		bootWarning = fmt.Sprintf("tsnet probe: gateway unreachable via exit-node routing (%v). "+
			"Check autoApprovers.exitNode in your tailnet ACL — see doc/tailscale.md. "+
			"Outbound traffic from `clawpatrol run` will fail until the ACL is fixed.", derr)
		log.Printf("%s", bootWarning)
	}
	probeCancel()

	// Let any code path that needs a tailnet-routed HTTP client (e.g.
	// gatewayClient → /api/env-pushdown) reach 100.x via tsnet.
	gatewayDialOverride = s.Dial

	apiToken := strings.TrimSpace(readFileSilent(filepath.Join(defaultClawpatrolDir(), "api-token")))

	// Register this tsnet IP with the gateway so it maps to the host's
	// device row (and therefore its profile). Best-effort: a failure
	// only means traffic lands in the default profile until the next
	// daemon restart.
	daemonRegisterTsnetPeer(s, tsIP)

	return &tsnetTransport{s: s, gatewayAddr: gwIP, apiToken: apiToken, localAddr: tsIP, bootWarning: bootWarning}, nil
}

// daemonRegisterTsnetPeer POSTs this daemon's tsnet IP to the
// gateway's /api/peer/tsnet/register so it maps to the host's device
// row (and therefore the host's profile). First call after approval
// promotes the synthetic placeholder; subsequent calls are no-ops on
// the server side. Best-effort.
func daemonRegisterTsnetPeer(s *tsnet.Server, tsIP netip.Addr) {
	caDir := defaultClawpatrolDir()
	gwURL := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "tailnet-url")))
	if gwURL == "" {
		gwURL = strings.TrimSpace(readFileSilent(filepath.Join(caDir, "gateway")))
	}
	token := strings.TrimSpace(readFileSilent(filepath.Join(caDir, "api-token")))
	if gwURL == "" || token == "" {
		log.Printf("daemon: register: missing gateway URL or api-token; skipping")
		return
	}
	cli := tsnetHTTPClient(s, filepath.Join(caDir, "ca.crt"))
	if err := registerTsnetPeer(cli, gwURL, token, tsIP.String()); err != nil {
		log.Printf("daemon: register: %v (default profile until next restart)", err)
	}
}
