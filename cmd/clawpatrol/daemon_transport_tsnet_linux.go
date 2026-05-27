//go:build linux

package main

// tsnetTransport: daemonTransport implementation backed by an embedded
// tsnet.Server with the gateway pinned as its exit node. Every Dial
// returns a tsnet.Server.Dial conn, which the tailnet routes through
// the gateway — the gateway then picks it up in its tsnet
// RegisterFallbackTCPHandler with the original dst intact (no
// PROXY-v1 framing).

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"tailscale.com/tsnet"
)

type tsnetTransport struct {
	s           *tsnet.Server
	localAddr   netip.Addr
	gwIP        netip.Addr
	bootWarning string
	// ready caches the first observed successful exit-node probe so
	// warm-path WaitReady is a single atomic load. Set on boot if the
	// startup probe succeeded; set by WaitReady on the first cold-path
	// success. Never flips back — once routing has worked, the
	// "we've never been usable" distinction the wrapper cares about
	// is permanently resolved for this daemon lifetime.
	ready atomic.Bool
}

func (t *tsnetTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.s.Dial(ctx, network, addr)
}

func (t *tsnetTransport) LocalAddr() netip.Addr { return t.localAddr }
func (t *tsnetTransport) BootWarning() string   { return t.bootWarning }
func (t *tsnetTransport) Close() error          { return t.s.Close() }

// WaitReady blocks until a probe dial to the gateway's tailnet IP on
// port 53 succeeds (proving exit-node routing is up), or ctx expires.
// Warm-path returns nil on the first atomic load. Cold-path is the
// fallback for boots where the startup probe failed: we keep retrying
// until the operator's tailnet ACL catches up or the timeout fires.
func (t *tsnetTransport) WaitReady(ctx context.Context) error {
	if t.ready.Load() {
		return nil
	}
	dial := func(ctx context.Context) error {
		c, err := t.s.Dial(ctx, "tcp", net.JoinHostPort(t.gwIP.String(), "53"))
		if err != nil {
			return err
		}
		_ = c.Close()
		return nil
	}
	if err := pollTsnetReady(ctx, dial, tsnetReadyDialTimeout, tsnetReadyPollInterval); err != nil {
		return fmt.Errorf("tsnet exit-node probe failed: %w", err)
	}
	t.ready.Store(true)
	return nil
}

const (
	tsnetReadyDialTimeout  = 2 * time.Second
	tsnetReadyPollInterval = 200 * time.Millisecond
)

// pollTsnetReady runs dial in a loop until it returns nil or ctx is
// done. Each call gets its own dialTimeout-bounded child ctx so a
// hung exit-node hop can't consume the entire wait budget on one try.
// Split out so the polling loop is testable without booting tsnet.
func pollTsnetReady(ctx context.Context, dial func(context.Context) error, dialTimeout, interval time.Duration) error {
	for {
		probeCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		err := dial(probeCtx)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

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
	var (
		bootWarning string
		bootReady   bool
	)
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 8*time.Second)
	if c, derr := s.Dial(probeCtx, "tcp", net.JoinHostPort(gwIP.String(), "53")); derr == nil {
		_ = c.Close()
		bootReady = true
	} else {
		bootWarning = fmt.Sprintf("tsnet probe: gateway unreachable via exit-node routing (%v). "+
			"Check autoApprovers.exitNode in your tailnet ACL — see doc/tailscale.md. "+
			"`clawpatrol run` will block on the next session until the ACL is fixed.", derr)
		log.Printf("%s", bootWarning)
	}
	probeCancel()

	// Let any code path that needs a tailnet-routed HTTP client (e.g.
	// gatewayClient → /api/env-pushdown) reach 100.x via tsnet.
	gatewayDialOverride = s.Dial

	// Register this tsnet IP with the gateway so it maps to the host's
	// device row (and therefore its profile). Best-effort: a failure
	// only means traffic lands in the default profile until the next
	// daemon restart.
	daemonRegisterTsnetPeer(s, tsIP)

	t := &tsnetTransport{s: s, localAddr: tsIP, gwIP: gwIP, bootWarning: bootWarning}
	if bootReady {
		t.ready.Store(true)
	}
	return t, nil
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
