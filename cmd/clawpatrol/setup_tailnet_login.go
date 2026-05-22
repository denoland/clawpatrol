package main

// Tailnet-bootstrap path for `clawpatrol join` against a gateway that
// isn't reachable from the public internet — typical for production
// gateways with Funnel disabled or with Funnel exposing only a strict
// allowlist that omits /ca.crt.
//
// The trick: the clawpatrol binary already statically links tsnet, so
// the CLI can stand up a temporary tsnet node, drive an interactive
// Tailscale login (browser → IdP → control-plane), reach the gateway
// over the tailnet, run the existing device-flow approval, then tear
// the bootstrap node down. The agent's persistent identity is the
// gateway-minted tagged auth-key, NOT the human operator's tailnet
// account — so the join doesn't leave the machine logged in as a
// human user.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	neturl "net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

// tailnetBootstrap is a transient tsnet.Server that exists only for
// the duration of `clawpatrol join`. Use Client() to talk to the
// gateway over the tailnet, then call Close to log the node out and
// remove its on-disk state.
type tailnetBootstrap struct {
	server *tsnet.Server
	lc     *local.Client
	client *http.Client
	dir    string
}

// Client returns an *http.Client whose Transport dials through the
// bootstrap tsnet node. Callers thread it into preJoinFetchCA and
// onboardViaDeviceFlow in place of the default cli.
func (b *tailnetBootstrap) Client() *http.Client { return b.client }

// Close logs the bootstrap node out of the tailnet, stops tsnet, and
// deletes the temp state dir. Best-effort: a failed Logout still
// removes the local state, so the node lingers in the tailnet admin
// as offline but has no path back online. ctx caps how long we wait
// for the Logout RPC to complete — Close is called from a defer in
// runJoin and the operator shouldn't have to wait forever on a stuck
// control plane.
func (b *tailnetBootstrap) Close(ctx context.Context) {
	if b == nil {
		return
	}
	if b.lc != nil {
		logoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_ = b.lc.Logout(logoutCtx)
		cancel()
	}
	if b.server != nil {
		_ = b.server.Close()
	}
	if b.dir != "" {
		_ = os.RemoveAll(b.dir)
	}
}

// bootstrapTailnetForJoin stands up a temporary tsnet node and walks
// the operator through Tailscale's standard interactive auth flow
// (browser → IdP → control-plane assigns a tailnet IP). The auth URL
// is printed to stdout and best-effort opened in the local browser;
// if the operator is on a headless box, the URL is still copy-
// pasteable. Blocks until the node reaches Running or ctx fires.
//
// Why disk-backed state and not mem.Store/Ephemeral: tsnet allows
// `Store: &mem.Store{}` only when `Ephemeral: true` (see
// tsnet/tsnet.go's isMemStore guard). Setting Ephemeral=true sends
// LoginEphemeral to the control server at registration — but for
// Tailscale SaaS that flag is only honored on the auth-key flow,
// not on browser-driven interactive auth. Empirically: the browser
// completes auth fine, but the resulting node never transitions to
// BackendState=Running and the join times out. Until tsnet gains a
// way to mark a browser-auth registration as ephemeral, we keep the
// credentials in a temp dir and rely on Close→Logout+RemoveAll for
// cleanup. SIGKILL during the bootstrap window can leak the temp
// dir; the credentials inside it are still constrained by the
// human's tailnet ACL, not a tagged-bot identity.
func bootstrapTailnetForJoin(ctx context.Context) (*tailnetBootstrap, error) {
	dir, err := os.MkdirTemp("", "clawpatrol-bootstrap-")
	if err != nil {
		return nil, fmt.Errorf("tailnet bootstrap: mkdir temp: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	// A distinct hostname per invocation so two concurrent joins on
	// the same machine don't collide on the tailnet, and so the
	// operator can find this node in the tailnet admin if cleanup
	// fails. We aim for ephemeral by tearing the node down at the
	// end, not by relying on tailnet-side ACL rules (most users
	// don't control the policy file of the tailnet they're joining).
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		cleanup()
		return nil, fmt.Errorf("tailnet bootstrap: random: %w", err)
	}
	hostname := "clawpatrol-bootstrap-" + hex.EncodeToString(suffix)

	s := &tsnet.Server{
		Dir:      dir,
		Hostname: hostname,
		// Silence tsnet's internal chatter — we drive the auth-URL
		// display ourselves below so the operator sees one clean
		// message, not interleaved control-plane debug lines.
		Logf:     func(string, ...any) {},
		UserLogf: func(string, ...any) {},
	}

	if err := s.Start(); err != nil {
		_ = s.Close()
		cleanup()
		return nil, fmt.Errorf("tailnet bootstrap: start tsnet: %w", err)
	}
	lc, err := s.LocalClient()
	if err != nil {
		_ = s.Close()
		cleanup()
		return nil, fmt.Errorf("tailnet bootstrap: local client: %w", err)
	}

	if err := awaitTailnetAuth(ctx, lc); err != nil {
		// Best-effort cleanup of a partially-onboarded node so we
		// don't leave a NeedsLogin entry in the tailnet admin.
		logoutCtx, lcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = lc.Logout(logoutCtx)
		lcancel()
		_ = s.Close()
		cleanup()
		return nil, err
	}

	return &tailnetBootstrap{
		server: s,
		lc:     lc,
		client: s.HTTPClient(),
		dir:    dir,
	}, nil
}

// awaitTailnetAuth blocks until the tsnet node reaches Running,
// printing the BrowseToURL exactly once when the control plane
// surfaces it. Polls the LocalClient because StatusWithoutPeers is
// cheap and the auth phase rarely lasts more than a few seconds in
// the happy path — a wait of 10 minutes (the device-flow timeout
// elsewhere in the join code) is the soft upper bound.
func awaitTailnetAuth(ctx context.Context, lc *local.Client) error {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	fmt.Println()
	fmt.Println("Reaching the gateway requires Tailscale tailnet access.")
	fmt.Println("Opening browser for one-time interactive login.")
	fmt.Println("(These credentials are discarded as soon as join completes —")
	fmt.Println(" the agent's persistent identity is the gateway-minted tag.)")

	printed := false
	for {
		select {
		case <-deadline.Done():
			return fmt.Errorf("tailnet bootstrap: timed out waiting for login")
		default:
		}
		st, err := lc.StatusWithoutPeers(deadline)
		if err != nil {
			// tsnet isn't ready yet during the first few hundred ms
			// after Start(); back off briefly and retry.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if !printed && st.AuthURL != "" {
			fmt.Println()
			fmt.Printf("    %s\n", st.AuthURL)
			fmt.Println()
			tryOpen(st.AuthURL)
			printed = true
		}
		if st.BackendState == "Running" {
			fmt.Println("Tailnet login complete.")
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// isTailnetShapedURL reports whether u points at a host that is
// reachable only from inside a tailnet — a 100.64.0.0/10 (CGNAT)
// literal or a *.ts.net MagicDNS hostname. When the initial probe
// against such a URL fails with a network error, the auto-fallback
// to bootstrapTailnetForJoin kicks in.
func isTailnetShapedURL(u string) bool {
	p, err := neturl.Parse(u)
	if err != nil {
		return false
	}
	host := p.Hostname()
	if host == "" {
		return false
	}
	if strings.HasSuffix(strings.ToLower(host), ".ts.net") {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		// CGNAT 100.64.0.0/10 — Tailscale's tailnet IP range.
		return ip.Is4() && ip.As4()[0] == 100 && (ip.As4()[1]&0xc0) == 64
	}
	return false
}

// isNetworkUnreachableErr returns true for the dial errors that mean
// "this URL isn't reachable from the network we're currently on" —
// the signal the auto-fallback to a tailnet bootstrap uses to decide
// whether to retry. Other errors (TLS, HTTP 5xx, etc.) mean the
// gateway IS reachable but something else is wrong, and bootstrapping
// a tailnet won't help.
func isNetworkUnreachableErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// net.DNSError and i/o timeouts don't expose a stable sentinel,
	// so we fall back to string matching on the error chain.
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "Client.Timeout") ||
		strings.Contains(s, "no route to host") ||
		strings.Contains(s, "network is unreachable")
}
