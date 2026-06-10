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
	"bytes"
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
	"sync"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// ramStateStore is a private in-memory ipn.StateStore. tsnet has its
// own ipn/store/mem.Store, but tsnet.Server gates that one behind
// `Ephemeral: true` (tsnet/tsnet.go isMemStore type-assert), and
// Ephemeral isn't honored on browser-driven interactive auth — only
// on auth-key registration. By presenting our own
// non-`*mem.Store` implementation we satisfy the same interface,
// dodge the gate, and never touch disk for credentials. The bootstrap
// node's machine key, login profile, and netmap snapshot all live in
// this map for the lifetime of the join. On process exit (clean or
// SIGKILL) the RAM is reclaimed; nothing to clean up, nothing to
// leak.
type ramStateStore struct {
	mu sync.Mutex
	m  map[ipn.StateKey][]byte
}

func (s *ramStateStore) ReadState(k ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return bytes.Clone(v), nil
}

func (s *ramStateStore) WriteState(k ipn.StateKey, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[ipn.StateKey][]byte{}
	}
	s.m[k] = bytes.Clone(v)
	return nil
}

// tailnetBootstrap is a transient tsnet.Server that exists only for
// the duration of `clawpatrol join`. Use Client() to talk to the
// bootstrapHostnamePrefix names the ephemeral tsnet node a `--login`
// join spins up to reach the gateway over the tailnet. The gateway
// filters agents whose whois hostname carries this prefix out of the
// device list — the node is discarded the instant join completes and
// is never a managed device.
const bootstrapHostnamePrefix = "clawpatrol-bootstrap-"

// gateway over the tailnet, then call Close to log the node out and
// reclaim the log dir.
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

// Close tears the bootstrap down on the happy path. Logout makes
// the node disappear from the tailnet admin promptly; Server.Close
// drops the local tsnet engine; the temp dir holding tsnet's log
// files gets removed.
//
// There is no SIGINT/SIGTERM/SIGKILL handler and intentionally so:
// credentials live in RAM (ramStateStore), so process exit by any
// means leaves nothing sensitive on disk. The only consequences of
// an uncaught signal are a few KB of tsnet log files in /tmp
// (which the OS reaps), and the bootstrap node lingering in the
// tailnet admin as offline for a minute or two until the control
// server times the connection out. Neither is worth a signal
// handler.
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
// Credentials live in RAM (ramStateStore), so the machine key and
// login profile never touch disk and the only thing in the temp Dir
// is tsnet's log buffer. We can't use tsnet's own ipn/store/mem
// implementation because tsnet gates it behind Ephemeral=true
// (tsnet/tsnet.go isMemStore type-assert), and Tailscale SaaS only
// honors LoginEphemeral on the auth-key registration flow, not on
// browser-driven interactive auth — empirically the resulting node
// never transitions to BackendState=Running. ramStateStore is a
// drop-in implementation of the same ipn.StateStore interface but
// isn't *mem.Store, so it dodges the gate while keeping browser
// auth working.
func bootstrapTailnetForJoin(ctx context.Context) (*tailnetBootstrap, error) {
	dir, err := os.MkdirTemp("", "clawpatrol-bootstrap-")
	if err != nil {
		return nil, fmt.Errorf("tailnet bootstrap: mkdir temp: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	// A distinct hostname per invocation so two concurrent joins on
	// the same machine don't collide on the tailnet, and so the
	// operator can find this node in the tailnet admin if cleanup
	// fails. Logout on Close removes it promptly on the happy path.
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		cleanup()
		return nil, fmt.Errorf("tailnet bootstrap: random: %w", err)
	}
	hostname := bootstrapHostnamePrefix + hex.EncodeToString(suffix)

	s := &tsnet.Server{
		// Dir still hosts tsnet's log buffer (tailscaled.log.conf
		// and the tailscaled/ subdir) regardless of Store — no
		// credentials here, just operational logs the temp dir
		// disposes of on Close.
		Dir:      dir,
		Hostname: hostname,
		// In-memory state store. The bootstrap's machine key, login
		// profile, and netmap snapshot all live in this map and are
		// gone the instant the process exits — clean or otherwise.
		Store: &ramStateStore{},
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

	var finish func(string)
	lastState := "unknown"
	// settle resolves the pending step (if shown) with line, else prints
	// line on its own.
	settle := func(line string) {
		if finish != nil {
			finish(line)
		} else {
			fmt.Println(line)
		}
	}
	for {
		select {
		case <-deadline.Done():
			return fmt.Errorf("tailnet bootstrap: timed out waiting for login (last state: %s)", lastState)
		default:
		}
		st, err := lc.StatusWithoutPeers(deadline)
		if err != nil {
			// tsnet isn't ready yet during the first few hundred ms
			// after Start(); back off briefly and retry.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		lastState = st.BackendState
		if finish == nil && st.AuthURL != "" {
			// The box running `clawpatrol join` is usually headless
			// (SSH session, no browser). Show the login URL + a QR so
			// the operator can scan from a phone — it's a public
			// login.tailscale.com link, reachable from any device. The
			// whole block collapses to "✓ logged in" once auth lands.
			finish = beginStep("Log in to the tailnet to reach the gateway", linkDetail(st.AuthURL, true), true)
			tryOpen(st.AuthURL) // best-effort local browser if one exists
		}
		switch st.BackendState {
		case "Running":
			settle("✓ logged in to the tailnet")
			return nil
		case "NeedsMachineAuth":
			// Authenticated but the tailnet gates new devices on admin
			// approval — it'll never reach Running on its own. Fail with
			// a reason instead of waiting out the 10-minute deadline.
			settle("! tailnet requires admin approval for this device")
			return fmt.Errorf("tailnet bootstrap: device needs admin approval — approve it in the Tailscale admin console (Machines), then re-run")
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
