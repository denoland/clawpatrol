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

// clawpatrolDebugEnabled reports whether CLAWPATROL_DEBUG selects the
// verbose diagnostics (same semantics as the Linux relay / macOS
// helper: any value other than "" or "0").
func clawpatrolDebugEnabled() bool {
	v := os.Getenv("CLAWPATROL_DEBUG")
	return v != "" && v != "0"
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

// bootstrapTsnetLogf returns the logf the bootstrap tsnet node uses:
// silent unless CLAWPATROL_DEBUG is set, in which case it forwards
// tsnet's lines to stderr behind a [tsnet] prefix.
func bootstrapTsnetLogf() func(string, ...any) {
	if !clawpatrolDebugEnabled() {
		return func(string, ...any) {}
	}
	return func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "[tsnet] "+strings.TrimRight(format, "\n")+"\n", a...)
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

	// One overall budget across every re-registration attempt below.
	// awaitTailnetAuth derives its own deadline from this ctx, so a
	// pathological wedge can't multiply the wait by recovering N times —
	// the whole bootstrap still caps at the documented ~10 minutes.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// One state store, reused across any re-registration below. It holds
	// the node key, so once the single-use interactive auth URL is
	// consumed (the operator approved it), a fresh Server can re-register
	// that same — now authorized — key and reach Running without a second
	// browser round-trip.
	store := &ramStateStore{}
	newServer := func() *tsnet.Server {
		return &tsnet.Server{
			// Dir hosts only tsnet's log buffer (state lives in `store`),
			// so it's safe to reuse across re-registration.
			Dir:      dir,
			Hostname: hostname,
			Store:    store,
			// Silent by default — we drive the auth-URL display ourselves.
			// CLAWPATROL_DEBUG surfaces tsnet's control-plane chatter for
			// diagnosing a stuck login.
			Logf:     bootstrapTsnetLogf(),
			UserLogf: bootstrapTsnetLogf(),
		}
	}

	// The interactive auth URL is single-use. Once the operator approves
	// it, control returns "auth path not found" (HTTP 410) on tsnet's
	// follow-up poll — and tsnet wedges re-polling the dead path forever
	// instead of re-registering the now-authorized node key.
	// awaitTailnetAuth detects that (errLoginPathConsumed); we recover by
	// starting a fresh node on the same store, whose plain re-register
	// picks up the authorization and reaches Running. The cap guards
	// against an unexpected loop.
	const maxLoginRecoveries = 3
	for attempt := 0; ; attempt++ {
		s := newServer()
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

		awErr := awaitTailnetAuth(ctx, lc)
		if awErr == nil {
			// tsnet's HTTPClient() has neither a client Timeout nor a dial
			// deadline. The gateway calls the join flow makes through it
			// run right after the node comes up, before routes/MagicDNS
			// have settled, so a stalled dial would hang the whole join.
			// Cap it so a stalled request surfaces an error instead.
			hc := s.HTTPClient()
			hc.Timeout = 30 * time.Second
			return &tailnetBootstrap{server: s, lc: lc, client: hc, dir: dir}, nil
		}

		if errors.Is(awErr, errLoginPathConsumed) && attempt < maxLoginRecoveries {
			// Stop this engine WITHOUT logging out — logout would discard
			// the authorized node key in `store` that we're about to
			// reuse — then loop to start a fresh node on the same store.
			if clawpatrolDebugEnabled() {
				fmt.Fprintf(os.Stderr, "[bootstrap] auth path consumed (device approved); re-registering the approved key (attempt %d/%d)\n", attempt+1, maxLoginRecoveries)
			}
			_ = s.Close()
			continue
		}

		// Genuine failure, or out of recoveries: log the node out so it
		// doesn't linger in the tailnet admin, then give up.
		logoutCtx, lcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = lc.Logout(logoutCtx)
		lcancel()
		_ = s.Close()
		cleanup()
		if errors.Is(awErr, errLoginPathConsumed) {
			return nil, fmt.Errorf("tailnet bootstrap: login did not finalize after %d re-registration attempts", maxLoginRecoveries)
		}
		return nil, awErr
	}
}

// errLoginPathConsumed signals that the interactive auth path was
// consumed: control returned "auth path not found" (HTTP 410) on the
// login follow-up, which is what happens once the operator approves the
// single-use URL. The node key is authorized at that point;
// bootstrapTailnetForJoin recovers by re-registering it on a fresh node.
var errLoginPathConsumed = errors.New("tailnet bootstrap: interactive auth path consumed")

// loginConsumedGrace is how long the "auth path not found" error must
// persist before we treat the login as wedged and re-register. tsnet
// usually retries the follow-up poll and picks up the authorization
// within milliseconds; we only step in when it stays stuck on the dead
// path well past that, so we never interfere with the common self-heal.
const loginConsumedGrace = 8 * time.Second

// loginPathConsumed reports whether the backend health includes the
// control-plane "auth path not found" error.
func loginPathConsumed(health []string) bool {
	for _, h := range health {
		if strings.Contains(h, "auth path not found") {
			return true
		}
	}
	return false
}

// awaitTailnetAuth blocks until the tsnet node reaches Running,
// printing the BrowseToURL the control plane surfaces and re-printing
// it if it changes (the interactive URL is short-lived). Polls the
// LocalClient because StatusWithoutPeers is cheap and the auth phase
// rarely lasts more than a few seconds in the happy path — a wait of
// 10 minutes (the device-flow timeout elsewhere in the join code) is
// the soft upper bound. Each poll is itself time-bounded so a wedged
// localapi call can't silently eat that whole budget.
func awaitTailnetAuth(ctx context.Context, lc *local.Client) error {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	var finish func(string)
	shownURL := ""
	lastState := "unknown"
	var consumedSince time.Time
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
		sctx, scancel := context.WithTimeout(deadline, 10*time.Second)
		st, err := lc.StatusWithoutPeers(sctx)
		scancel()
		if err != nil {
			// tsnet isn't ready yet during the first few hundred ms
			// after Start(); a later call can also wedge mid-login. Back
			// off briefly and retry rather than blocking on one call.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if st.BackendState != lastState {
			if clawpatrolDebugEnabled() {
				fmt.Fprintf(os.Stderr, "[bootstrap] backend state: %s -> %s\n", lastState, st.BackendState)
			}
			lastState = st.BackendState
		}
		if loginPathConsumed(st.Health) && st.BackendState != "Running" {
			// The single-use auth URL was consumed (operator approved).
			// tsnet normally retries the follow-up poll and picks up the
			// authorization within milliseconds — let that self-heal
			// happen. Only if it stays wedged on the dead path past the
			// grace do we clear the QR and hand back to
			// bootstrapTailnetForJoin to re-register the now-authorized
			// key on a fresh node.
			if consumedSince.IsZero() {
				consumedSince = time.Now()
			} else if time.Since(consumedSince) > loginConsumedGrace {
				if finish != nil {
					finish("")
				}
				return errLoginPathConsumed
			}
		} else {
			consumedSince = time.Time{}
		}
		if st.AuthURL != "" && st.AuthURL != shownURL {
			// The box running `clawpatrol join` is usually headless
			// (SSH session, no browser). Show the login URL + a QR so
			// the operator can scan from a phone — it's a public
			// login.tailscale.com link, reachable from any device. The
			// whole block collapses to "✓ logged in" once auth lands.
			//
			// Re-display whenever the URL changes rather than latching
			// the first one: the interactive login URL is short-lived,
			// so an operator slow to complete it sees the control plane
			// expire it and tsnet re-register for a fresh URL. Latching
			// the first link left a slow operator scanning a dead URL
			// while the node sat in NeedsLogin until the 10-minute
			// deadline — i.e. an apparent hang.
			headline := "Log in to the tailnet to reach the gateway"
			if shownURL != "" {
				// Collapse the dead link's block before reprinting so
				// the erase accounting stays balanced.
				if finish != nil {
					finish("")
				}
				headline = "Previous login link expired — open the refreshed link"
			}
			finish = beginStep(headline, linkDetail(st.AuthURL, true), true)
			tryOpen(st.AuthURL) // best-effort local browser if one exists
			shownURL = st.AuthURL
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
