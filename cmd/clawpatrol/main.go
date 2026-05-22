package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol/cmd/clawpatrol/dnsvip"
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	"github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/google/uuid"
	"tailscale.com/client/local"
)

// JoinConfig aliases config.JoinConfig so call sites (newWebMux /
// StartWGServer / newOnboarder / mintTailscaleAuthKey) can refer to
// it as a bare name.
type JoinConfig = config.JoinConfig

// resolveStateDir picks the directory where the gateway keeps its
// sqlite DB. The HCL `state_dir` attribute is the only knob;
// defaults to ${HOME}/.clawpatrol when unset. The DB filename
// (clawpatrol.db) coexists with the client-side ca.crt that lives
// in the same dir on dev machines.
func resolveStateDir(cfg *config.Gateway) string {
	if d := cfg.StateDir(); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		log.Fatalf("state_dir unset and $HOME unavailable")
	}
	return filepath.Join(home, ".clawpatrol")
}

const hitlOperationTerminalRetention = 7 * 24 * time.Hour

func runHITLOperationStartupMaintenance(ctx context.Context, db *sql.DB) (HITLOperationMaintenanceResult, error) {
	store := NewHITLOperationStore(db)
	now := time.Now().UTC()
	retention := hitlOperationTerminalRetention
	var out HITLOperationMaintenanceResult
	recovered, err := store.RecoverStaleInProgressOperations(ctx, now, retention)
	if err != nil {
		return HITLOperationMaintenanceResult{}, err
	}
	out.SyncWaitingRecovered = recovered.SyncWaitingRecovered
	out.ExecutingRecovered = recovered.ExecutingRecovered
	expired, err := store.ExpireDueOperations(ctx, now, retention)
	if err != nil {
		return HITLOperationMaintenanceResult{}, err
	}
	out.PendingApprovalExpired = expired.PendingApprovalExpired
	out.ApprovedRetryExpired = expired.ApprovedRetryExpired
	purged, err := store.PurgeTerminalOperations(ctx, now)
	if err != nil {
		return HITLOperationMaintenanceResult{}, err
	}
	out.PurgedTerminal = purged
	return out, nil
}

// warnIfStateLooselyPermissioned logs a warning when state_dir or
// clawpatrol.db is readable by group / others. The sqlite db holds
// the CA private key, OAuth tokens, and audit log — anything not
// owned and 0700/0600 is a credential-leak path. Non-fatal so a
// fresh-from-mkdir setup that hasn't yet been tightened can still
// boot.
func warnIfStateLooselyPermissioned(stateDir string) {
	check := func(path string, want os.FileMode) {
		st, err := os.Stat(path)
		if err != nil {
			return
		}
		mode := st.Mode().Perm()
		if mode&0o077 != 0 {
			log.Printf("warning: %s has mode %#o (want %#o); CA key + OAuth tokens are readable beyond owner. Tighten with: chmod %#o %s", path, mode, want, want, path)
		}
	}
	check(stateDir, 0o700)
	check(filepath.Join(stateDir, "clawpatrol.db"), 0o600)
}

// emit a terminal request event to both the SSE sink and OTel.
// ev.Action and ev.Ms must be populated. Non-request events (e.g.
// hitl_pending) call g.sink.Emit directly to stay out of the
// request-duration histogram.
func (g *Gateway) emit(ev Event) {
	g.sink.Emit(ev)
	otelRecordVerdict(ev.Action)
	otelRecordRequest(time.Duration(ev.Ms)*time.Millisecond, ev.Action, ev.Status)
}

// emitEnd marks ev as the terminal event for its request and emits.
// Skip-noop for events without an ID (legacy callers that don't have
// the start/end pairing yet — splice end events keep working).
func (g *Gateway) emitEnd(ev Event) {
	if ev.ID != "" {
		ev.Phase = "end"
	}
	g.emit(ev)
}

// parseDurationOr parses an HCL duration string ("30m", "2h"). Empty
// string falls back to def. "0" / "off" disables (returns 0). Used by
// session_keep + similar knobs that need a default with an opt-out.
func parseDurationOr(s string, def time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	if s == "0" || s == "off" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Printf("parseDuration %q: %v (using default %s)", s, err, def)
		return def
	}
	return d
}

// newReqID returns a UUIDv7 string. Time-ordered + random tail;
// used both for start/end/frame correlation and as the persistent
// action key in the DB / detail page URL.
func newReqID() string {
	return uuid.Must(uuid.NewV7()).String()
}

// loadConfig parses the gateway HCL via the typed-block grammar and
// compiles it into a runtime CompiledPolicy. Plugin loading goes
// through config's package-global PluginLoader, installed once at
// process startup via config.SetPluginLoader.
func loadConfig(path string) (*config.Gateway, *config.CompiledPolicy, error) {
	gw, diags := config.Load(path)
	if diags.HasErrors() {
		return nil, nil, fmt.Errorf("%s", diags.Error())
	}
	cp, err := config.Compile(gw)
	if err != nil {
		return nil, nil, fmt.Errorf("compile: %w", err)
	}
	return gw, cp, nil
}

// orderedProfileNames returns the declared profile names in source
// order. Map iteration over Policy.Profiles isn't deterministic, so
// we re-sort by the Order slice (which buildSymbols populates in
// declaration order) and filter to KindProfile entries.
func orderedProfileNames(p *config.Policy) []string {
	out := []string{}
	if p == nil {
		return out
	}
	seen := map[string]bool{}
	for _, name := range p.Order {
		if seen[name] {
			continue
		}
		if _, ok := p.Profiles[name]; ok {
			out = append(out, name)
			seen[name] = true
		}
	}
	for name := range p.Profiles {
		if !seen[name] {
			out = append(out, name)
		}
	}
	return out
}

func peekSNI(c net.Conn) (string, []byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", nil, err
	}
	if hdr[0] != 0x16 {
		return "", hdr, errors.New("not TLS")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 42 || recLen > 16384 {
		return "", hdr, errors.New("bad TLS record length")
	}
	rec := make([]byte, recLen)
	if _, err := io.ReadFull(c, rec); err != nil {
		return "", nil, err
	}
	buf := append(hdr, rec...)

	p := rec
	if len(p) < 38 || p[0] != 0x01 {
		return "", buf, errors.New("not ClientHello")
	}
	p = p[38:]
	if len(p) < 1 {
		return "", buf, errors.New("truncated")
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return "", buf, errors.New("truncated sid")
	}
	p = p[sidLen:]
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen+1 {
		return "", buf, errors.New("truncated cs")
	}
	p = p[csLen:]
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen+2 {
		return "", buf, errors.New("truncated cm")
	}
	p = p[cmLen:]
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return "", buf, errors.New("truncated ext")
	}
	exts := p[:extLen]
	for len(exts) >= 4 {
		t := int(exts[0])<<8 | int(exts[1])
		l := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if l > len(exts) {
			return "", buf, errors.New("truncated ext body")
		}
		if t == 0x00 {
			body := exts[:l]
			if len(body) < 5 {
				return "", buf, errors.New("bad sni")
			}
			n := int(body[3])<<8 | int(body[4])
			if 5+n > len(body) {
				return "", buf, errors.New("truncated sni name")
			}
			return string(body[5 : 5+n]), buf, nil
		}
		exts = exts[l:]
	}
	return "", buf, errors.New("no SNI")
}

type peekConn struct {
	net.Conn
	r io.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *peekConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func wrapPeek(c net.Conn, prefix []byte) net.Conn {
	return &peekConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

func newUpstreamDialer(resolver string) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if resolver == "" {
		return d
	}
	d.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dd net.Dialer
			return dd.DialContext(ctx, network, resolver)
		},
	}
	return d
}

type Gateway struct {
	cfg      *config.Gateway
	cfgPath  string // path the HCL config was loaded from
	stateDir string // resolved gateway state dir (sqlite + plugin blobs)
	db       *sql.DB
	policy   atomic.Pointer[config.CompiledPolicy]
	certs    *CertCache
	dialer   *net.Dialer
	sink     *Sink
	// blobs is the gateway-side plugin blob store (sqlite-backed).
	// Used by endpoint plugins that need per-endpoint persistent
	// bytes — SSH host keys today, future JWT signing keys.
	// Exposed to plugins via ConnHandle.Blobs.
	blobs   runtime.BlobStore
	oauth   *OAuthRegistry
	agents  *AgentRegistry
	hitl    *HITLRegistry
	onboard *onboardRegistry
	// secrets hands credential plugins the secret bytes they inject
	// at request time. gatewaySecretStore stacks the credential_secrets
	// table (dashboard slots), OAuthRegistry (refreshed access tokens),
	// and CLAWPATROL_SECRET_<NAME> env vars in that priority.
	secrets runtime.SecretStore
	// connIdx maps WG-forwarder dstIPs back to the endpoint that
	// claims them — populated by every endpoint plugin whose body
	// implements runtime.ConnRouter (postgres today, future binary
	// protocols). Rebuilt on every policy load.
	connIdx atomic.Pointer[runtime.ConnIndex]
	// dnsvip owns the hostname↔virtual-IP table for endpoints whose
	// wire protocol can't be disambiguated at TCP-accept time (SSH
	// today).
	dnsvip *dnsvip.Allocator
	// tunnels is the lifecycle manager for endpoints whose
	// CompiledEndpoint.Tunnel is non-nil. Refcounts runtime tunnel
	// instances across endpoints; the dispatcher consults it from
	// dialUpstream / ConnHandle.DialUpstream callbacks.
	tunnels *TunnelManager
	// transports memoizes one http.Transport per endpoint. Avoids the
	// per-request allocation + idle-conn-pool reset of the old path.
	transports sync.Map // *config.CompiledEndpoint -> *http.Transport
	// tailscaleIP is the gateway's own Tailscale IPv4 (100.x.x.x).
	// Set at startup in Tailscale control mode; included in onboard join
	// responses so clients can write tailnet-url without a peer-name lookup.
	tailscaleIP string
	// tailscaleHostname is the actual registered node name (e.g.
	// "clawpatrol-gateway-1") — may differ from cfg.Hostname when tsnet
	// resolves a conflict. Included in onboard join responses as
	// gateway_host so clawpatrol-run peer lookups succeed.
	tailscaleHostname string
	// tsnetLC is the embedded tsnet's LocalClient. Used to resolve a
	// peer's full address set (e.g. IPv4 → IPv6 ULA) when seeding
	// profile mappings — tsnet whole-machine traffic arrives on the
	// IPv6 ULA, so the IPv4 entry alone isn't enough.
	tsnetLC *local.Client
}

// transportFor returns the cached http.Transport for ep, building it
// on first use. dialBrowserTLS for Cloudflare-fronted hosts; mTLS
// endpoints stay on dialUpstream so credential plugins run.
func (g *Gateway) transportFor(ep *config.CompiledEndpoint) *http.Transport {
	if v, ok := g.transports.Load(ep); ok {
		return v.(*http.Transport)
	}
	tr := &http.Transport{
		DialContext: g.dialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, _, err := net.SplitHostPort(addr)
			if err != nil {
				h = addr
			}
			if needsBrowserTLS(h) && !endpointWantsClientCert(ep) {
				return g.dialBrowserTLS(ctx, network, addr, h, ep)
			}
			profile, _ := ctx.Value(profileCtxKey{}).(string)
			return g.dialUpstream(ctx, network, addr, h, ep, profile)
		},
		ForceAttemptHTTP2:   false,
		IdleConnTimeout:     5 * time.Second,
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 8,
	}
	actual, _ := g.transports.LoadOrStore(ep, tr)
	return actual.(*http.Transport)
}

// Policy returns the current snapshot of the lowered runtime policy.
// nil before the first successful Load. Cheap (atomic load).
func (g *Gateway) Policy() *config.CompiledPolicy {
	return g.policy.Load()
}

// profileFor returns the profile name to use when applying rules /
// looking up OAuth credentials for a given peer IP. Falls back to the
// "default" profile when declared, otherwise to the first declared
// profile (single-tenant default).
func (g *Gateway) profileFor(peerIP string) string {
	if g.onboard != nil {
		if p := g.onboard.ProfileForIP(peerIP); p != "" {
			return p
		}
		// Lazy alias resolution via tsnet WhoIs. Two cases this catches:
		//
		//   1. Same Tailscale node, different address family — whole-
		//      machine tsnet traffic arrives on the peer's IPv6 ULA
		//      (fd7a:115c:a1e0::/48) but only the IPv4 is registered.
		//   2. Same logical host, new Tailscale node — the host rejoined
		//      the tailnet and got a fresh 100.x; without coalescing the
		//      dashboard sprouts a phantom row per rejoin.
		//
		// ClaimAliasResolve guards against re-running WhoIs per packet
		// for peers that have no matching device.
		if g.tsnetLC != nil && g.onboard.ClaimAliasResolve(peerIP, 5*time.Minute) {
			if canonical := g.resolveTsnetAlias(peerIP); canonical != "" {
				if p := g.onboard.ProfileForIP(canonical); p != "" {
					return p
				}
			}
		}
	}
	return defaultProfileName(g.cfg.Policy)
}

// resolveTsnetAlias does a one-shot tsnet WhoIs for peerIP and, on a
// match, registers an alias from peerIP onto the existing device IP.
// Returns the canonical device IP on success, or "" when no match is
// found. Both passes (address-match and hostname-match) only consider
// IPs that already have a devices row, so an unknown tailnet peer with
// no devices entry can never accidentally absorb traffic from another
// peer.
//
// Hostname matches require exactly one devices row with that name (see
// UniqueIPForHostname) so ephemeral pools that share a hostname — e.g.
// the clawpatrol-run-* nodes Tailscale auto-suffixes on collision — are
// never collapsed into one another.
func (g *Gateway) resolveTsnetAlias(peerIP string) string {
	if g.tsnetLC == nil || g.onboard == nil || peerIP == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	w, err := g.tsnetLC.WhoIs(ctx, net.JoinHostPort(peerIP, "0"))
	if err != nil || w == nil || w.Node == nil {
		return ""
	}
	for _, addr := range w.Node.Addresses {
		ip := addr.Addr().String()
		if ip == peerIP {
			continue
		}
		if g.onboard.HasDevice(ip) {
			g.onboard.RegisterIPAlias(peerIP, ip)
			return ip
		}
	}
	hostname := w.Node.ComputedName
	if hostname == "" && w.Node.Hostinfo.Valid() {
		hostname = w.Node.Hostinfo.Hostname()
	}
	if canonical := g.onboard.UniqueIPForHostname(hostname); canonical != "" && canonical != peerIP {
		g.onboard.RegisterIPAlias(peerIP, canonical)
		return canonical
	}
	return ""
}

// seedTsnetIPv6Alias resolves peerIP (IPv4) to the peer's IPv6 ULA via
// tsnet WhoIs and mirrors the same profile mapping onto the v6 in the
// onboard registry. Whole-machine tsnet traffic frequently arrives on
// the fd7a:115c:a1e0::/48 ULA rather than the 100.x IPv4 — without
// the alias profileFor falls back to "default" and dispatch misses
// every endpoint declared on the actual profile.
func (g *Gateway) seedTsnetIPv6Alias(peerIP string) {
	if g.tsnetLC == nil || g.onboard == nil || peerIP == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	w, err := g.tsnetLC.WhoIs(ctx, net.JoinHostPort(peerIP, "0"))
	if err != nil || w == nil || w.Node == nil {
		return
	}
	for _, addr := range w.Node.Addresses {
		ip := addr.Addr()
		if !ip.Is6() {
			continue
		}
		alias := ip.String()
		g.onboard.RegisterIPAlias(alias, peerIP)
		// Drop any ghost agent row that was seeded under the v6 before
		// the alias landed — traffic now folds to the v4 parent.
		if g.agents != nil {
			g.agents.Delete(alias)
		}
	}
}

// agentIPFor returns the IP to use for traffic attribution. Ephemeral
// peers are remapped to their parent device's IP so all activity shows
// under a single device in the dashboard.
func (g *Gateway) agentIPFor(c net.Conn) string {
	ip := peerIP(c)
	if g.onboard == nil {
		return ip
	}
	// Mirror the lazy WhoIs lookup in profileFor here so callers that
	// reach agentIPFor without first going through profileFor (e.g. the
	// LLM-session bookkeeping paths) still benefit from alias resolution.
	// Both functions use the same ClaimAliasResolve guard, so the WhoIs
	// runs at most once per peer per 5-minute window regardless of which
	// one is called first.
	if g.tsnetLC != nil && g.onboard.ClaimAliasResolve(ip, 5*time.Minute) {
		g.resolveTsnetAlias(ip)
	}
	return g.onboard.AgentIPFor(ip)
}

// defaultProfileName returns the profile a freshly-onboarded peer
// should attach to. Prefers a profile literally named "default";
// otherwise the first declared profile in source order. Empty when
// no profiles are configured (legacy single-tenant mode).
func defaultProfileName(p *config.Policy) string {
	names := orderedProfileNames(p)
	for _, n := range names {
		if n == "default" {
			return "default"
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

// watchConfig polls the config file's mtime every 3s. On change it
// re-decodes the HCL and atomically swaps in the new rules + admin_email
// + integrations list. Listen ports / CA dir / OAuth dir / Tailscale
// block changes still require a restart (logged but not applied).
func (g *Gateway) watchConfig(path string) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	last := st.ModTime()
	for {
		time.Sleep(3 * time.Second)
		st, err := os.Stat(path)
		if err != nil || !st.ModTime().After(last) {
			continue
		}
		last = st.ModTime()
		next, policy, err := loadConfig(path)
		if err != nil {
			log.Printf("config reload: %v", err)
			continue
		}
		g.policy.Store(policy)
		registerOAuthCredentials(g.oauth, policy)
		newConnIdx := runtime.BuildConnIndex(policy)
		g.connIdx.Store(newConnIdx)
		if g.tunnels != nil {
			g.tunnels.SetPolicy(context.Background(), policy)
		}
		if g.dnsvip != nil {
			if err := g.dnsvip.RebuildFromPolicy(policy); err != nil {
				log.Printf("dnsvip rebuild on reload: %v", err)
			}
		}
		// Hot-swap the operational *config.Gateway too — AdminEmail /
		// PublicURL / DashboardOperators reads pick up immediately.
		// Listen / CADir / Tailscale changes are not applied (restart).
		g.cfg = next
		log.Printf("config reloaded: %d endpoints across %d profile(s)",
			len(policy.Endpoints), len(policy.Profiles))
		logDashboardAuthState(g.db, next)
	}
}

// logDashboardAuthState emits a one-line summary of dashboard-auth
// state every time the config (re)loads, so an uninitialized or
// misconfigured dashboard shows up in `journalctl -u clawpatrol-
// gateway` even when nobody opens the dashboard in a browser.
//
// The root password lives in clawpatrol.db, not in gateway.hcl —
// so we resolve its presence by querying the DB.
func logDashboardAuthState(db *sql.DB, cfg *config.Gateway) {
	_, rootSet, err := lookupDashboardUser(db, dashboardRootUsername)
	if err != nil {
		log.Printf("dashboard auth: UNKNOWN — lookup failed: %v", err)
		return
	}
	tailnetMode := cfg.IsTailscaleEnabled()
	operators := cfg.Operators()
	allowlist := len(operators) > 0

	switch {
	case rootSet && allowlist && tailnetMode:
		log.Printf("dashboard auth: enabled (root password + %d-entry tailnet operator allowlist)", len(operators))
	case rootSet && allowlist && !tailnetMode:
		log.Printf("dashboard auth: enabled (root password); operators is set but ignored — no tailscale block, no tailnet whois")
	case rootSet:
		log.Printf("dashboard auth: enabled (root password)")
	case !rootSet && allowlist && tailnetMode:
		log.Printf("dashboard auth: pending — no root password yet; tailnet operator allowlist alone cannot bootstrap. Open the dashboard or run `clawpatrol gateway --set-dashboard-password <pw>`.")
	default:
		log.Printf("dashboard auth: pending — no root password yet. Open the dashboard at dashboard_listen %q to set one, or run `clawpatrol gateway --set-dashboard-password <pw>`.", cfg.DashboardListen())
	}
}

// sweepDashboardSessions deletes expired session rows on a slow tick.
// Lazy expiry on lookup already filters expired sessions out of auth
// decisions; this loop is purely a vacuum so a long-running gateway
// doesn't accumulate rows for browsers that never come back. Runs
// for the life of the gateway.
func (g *Gateway) sweepDashboardSessions() {
	const interval = 15 * time.Minute
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if n, err := sweepExpiredDashboardSessions(g.db); err != nil {
			log.Printf("dashboard session sweep: %v", err)
		} else if n > 0 {
			log.Printf("dashboard session sweep: deleted %d expired row(s)", n)
		}
	}
}

// applyDashboardPasswordFlags handles --set-dashboard-password and
// --reset-dashboard-password before the HTTP listener boots. The
// flags are deliberately verbose: each one log-prints what it did so
// the journalctl trail shows when an operator intervened.
//
// Mutual exclusion: --reset wins if both are passed. Empty
// --set-dashboard-password is a no-op (Go's flag package treats it
// the same as not passing the flag at all).
func applyDashboardPasswordFlags(db *sql.DB, setPassword string, reset bool) {
	if reset {
		if err := deleteDashboardUser(db, dashboardRootUsername); err != nil {
			log.Fatalf("--reset-dashboard-password: %v", err)
		}
		log.Printf("dashboard auth: root password cleared via --reset-dashboard-password (next dashboard hit will re-run first-run setup)")
		return
	}
	if setPassword == "" {
		return
	}
	if err := setDashboardUser(db, dashboardRootUsername, setPassword); err != nil {
		log.Fatalf("--set-dashboard-password: %v", err)
	}
	log.Printf("dashboard auth: root password set via --set-dashboard-password")
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gateway":
		runGateway(os.Args[2:])
	case "join":
		runJoin(os.Args[2:])
	case "run":
		runRun(os.Args[2:])
	case "daemon-internal":
		// internal: re-exec'd by `clawpatrol run` (Linux only) to host
		// the per-user tsnet daemon. Hidden from usage(); name carries
		// the -internal suffix so it doesn't read like a user-facing
		// command if it leaks into help text or shell history.
		runDaemon(os.Args[2:])
	case "relay-supervisor":
		// internal: re-exec'd by `clawpatrol run` to host the auto-expose
		// supervisor in the host netns. Hidden from usage.
		runRelaySupervisor(os.Args[2:])
	case "relay-worker":
		// internal: re-exec'd from inside the agent netns to host the
		// auto-expose worker. Hidden from usage.
		runRelayWorker(os.Args[2:])
	case "env":
		runEnv(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	case "test":
		runTest(os.Args[2:])
	case "uninstall":
		runUninstall(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "version", "-v", "--version":
		printVersion()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
	}
}

func peerIP(c net.Conn) string {
	if c == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return canonicalPeerIP(host)
}

// canonicalPeerIP collapses a wg-side v6 source (fd77::<n>) into its
// v4 equivalent (<wg-subnet-prefix>.<n>) so the agent registry,
// onboard registry, and dashboard track one device per peer
// regardless of which IP family the inbound flow used. Non-wg
// addresses pass through unchanged.
func canonicalPeerIP(ip string) string {
	if !strings.Contains(ip, ":") {
		return ip
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() {
		return ip
	}
	b := a.As16()
	if b[0] != 0xfd || b[1] != 0x77 {
		return ip
	}
	last := b[15]
	// Use the configured wg subnet prefix to reconstruct the v4. Fall
	// back to 10.55.0.0/24 — same default the example config uses —
	// when nothing's loaded yet (early-boot).
	prefixV4 := defaultWGV4Prefix
	if globalWG != nil && globalWG.serverIP.Is4() {
		s := globalWG.serverIP.As4()
		prefixV4 = [3]byte{s[0], s[1], s[2]}
	}
	v4 := netip.AddrFrom4([4]byte{prefixV4[0], prefixV4[1], prefixV4[2], last})
	return v4.String()
}

// defaultWGV4Prefix matches the example config's wg_subnet_cidr
// (10.55.0.0/24). Lets canonicalPeerIP work before the WGServer is
// up.
var defaultWGV4Prefix = [3]byte{10, 55, 0}

func printVersion() {
	v := buildVersion
	if buildGitSHA != "" {
		v += " (" + buildGitSHA + ")"
	}
	fmt.Println("clawpatrol", v)
}

func usage() {
	fmt.Fprintln(os.Stderr, `clawpatrol — secret-injection MITM proxy for AI agents

usage:
  clawpatrol gateway <config.hcl>        run the gateway server
  clawpatrol join [flags] <gateway-url>  onboard this machine via wg device flow
                  --hostname NAME        device name to register (default: os.Hostname)
                  --profile NAME         suggest a profile for the approver
                  --whole-machine        bring up wg-quick (route all traffic)
  clawpatrol run -- <cmd> [args...]      route one process tree through gateway
  clawpatrol status                      report install + tunnel state
  clawpatrol uninstall                   remove local join state and tunnel config
  clawpatrol env                         print shell exports for sourcing
  clawpatrol validate <config.hcl>       parse + compile a config and exit
  clawpatrol test <config> <path>        replay action fixtures against a candidate policy
  clawpatrol version | -v | --version    print version and exit

Documentation: https://clawpatrol.dev/docs/`)
	os.Exit(2)
}

// gatewayHelp is shown for `clawpatrol gateway -h` and any wrong
// invocation. The example HCL + config-reference URL is the
// discoverability path for first-time users.
const gatewayHelp = `usage: clawpatrol gateway [flags] <config.hcl>

flags:
  --set-dashboard-password <pw>   upsert the dashboard root password from this
                                  value, then start (skips the first-run web
                                  flow). The password is stored bcrypt-hashed
                                  in clawpatrol.db.
  --reset-dashboard-password      delete the stored dashboard root password,
                                  then start. The next dashboard request will
                                  re-run first-run setup.

Start from the example config:
  https://github.com/denoland/clawpatrol/blob/main/examples/gateway.example.hcl

HCL reference:
  https://clawpatrol.dev/docs/config-reference`

func runGateway(args []string) {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	setDashboardPassword := fs.String("set-dashboard-password", "",
		"upsert the dashboard root password from this value, then continue starting (skips the first-run web flow)")
	resetDashboardPassword := fs.Bool("reset-dashboard-password", false,
		"delete the stored dashboard root password before starting (the next dashboard hit goes back to first-run)")
	seedHook := devSeedAttach(fs)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, gatewayHelp) }
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, gatewayHelp)
		os.Exit(2)
	}
	cfgPath := rest[0]

	startModelRefresh()
	config.SetPluginLoader(extplugin.New(log.Default()))
	cfg, policy, err := loadConfig(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
			fmt.Fprintf(os.Stderr, "config file %q does not exist.\n\n%s\n", cfgPath, gatewayHelp)
			os.Exit(2)
		}
		log.Fatalf("config: %v", err)
	}
	stateDir := resolveStateDir(cfg)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Fatalf("state dir: %v", err)
	}
	db, err := OpenDB(filepath.Join(stateDir, "clawpatrol.db"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	if result, err := runHITLOperationStartupMaintenance(context.Background(), db); err != nil {
		log.Fatalf("hitl operation maintenance: %v", err)
	} else if result.PendingApprovalExpired != 0 || result.ApprovedRetryExpired != 0 || result.SyncWaitingRecovered != 0 || result.ExecutingRecovered != 0 || result.PurgedTerminal != 0 {
		log.Printf("hitl operation maintenance: expired pending=%d retry=%d recovered sync=%d executing=%d purged=%d", result.PendingApprovalExpired, result.ApprovedRetryExpired, result.SyncWaitingRecovered, result.ExecutingRecovered, result.PurgedTerminal)
	}
	warnIfStateLooselyPermissioned(stateDir)
	setDB(db)
	applyDashboardPasswordFlags(db, *setDashboardPassword, *resetDashboardPassword)
	logDashboardAuthState(db, cfg)
	blobs := newGatewayBlobStore(db)
	endpoints.SetBlobStore(blobs)
	certs, err := loadOrMintCA(db)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	sink, err := NewSink(db, 4096)
	if err != nil {
		log.Fatalf("log: %v", err)
	}
	// OAuthRegistry seeds at boot from the policy via
	// registerOAuthCredentials below — credential plugins own credential
	// discovery, the registry just persists per-owner tokens + handles
	// refresh. gatewaySecretStore consults it for OAuth-flow credentials.
	oauthReg, err := NewOAuthRegistry(nil, db)
	if err != nil {
		log.Fatalf("oauth: %v", err)
	}
	g := &Gateway{
		cfg:      cfg,
		cfgPath:  cfgPath,
		stateDir: stateDir,
		db:       db,
		certs:    certs,
		dialer:   newUpstreamDialer(cfg.Resolver()),
		sink:     sink,
		blobs:    blobs,
		oauth:    oauthReg,
		agents:   NewAgentRegistry(),
		hitl:     newHITLRegistry(sink),
		onboard:  newOnboardRegistry(),
	}
	log.Printf("config: read-only (the dashboard cannot edit gateway.hcl)")
	g.secrets = newGatewaySecretStore(db, oauthReg)
	g.hitl.asyncGrantResolver = g.resolveAsyncHITLGrant
	g.hitl.pendingMessageUpdater = g.updatePendingHITLMessage
	g.tunnels = NewTunnelManager(g.secrets, stateDir)
	registerOAuthCredentials(oauthReg, policy)
	g.policy.Store(policy)
	g.connIdx.Store(runtime.BuildConnIndex(policy))
	g.tunnels.SetPolicy(context.Background(), policy)
	// dnsvip is opt-in by policy: if no endpoint requires VIPs, the
	// allocator stays empty and ServeUDP / ServeTCP are never called
	// (no endpoint dispatches port-53 to them). Construct
	// unconditionally so reloads that *add* an SSH endpoint don't
	// have to re-init. Persists to <stateDir>/dnsvip.json so VIPs
	// survive restarts.
	dvip, err := dnsvip.New(db, dnsvip.DefaultCIDR4, dnsvip.DefaultCIDR6)
	if err != nil {
		log.Fatalf("dnsvip init: %v", err)
	}
	g.dnsvip = dvip
	if err := g.dnsvip.RebuildFromPolicy(policy); err != nil {
		log.Fatalf("dnsvip build: %v", err)
	}
	log.Printf("policy: %d endpoints across %d profiles", len(policy.Endpoints), len(policy.Profiles))
	go g.sweepDashboardSessions()
	go g.watchConfig(cfgPath)
	if err := g.onboard.Load(db); err != nil {
		log.Fatalf("onboard load: %v", err)
	}
	g.agents.onboard = g.onboard
	// Seed agent entries for every persisted device so the dashboard
	// renders them on boot, before any traffic arrives. Without this,
	// devices disappear after every gateway restart and only reappear
	// on the next request from each peer.
	// Clean fd77:: ghost rows (WG) and fd7a:: ghost rows (Tailscale IPv6)
	// left by builds that upserted IPv6 peer addresses as separate device
	// IDs. Drop them on every boot — the v4 row carries the same metadata.
	_, _ = db.Exec("DELETE FROM devices WHERE id LIKE 'fd77:%' OR id LIKE 'fd7a:%'")
	if rows, err := db.Query("SELECT id FROM devices"); err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var ip string
			if rows.Scan(&ip) == nil {
				g.agents.Seed(canonicalPeerIP(ip))
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("seed devices: %v", err)
		}
	}

	// Sessions: rehydrate persisted rows + start the sweeper.
	//   session_keep — hard retention floor by last_at (default
	//                  720h / 30d, "0" / "off" disables sweep).
	// Sessions can revive on new activity at any time, so there's no
	// "closed" intermediate state — keep is the only knob.
	g.agents.LoadSessions(db)
	g.agents.startSessionSweeper(parseDurationOr(cfg.SessionKeep(), 10*time.Minute))

	// HITL notifications fan-out via the approver runtimes
	// (config/plugins/approvers); the registry's Add hook emits
	// the SSE event for the dashboard.

	if _, err := StartOtel(g); err != nil {
		log.Printf("otel: %v", err)
	}

	startTelemetry(g)

	seedHook.Run(context.Background(), g)

	dashListen := cfg.DashboardListen()
	if dashListen != "" {
		mux := newWebMux(g, cfg.Join(), cfg.PublicURL())
		go serveHTTPLogged("dashboard", dashListen, mux)
		log.Printf("dashboard: http://%s", dashListen)
	}
	go serveHTTPLogged("pprof", "127.0.0.1:6060", nil)
	go g.servePorts()

	// Embedded userspace WireGuard server. When the `wireguard {}`
	// block is present, the clawpatrol process becomes the WG endpoint
	// — peers established at onboard time route ALL traffic into our
	// netstack (AllowedIPs=0.0.0.0/0). The promiscuous forwarder
	// accepts SYNs to any dst IP/port:
	//   - 443    → MITM (g.handle does SNI peek + rule dispatch)
	//   - dash   → dashboard mux
	//   - else   → transparent relay to the real upstream
	// No /etc/hosts hack needed on clients — agents resolve real
	// hostnames via public DNS and the gateway intercepts at L3.
	if cfg.IsWireGuardEnabled() {
		wg, err := StartWGServer(cfg.Join())
		if err != nil {
			log.Fatalf("wireguard: %v", err)
		}
		setWGServer(wg)
		dashMux := newWebMux(g, cfg.Join(), cfg.PublicURL())
		dashPort := portOf(dashListen)
		tcpDispatch := func(c net.Conn, dstIP string, dstPort uint16) {
			log.Printf("wg-fwd: %s:%d", dstIP, dstPort)
			switch {
			case dstPort == 443:
				g.handle(c, dstIP)
			case dstPort == 5432:
				g.handlePostgresConn(c, dstIP)
			case dstPort == 53:
				g.handleDNSTCPConn(c, dstIP)
			case g.dnsvip.IsVIP(dstIP):
				// Any port on a VIP belongs to the SSH endpoint that
				// hostname maps to. Future RequiresVIP plugins can
				// branch on ep.Plugin.Type inside handleVIPConn.
				g.handleVIPConn(c, dstIP, dstPort)
			case dashPort != 0 && int(dstPort) == dashPort:
				_ = http.Serve(&oneShotListener{c: c}, dashMux)
			default:
				// Direct-IP dispatch via conn-index: catches
				// clickhouse_native and friends when the operator
				// binds them to IP-literal hosts (dnsvip skips
				// those — they don't need DNS interception). Falls
				// through to transparent relay when no endpoint
				// claims the dst.
				if g.tryDirectIPConn(c, dstIP, dstPort) {
					return
				}
				g.wgRelay(c, dstIP, int(dstPort))
			}
		}
		udpDispatch := func(c net.Conn, dstIP string, dstPort uint16) bool {
			if dstPort == 53 {
				g.dnsvip.ServeUDP(c, dstIP)
				return true
			}
			return false
		}
		if err := wg.EnablePromiscuousForwarder(tcpDispatch, udpDispatch); err != nil {
			log.Fatalf("wireguard forwarder: %v", err)
		}
		log.Printf("wireguard promiscuous forwarder ready (any dst → :443=mitm, :5432=pg, :53=dns-vip, VIP=ssh|ch_native, :%d=dash, plugins=conn-index, else=relay)", dashPort)
	}

	tsnetServer, ln, err := openListener(cfg, stateDir)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if ln != nil {
		log.Printf("gateway listening on %s, %d endpoints across %d profiles",
			ln.Addr(), len(policy.Endpoints), len(policy.Profiles))
	} else {
		log.Printf("gateway listening on tsnet (exit-node routed), %d endpoints across %d profiles",
			len(policy.Endpoints), len(policy.Profiles))
	}

	if tsnetServer != nil && cfg.Funnel() && cfg.PublicURL() == "" {
		// Auto-derive public_url from the tsnet cert domain so that
		// join responses, HITL status links, and OAuth redirect URIs use
		// the correct internet-reachable URL when funnel = true. Cert
		// provisioning can lag Funnel listener start by a few seconds,
		// so retry async.
		go func() {
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				if domain := tsnetCertDomain(tsnetServer); domain != "" {
					cfg.SetPublicURL(domain)
					log.Printf("tsnet: funnel public_url auto-derived: %s", domain)
					return
				}
				time.Sleep(2 * time.Second)
			}
			log.Printf("tsnet: funnel public_url not derived after 60s — dashboard will show the loopback URL in join hints")
		}()
	}
	tsnetDashMux := newWebMux(g, cfg.Join(), cfg.PublicURL())
	tsnetDashPort := portOf(dashListen)
	if tsnetServer != nil {
		// Seed gateway tailscale IP for /api/join responses so clients
		// know the tailnet-direct URL without a DNS lookup.
		// Retry status query — DNSName populates after netmap arrives from
		// control, which can lag Listen() by a second or two. Without retry
		// we'd read empty DNSName and fall back to OS hostname, which is
		// often wrong (tsnet may have registered under a different name
		// from saved state). Retry for up to 15s.
		go func() {
			lc2, err2 := tsnetServer.LocalClient()
			if err2 != nil {
				log.Printf("tsnet: LocalClient err: %v", err2)
				return
			}
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				st, err3 := lc2.StatusWithoutPeers(context.Background())
				if err3 != nil || st.Self == nil {
					time.Sleep(500 * time.Millisecond)
					continue
				}
				if g.tailscaleIP == "" {
					for _, ip := range st.Self.TailscaleIPs {
						if ip.Is4() {
							g.tailscaleIP = ip.String()
							break
						}
					}
				}
				hn := st.Self.DNSName
				if i := strings.IndexByte(hn, '.'); i > 0 {
					hn = hn[:i]
				}
				if hn != "" {
					g.tailscaleHostname = hn
					log.Printf("tsnet: node name %q IP %s", hn, g.tailscaleIP)
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
			log.Printf("tsnet: never got DNSName from status — gateway_host may be wrong")
		}()
		// Replace the default system-tailscaled LocalClient with the tsnet
		// one so that whois lookups (dashboard auth, identity derivation)
		// work on machines without a system tailscaled daemon.
		if lc, err := tsnetServer.LocalClient(); err == nil {
			g.agents.SetLocalClient(lc)
			g.tsnetLC = lc
		} else {
			log.Printf("tsnet: LocalClient for whois: %v", err)
		}
		// Serve the dashboard mux on tsnet's virtual network so
		// clawpatrol-run clients connecting to this tsnet IP on the
		// dashboard port can mint ephemeral auth keys and reach the
		// dashboard.
		if dashPort := portOf(dashListen); dashPort != 0 {
			if tsnetDashLn, err := tsnetServer.Listen("tcp", fmt.Sprintf(":%d", dashPort)); err != nil {
				log.Printf("tsnet: dashboard listen :%d: %v", dashPort, err)
			} else {
				go http.Serve(tsnetDashLn, tsnetDashMux)
				log.Printf("tsnet: dashboard also listening on tsnet :%d", dashPort)
			}
		}
		if cfg.Funnel() {
			startFunnelListener(tsnetServer, tsnetDashMux)
		}
		// UDP/53 DNS server on the tsnet node. Whole-machine clients with
		// the gateway as exit-node send DNS via UDP/53 to the gateway's
		// tailnet IP; dnsvip allocates a VIP per intercepted hostname so
		// the subsequent TCP connection has a VIP the gateway recognises
		// and dispatches. WG mode's promiscuous forwarder caught this
		// already; tsnet exit-node needs an explicit listener.
		//
		// ListenPacket requires a concrete IP (not the wildcard). Wait
		// for the tailnet IP to be assigned, then bind there.
		if g.dnsvip != nil {
			go func() {
				for i := 0; i < 60 && g.tailscaleIP == ""; i++ {
					time.Sleep(500 * time.Millisecond)
				}
				if g.tailscaleIP == "" {
					log.Printf("tsnet: dnsvip UDP listener skipped — no tailscale IP")
					return
				}
				pc, err := tsnetServer.ListenPacket("udp", g.tailscaleIP+":53")
				if err != nil {
					log.Printf("tsnet: udp %s:53 (dns): %v", g.tailscaleIP, err)
					return
				}
				log.Printf("tsnet: dnsvip UDP listener on %s:53", g.tailscaleIP)
				serveTsnetDNSUDP(pc, g.dnsvip)
			}()
			// Layer a UDP/53 catch-all onto tsnet's underlying netstack so
			// exit-node clients whose system resolver targets a public IP
			// (8.8.8.8, 1.1.1.1) still reach dnsvip — the IP-bound listener
			// above only catches packets aimed at the gateway's own tailnet
			// IP. tsnet has no public UDP fallback hook, so this reaches
			// through Sys().Netstack (see installTsnetUDPDNSCatchAll).
			g.installTsnetUDPDNSCatchAll(tsnetServer)
		}
		// Intercept all TCP forwarded through this exit node (whole-machine
		// clients). dst is the original internet destination — same dispatch
		// as the per-process PROXY-header path and the WG promiscuous forwarder.
		tsnetServer.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
			dstIP := dst.Addr().String()
			dstPort := dst.Port()
			return func(c net.Conn) {
				switch {
				case dstPort == 443:
					g.handle(c, dstIP)
				case dstPort == 5432:
					g.handlePostgresConn(c, dstIP)
				case dstPort == 53:
					g.handleDNSTCPConn(c, dstIP)
				case g.dnsvip.IsVIP(dstIP):
					g.handleVIPConn(c, dstIP, dstPort)
				case tsnetDashPort != 0 && int(dstPort) == tsnetDashPort:
					_ = http.Serve(&oneShotListener{c: c}, tsnetDashMux)
				default:
					if g.tryDirectIPConn(c, dstIP, dstPort) {
						return
					}
					g.wgRelay(c, dstIP, int(dstPort))
				}
			}, true
		})
	}
	if ln == nil {
		// Tailscale mode: nothing more to accept here. All client TCP
		// arrives via the tsnet fallback handler above; UDP/53 via the
		// dnsvip listener; HTTPS/info via the Funnel + tsnet info
		// listeners. Block forever so runGateway doesn't return.
		select {}
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go func(c net.Conn) {
			// Host-local TCP listener (only opened when wireguard is
			// enabled). Used by single-host deployments where the
			// gateway runs under one user account and clawpatrol-run
			// is invoked from another on the same machine — both
			// loop back through 127.0.0.1:8443. No PROXY framing in
			// this mode — terminate TLS, serve the dashboard mux.
			g.serveTSNetDirect(c, tsnetDashMux)
		}(c)
	}
}

func serveHTTPLogged(name, addr string, handler http.Handler) {
	if err := http.ListenAndServe(addr, handler); err != nil {
		logHTTPServerExit(name, addr, err)
	}
}

func logHTTPServerExit(name, addr string, err error) {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return
	}
	log.Printf("%s http server on %s stopped: %v", name, addr, err)
}

// portOf extracts the numeric port from a "host:port" or ":port" listen
// string. Returns 0 when the input is empty or unparseable.
func portOf(addr string) int {
	if addr == "" {
		return 0
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// oneShotListener wraps a single net.Conn so http.Serve can hand it to
// the dashboard mux. After the first Accept, subsequent calls block
// until Close — the netstack forwarder spawns one goroutine per conn
// so http.Serve cleanly exits when the connection ends.
type oneShotListener struct {
	c    net.Conn
	done chan struct{}
	once bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.once {
		<-l.done
		return nil, net.ErrClosed
	}
	l.once = true
	if l.done == nil {
		l.done = make(chan struct{})
	}
	return l.c, nil
}

func (l *oneShotListener) Close() error {
	if l.done != nil {
		select {
		case <-l.done:
		default:
			close(l.done)
		}
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	if l.c == nil {
		return &net.TCPAddr{}
	}
	return l.c.LocalAddr()
}
