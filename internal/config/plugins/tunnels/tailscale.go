package tunnels

// tailscale tunnel: dials upstream via an embedded tsnet.Server.
// Useful for endpoints that live in a tailnet and aren't reachable
// from the host's namespace — an internal ClickHouse o11y target is
// the canonical case.
//
// HCL:
//
//   tunnel "tailscale" "ts-prod" {
//     # authkey injected via CLAWPATROL_TUNNEL_TS_PROD_AUTHKEY
//     # (the literal authkey = "..." HCL form is also accepted)
//     hostname  = "clawpatrol-tunnel-prod"
//     keepalive = "always"   # default — once joined, stay joined
//   }
//
//   endpoint "clickhouse_native" "o11y" {
//     hosts  = ["clickhouse-o11y:9440"]
//     tunnel = ts-prod
//     ...
//   }
//
// Compile cost: tsnet pulls a sizeable dep tree (a fresh build
// adds ~12s wall-time + 18 MB to the binary). The plugin is always
// compiled in — operators who declare `tunnel "tailscale"` need it
// to work, and the cost amortises over the many use cases (every
// endpoint that references the tunnel benefits from a single
// embedded node).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	// Registers the OAuth-client auth-key resolver hook tsnet uses when
	// a tunnel is configured with `oauth_client_secret` — tsnet exchanges
	// the `tskey-client-...` secret for a fresh device key on every join.
	_ "tailscale.com/feature/oauthkey"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/tailscaleproto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TailscaleTunnel configures the tunnel runtime.
type TailscaleTunnel struct {
	// AuthKey is the Tailscale auth key; env fallback is CLAWPATROL_TUNNEL_<NAME>_AUTHKEY.
	AuthKey string `hcl:"authkey,optional"`
	// OAuthClientSecret is a Tailscale OAuth client secret
	// (tskey-client-...). When set, tsnet mints a fresh, short-lived
	// device key from the OAuth client on every join instead of relying
	// on a static authkey — so there is no long-lived key that can
	// expire out from under the tunnel. Requires `tags` (untagged OAuth
	// keys are rejected by Tailscale). Env fallback is
	// CLAWPATROL_TUNNEL_<NAME>_OAUTH_CLIENT_SECRET.
	OAuthClientSecret string `hcl:"oauth_client_secret,optional"`
	// ControlURL overrides the Tailscale control-plane URL.
	ControlURL string `hcl:"control_url,optional"`
	// Hostname is the tsnet node name; defaults to clawpatrol-tunnel-<name>.
	Hostname string `hcl:"hostname,optional"`
	// StateDir stores tsnet node state; defaults under the gateway CA directory.
	StateDir string `hcl:"state_dir,optional"`
	// Tags are Tailscale tags requested for the tsnet node.
	Tags []string `hcl:"tags,optional"`

	// Share controls whether runtime instances are singleton, per-endpoint, or per-request.
	Share string `hcl:"share,optional"`
	// Keepalive keeps an idle tunnel runtime warm for the given duration.
	Keepalive string `hcl:"keepalive,optional"`
	// Via chains this tunnel through another tunnel.
	Via string `hcl:"via,optional"`
	// Credential references an optional credential block for the tunnel runtime.
	Credential string `hcl:"credential,optional"`
}

// TunnelCommon returns shared tunnel settings.
func (t *TailscaleTunnel) TunnelCommon() config.TunnelCommon {
	return config.TunnelCommon{
		Share:      t.Share,
		Keepalive:  t.Keepalive,
		Via:        t.Via,
		Credential: t.Credential,
	}
}

// Sharing defaults to singleton: one tsnet node per tailscale
// tunnel block, shared by every endpoint that references it.
func (*TailscaleTunnel) Sharing() runtime.TunnelSharing { return runtime.TunnelShareSingleton }

// tunnelStateDir resolves the on-disk path passed to tsnet.Server.Dir.
// Honours `state_dir = ...` on the tunnel block; otherwise carves
// tunnels/tailscale/<name> out of the gateway's state_dir. The dir is
// created 0700 because tsnet writes private node-state material here
// (literal-authkey branch) and derp / logtail caches (both branches).
//
// Setting Dir explicitly keeps tsnet from consulting
// $XDG_CONFIG_HOME / $HOME, which may be unset under hardened systemd
// units, minimal containers, etc.
func tunnelStateDir(t *TailscaleTunnel, host runtime.TunnelHost) (string, error) {
	dir := t.StateDir
	if dir == "" && host.StateDir != "" {
		dir = filepath.Join(host.StateDir, "tunnels", "tailscale", host.Name)
	}
	if dir == "" {
		return "", errors.New("tailscale tunnel: state_dir is required (HCL `state_dir = ...` on the tunnel or the gateway)")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("tailscale tunnel %q: state dir: %w", host.Name, err)
	}
	return dir, nil
}

// Open brings up an embedded tsnet node and returns a Tunnel whose
// Dial routes through it. Two paths:
//
//   - Credential-driven (`credential = my-tailnet` on the HCL block):
//     tsnet runs without a pre-minted authkey. The credential supplies
//     an ipn.StateStore so node identity persists into sqlite. On first
//     boot, tsnet emits an interactive login URL captured into
//     tailscaleproto.Default for the dashboard to surface. Open returns
//     immediately with a tunnel whose Dial errors with "node not
//     connected" until tsnet finishes joining — this keeps the gateway
//     (and its dashboard) responsive while the operator clicks Connect.
//   - Literal authkey (existing path, unchanged): the HCL `authkey`
//     literal — or its `CLAWPATROL_TUNNEL_<NAME>_AUTHKEY` env-var
//     fallback — supplies the auth material, tsnet state lives on disk
//     under `state_dir`, and Up blocks until joined as before.
func (t *TailscaleTunnel) Open(ctx context.Context, host runtime.TunnelHost, _ runtime.Tunnel) (runtime.Tunnel, error) {
	hn := t.Hostname
	if hn == "" {
		hn = "clawpatrol-tunnel-" + host.Name
	}
	logger := host.Logger
	if logger == nil {
		logger = log.Default()
	}

	if host.Credential != nil {
		return t.openWithCredential(ctx, host, hn, logger)
	}

	authKey := t.AuthKey
	if authKey == "" {
		authKey = os.Getenv(envAuthKey(host.Name))
	}
	oauthSecret := t.oauthClientSecret(host.Name)
	if authKey == "" && oauthSecret == "" {
		return nil, fmt.Errorf("tailscale tunnel %q: no auth material (set HCL `authkey`/`oauth_client_secret`, env %s/%s, or wire a `credential = ...` reference)", host.Name, envAuthKey(host.Name), envOAuthClientSecret(host.Name))
	}
	stateDir, err := tunnelStateDir(t, host)
	if err != nil {
		return nil, err
	}

	srv := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: t.ControlURL,
		Dir:        stateDir,
		Logf:       func(f string, args ...any) { logger.Printf(f, args...) },
	}
	// A static authkey wins if both are set; otherwise mint via OAuth.
	if authKey == "" {
		if err := t.applyOAuth(srv, host.Name, oauthSecret); err != nil {
			return nil, err
		}
	}
	// Up brings the node online and waits for it to register with
	// the control plane. Without this, the first Dial after Open
	// would race the join.
	if _, err := srv.Up(ctx); err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("tailscale tunnel %q: up: %w", host.Name, err)
	}
	logger.Printf("tailscale/%s: joined as %q", host.Name, hn)
	tc := newTailscaleTunnelConn(host.Name, srv, logger)
	close(tc.joined)
	return tc, nil
}

// openWithCredential brings tsnet up using the credential-supplied
// state store. The node-identity bytes (machine key, node key, login
// profile) live in credential_secrets via the StateStore returned by
// the credential plugin; the operator never pastes an authkey.
//
// Open returns synchronously with a "pending" tunnel — Dial errors
// with "node not connected" until the background Up goroutine finishes.
// In parallel, an IPN-bus watcher parks tsnet's login URL into
// tailscaleproto.Default so the dashboard's Connect button can surface
// it. On subsequent boots (state already in sqlite) tsnet joins in
// seconds and the pending window is invisible to dependent endpoints.
func (t *TailscaleTunnel) openWithCredential(_ context.Context, host runtime.TunnelHost, hostname string, logger *log.Logger) (runtime.Tunnel, error) {
	ni, ok := host.Credential.Body.(tailscaleproto.NodeIdentity)
	if !ok {
		return nil, fmt.Errorf("tailscale tunnel %q: credential %q is not a tailscale node identity (got %T)", host.Name, host.Credential.Name, host.Credential.Body)
	}
	store, err := ni.StateStore(host.Credential.Name, host.SecretStore)
	if err != nil {
		return nil, fmt.Errorf("tailscale tunnel %q: %w", host.Name, err)
	}
	if t.AuthKey != "" {
		logger.Printf("tailscale/%s: literal authkey ignored — credential %q takes precedence", host.Name, host.Credential.Name)
	}

	// tsnet still wants a Dir even when Store carries the node
	// identity — it caches derp maps, logtail buffers, etc. Leaving
	// it unset makes tsnet fall back to $XDG_CONFIG_HOME / $HOME,
	// which are absent under hardened systemd units and minimal
	// container images.
	dir, err := tunnelStateDir(t, host)
	if err != nil {
		return nil, err
	}

	srv := &tsnet.Server{
		Hostname:   hostname,
		ControlURL: t.ControlURL,
		Store:      store,
		Dir:        dir,
		Logf:       func(f string, args ...any) { logger.Printf(f, args...) },
	}
	// When the tunnel carries an OAuth client, mint join keys through it
	// rather than leaning on the persisted StateStore alone. This both
	// drives the very first join without an interactive Connect click
	// and, crucially, overrides any ambient TS_AUTHKEY in the gateway
	// environment that tsnet would otherwise pick up — a static key that
	// expires (and whose expiry silently breaks re-auth) is exactly the
	// failure OAuth minting avoids. The StateStore still persists node
	// identity, so the key only matters on first join and on re-auth.
	if oauthSecret := t.oauthClientSecret(host.Name); oauthSecret != "" {
		if err := t.applyOAuth(srv, host.Name, oauthSecret); err != nil {
			return nil, err
		}
	}

	tc := newTailscaleTunnelConn(host.Name, srv, logger)
	tc.credential = host.Credential.Name

	upCtx, cancelUp := context.WithCancel(context.Background())
	tc.cancelUp = cancelUp

	// IPN-bus watcher: surfaces tsnet's dynamic login URL into the
	// PendingNodeAuth side-channel and pushes BackendState transitions
	// into DefaultStates so the dashboard renders "Running" only when
	// tsnet has actually joined the tailnet (not just when Up() began).
	// Returns when ctx fires or the server closes.
	go tc.watchIPNBus(upCtx)
	go tc.runUp(upCtx)

	return tc, nil
}

// tailscaleTunnelConn is the runtime handle returned from Open. It
// represents both the synchronous literal-authkey path (joined is
// pre-closed, no background goroutines) and the async credential-driven
// path (joined closes when the background tsnet.Up succeeds; upErr
// carries a permanent failure).
type tailscaleTunnelConn struct {
	name       string
	credential string // bare credential name; "" for literal-authkey path
	srv        *tsnet.Server
	logger     *log.Logger

	once     sync.Once
	cancelUp context.CancelFunc // nil for literal-authkey path
	joined   chan struct{}
	upErr    atomic.Value // error
}

// newTailscaleTunnelConn allocates a tunnel handle with its joined
// channel ready. The literal-authkey path closes joined immediately;
// the credential path leaves it open until tsnet finishes Up. Inline
// allocation (`tailscaleTunnelConn{...}`) without the channel-init
// step would deadlock Dial — go through this helper instead.
func newTailscaleTunnelConn(name string, srv *tsnet.Server, logger *log.Logger) *tailscaleTunnelConn {
	return &tailscaleTunnelConn{
		name:   name,
		srv:    srv,
		logger: logger,
		joined: make(chan struct{}),
	}
}

// dialJoinWait bounds how long Dial waits for a still-joining node before
// giving up. The (re)join window is normally ~2s (state is cached in
// sqlite); this cap only matters when a join is wedged, so a dependent
// endpoint returns a clear error instead of blocking on a request whose
// own deadline never fires.
const dialJoinWait = 15 * time.Second

// Dial routes through the embedded tsnet node. If the node is still
// (re)joining, Dial waits for the join to finish rather than failing fast
// — the pending window after Open or a restart is brief, and an endpoint
// dialing through it should ride across it, not error. The wait is bounded
// by the caller's ctx and dialJoinWait; runUp always closes `joined` (on
// success and on permanent failure, where it also sets upErr), so the wait
// can't hang. A genuinely unjoined node still returns the same
// dashboard-friendly "node not connected" error.
func (t *tailscaleTunnelConn) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.srv == nil {
		return nil, errors.New("tailscale tunnel closed")
	}
	select {
	case <-t.joined:
		// joined (success or permanent failure) — fall through.
	case <-ctx.Done():
		return nil, t.notConnectedErr(ctx.Err())
	case <-time.After(dialJoinWait):
		return nil, t.notConnectedErr(fmt.Errorf("still joining after %s", dialJoinWait))
	}
	if e := t.upErr.Load(); e != nil {
		if err, ok := e.(error); ok && err != nil {
			return nil, err
		}
	}
	return t.srv.Dial(ctx, network, addr)
}

// notConnectedErr formats the pending-window error. Credential-driven
// tunnels point the operator at the dashboard sign-in (the pending
// integrations list keys off this); the literal-authkey path has no
// sign-in to complete.
func (t *tailscaleTunnelConn) notConnectedErr(cause error) error {
	if t.credential != "" {
		return fmt.Errorf("tailscale tunnel %q: node not connected — visit dashboard to complete %q sign-in (%w)", t.name, t.credential, cause)
	}
	return fmt.Errorf("tailscale tunnel %q: still joining (%w)", t.name, cause)
}

// CredentialName implements runtime.TunnelCredentialNamer so the
// TunnelManager can route a credential-targeted disconnect to this
// live runtime. Empty for the literal-authkey path — there's no
// credential identity to sign out.
func (t *tailscaleTunnelConn) CredentialName() string { return t.credential }

// Disconnect implements runtime.TunnelDisconnector: signs the tsnet
// node out of the control plane before the manager evicts the entry.
//
// Without this, the dashboard's Disconnect button only wipes the
// secret store; the in-process tsnet keeps its (mkey, nkey) pair
// resident and registered. tsnet's reconnect / key-rotation loop then
// re-enters initMachineKeyLocked, finds the cleared store, mints a
// fresh machine key, and tries to register the still-cached node key
// under it — control answers 403 "bad machine key" in a tight backoff
// loop. Logging out first deregisters the node upstream so the next
// boot's fresh keys join a clean slate.
func (t *tailscaleTunnelConn) Disconnect(ctx context.Context) error {
	srv := t.srv
	if srv == nil {
		return nil
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("tailscale tunnel %q: local client: %w", t.name, err)
	}
	return lc.Logout(ctx)
}

func (t *tailscaleTunnelConn) Close() error {
	var err error
	t.once.Do(func() {
		if t.cancelUp != nil {
			t.cancelUp()
		}
		if t.credential != "" {
			tailscaleproto.Default.Set(t.credential, "")
			tailscaleproto.DefaultStates.Set(t.credential, tailscaleproto.NodeStateUnknown)
		}
		if t.srv != nil {
			err = t.srv.Close()
			t.srv = nil
		}
	})
	return err
}

// runUp drives tsnet.Server.Up to completion. On success, closes
// joined so pending Dials unblock; on failure, stashes the error in
// upErr (which Dial surfaces on subsequent calls) and closes joined
// to release waiters with a permanent error.
func (t *tailscaleTunnelConn) runUp(ctx context.Context) {
	if _, err := t.srv.Up(ctx); err != nil {
		if ctx.Err() == nil {
			t.logger.Printf("tailscale/%s: up failed: %v", t.name, err)
		}
		t.upErr.Store(fmt.Errorf("tailscale tunnel %q: up: %w", t.name, err))
		close(t.joined)
		return
	}
	if t.credential != "" {
		tailscaleproto.Default.Set(t.credential, "")
		t.logger.Printf("tailscale/%s: joined as %q (credential=%q)", t.name, t.srv.Hostname, t.credential)
	} else {
		t.logger.Printf("tailscale/%s: joined as %q", t.name, t.srv.Hostname)
	}
	close(t.joined)
}

// watchIPNBus drains the IPN bus for BrowseToURL notifications and
// State transitions. URLs go into the package-level PendingNodeAuth
// registry (so the dashboard's Connect button can redirect the
// operator); state labels go into DefaultStates (so the credential
// card renders "Connected" only when tsnet has actually reached the
// Running state, not just when Up() began). Multiple watchers on the
// same bus are fine — Up() runs its own watcher in parallel for the
// Running-state transition.
func (t *tailscaleTunnelConn) watchIPNBus(ctx context.Context) {
	if t.credential == "" {
		return
	}
	lc, err := t.srv.LocalClient()
	if err != nil {
		if ctx.Err() == nil {
			t.logger.Printf("tailscale/%s: local client for credential %q: %v", t.name, t.credential, err)
		}
		return
	}
	watcher, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialState)
	if err != nil {
		if ctx.Err() == nil {
			t.logger.Printf("tailscale/%s: watch ipn bus: %v", t.name, err)
		}
		return
	}
	defer func() { _ = watcher.Close() }()
	for {
		n, err := watcher.Next()
		if err != nil {
			return
		}
		if n.BrowseToURL != nil {
			tailscaleproto.Default.Set(t.credential, *n.BrowseToURL)
			t.logger.Printf("tailscale/%s: login URL pending — visit dashboard to Connect credential %q", t.name, t.credential)
		}
		if n.State != nil {
			label := tailscaleproto.LabelFromIPNState(*n.State)
			tailscaleproto.DefaultStates.Set(t.credential, label)
			// Once the node is Running, no auth URL is in flight —
			// drop any stale parked URL so the dashboard doesn't
			// keep offering a click-through that's already complete.
			if *n.State == ipn.Running {
				tailscaleproto.Default.Set(t.credential, "")
			}
		}
	}
}

// envAuthKey returns the env-var name for this tunnel's auth key
// fallback. CLAWPATROL_TUNNEL_<UPPER_NAME>_AUTHKEY, with hyphens
// folded to underscores.
func envAuthKey(name string) string {
	return "CLAWPATROL_TUNNEL_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_AUTHKEY"
}

// envOAuthClientSecret returns the env-var name for this tunnel's OAuth
// client-secret fallback, mirroring envAuthKey:
// CLAWPATROL_TUNNEL_<UPPER_NAME>_OAUTH_CLIENT_SECRET.
func envOAuthClientSecret(name string) string {
	return "CLAWPATROL_TUNNEL_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_OAUTH_CLIENT_SECRET"
}

// oauthClientSecret resolves the tunnel's OAuth client secret from the
// HCL field, falling back to the per-tunnel env var. Returns "" when
// neither is set.
func (t *TailscaleTunnel) oauthClientSecret(name string) string {
	if t.OAuthClientSecret != "" {
		return t.OAuthClientSecret
	}
	return os.Getenv(envOAuthClientSecret(name))
}

// oauthSecretWithDefaults appends the device-key attributes a gateway
// tunnel needs onto a bare OAuth client secret. tsnet's oauthkey
// resolver defaults to ephemeral=true, preauthorized=false — both wrong
// here: the credential's StateStore persists node identity across
// restarts (so the node must not be ephemeral), and there is no
// operator approval step in the gateway path (so it must be
// preauthorized). A secret that already carries a `?` query string is
// left untouched, letting an operator override either default.
func oauthSecretWithDefaults(secret string) string {
	if secret == "" || strings.Contains(secret, "?") {
		return secret
	}
	return secret + "?ephemeral=false&preauthorized=true"
}

// applyOAuth points srv's auth material at the OAuth client secret so
// tsnet's resolveAuthKey hands it to the oauthkey hook and mints a
// fresh device key per join. The secret goes in AuthKey (not
// ClientSecret) deliberately: AuthKey takes precedence over an ambient
// TS_AUTHKEY in the gateway environment, so a stray static key in the
// process env can't shadow the OAuth flow. The oauthkey resolver
// requires non-empty tags, so reject an untagged config up front with a
// clear error rather than failing deep inside tsnet.Up.
func (t *TailscaleTunnel) applyOAuth(srv *tsnet.Server, name, secret string) error {
	if len(t.Tags) == 0 {
		return fmt.Errorf("tailscale tunnel %q: oauth_client_secret requires `tags` (untagged OAuth keys are rejected by Tailscale)", name)
	}
	srv.AuthKey = oauthSecretWithDefaults(secret)
	srv.AdvertiseTags = t.Tags
	return nil
}

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindTunnel,
		Type:    "tailscale",
		New:     newer[TailscaleTunnel](),
		Refs:    commonRefs,
		Build:   passthrough,
		Runtime: (*TailscaleTunnel)(nil),
		Emit: func(body any, _ string, b *hclwrite.Body) {
			t := body.(*TailscaleTunnel)
			if t.AuthKey != "" {
				b.SetAttributeValue("authkey", cty.StringVal(t.AuthKey))
			}
			if t.OAuthClientSecret != "" {
				b.SetAttributeValue("oauth_client_secret", cty.StringVal(t.OAuthClientSecret))
			}
			if t.ControlURL != "" {
				b.SetAttributeValue("control_url", cty.StringVal(t.ControlURL))
			}
			if t.Hostname != "" {
				b.SetAttributeValue("hostname", cty.StringVal(t.Hostname))
			}
			if t.StateDir != "" {
				b.SetAttributeValue("state_dir", cty.StringVal(t.StateDir))
			}
			if len(t.Tags) > 0 {
				b.SetAttributeValue("tags", config.StringListVal(t.Tags))
			}
			emitCommon(b, t.TunnelCommon())
		},
	})
}
