package tunnels

// tailscale tunnel: dials upstream via an embedded tsnet.Server.
// Useful for endpoints that live in a tailnet and aren't reachable
// from the host's namespace — Avocet's ClickHouse o11y target is the
// canonical case.
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

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/plugins/tailscaleproto"
	"github.com/denoland/clawpatrol/config/runtime"
)

// TailscaleTunnel configures the tunnel runtime.
type TailscaleTunnel struct {
	// AuthKey is the Tailscale auth key; env fallback is CLAWPATROL_TUNNEL_<NAME>_AUTHKEY.
	AuthKey string `hcl:"authkey,optional"`
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
	if authKey == "" {
		return nil, fmt.Errorf("tailscale tunnel %q: no authkey (set HCL `authkey = ...`, env %s, or wire a `credential = ...` reference)", host.Name, envAuthKey(host.Name))
	}
	stateDir := t.StateDir
	if stateDir == "" && host.StateDir != "" {
		stateDir = filepath.Join(host.StateDir, "tunnels", "tailscale", host.Name)
	}
	if stateDir == "" {
		return nil, errors.New("tailscale tunnel: state_dir is required (HCL `state_dir = ...` on the tunnel or the gateway)")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("tailscale tunnel %q: state dir: %w", host.Name, err)
	}

	srv := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: t.ControlURL,
		Dir:        stateDir,
		Logf:       func(f string, args ...any) { logger.Printf(f, args...) },
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

	srv := &tsnet.Server{
		Hostname:   hostname,
		ControlURL: t.ControlURL,
		Store:      store,
		Logf:       func(f string, args ...any) { logger.Printf(f, args...) },
	}

	tc := newTailscaleTunnelConn(host.Name, srv, logger)
	tc.credential = host.Credential.Name

	upCtx, cancelUp := context.WithCancel(context.Background())
	tc.cancelUp = cancelUp

	// IPN-bus watcher: surfaces tsnet's dynamic login URL into the
	// PendingNodeAuth side-channel so the dashboard's Connect button
	// can redirect the operator. Returns when ctx fires or the server
	// closes.
	go tc.watchLoginURL(upCtx)
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

// Dial routes through the embedded tsnet node. For credential-driven
// tunnels in the pending-auth window, returns a clear "node not
// connected" error so the dashboard's pending integrations list reads
// correctly; the literal-authkey path is always already joined.
func (t *tailscaleTunnelConn) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.srv == nil {
		return nil, errors.New("tailscale tunnel closed")
	}
	select {
	case <-t.joined:
		if e := t.upErr.Load(); e != nil {
			if err, ok := e.(error); ok && err != nil {
				return nil, err
			}
		}
		return t.srv.Dial(ctx, network, addr)
	default:
		if t.credential != "" {
			return nil, fmt.Errorf("tailscale tunnel %q: node not connected — visit dashboard to complete %q sign-in", t.name, t.credential)
		}
		return nil, fmt.Errorf("tailscale tunnel %q: still joining", t.name)
	}
}

func (t *tailscaleTunnelConn) Close() error {
	var err error
	t.once.Do(func() {
		if t.cancelUp != nil {
			t.cancelUp()
		}
		if t.credential != "" {
			tailscaleproto.Default.Set(t.credential, "")
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

// watchLoginURL drains the IPN bus for BrowseToURL notifications and
// parks them in the package-level PendingNodeAuth registry so the
// dashboard's Connect button can redirect the operator. Multiple
// watchers on the same bus are fine — Up() runs its own watcher in
// parallel for the Running-state transition.
func (t *tailscaleTunnelConn) watchLoginURL(ctx context.Context) {
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
	}
}

// envAuthKey returns the env-var name for this tunnel's auth key
// fallback. CLAWPATROL_TUNNEL_<UPPER_NAME>_AUTHKEY, with hyphens
// folded to underscores.
func envAuthKey(name string) string {
	return "CLAWPATROL_TUNNEL_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_AUTHKEY"
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
