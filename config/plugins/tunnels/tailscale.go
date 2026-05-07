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

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"tailscale.com/tsnet"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type TailscaleTunnel struct {
	AuthKey    string   `hcl:"authkey,optional"`
	ControlURL string   `hcl:"control_url,optional"`
	Hostname   string   `hcl:"hostname,optional"`
	StateDir   string   `hcl:"state_dir,optional"`
	Tags       []string `hcl:"tags,optional"`

	// Framework-level common attrs.
	Share      string `hcl:"share,optional"`
	Keepalive  string `hcl:"keepalive,optional"`
	Via        string `hcl:"via,optional"`
	Credential string `hcl:"credential,optional"`
}

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

// Open brings up an embedded tsnet node, waits for it to register
// with the control plane, and returns a Tunnel whose Dial routes
// through it. Auth-key sourcing: HCL `authkey = "..."` literal
// wins; falls back to the env var named by envAuthKey.
func (t *TailscaleTunnel) Open(ctx context.Context, host runtime.TunnelHost, _ runtime.Tunnel) (runtime.Tunnel, error) {
	authKey := t.AuthKey
	if authKey == "" {
		authKey = os.Getenv(envAuthKey(host.Name))
	}
	if authKey == "" {
		return nil, fmt.Errorf("tailscale tunnel %q: no authkey (set HCL `authkey = ...` or env %s)", host.Name, envAuthKey(host.Name))
	}
	hn := t.Hostname
	if hn == "" {
		hn = "clawpatrol-tunnel-" + host.Name
	}
	stateDir := t.StateDir
	if stateDir == "" && host.CADir != "" {
		stateDir = filepath.Join(host.CADir, "tunnels", "tailscale", host.Name)
	}
	if stateDir == "" {
		return nil, errors.New("tailscale tunnel: state_dir is required (HCL `state_dir = ...` or set the gateway's ca_dir so a default can be derived)")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("tailscale tunnel %q: state dir: %w", host.Name, err)
	}
	logger := host.Logger
	if logger == nil {
		logger = log.Default()
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
	return &tailscaleTunnelConn{name: host.Name, srv: srv, logger: logger}, nil
}

type tailscaleTunnelConn struct {
	name   string
	srv    *tsnet.Server
	logger *log.Logger
	once   sync.Once
}

func (t *tailscaleTunnelConn) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.srv == nil {
		return nil, errors.New("tailscale tunnel closed")
	}
	return t.srv.Dial(ctx, network, addr)
}

func (t *tailscaleTunnelConn) Close() error {
	var err error
	t.once.Do(func() {
		if t.srv != nil {
			err = t.srv.Close()
			t.srv = nil
		}
	})
	return err
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
