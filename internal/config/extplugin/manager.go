package extplugin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/sandbox"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl/v2"
	"google.golang.org/grpc"
)

// Manager spawns and supervises one subprocess per declared plugin
// source. Manifests fetched at Start() time get registered as virtual
// *config.Plugin entries by the (config-side) registration code.
//
// Lifecycle: Start each plugin once before the loader's policy decode
// pass runs (so the registry has the plugin's types). Call Stop on
// gateway shutdown.
type Manager struct {
	mu      sync.Mutex
	plugins map[string]*Client // keyed by plugin name from Manifest
	logger  hclog.Logger
}

// New constructs an empty Manager. The logger is wrapped so plugin
// stdio surfaces in the gateway's log stream tagged with the plugin
// name; pass nil to use a default discarding logger.
func New(out *log.Logger) *Manager {
	level := hclog.Info
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "plugin",
		Output: hclogWriter{out},
		Level:  level,
	})
	return &Manager{
		plugins: make(map[string]*Client),
		logger:  logger,
	}
}

// Start spawns the plugin binary declared by sp inside the sandbox
// its grants call for, performs the gRPC handshake, fetches the
// Manifest, and returns a *Client whose Manifest method exposes the
// declared types. The caller (the register helper in this package)
// typically immediately registers every type with the global config
// registry.
//
// Start blocks until the subprocess is ready or fails. Returns the
// client + manifest, or an error suitable for surfacing as an HCL
// diagnostic on the `plugin` block.
func (m *Manager) Start(ctx context.Context, sp config.PluginSource) (*Client, *pb.ManifestResponse, error) {
	source := sp.Source
	spec, mode, warning, err := buildSandboxSpec(sp)
	if err != nil {
		return nil, nil, err
	}
	cmd, err := sandbox.Command(spec, mode)
	if err != nil {
		_ = os.RemoveAll(spec.SocketDir)
		return nil, nil, fmt.Errorf("plugin %q: %w", source, err)
	}
	if warning != "" {
		m.logger.Warn("plugin sandbox degraded", "plugin", sp.Name, "warning", warning)
	}
	cli := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			PluginName: &grpcClient{},
		},
		Cmd: cmd,
		// The plugin's environment is exactly what sandbox.Command
		// set (plus go-plugin's handshake vars): the gateway's own
		// environment — CLAWPATROL_SECRET_*, cloud credentials —
		// must never reach plugin code.
		SkipHostEnv:      true,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           m.logger,
	})
	kill := func() {
		cli.Kill()
		_ = os.RemoveAll(spec.SocketDir)
	}
	rpcCli, err := cli.Client()
	if err != nil {
		kill()
		return nil, nil, fmt.Errorf("plugin %q: handshake: %w", source, err)
	}
	raw, err := rpcCli.Dispense(PluginName)
	if err != nil {
		kill()
		return nil, nil, fmt.Errorf("plugin %q: dispense: %w", source, err)
	}
	conn, ok := raw.(*grpc.ClientConn)
	if !ok {
		kill()
		return nil, nil, fmt.Errorf("plugin %q: unexpected client type %T", source, raw)
	}
	c := &Client{
		source:         source,
		sandboxMode:    mode,
		sandboxWarning: warning,
		socketDir:      spec.SocketDir,
		gp:             cli,
		conn:           conn,
		pluginCli:      pb.NewPluginClient(conn),
		credential:     pb.NewCredentialClient(conn),
		endpoint:       pb.NewEndpointClient(conn),
		tunnel:         pb.NewTunnelClient(conn),
	}
	manifest, err := c.pluginCli.Manifest(ctx, &pb.ManifestRequest{})
	if err != nil {
		kill()
		return nil, nil, fmt.Errorf("plugin %q: manifest: %w", source, err)
	}
	if manifest.Name == "" {
		kill()
		return nil, nil, fmt.Errorf("plugin %q: empty manifest name", source)
	}
	c.name = manifest.Name
	c.manifest = manifest

	m.mu.Lock()
	if _, dup := m.plugins[manifest.Name]; dup {
		m.mu.Unlock()
		kill()
		return nil, nil, fmt.Errorf("plugin %q (%q) already registered", manifest.Name, source)
	}
	m.plugins[manifest.Name] = c
	m.mu.Unlock()

	return c, manifest, nil
}

// LoadPlugins satisfies config.PluginLoader. Called from inside
// config.Load after the operational decode and before pass-1
// symbol building. For each plugin source: spawn the
// subprocess, fetch the manifest, register virtual *config.Plugin
// entries.
//
// Already-loaded plugins (matched by manifest name) are skipped so
// reload-style flows don't re-spawn or trip the "duplicate plugin"
// panic in config.Register.
func (m *Manager) LoadPlugins(specs []config.PluginSource) hcl.Diagnostics {
	var diags hcl.Diagnostics
	ctx := context.Background()
	for _, sp := range specs {
		if sp.Source == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Plugin %q: source is required", sp.Name),
			})
			continue
		}
		m.mu.Lock()
		_, dup := m.plugins[sp.Name]
		m.mu.Unlock()
		if dup {
			continue // already loaded — caller is reloading
		}
		client, manifest, err := m.Start(ctx, sp)
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Plugin %q failed to start", sp.Name),
				Detail:   err.Error(),
			})
			continue
		}
		if w := client.SandboxWarning(); w != "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagWarning,
				Summary:  fmt.Sprintf("Plugin %q: running under a reduced sandbox", sp.Name),
				Detail:   w,
			})
		}
		if manifest.Name != sp.Name {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagWarning,
				Summary:  fmt.Sprintf("Plugin name mismatch: HCL block %q, manifest %q", sp.Name, manifest.Name),
				Detail:   "Type names will be namespaced under the manifest name.",
			})
		}
		regDiags := RegisterManifest(client, manifest)
		diags = append(diags, regDiags...)
	}
	return diags
}

// Verify runs post-load schema validation against every spawned
// plugin's manifest. Catches problems that wouldn't surface
// otherwise until a rule happened to target a particular facet or
// an HCL block happened to use a particular type:
//
//   - Each declared facet's CEL env is built eagerly (with a probe
//     condition) so an invalid identifier in a facet or field name
//     fails the validate command instead of waiting for a rule.
//   - Each declared endpoint's Family is resolved against the
//     facet registry (built-in or another plugin's). A typo in
//     Family that no rule references would otherwise just silently
//     route every request to default-deny at runtime.
//
// Returns hcl.Diagnostics with one entry per problem.
func (m *Manager) Verify() hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, c := range m.Plugins() {
		mf := c.Manifest()
		if mf == nil {
			continue
		}
		for _, f := range mf.Facets {
			if _, err := newPluginFacetMatcher(f.Name, "true", facetStreamFieldNames(f)); err != nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Plugin %q facet %q: invalid schema", mf.Name, f.Name),
					Detail:   err.Error(),
				})
			}
		}
		for _, e := range mf.Endpoints {
			if e.Family == "" {
				continue // already reported by validateManifestShape
			}
			if facet.Lookup(e.Family) == nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("Plugin %q endpoint %q: family %q does not resolve", mf.Name, e.TypeName, e.Family),
					Detail:   "Family must name a built-in facet (\"http\", \"sql\", \"k8s\") or one of this plugin's declared facets. Rules attached to this endpoint cannot compile against an unknown family.",
				})
			}
		}
	}
	return diags
}

// facetStreamFieldNames extracts FACET_STREAM field names from a
// FacetDecl — pulled out as a helper so Verify can build the same
// CEL env newPluginFacetMatcher does at NewMatcher time.
func facetStreamFieldNames(decl *pb.FacetDecl) []string {
	var out []string
	for _, f := range decl.Fields {
		if f.Kind == pb.FacetKind_FACET_STREAM {
			out = append(out, f.Name)
		}
	}
	return out
}

// Plugins returns every loaded plugin's *Client, sorted by name.
// Used by callers (clawpatrol validate, dashboard surfaces, etc.)
// that want to enumerate manifests after LoadPlugins has run.
func (m *Manager) Plugins() []*Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Client, 0, len(m.plugins))
	for _, c := range m.plugins {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// Stop tears down every spawned subprocess. Idempotent.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.plugins {
		c.gp.Kill()
		if c.socketDir != "" {
			_ = os.RemoveAll(c.socketDir)
		}
	}
	m.plugins = make(map[string]*Client)
}

// Client is the gateway-side handle to one running plugin subprocess.
// Adapters use it to issue RPCs.
type Client struct {
	name           string
	source         string
	sandboxMode    sandbox.Mode
	sandboxWarning string
	socketDir      string
	manifest       *pb.ManifestResponse
	gp             *plugin.Client
	conn           *grpc.ClientConn
	pluginCli      pb.PluginClient
	credential     pb.CredentialClient
	endpoint       pb.EndpointClient
	tunnel         pb.TunnelClient
}

// SandboxMode reports which sandbox backend the subprocess runs
// under ("off" when the operator opted out).
func (c *Client) SandboxMode() string { return string(c.sandboxMode) }

// SandboxWarning is non-empty when the plugin runs under a degraded
// fallback backend; it describes what the fallback does not cover.
func (c *Client) SandboxWarning() string { return c.sandboxWarning }

// Name returns the plugin's manifest name (lower-case identifier).
func (c *Client) Name() string { return c.name }

// Source returns the binary path the manager was started with.
func (c *Client) Source() string { return c.source }

// Manifest returns the manifest the subprocess reported at startup.
// Stable across the plugin's lifetime (manifests aren't refreshed
// in v1).
func (c *Client) Manifest() *pb.ManifestResponse { return c.manifest }

// PluginRPC exposes the Build RPC; used by the registration helper.
func (c *Client) PluginRPC() pb.PluginClient { return c.pluginCli }

// CredentialRPC exposes InjectHTTP for credential adapters.
func (c *Client) CredentialRPC() pb.CredentialClient { return c.credential }

// EndpointRPC exposes HandleConn for endpoint adapters.
func (c *Client) EndpointRPC() pb.EndpointClient { return c.endpoint }

// TunnelRPC exposes OpenTunnel / Dial / CloseTunnel for tunnel
// adapters.
func (c *Client) TunnelRPC() pb.TunnelClient { return c.tunnel }

// =====================================================================
// plugin.Plugin implementation (client side)
// =====================================================================

// grpcClient satisfies plugin.GRPCPlugin on the gateway side. We don't
// need the broker indirection — Dispense returns the raw
// *grpc.ClientConn and we instantiate stubs ourselves on Client.
type grpcClient struct {
	plugin.NetRPCUnsupportedPlugin
}

func (g *grpcClient) GRPCServer(_ *plugin.GRPCBroker, _ *grpc.Server) error {
	return errors.New("extplugin: gateway does not implement the gRPC server side")
}

func (g *grpcClient) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return conn, nil
}

// =====================================================================
// log glue
// =====================================================================

type hclogWriter struct{ inner *log.Logger }

func (h hclogWriter) Write(p []byte) (int, error) {
	if h.inner != nil {
		h.inner.Print(string(p))
	}
	return len(p), nil
}
