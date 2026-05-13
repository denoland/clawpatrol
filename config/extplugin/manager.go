package extplugin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/denoland/clawpatrol/config"
	pb "github.com/denoland/clawpatrol/config/extplugin/proto"
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

// Start spawns the plugin binary at source, performs the
// gRPC handshake, fetches the Manifest, and returns a *Client whose
// Manifest method exposes the declared types. The caller (the
// register helper in this package) typically immediately registers
// every type with the global config registry.
//
// Start blocks until the subprocess is ready or fails. Returns the
// client + manifest, or an error suitable for surfacing as an HCL
// diagnostic on the `plugin` block.
func (m *Manager) Start(ctx context.Context, source string) (*Client, *pb.ManifestResponse, error) {
	if _, err := os.Stat(source); err != nil {
		return nil, nil, fmt.Errorf("plugin source %q: %w", source, err)
	}
	cli := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			PluginName: &grpcClient{},
		},
		Cmd:              exec.Command(source),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           m.logger,
	})
	rpcCli, err := cli.Client()
	if err != nil {
		cli.Kill()
		return nil, nil, fmt.Errorf("plugin %q: handshake: %w", source, err)
	}
	raw, err := rpcCli.Dispense(PluginName)
	if err != nil {
		cli.Kill()
		return nil, nil, fmt.Errorf("plugin %q: dispense: %w", source, err)
	}
	conn, ok := raw.(*grpc.ClientConn)
	if !ok {
		cli.Kill()
		return nil, nil, fmt.Errorf("plugin %q: unexpected client type %T", source, raw)
	}
	c := &Client{
		source:    source,
		gp:        cli,
		conn:      conn,
		pluginCli: pb.NewPluginClient(conn),
		endpoint:  pb.NewEndpointClient(conn),
		tunnel:    pb.NewTunnelClient(conn),
	}
	manifest, err := c.pluginCli.Manifest(ctx, &pb.ManifestRequest{})
	if err != nil {
		cli.Kill()
		return nil, nil, fmt.Errorf("plugin %q: manifest: %w", source, err)
	}
	if manifest.Name == "" {
		cli.Kill()
		return nil, nil, fmt.Errorf("plugin %q: empty manifest name", source)
	}
	c.name = manifest.Name

	m.mu.Lock()
	if _, dup := m.plugins[manifest.Name]; dup {
		m.mu.Unlock()
		cli.Kill()
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
		client, manifest, err := m.Start(ctx, sp.Source)
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Plugin %q failed to start", sp.Name),
				Detail:   err.Error(),
			})
			continue
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

// Stop tears down every spawned subprocess. Idempotent.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.plugins {
		c.gp.Kill()
	}
	m.plugins = make(map[string]*Client)
}

// Client is the gateway-side handle to one running plugin subprocess.
// Adapters use it to issue RPCs.
type Client struct {
	name      string
	source    string
	gp        *plugin.Client
	conn      *grpc.ClientConn
	pluginCli pb.PluginClient
	endpoint  pb.EndpointClient
	tunnel    pb.TunnelClient
}

// Name returns the plugin's manifest name (lower-case identifier).
func (c *Client) Name() string { return c.name }

// Source returns the binary path the manager was started with.
func (c *Client) Source() string { return c.source }

// PluginRPC exposes the Build RPC; used by the registration helper.
func (c *Client) PluginRPC() pb.PluginClient { return c.pluginCli }

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
