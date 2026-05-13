package runtime

import (
	"context"
	"errors"
	"log"
	"net"
)

// TunnelRuntime is the request-time contract a tunnel plugin's body
// implements. The TunnelManager (host-side, in the main package)
// owns the lifecycle: refcounting, idle teardown, the `via` chain.
// The plugin owns one job — bringing up an underlying transport in
// Open and exposing Dial / Close on the returned Tunnel handle.
//
// Plugins that need to fan out one HCL declaration into multiple
// runtime instances (per_endpoint or per_conn sharing) don't have
// to do anything special: the manager calls Open once per distinct
// (tunnel-name, sharing-key) tuple and refcounts each instance
// independently.
type TunnelRuntime interface {
	// Sharing reports the plugin's preferred sharing model when the
	// operator hasn't set `share = ...` on the block. The manager
	// honours the HCL override when present.
	Sharing() TunnelSharing

	// Open builds a fresh Tunnel instance. The manager calls this
	// exactly once per (tunnel, sharing-key) regardless of refcount
	// — refcounting is the manager's job, not the plugin's.
	//
	// For chained tunnels, `via` is the underlying Tunnel handle
	// (already Acquire'd by the manager and ref-attached to the
	// child); the plugin uses `via.Dial(...)` instead of
	// `net.Dial(...)` to bring up its transport. nil when the
	// HCL has no `via = ...`.
	Open(ctx context.Context, host TunnelHost, via Tunnel) (Tunnel, error)
}

// TunnelSharing controls how the manager keys runtime instances of
// a tunnel against repeat Acquire calls. Aliased to string so the
// compile pass (in config/) can type-assert `Sharing() string` on a
// plugin's runtime without taking a dependency on this package and
// inviting an import cycle.
type TunnelSharing = string

const (
	// TunnelShareSingleton creates one runtime instance per tunnel name.
	// All endpoints, all connections, share the same Tunnel. Idle
	// teardown is shared too. Right default for tailscale (one node
	// in the tailnet) and singleton local listeners (cloud_sql_proxy).
	TunnelShareSingleton TunnelSharing = "singleton"

	// TunnelSharePerEndpoint creates one runtime instance per (tunnel,
	// endpoint) pair. Right default for kubernetes_port_forward,
	// where each endpoint allocates its own ephemeral local port
	// and two endpoints can't share the same forwarder.
	TunnelSharePerEndpoint TunnelSharing = "per_endpoint"

	// TunnelSharePerConn creates a fresh instance per inbound connection,
	// torn down on conn close. Niche but useful for stateless
	// "tunnels" whose lifetime should track a single request.
	TunnelSharePerConn TunnelSharing = "per_conn"
)

// Tunnel is the live runtime handle the manager hands to the
// dispatcher. The dispatcher calls Dial to open an upstream
// connection for one inbound conn; Close runs when the manager
// decides this instance has been idle long enough.
type Tunnel interface {
	// Dial opens an upstream connection through the tunnel. addr
	// is what the endpoint asks for ("host:port", typically the
	// hostname recovered from the VIP table). Tunnels that own
	// the upstream addressing (cloud_sql_proxy's local listener,
	// kubectl port-forward's ephemeral port) ignore addr and dial
	// their own configured target.
	Dial(ctx context.Context, network, addr string) (net.Conn, error)

	// Close tears down the underlying transport. The manager calls
	// it exactly once when refcount reaches 0 and the configured
	// keepalive window has elapsed.
	Close() error
}

// TunnelHost bundles host-side dependencies a tunnel plugin's Open
// callback may need. Kept narrow so plugin packages don't have to
// import the gateway main package.
//
// Open is invoked as a method on the plugin's decoded body (the same
// struct the loader populated from HCL), so the plugin reads its own
// configuration directly off `t` — TunnelHost only carries the host-
// side bits (logger, secret store, etc.) that aren't expressible in
// HCL.
type TunnelHost struct {
	// Name is the tunnel's HCL name, useful for log line prefixes.
	Name string

	// SecretStore lets a tunnel plugin fetch its credential's
	// secret bytes by name (the credential ref resolves at compile
	// time; the actual material lives in the host's secret store).
	SecretStore SecretStore

	// Credential is the resolved credential entity for this tunnel,
	// or nil if the HCL didn't specify one. The plugin reads
	// Credential.Name to feed SecretStore.Get and type-asserts
	// Credential.Body to its expected runtime interface (e.g. ssh
	// credentials expose a known shape).
	Credential *TunnelCredential

	// StateDir is the gateway's persistent state root (cfg.StateDir).
	// Tunnel plugins that need to persist material between policy
	// reloads — e.g. tailscale tsnet's state directory — derive
	// paths from this. Always non-empty (the host resolves a default
	// when no explicit StateDir is configured).
	StateDir string

	// Logger is a per-tunnel logger pre-tagged with the tunnel name.
	// Plugins should prefer it over package-level log.Printf so the
	// dashboard's log surface attributes lines correctly.
	Logger *log.Logger
}

// TunnelCredential is the slice of a credential entity a tunnel
// plugin needs to drive secret lookup and runtime behaviour. The
// host populates it from the credential symbol resolved at compile
// time, so plugins don't have to reach back into the registry.
//
// Body is the credential plugin's decoded HCL struct (same value
// stored on Entity.Body). Plugins type-assert it to their expected
// shape — e.g. ssh_port_forward asserts to the ssh credential's
// runtime interface to read username + private-key handling.
type TunnelCredential struct {
	Name string
	Type string
	Body any
}

// ErrTunnelUnsupported is returned by a tunnel plugin's Open when
// the binary lacks the build tag (or the host lacks the platform
// support) needed to bring the tunnel up. The manager translates
// this into a clear "rebuild with -tags X" log entry and fails the
// inbound conn with a 503-equivalent rather than panicking the
// plugin's init() at policy load.
var ErrTunnelUnsupported = errors.New("tunnel plugin not available in this build")
