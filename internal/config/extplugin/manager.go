package extplugin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/runtime"
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
	// blocked records plugins that failed to load on the last pass —
	// most importantly the ones held back by a permission escalation,
	// which never enter `plugins`. Rebuilt every LoadPlugins pass so
	// the dashboard reflects the current state. Keyed by HCL name.
	blocked  map[string]blockedRecord
	logger   hclog.Logger
	lock     *lockStore
	stateDir string // gateway secret-store dir; read_paths may not overlap it

	// blobs backs the per-plugin HostState service (the v2 state service):
	// a plugin calls into the gateway over the go-plugin broker to persist
	// opaque bytes across restarts. nil disables state (plugins that try to
	// use it get an error); the gateway wires its BlobStore here.
	blobs runtime.BlobStore

	// transportDial is the gateway's direct upstream dialer, used to serve a
	// tunnel plugin's HostTunnel.DialUpstream when the tunnel has no parent
	// (no `via`). The gateway wires its own dialer here; nil means a tunnel
	// plugin with no via can't open its transport (the CLI install/probe
	// paths leave it nil — they never run a tunnel).
	transportDial func(network, addr string) (net.Conn, error)

	// ghBase overrides the GitHub API base URL (tests point it at an
	// httptest server); empty means api.github.com. prov gates a
	// downloaded archive on its build-provenance attestation; nil skips
	// the check.
	ghBase string
	prov   provenanceVerifier

	// updates records the newest release tag satisfying a plugin's
	// constraint that is newer than the locked version, keyed by the
	// plugin's raw `source` string (which is what PluginInfo.Source
	// carries, so the dashboard can join them). Two plugin blocks sharing
	// one source collide on the key — an unusual config. Populated by the
	// background CheckUpdates pass; never triggers a download.
	updates map[string]string
}

type blockedRecord struct {
	source string
	reason string
	// requested is the privileges the plugin's resolvable version
	// declares, read (best-effort) from its signed static manifest — so
	// the dashboard can show what a blocked/unapproved plugin wants
	// before it is approved. nil when no static manifest is available.
	requested *ManifestPreview
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
		blocked: make(map[string]blockedRecord),
		logger:  logger,
		lock:    newLockStore(),
		updates: make(map[string]string),
	}
}

// SetLockfile points the manager at the permission lockfile beside the
// gateway config. Without it (tests, config.LoadBytes) plugins fall
// back to their manifest-declared capabilities with no persistence or
// escalation check. readOnly (used by `clawpatrol validate`) resolves
// and reports escalations but never writes the lockfile.
func (m *Manager) SetLockfile(path string, readOnly bool) {
	m.lock.configure(path, readOnly)
}

// setStateDir / stateDirLocked guard m.stateDir behind m.mu. LoadPlugins
// (startup + reload) writes it; the spawn path (Start, probeNetwork,
// Approve) reads it via buildSandboxSpec. Callers are already serialized
// by the gateway's configMu, but guarding here keeps the field
// memory-safe on its own terms.
func (m *Manager) setStateDir(d string) {
	m.mu.Lock()
	m.stateDir = d
	m.mu.Unlock()
}

// SetStateDir sets the gateway state dir — where GitHub-sourced plugins
// are cached, and the dir read_paths may not overlap. The gateway sets
// it via LoadPlugins; the `plugins install|update|lock` commands set it
// from the resolved config so the cache lands in the same place.
func (m *Manager) SetStateDir(d string) { m.setStateDir(d) }

// SetBlobStore wires the persistent byte store that backs the per-plugin
// HostState service. Without it, a plugin that calls State gets an error
// (the gateway main provides one; the CLI install/probe paths leave it
// nil — they never run a plugin long enough to need state).
func (m *Manager) SetBlobStore(b runtime.BlobStore) {
	m.mu.Lock()
	m.blobs = b
	m.mu.Unlock()
}

func (m *Manager) blobStore() runtime.BlobStore {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blobs
}

// SetTransportDialer wires the gateway's direct upstream dialer, used to
// serve a tunnel plugin's HostTunnel.DialUpstream when the tunnel has no
// `via` parent. The gateway main provides its own dialer; CLI
// install/probe paths leave it nil (they never run a tunnel).
func (m *Manager) SetTransportDialer(d func(network, addr string) (net.Conn, error)) {
	m.mu.Lock()
	m.transportDial = d
	m.mu.Unlock()
}

func (m *Manager) transportDialer() func(network, addr string) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.transportDial
}

// VerifyProvenance turns on GitHub build-provenance attestation checks
// for downloaded plugins. When enabled, an archive that carries an
// attestation must verify against owner/repo's GitHub Actions identity
// (via Sigstore); an archive with no attestation falls back to the
// SHA256SUMS + lockfile-TOFU floor with a warning. The gateway and the
// install/update/lock commands enable it; tests inject a stub instead.
func (m *Manager) VerifyProvenance(enabled bool) {
	if !enabled {
		m.prov = nil
		return
	}
	c := newGHClient()
	if m.ghBase != "" {
		c.base = m.ghBase
	}
	m.prov = newGitHubProvenance(c, nil)
}

func (m *Manager) stateDirLocked() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stateDir
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

	// Resolve the source to a local binary path first: a GitHub source is
	// downloaded to (or read from) the cache here; a local path passes
	// through unchanged. accept=false enforces the pinned version, hashes,
	// and provenance level. staticMf is the plugin's signed static
	// manifest (nil for a local plugin, a cache hit, or a release without
	// one) — its declared capabilities are authoritative, so no
	// reconnaissance spawn is needed to learn them.
	local, staticMf, err := m.resolvePluginBinary(ctx, sp, false)
	if err != nil {
		return nil, nil, fmt.Errorf("plugin source %q: %w", source, err)
	}
	bin, err := resolveSandboxPath(local)
	if err != nil {
		return nil, nil, fmt.Errorf("plugin source %q: %w", source, err)
	}
	hash, err := hashFile(bin)
	if err != nil {
		return nil, nil, fmt.Errorf("plugin source %q: %w", source, err)
	}

	// Snapshot the lockfile entry as loaded from disk, before
	// resolveNetwork's addHash records this binary's hash. resolveEgress
	// needs the pre-pass view to tell a first load (record the declared
	// egress) from an already-approved binary (trust the recorded set):
	// once addHash adds the hash below, a live re-read would make every
	// fresh load look approved and silently drop the declared egress.
	priorLock, priorLocked := m.lock.get(sp.Name)

	// declaredMf is the manifest the capability resolvers read to learn what
	// this binary requires. For a release with a signed static manifest it
	// is that manifest (no plugin code runs). Otherwise, when the binary is
	// not already approved in the lockfile (a first load or an upgrade), we
	// probe once — a throwaway network-denied spawn — and share the result
	// across resolveSandboxOff and resolveNetwork so neither probes again.
	// An already-approved binary takes both resolvers' lockfile fast paths
	// and needs no manifest, so declaredMf stays nil there.
	declaredMf := staticMf
	if declaredMf == nil && (!priorLocked || !priorLock.hasHash(hash)) {
		declaredMf, err = m.probeManifest(ctx, sp, bin)
		if err != nil {
			return nil, nil, fmt.Errorf("plugin source %q: read manifest: %w", source, err)
		}
	}

	// resolvePrivileged runs BEFORE resolveNetwork on purpose: an unapproved
	// privileged declaration must fail closed here, before resolveNetwork
	// records this binary's hash. Otherwise a same-or-reduced network
	// upgrade would silently add the new hash to the approved set, and the
	// next load would see it as approved-for-privileged without the operator
	// ever running `plugins approve`.
	privileged, privWarn, err := m.resolvePrivileged(sp, priorLock, priorLocked, hash, declaredMf)
	if err != nil {
		return nil, nil, err
	}
	if privWarn != "" {
		m.logger.Warn("plugin permission", "plugin", sp.Name, "note", privWarn)
	}

	network, warn, err := m.resolveNetwork(ctx, sp, bin, hash, declaredMf)
	if err != nil {
		return nil, nil, err
	}
	if warn != "" {
		m.logger.Warn("plugin permission", "plugin", sp.Name, "note", warn)
	}

	spec, mode, sbWarn, err := buildSandboxSpec(sp, bin, network, privileged, m.stateDirLocked())
	if err != nil {
		return nil, nil, err
	}
	if sbWarn != "" {
		m.logger.Warn("plugin sandbox degraded", "plugin", sp.Name, "warning", sbWarn)
	}

	c, manifest, err := m.spawnClient(ctx, source, spec, mode, sbWarn, sp.Name)
	if err != nil {
		return nil, nil, err
	}

	// Consistency check: the running binary's manifest must match the
	// signed static manifest it published. A mismatch means the binary
	// does not do what its signed declaration claims — fail closed.
	if err := checkManifestConsistency(sp.Name, staticMf, manifest); err != nil {
		c.kill()
		return nil, nil, err
	}

	// Resolve the approved brokered-dial egress set from the (now
	// consistency-checked) manifest and the lockfile. A version that
	// broadens egress beyond what was approved fails closed here, the same
	// trust-on-first-use model as the network grant. Egress doesn't gate
	// the sandbox — the plugin already runs network=none — so this happens
	// after the spawn, off the real manifest.
	egress, eWarn, err := m.resolveEgress(sp, priorLock, priorLocked, hash, egressFromManifest(manifest))
	if err != nil {
		c.kill()
		return nil, nil, err
	}
	if eWarn != "" {
		m.logger.Warn("plugin permission", "plugin", sp.Name, "note", eWarn)
	}
	c.egress = egress

	m.mu.Lock()
	if _, dup := m.plugins[manifest.Name]; dup {
		m.mu.Unlock()
		c.kill()
		return nil, nil, fmt.Errorf("plugin %q (%q) already registered", manifest.Name, source)
	}
	m.plugins[manifest.Name] = c
	m.mu.Unlock()

	return c, manifest, nil
}

// spawnClient launches the plugin under the given sandbox spec/mode,
// performs the handshake, and fetches the Manifest. The returned
// *Client owns its socket dir; call c.kill() to tear it down. Used by
// both Start (the real, capability-approved spawn) and the throwaway
// capability probe.
func (m *Manager) spawnClient(ctx context.Context, source string, spec sandbox.Spec, mode sandbox.Mode, warning, stateNS string) (*Client, *pb.ManifestResponse, error) {
	cmd, err := sandbox.Command(spec, mode)
	if err != nil {
		_ = os.RemoveAll(spec.SocketDir)
		return nil, nil, fmt.Errorf("plugin %q: %w", source, err)
	}
	// Wire the per-plugin HostState service for a real load (a state
	// namespace is given; throwaway probes pass ""). The store is resolved
	// lazily per call, so it works even though the gateway's blob store is
	// wired only after the first config load. The gateway serves it over
	// the broker; the plugin dials it.
	// For a real load (a state namespace is given; throwaway probes pass
	// ""), wire the per-plugin HostState + HostControl services. The session
	// registry is shared between the broker server that serves HostControl
	// (gc) and the adapter that registers a session per connection (c);
	// HandleConn populates it. Probes never handle connections, so they get
	// neither service (no idle broker goroutine).
	gc := &grpcClient{}
	var sessions *sessionRegistry
	var routeReg *transportRouteRegistry
	if stateNS != "" {
		gc.hostState = newHostState(m.blobStore, stateNS)
		sessions = newSessionRegistry()
		gc.sessions = sessions
		routeReg = newTransportRouteRegistry()
		gc.routeReg = routeReg
		gc.transportDial = m.transportDialer()
	}
	cli := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			PluginName: gc,
		},
		Cmd: cmd,
		// The plugin's environment is exactly what sandbox.Command
		// set (plus go-plugin's handshake vars): the gateway's own
		// environment — CLAWPATROL_SECRET_*, cloud credentials —
		// must never reach plugin code.
		SkipHostEnv:      true,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           m.logger,
		// Multiplex the host-services broker (HostState/HostControl/
		// HostTunnel) over the plugin's main gRPC connection instead of a
		// separate unix socket. The broker's own socket would land in the
		// gateway's temp dir, which the namespaces sandbox's private /tmp
		// hides from the plugin — so a sandboxed plugin could never reach
		// host services. Multiplexing reuses the main connection (already
		// sandbox-visible), so it works under the sandbox. Both sides run
		// the same go-plugin version, so the plugin negotiates support
		// automatically.
		GRPCBrokerMultiplex: true,
	})
	c := &Client{
		source:         source,
		sandboxMode:    mode,
		sandboxWarning: warning,
		network:        spec.Network,
		socketDir:      spec.SocketDir,
		gp:             cli,
		sessions:       sessions,
		routeReg:       routeReg,
	}
	rpcCli, err := cli.Client()
	if err != nil {
		c.kill()
		return nil, nil, fmt.Errorf("plugin %q: handshake: %w", source, err)
	}
	raw, err := rpcCli.Dispense(PluginName)
	if err != nil {
		c.kill()
		return nil, nil, fmt.Errorf("plugin %q: dispense: %w", source, err)
	}
	conn, ok := raw.(*grpc.ClientConn)
	if !ok {
		c.kill()
		return nil, nil, fmt.Errorf("plugin %q: unexpected client type %T", source, raw)
	}
	c.conn = conn
	c.pluginCli = pb.NewPluginClient(conn)
	c.credential = pb.NewCredentialClient(conn)
	c.endpoint = pb.NewEndpointClient(conn)
	c.tunnel = pb.NewTunnelClient(conn)

	manifest, err := c.pluginCli.Manifest(ctx, &pb.ManifestRequest{})
	if err != nil {
		c.kill()
		return nil, nil, fmt.Errorf("plugin %q: manifest: %w", source, err)
	}
	if manifest.Name == "" {
		c.kill()
		return nil, nil, fmt.Errorf("plugin %q: empty manifest name", source)
	}
	c.name = manifest.Name
	c.manifest = manifest
	return c, manifest, nil
}

// pluginDeclaredNetwork returns the plugin's declared network capability.
// For a GitHub plugin whose release ships a signed static manifest this
// comes from that manifest — no plugin code is run. Otherwise (a local
// plugin, or a release without a static manifest) it falls back to a
// throwaway network-denied probe spawn.
func (m *Manager) pluginDeclaredNetwork(ctx context.Context, sp config.PluginSource, binPath string, staticMf *pb.ManifestResponse) (sandbox.Network, error) {
	if staticMf != nil {
		return networkFromManifest(staticMf), nil
	}
	return m.probeNetwork(ctx, sp, binPath)
}

// resolveNetwork determines the approved network grant for sp from the
// declared capability (the signed static manifest, or a probe), the
// lockfile (trust-on-first-use), and an optional operator HCL override.
// It returns the grant plus an optional human note for logging, or an
// error — including the fail-closed escalation error when an upgraded
// plugin requests more than the lockfile recorded.
func (m *Manager) resolveNetwork(ctx context.Context, sp config.PluginSource, binPath, hash string, staticMf *pb.ManifestResponse) (sandbox.Network, string, error) {
	// An operator HCL `network` override always wins (force or veto)
	// and is what gets recorded — an explicit, lockfile-visible choice.
	if sp.Network != "" {
		net, err := parseNetwork(sp.Network)
		if err != nil {
			return "", "", err
		}
		if m.lock.active() {
			m.lock.addHash(sp.Name, hash, string(net))
		}
		return net, "", nil
	}

	// No lockfile (tests, config.LoadBytes): use the declared capability
	// directly, no persistence or escalation check.
	if !m.lock.active() {
		net, err := m.pluginDeclaredNetwork(ctx, sp, binPath, staticMf)
		return net, "", err
	}

	if entry, ok := m.lock.get(sp.Name); ok && entry.hasHash(hash) {
		// Fast path: this binary is in the approved set — no probe.
		net, err := parseNetwork(entry.Network)
		if err != nil {
			return "", "", fmt.Errorf("plugin %q: lockfile network %q: %w", sp.Name, entry.Network, err)
		}
		return net, "", nil
	}

	// Unknown binary (new plugin, new version, or a platform build not
	// yet in the set): read what it now declares (signed manifest, or a
	// probe fallback).
	declared, err := m.pluginDeclaredNetwork(ctx, sp, binPath, staticMf)
	if err != nil {
		return "", "", err
	}

	entry, recorded := m.lock.get(sp.Name)
	if !recorded {
		// Trust on first use: record and proceed.
		m.lock.addHash(sp.Name, hash, string(declared))
		return declared, fmt.Sprintf("first load: recorded network=%q in %s", declared, LockfileName), nil
	}

	rec, err := parseNetwork(entry.Network)
	if err != nil {
		return "", "", fmt.Errorf("plugin %q: lockfile network %q: %w", sp.Name, entry.Network, err)
	}
	if networkRank(declared) > networkRank(rec) {
		return "", "", fmt.Errorf(
			"plugin %q upgrade escalates permissions: it now requests network=%q but was approved for network=%q. "+
				"A compromised plugin update gaining an exfiltration path looks exactly like this. "+
				"If you trust this update, re-approve it: clawpatrol plugins approve %s",
			sp.Name, declared, rec, sp.Name)
	}
	// Same or reduced permissions: add this binary's hash to the
	// approved set (a new platform build or a same-perms version) and
	// proceed.
	m.lock.addHash(sp.Name, hash, string(declared))
	return declared, "", nil
}

// resolveEgress determines the approved brokered-dial egress set for sp
// from the plugin's manifest-declared targets and the lockfile
// (trust-on-first-use). It records the set on first load and, on a later
// binary, fails closed when the declared set broadens beyond what was
// approved (a destination none of the approved entries cover). A same or
// narrower set is recorded and allowed. Egress does not gate the sandbox;
// it bounds which upstream targets the gateway's brokered dial will open.
func (m *Manager) resolveEgress(sp config.PluginSource, prior lockEntry, priorRecorded bool, hash string, declared []string) ([]string, string, error) {
	declared = normalizeEgress(declared)

	// No lockfile (tests, config.LoadBytes): use the declared set directly,
	// no persistence or broadening check.
	if !m.lock.active() {
		return declared, "", nil
	}

	// Every decision below reads `prior` — the lockfile entry as it was on
	// disk at the start of this pass, captured before resolveNetwork's
	// addHash recorded this binary's hash. Reading the live entry here
	// would see that freshly-added hash and mistake a first load for an
	// already-approved binary, taking the fast path and dropping the
	// declared egress.
	if priorRecorded && prior.hasHash(hash) {
		// This exact binary was approved in a prior load — trust its
		// recorded egress. But `plugins install` from a release without a
		// signed static manifest records the hash with egress deferred to
		// the first real load (see install.go); record the declared set now
		// when none is recorded yet. The binary is already approved, so this
		// is trust-on-first-use, not an escalation.
		if len(prior.Egress) == 0 && len(declared) > 0 {
			m.lock.setEgress(sp.Name, declared)
			return declared, fmt.Sprintf("first load: recorded deferred egress %v in %s", declared, LockfileName), nil
		}
		return prior.Egress, "", nil
	}
	if !priorRecorded {
		// Trust on first use: record and proceed.
		m.lock.setEgress(sp.Name, declared)
		if len(declared) > 0 {
			return declared, fmt.Sprintf("first load: recorded egress %v in %s", declared, LockfileName), nil
		}
		return declared, "", nil
	}
	if broadened := egressBroadened(prior.Egress, declared); len(broadened) > 0 {
		return nil, "", fmt.Errorf(
			"plugin %q upgrade broadens its network egress: it now wants to reach %v but was approved only for %v. "+
				"A compromised plugin update adding an exfiltration destination looks exactly like this. "+
				"If you trust this update, re-approve it: clawpatrol plugins approve %s",
			sp.Name, broadened, prior.Egress, sp.Name)
	}
	// Same or narrowed: record the (possibly tightened) declared set.
	m.lock.setEgress(sp.Name, declared)
	return declared, "", nil
}

// probeNetwork reads the plugin's manifest-declared network capability via
// a throwaway probe spawn (see probeManifest).
func (m *Manager) probeNetwork(ctx context.Context, sp config.PluginSource, binPath string) (sandbox.Network, error) {
	mf, err := m.probeManifest(ctx, sp, binPath)
	if err != nil {
		return "", err
	}
	return networkFromManifest(mf), nil
}

// probeManifest spawns the plugin in a throwaway, network-denied sandbox
// just long enough to read its manifest, then tears it down. Manifest
// fetch needs no network, so this is safe even for a plugin that will
// ultimately run with outbound access. Used to learn a local plugin's (or
// a static-manifest-less release's) declared capabilities without granting
// them — privileged=false here so the probe stays sandboxed even when the
// plugin declares the privileged capability (the operator's own
// `sandbox = "off"` HCL still takes effect via buildSandboxSpec).
func (m *Manager) probeManifest(ctx context.Context, sp config.PluginSource, binPath string) (*pb.ManifestResponse, error) {
	spec, mode, _, err := buildSandboxSpec(sp, binPath, sandbox.NetworkNone, false, m.stateDirLocked())
	if err != nil {
		return nil, err
	}
	// Throwaway probe: no state namespace, so the broker host service is
	// not wired (the probe never runs plugin logic that would use it).
	c, manifest, err := m.spawnClient(ctx, sp.Source, spec, mode, "", "")
	if err != nil {
		return nil, err
	}
	defer c.kill()
	return manifest, nil
}

// privilegedFromManifest reports whether the plugin's manifest declares the
// privileged (run-unsandboxed) capability.
func privilegedFromManifest(mf *pb.ManifestResponse) bool {
	return mf.GetCapabilities().GetPrivileged()
}

// resolvePrivileged decides whether sp runs unsandboxed. Privileged is the
// strongest grant a plugin can ask for — full host access — so unlike
// network and egress it is NEVER trust-on-first-use: the operator must
// approve it explicitly with `clawpatrol plugins approve` (or the
// dashboard), which records it in the lockfile gated on the binary's hash.
//
// prior is the lockfile entry as it was at the start of this pass (the
// snapshot Start captures before resolveNetwork records anything), so an
// upgraded binary — whose hash is not yet in prior.Hashes — fails closed
// here until re-approved. resolvePrivileged must run before resolveNetwork
// so this fail-closed happens before the new hash is recorded.
//
// declaredMf is the plugin's manifest (signed static, or a probe), nil only
// on the lockfile fast path where prior already records this exact binary.
func (m *Manager) resolvePrivileged(sp config.PluginSource, prior lockEntry, priorRecorded bool, hash string, declaredMf *pb.ManifestResponse) (bool, string, error) {
	// An operator `sandbox = "off"` HCL attribute is the operator already
	// accepting full host access in a reviewable, committed file — it wins
	// outright, no lockfile approval needed (buildSandboxSpec honours it
	// too; returning true here keeps the two in step and short-circuits the
	// declaration check).
	if sp.Sandbox == "off" {
		return true, "", nil
	}

	// Fast path: this exact binary is already recorded. Trust its recorded
	// privileged flag without consulting the manifest.
	if priorRecorded && prior.hasHash(hash) {
		return prior.Privileged, "", nil
	}

	if !privilegedFromManifest(declaredMf) {
		return false, "", nil // plugin runs sandboxed; nothing to approve.
	}

	// The plugin declares it needs full host access.
	//
	// No lockfile (tests, config.LoadBytes): there is no approval channel,
	// so fall back to the declared capability directly — the same "trust the
	// declaration, no enforcement" behaviour network and egress have without
	// a lockfile. A real deployment always has a lockfile.
	if !m.lock.active() {
		return true, fmt.Sprintf("no lockfile: running plugin %q unsandboxed as it declares the privileged capability", sp.Name), nil
	}

	// Lockfile active but this binary is not approved-for-privileged: fail
	// closed. resolvePrivileged never records the grant itself — only an
	// explicit `plugins approve` does.
	return false, "", fmt.Errorf(
		"plugin %q declares the privileged capability: it needs to run with the sandbox OFF (full host access — "+
			"it can read every file this user can, including clawpatrol's own secrets, and run any command). "+
			"clawpatrol will not grant that silently. If you trust this plugin, approve it explicitly: "+
			"clawpatrol plugins approve %s", sp.Name, sp.Name)
}

func networkFromManifest(mf *pb.ManifestResponse) sandbox.Network {
	if mf.GetCapabilities().GetNetwork() == pb.NetworkAccess_NETWORK_OUTBOUND {
		return sandbox.NetworkOutbound
	}
	return sandbox.NetworkNone
}

func networkRank(n sandbox.Network) int {
	if n == sandbox.NetworkOutbound {
		return 1
	}
	return 0
}

// checkManifestConsistency verifies the running binary's gRPC manifest
// matches the signed static manifest it published — the required network
// capability, the manifest name, and the declared type set. A mismatch
// means the binary does not do what its signed declaration claims, so it
// fails closed. A nil staticMf (local plugin, or a release without a
// static manifest) skips the check.
func checkManifestConsistency(name string, staticMf, runtimeMf *pb.ManifestResponse) error {
	if staticMf == nil {
		return nil
	}
	if s, g := networkFromManifest(staticMf), networkFromManifest(runtimeMf); s != g {
		return fmt.Errorf(
			"plugin %q binary requests network=%q but its signed release manifest declares network=%q; "+
				"the binary does not match its published manifest", name, g, s)
	}
	if staticMf.GetName() != runtimeMf.GetName() || manifestTypeKey(staticMf) != manifestTypeKey(runtimeMf) {
		return fmt.Errorf(
			"plugin %q binary declares different identity or types than its signed release manifest; "+
				"the binary does not match its published manifest", name)
	}
	if s, g := egressFromManifest(staticMf), egressFromManifest(runtimeMf); !slices.Equal(s, g) {
		return fmt.Errorf(
			"plugin %q binary requests network egress %v but its signed release manifest declares %v; "+
				"the binary does not match its published manifest", name, g, s)
	}
	if s, g := privilegedFromManifest(staticMf), privilegedFromManifest(runtimeMf); s != g {
		return fmt.Errorf(
			"plugin %q binary requests privileged=%v but its signed release manifest declares privileged=%v; "+
				"the binary does not match its published manifest", name, g, s)
	}
	return nil
}

// manifestTypeKey is a stable, comparable summary of a manifest's
// declared name (its types), independent of ordering.
func manifestTypeKey(mf *pb.ManifestResponse) string {
	var names []string
	for _, c := range mf.GetCredentials() {
		names = append(names, "c:"+c.GetTypeName())
	}
	for _, e := range mf.GetEndpoints() {
		names = append(names, "e:"+e.GetTypeName())
	}
	for _, t := range mf.GetTunnels() {
		names = append(names, "t:"+t.GetTypeName())
	}
	for _, f := range mf.GetFacets() {
		names = append(names, "f:"+f.GetName())
	}
	sort.Strings(names)
	return strings.Join(names, "\n")
}

// ApprovedPlugin is one result row from Approve.
type ApprovedPlugin struct {
	Name       string
	Network    string
	Privileged bool
}

// Approve (re)records the current permissions of the named plugins
// (or all when names is empty) in the lockfile: for a GitHub source it
// re-resolves the constraint's newest release and downloads it, then
// writes {source, version, commit, attested, hash, declared network},
// bypassing both the network-escalation and the provenance-downgrade
// check — this is the operator deliberately accepting the current
// version. It does not register the plugin's types, so it is safe to
// call without a full config load.
func (m *Manager) Approve(ctx context.Context, specs []config.PluginSource, names []string) ([]ApprovedPlugin, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	if err := m.lock.load(); err != nil {
		return nil, err
	}
	var out []ApprovedPlugin
	for _, sp := range specs {
		if len(want) > 0 && !want[sp.Name] {
			continue
		}
		// accept=true: re-resolve the constraint's newest, download, and
		// re-record the source/version/commit/provenance, deliberately
		// accepting it (clears a provenance-downgrade or escalation block).
		local, staticMf, err := m.resolvePluginBinary(ctx, sp, true)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		bin, err := resolveSandboxPath(local)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		hash, err := hashFile(bin)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		// The declared manifest: the signed static one for a release, or a
		// throwaway probe for a local / manifest-less plugin. Resolved once
		// and reused for both network and privileged so a local plugin is
		// probed at most once per approve.
		declaredMf := staticMf
		if declaredMf == nil {
			declaredMf, err = m.probeManifest(ctx, sp, bin)
			if err != nil {
				return nil, fmt.Errorf("plugin %q: read manifest: %w", sp.Name, err)
			}
		}
		declared := sandbox.Network("")
		if sp.Network != "" {
			declared, err = parseNetwork(sp.Network)
			if err != nil {
				return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
			}
		} else {
			declared = networkFromManifest(declaredMf)
		}
		m.lock.addHash(sp.Name, hash, string(declared))
		// Record the manifest-declared egress when the release ships a
		// signed static manifest (no spawn); a manifest-less release has its
		// egress recorded trust-on-first-use at the first real load.
		if staticMf != nil {
			m.lock.setEgress(sp.Name, egressFromManifest(staticMf))
		}
		// Record the privileged grant explicitly. This is the whole point of
		// approving a privileged plugin: resolvePrivileged never records it
		// on its own, so a plugin that declares the capability fails closed
		// at load until this writes it. A plugin that does not declare it
		// records privileged=false (clearing any stale grant from a prior
		// version that did).
		privileged := privilegedFromManifest(declaredMf)
		m.lock.setPrivileged(sp.Name, privileged)
		out = append(out, ApprovedPlugin{Name: sp.Name, Network: string(declared), Privileged: privileged})
	}
	for n := range want {
		found := false
		for _, a := range out {
			if a.Name == n {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no plugin %q in config", n)
		}
	}
	if err := m.lock.save(); err != nil {
		return nil, err
	}
	return out, nil
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
func (m *Manager) LoadPlugins(specs []config.PluginSource, stateDir string) hcl.Diagnostics {
	var diags hcl.Diagnostics
	ctx := context.Background()
	m.setStateDir(stateDir)
	// Reload the lockfile each pass so manual edits and
	// `plugins approve` are picked up; write back any
	// trust-on-first-use records when done.
	if err := m.lock.load(); err != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Failed to read the plugin permission lockfile",
			Detail:   err.Error(),
		})
		return diags
	}
	defer func() {
		if err := m.lock.save(); err != nil {
			m.logger.Error("failed to write plugin lockfile", "err", err)
		}
	}()
	// Rebuild the blocked set from scratch this pass; a plugin that
	// now loads (or was removed from the config) drops out of it.
	blocked := map[string]blockedRecord{}
	defer func() {
		m.mu.Lock()
		m.blocked = blocked
		m.mu.Unlock()
	}()
	for _, sp := range specs {
		if sp.Source == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  fmt.Sprintf("Plugin %q: source is required", sp.Name),
			})
			blocked[sp.Name] = blockedRecord{source: sp.Source, reason: "source is required"}
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
			rec := blockedRecord{source: sp.Source, reason: err.Error()}
			// Best-effort: read what the resolvable version *requires* from
			// its signed static manifest so the dashboard can show the
			// privileges a blocked/unapproved plugin wants. No spawn.
			if pv, perr := m.previewManifest(ctx, sp); perr == nil {
				rec.requested = &pv
			}
			blocked[sp.Name] = rec
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

// PluginInfo is the dashboard-facing summary of one plugin — either
// loaded (with its permissions and declared types) or blocked (failed
// to load, with the reason; chiefly a permission escalation).
type PluginInfo struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	// Blocked plugins carry only Name, Source, Blocked, Reason.
	Blocked bool   `json:"blocked,omitempty"`
	Reason  string `json:"reason,omitempty"`

	Version        string   `json:"version,omitempty"`
	Network        string   `json:"network,omitempty"`     // approved grant it runs with
	Egress         []string `json:"egress,omitempty"`      // approved brokered-dial targets
	Privileged     bool     `json:"privileged,omitempty"`  // approved to run unsandboxed
	SandboxMode    string   `json:"sandboxMode,omitempty"` // namespaces | landlock | seatbelt | off
	SandboxWarning string   `json:"sandboxWarning,omitempty"`
	ApprovedHashes []string `json:"approvedHashes,omitempty"` // lockfile-approved binary hashes (one per platform build)
	// UpdateAvailable is the newest release tag satisfying the plugin's
	// constraint that is newer than the locked version (GitHub sources
	// only). Set by the background update check; the operator applies it
	// with `clawpatrol plugins update`.
	UpdateAvailable string   `json:"updateAvailable,omitempty"`
	Credentials     []string `json:"credentials,omitempty"`
	Tunnels         []string `json:"tunnels,omitempty"`
	Endpoints       []string `json:"endpoints,omitempty"`
	Facets          []string `json:"facets,omitempty"`
	// Requested is the privileges a blocked/unapproved plugin's
	// resolvable version declares in its signed static manifest — what it
	// wants, shown so an operator can review before approving. Read
	// without running the plugin; nil when no static manifest is
	// available.
	Requested *RequestedPrivileges `json:"requested,omitempty"`
}

// RequestedPrivileges is what a plugin version declares it needs, read
// from its signed static manifest (no spawn).
type RequestedPrivileges struct {
	Version     string   `json:"version,omitempty"`
	Network     string   `json:"network"`
	Egress      []string `json:"egress,omitempty"`
	Privileged  bool     `json:"privileged,omitempty"`
	Credentials []string `json:"credentials,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty"`
	Tunnels     []string `json:"tunnels,omitempty"`
	Facets      []string `json:"facets,omitempty"`
}

// PluginInfos returns a dashboard summary of every plugin — loaded
// ones with their permissions, plus any currently blocked (e.g. a
// permission escalation) with the failure reason.
func (m *Manager) PluginInfos() []PluginInfo {
	out := []PluginInfo{}
	loaded := map[string]bool{}
	m.mu.Lock()
	updates := make(map[string]string, len(m.updates))
	for k, v := range m.updates {
		updates[k] = v
	}
	m.mu.Unlock()
	for _, c := range m.Plugins() {
		loaded[c.Name()] = true
		info := PluginInfo{
			Name:           c.Name(),
			Source:         c.Source(),
			Network:        c.Network(),
			SandboxMode:    c.SandboxMode(),
			SandboxWarning: c.SandboxWarning(),
		}
		if mf := c.Manifest(); mf != nil {
			info.Version = mf.Version
			for _, cr := range mf.Credentials {
				info.Credentials = append(info.Credentials, cr.TypeName)
			}
			for _, t := range mf.Tunnels {
				info.Tunnels = append(info.Tunnels, t.TypeName)
			}
			for _, e := range mf.Endpoints {
				info.Endpoints = append(info.Endpoints, e.TypeName)
			}
			for _, f := range mf.Facets {
				info.Facets = append(info.Facets, f.Name)
			}
		}
		if e, ok := m.lock.get(c.Name()); ok {
			info.ApprovedHashes = e.Hashes
			info.Egress = e.Egress
			info.Privileged = e.Privileged
		}
		// A plugin forced unsandboxed by the operator's `sandbox = "off"`
		// HCL (rather than the approved capability) still runs privileged.
		if c.SandboxMode() == string(sandbox.ModeOff) {
			info.Privileged = true
		}
		if len(info.Egress) == 0 {
			info.Egress = c.Egress()
		}
		info.UpdateAvailable = updates[info.Source]
		out = append(out, info)
	}
	m.mu.Lock()
	for name, b := range m.blocked {
		if loaded[name] {
			continue
		}
		info := PluginInfo{
			Name: name, Source: b.source, Blocked: true, Reason: b.reason,
			UpdateAvailable: updates[b.source],
		}
		if r := b.requested; r != nil {
			info.Requested = &RequestedPrivileges{
				Version:     r.Version,
				Network:     r.Network,
				Egress:      r.Egress,
				Privileged:  r.Privileged,
				Credentials: r.Credentials,
				Endpoints:   r.Endpoints,
				Tunnels:     r.Tunnels,
				Facets:      r.Facets,
			}
		}
		out = append(out, info)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Stop tears down every spawned subprocess. Idempotent.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.plugins {
		c.kill()
	}
	m.plugins = make(map[string]*Client)
}

// kill tears down the subprocess and removes its socket dir.
// Idempotent and safe before the gRPC conn is wired (probe path).
func (c *Client) kill() {
	if c.gp != nil {
		c.gp.Kill()
	}
	if c.socketDir != "" {
		_ = os.RemoveAll(c.socketDir)
	}
}

// Client is the gateway-side handle to one running plugin subprocess.
// Adapters use it to issue RPCs.
type Client struct {
	name           string
	source         string
	sandboxMode    sandbox.Mode
	sandboxWarning string
	network        sandbox.Network
	// egress is the lockfile-approved set of brokered-dial targets the
	// plugin's manifest declared ("host:port" / "*.suffix:port"). Merged
	// into every endpoint binding's dial allow-list so the gateway opens
	// these upstreams on the plugin's behalf without operator `dial` HCL.
	egress     []string
	socketDir  string
	manifest   *pb.ManifestResponse
	gp         *plugin.Client
	conn       *grpc.ClientConn
	pluginCli  pb.PluginClient
	credential pb.CredentialClient
	endpoint   pb.EndpointClient
	tunnel     pb.TunnelClient
	// sessions maps a per-connection HostControl session token to the
	// connection's evaluation context. HandleConn registers a session and
	// removes it when the connection ends; the broker-served HostControl
	// resolves Evaluate calls against it. Shared with the grpcClient that
	// serves the bundle.
	sessions *sessionRegistry
	// routeReg holds the parent tunnels this plugin's tunnels are chained
	// through; the tunnelAdapter registers a parent at Open and the
	// broker-served hostTunnel resolves it at DialVia. Shared with the
	// grpcClient. nil on the probe path (no tunnels run).
	routeReg *transportRouteRegistry
}

// SandboxMode reports which sandbox backend the subprocess runs
// under ("off" when the operator opted out).
func (c *Client) SandboxMode() string { return string(c.sandboxMode) }

// SandboxWarning is non-empty when the plugin runs under a degraded
// fallback backend; it describes what the fallback does not cover.
func (c *Client) SandboxWarning() string { return c.sandboxWarning }

// Network reports the approved network grant the plugin runs with
// ("none" or "outbound").
func (c *Client) Network() string { return string(c.network) }

// Egress reports the lockfile-approved brokered-dial targets the
// plugin's manifest declared.
func (c *Client) Egress() []string { return c.egress }

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

// grpcClient satisfies plugin.GRPCPlugin on the gateway side. Dispense
// returns the raw *grpc.ClientConn and we instantiate the plugin stubs
// ourselves on Client. When hostState is set, the gateway also serves
// the HostState service to the plugin over the broker.
type grpcClient struct {
	plugin.NetRPCUnsupportedPlugin
	hostState     pb.HostStateServer      // nil = state service disabled
	sessions      *sessionRegistry        // nil = HostControl disabled (probe path)
	routeReg      *transportRouteRegistry // nil = HostTunnel disabled (probe path)
	transportDial func(network, addr string) (net.Conn, error)
}

func (g *grpcClient) GRPCServer(_ *plugin.GRPCBroker, _ *grpc.Server) error {
	return errors.New("extplugin: gateway does not implement the gRPC server side")
}

func (g *grpcClient) GRPCClient(_ context.Context, broker *plugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	// Serve the host-side services (HostState + HostControl) on the reserved
	// broker stream id. AcceptAndServe blocks until the plugin dials, so run
	// it in the background; the plugin only dials lazily on its first call.
	// When the client tears down, the broker closes and AcceptAndServe
	// returns.
	if broker == nil || (g.hostState == nil && g.sessions == nil && g.routeReg == nil) {
		return conn, nil
	}
	hs, sessions, routeReg, transportDial := g.hostState, g.sessions, g.routeReg, g.transportDial
	go broker.AcceptAndServe(HostServicesBrokerID, func(opts []grpc.ServerOption) *grpc.Server {
		// HostControl calls are session-scoped via metadata; the interceptor
		// resolves the token once. HostState carries no token and passes
		// through (the interceptor only acts on a present token). HostTunnel
		// is streaming and capability-scoped by its transport-dial token, so it is not
		// covered by the unary interceptor.
		if sessions != nil {
			opts = append(opts, grpc.ChainUnaryInterceptor(sessionUnaryInterceptor(sessions)))
		}
		s := grpc.NewServer(opts...)
		if hs != nil {
			pb.RegisterHostStateServer(s, hs)
		}
		if sessions != nil {
			pb.RegisterHostControlServer(s, hostControl{})
		}
		if routeReg != nil {
			pb.RegisterHostTunnelServer(s, &hostTunnel{reg: routeReg, directDial: transportDial})
		}
		return s
	})
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
