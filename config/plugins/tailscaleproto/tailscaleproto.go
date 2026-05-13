// Package tailscaleproto holds the protocol-specific contract that
// bridges the tailscale credential and the tailscale tunnel (plus the
// dashboard Connect modal). Lives in config/plugins/ rather than
// config/runtime/ so the runtime stays generic — runtime only knows
// about the cross-protocol shapes (HTTP / Postgres / TLS / ConnEndpoint)
// and discovers protocol extensions like this one through the
// AcceptCredentialRuntime hook. Mirrors the sshproto pattern.
//
// Three consumers import this package:
//
//   - config/plugins/credentials/tailscale.go: the credential body
//     declares it satisfies NodeIdentity (and TailscaleAuthProvider
//     for the dashboard).
//   - config/plugins/tunnels/tailscale.go: the tunnel type-asserts
//     host.Credential.Body to NodeIdentity and uses the returned
//     ipn.StateStore to bring up tsnet without a pre-minted authkey.
//   - the gateway main package: the dashboard reads PendingNodeAuth
//     to surface tsnet's live login URL to the operator.
package tailscaleproto

import (
	"sync"

	"tailscale.com/ipn"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// NodeIdentity is what the tailscale tunnel needs from a credential
// plugin to bring an embedded tsnet node into a tailnet *without* a
// pre-minted authkey. The credential owns persistence of the tsnet
// node identity (machine key + node key + login profile) through the
// gateway secret store; tsnet drives the interactive login flow when
// the store is empty and reuses the cached identity on every
// subsequent boot — exactly the `tailscale up` cached-state path.
type NodeIdentity interface {
	// StateStore returns an ipn.StateStore that persists tsnet's
	// identity bytes through the gateway secret store. `name` is the
	// credential's bare name (so multiple tunnels bound to the same
	// credential share one node identity). `store` is the gateway's
	// SecretStore handle plumbed through TunnelHost; the credential
	// is expected to type-assert it to SecretWriter for the
	// write-side of the round-trip.
	StateStore(name string, store runtime.SecretStore) (ipn.StateStore, error)
}

// TailscaleAuthProvider is the optional interface a credential plugin's
// decoded body implements when it surfaces a "Connect" affordance in
// the dashboard for tailscale node auth. The dashboard walks every
// loaded credential, type-asserts to this, and renders the returned
// integration in the connect modal.
//
// Distinct from config.OAuthFlowProvider on purpose:
//
//   - OAuthFlowProvider yields a *static* OAuthIntegration (auth /
//     token URLs, scopes, client id) and stashes a per-owner access
//     token via OAuthRegistry. Tailscale's auth URL is *dynamic* —
//     minted by tsnet per attempt — and the identity is gateway-wide
//     (one node per credential, shared across owners).
//   - TailscaleAuthProvider just exposes a BeginURL the dashboard
//     redirects to; the live URL is read off the PendingNodeAuth
//     registry that the tunnel side writes into.
type TailscaleAuthProvider interface {
	TailscaleAuth() *TailscaleAuthIntegration
}

// TailscaleAuthIntegration is the dashboard-facing description of a
// tailscale-node-auth credential's Connect flow.
type TailscaleAuthIntegration struct {
	// BeginURL is a dashboard-relative endpoint the frontend POSTs
	// to start (or re-fetch) the live auth URL. The handler reads
	// the runtime PendingNodeAuth registry and returns either the
	// URL or "node already connected".
	//
	// Filled in by the dashboard at render time, not by the
	// credential plugin (the plugin doesn't know its own bare name
	// when it returns this struct).
	BeginURL string
}

// PendingNodeAuth is the in-process side-channel through which the
// tailscale tunnel surfaces tsnet's dynamic login URL to the
// dashboard. Keyed by credential bare name — one entry per credential
// regardless of how many tunnels reference it (tailscale node identity
// is gateway-wide).
//
// The zero value is usable. Safe for concurrent use.
type PendingNodeAuth struct {
	mu      sync.RWMutex
	pending map[string]string
}

// Set parks the live login URL for credential `name`. The tunnel
// calls this when tsnet emits a BrowseToURL notification on the IPN
// bus. Clearing is `Set(name, "")`.
func (p *PendingNodeAuth) Set(name, url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		p.pending = map[string]string{}
	}
	if url == "" {
		delete(p.pending, name)
		return
	}
	p.pending[name] = url
}

// Get returns the current pending login URL for credential `name`, or
// "" when nothing is pending (either no auth in flight or the node
// has finished joining).
func (p *PendingNodeAuth) Get(name string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pending[name]
}

// Default is the process-wide PendingNodeAuth registry. The tunnel
// writes into it; the dashboard reads from it. The gateway plumbs
// this exact value into both — a single package-level instance
// avoids a TunnelHost extension for the first iteration. Future
// iterations may move this onto TunnelHost so embedders that run
// multiple gateway instances in one process can scope it.
var Default = &PendingNodeAuth{}

// SecretWriter is the optional interface a runtime.SecretStore
// implementation satisfies when it can persist slot bytes. The
// tailscale credential's StateStore type-asserts to this; the gateway-
// side store implements it via the credential_secrets table. Other
// stores (EnvSecretStore, in-memory test fakes) don't, and the
// credential errors with a clear message at StateStore time.
type SecretWriter interface {
	SetCredentialSlot(name, slot, value string) error
}

// Teach the runtime's credential checker about NodeIdentity and the
// optional TailscaleAuthProvider. Plugins that implement either pass
// init-time validation without runtime having to import this package.
func init() {
	runtime.AcceptCredentialRuntime(func(p *config.Plugin) bool {
		if _, ok := p.Runtime.(NodeIdentity); ok {
			return true
		}
		if _, ok := p.Runtime.(TailscaleAuthProvider); ok {
			return true
		}
		return false
	})
}
