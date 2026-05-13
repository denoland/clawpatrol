package main

// TunnelManager owns the lifecycle of tunnel runtime instances. It
// sits between the dispatcher (which wants `give me a conn to this
// upstream`) and the tunnel plugins (which know how to bring up the
// transport). Refcounting, idle teardown, and `via` chaining live
// here so plugins stay focused on a single hop.
//
// Sharing keys:
//   * singleton    → key = ""                (one instance per name)
//   * per_endpoint → key = endpoint name     (one per (tunnel, endpoint))
//   * per_conn     → key = monotonic uint64  (one per acquire)
//
// Lifecycle for each entry:
//
//   refcount == 0    nothing is live; entry absent from manager.
//   Acquire          increment refcount. If first-acquire, recursively
//                    Acquire the via chain and call body.Open. On
//                    failure, release the via chain so partial state
//                    doesn't leak.
//   Release          decrement refcount. When it hits 0:
//                      keepalive == "always":   keep entry around forever
//                      keepalive == 0:          Close immediately
//                      keepalive == <duration>: arm an idle timer; if a
//                                               new Acquire arrives before
//                                               it fires, cancel the timer
//                                               and bump refcount.

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// TunnelManager is the single owner of every live tunnel instance.
type TunnelManager struct {
	secrets  runtime.SecretStore
	stateDir string

	mu      sync.Mutex
	entries map[mgrKey]*tunnelEntry
	// pinned holds the manager's own release closure per pinned
	// (name, sharingKey, fingerprint) tuple. SetPolicy stores one
	// Acquire result per `keepalive = "always"` tunnel and drops it
	// again when the pin disappears from a subsequent policy.
	pinned map[mgrKey]func()

	// connSeq feeds per_conn sharing keys.
	connSeq atomic.Uint64
}

type mgrKey struct {
	Name        string
	Key         string
	Fingerprint string
}

type tunnelEntry struct {
	name      string
	sharing   string
	keepalive time.Duration
	always    bool

	// openOnce gates first-Open. Goroutines that race to Acquire
	// the same entry all increment refcount but only one of them
	// runs body.Open; the rest wait for openOnce.Do to return and
	// read tunnel / openErr.
	openOnce sync.Once
	openErr  error

	// tunnel is the live runtime.Tunnel returned by body.Open.
	tunnel runtime.Tunnel

	// viaRelease is the manager-issued release for the underlying
	// chain hop. Calling it decrements the parent's refcount.
	viaRelease func()

	refcount int
	timer    *time.Timer
}

// NewTunnelManager constructs an empty manager. SetPolicy must be
// called once at boot to populate keepalive=always pins.
func NewTunnelManager(secrets runtime.SecretStore, stateDir string) *TunnelManager {
	return &TunnelManager{
		secrets:  secrets,
		stateDir: stateDir,
		entries:  map[mgrKey]*tunnelEntry{},
		pinned:   map[mgrKey]func(){},
	}
}

// Acquire returns a Tunnel handle the dispatcher uses to dial.
// `endpoint` is the endpoint name making the request — used for
// per_endpoint sharing keys. release must be called exactly once
// when the caller is done.
func (m *TunnelManager) Acquire(ctx context.Context, ct *config.CompiledTunnel, endpoint string) (runtime.Tunnel, func(), error) {
	if ct == nil {
		return nil, func() {}, fmt.Errorf("tunnel manager: nil CompiledTunnel")
	}
	key := m.shareKey(ct, endpoint)
	mk := mgrKey{Name: ct.Name, Key: key, Fingerprint: ct.Fingerprint}

	m.mu.Lock()
	e, exists := m.entries[mk]
	if !exists {
		e = &tunnelEntry{
			name:      ct.Name,
			sharing:   ct.Sharing,
			keepalive: ct.Keepalive,
			always:    ct.KeepaliveAlways,
		}
		m.entries[mk] = e
	}
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	e.refcount++
	m.mu.Unlock()

	// Exactly one Acquire per entry runs body.Open; the others
	// wait on openOnce and read the result.
	e.openOnce.Do(func() {
		var viaHandle runtime.Tunnel
		var viaRelease func()
		if ct.Via != nil {
			v, rel, err := m.Acquire(ctx, ct.Via, endpoint)
			if err != nil {
				e.openErr = fmt.Errorf("tunnel %q via %q: %w", ct.Name, ct.Via.Name, err)
				return
			}
			viaHandle = v
			viaRelease = rel
		}
		body, ok := ct.Body.(runtime.TunnelRuntime)
		if !ok {
			if viaRelease != nil {
				viaRelease()
			}
			e.openErr = fmt.Errorf("tunnel %q: body %T does not implement TunnelRuntime", ct.Name, ct.Body)
			return
		}
		host := runtime.TunnelHost{
			Name:        ct.Name,
			SecretStore: m.secrets,
			StateDir:    m.stateDir,
			Logger:      log.New(log.Writer(), "tunnel/"+ct.Name+": ", log.LstdFlags),
		}
		if ct.Credential != nil {
			host.Credential = &runtime.TunnelCredential{
				Name: ct.Credential.Symbol.Name,
				Type: ct.Credential.Plugin.Type,
				Body: ct.Credential.Body,
			}
		}
		t, err := body.Open(ctx, host, viaHandle)
		if err != nil {
			if viaRelease != nil {
				viaRelease()
			}
			e.openErr = fmt.Errorf("tunnel %q open: %w", ct.Name, err)
			return
		}
		m.mu.Lock()
		e.tunnel = t
		e.viaRelease = viaRelease
		m.mu.Unlock()
	})

	if e.openErr != nil {
		// Drop our refcount and evict the failed entry so the next
		// Acquire is a fresh first-attempt.
		m.mu.Lock()
		if e.refcount > 0 {
			e.refcount--
		}
		if cur, ok := m.entries[mk]; ok && cur == e {
			delete(m.entries, mk)
		}
		m.mu.Unlock()
		return nil, func() {}, e.openErr
	}

	return wrapTunnel(e.tunnel), m.releaseFunc(mk), nil
}

// shareKey produces the sharing-bucket key for a tunnel + endpoint.
func (m *TunnelManager) shareKey(ct *config.CompiledTunnel, endpoint string) string {
	switch ct.Sharing {
	case runtime.TunnelSharePerEndpoint:
		return endpoint
	case runtime.TunnelSharePerConn:
		return fmt.Sprintf("c%d", m.connSeq.Add(1))
	default:
		return ""
	}
}

// releaseFunc returns a closure that decrements refcount on the
// keyed entry exactly once.
func (m *TunnelManager) releaseFunc(mk mgrKey) func() {
	var once sync.Once
	return func() { once.Do(func() { m.releaseEntry(mk) }) }
}

// releaseEntry decrements the entry's refcount and either tears it
// down immediately or arms an idle timer. `keepalive = "always"` is
// not a special case here — SetPolicy is the sole owner of the
// synthetic +1 that keeps pinned tunnels up; once that pin is
// released, this method tears down like any other.
func (m *TunnelManager) releaseEntry(mk mgrKey) {
	m.mu.Lock()
	e, ok := m.entries[mk]
	if !ok {
		m.mu.Unlock()
		return
	}
	if e.refcount > 0 {
		e.refcount--
	}
	if e.refcount > 0 {
		m.mu.Unlock()
		return
	}
	if e.keepalive == 0 {
		t, vr := e.tunnel, e.viaRelease
		delete(m.entries, mk)
		m.mu.Unlock()
		if t != nil {
			_ = t.Close()
		}
		if vr != nil {
			vr()
		}
		return
	}
	// Idle window: arm a timer.
	d := e.keepalive
	e.timer = time.AfterFunc(d, func() {
		m.mu.Lock()
		cur, ok := m.entries[mk]
		if !ok || cur != e || cur.refcount > 0 {
			m.mu.Unlock()
			return
		}
		t, vr := cur.tunnel, cur.viaRelease
		delete(m.entries, mk)
		m.mu.Unlock()
		if t != nil {
			_ = t.Close()
		}
		if vr != nil {
			vr()
		}
	})
	m.mu.Unlock()
}

// SetPolicy is called on boot and on every policy reload. It diffs
// pinned (`keepalive = "always"`) entries against the new policy:
// new pins get a manager-held +1 refcount (and an Open if the
// tunnel isn't already up); pins removed in the new policy lose
// their +1 (which may immediately tear them down).
//
// Non-pinned entries are unaffected — they survive a reload and
// continue to serve in-flight conns; the policy diff that drops a
// tunnel name entirely is handled lazily, on next Release for the
// affected entry, since dispatchers in flight still hold a handle.
func (m *TunnelManager) SetPolicy(ctx context.Context, policy *config.CompiledPolicy) {
	wantPin := map[mgrKey]*config.CompiledTunnel{}
	if policy != nil {
		for _, ct := range policy.Tunnels {
			if !ct.KeepaliveAlways {
				continue
			}
			// Always-on tunnels pin the singleton bucket. Non-
			// singleton sharings combined with keepalive=always
			// are rare but legal — treat the empty key as the pin
			// target because there's no per-endpoint identity at
			// pin time.
			wantPin[mgrKey{Name: ct.Name, Key: "", Fingerprint: ct.Fingerprint}] = ct
		}
	}

	// Snapshot pinned releases that need to be dropped.
	m.mu.Lock()
	staleRels := make([]func(), 0)
	for mk, rel := range m.pinned {
		if _, keep := wantPin[mk]; !keep {
			staleRels = append(staleRels, rel)
			delete(m.pinned, mk)
		}
	}
	// Tunnels that are still pinned in the new policy don't need
	// re-Acquire — their existing rel keeps the entry alive.
	for mk := range wantPin {
		if _, already := m.pinned[mk]; already {
			delete(wantPin, mk)
		}
	}
	m.mu.Unlock()

	// Drop stale pins outside the lock; each rel calls releaseEntry.
	for _, rel := range staleRels {
		rel()
	}

	// Add new pins. Acquire takes care of the +1; we hold the rel.
	for mk, ct := range wantPin {
		_, rel, err := m.Acquire(ctx, ct, "")
		if err != nil {
			log.Printf("tunnel %q (always-on): pin failed: %v", ct.Name, err)
			continue
		}
		m.mu.Lock()
		m.pinned[mk] = rel
		m.mu.Unlock()
	}
}

// Close tears down every entry. Called at gateway shutdown.
func (m *TunnelManager) Close() {
	m.mu.Lock()
	entries := m.entries
	m.entries = map[mgrKey]*tunnelEntry{}
	m.pinned = map[mgrKey]func(){}
	m.mu.Unlock()
	for _, e := range entries {
		if e.timer != nil {
			e.timer.Stop()
		}
		if e.tunnel != nil {
			_ = e.tunnel.Close()
		}
		if e.viaRelease != nil {
			e.viaRelease()
		}
	}
}

// wrapTunnel hides Close from callers — only the manager closes.
// Dial passes through to the underlying tunnel.
func wrapTunnel(t runtime.Tunnel) runtime.Tunnel {
	return &mgrTunnel{inner: t}
}

type mgrTunnel struct{ inner runtime.Tunnel }

func (m *mgrTunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return m.inner.Dial(ctx, network, addr)
}

// Close on the wrapped handle is a no-op — the manager owns the
// real teardown. release functions are the only way refcount
// drops.
func (m *mgrTunnel) Close() error { return nil }

// dialThrough opens an upstream net.Conn for ep, going through the
// tunnel manager when ep.Tunnel is set or falling back to the
// gateway's direct dialer otherwise. The returned conn carries the
// manager release on its Close method, so callers don't have to
// thread a separate cleanup channel through the dispatcher.
func (g *Gateway) dialThrough(ctx context.Context, ep *config.CompiledEndpoint, network, addr string) (net.Conn, error) {
	if ep == nil || ep.Tunnel == nil || g.tunnels == nil {
		return g.dialer.DialContext(ctx, network, addr)
	}
	t, release, err := g.tunnels.Acquire(ctx, ep.Tunnel, ep.Name)
	if err != nil {
		return nil, err
	}
	c, err := t.Dial(ctx, network, addr)
	if err != nil {
		release()
		return nil, err
	}
	return &releaseConn{Conn: c, release: release}, nil
}

// releaseConn wraps a net.Conn so its Close also releases the
// tunnel handle the manager handed out for this dial. The release
// is idempotent — Close called twice is fine.
type releaseConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (r *releaseConn) Close() error {
	err := r.Conn.Close()
	r.once.Do(func() {
		if r.release != nil {
			r.release()
		}
	})
	return err
}
