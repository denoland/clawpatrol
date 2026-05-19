package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// fakeTunnel implements runtime.TunnelRuntime for tests. Open returns
// a fakeOpenedTunnel; the test inspects open / close counts.
type fakeTunnel struct {
	openCount       atomic.Int32
	closeCount      atomic.Int32
	dialCount       atomic.Int32
	openErr         error
	dialErr         error
	dialAddr        string
	closePeerOnDial bool
	openDelay       time.Duration
}

func (f *fakeTunnel) Sharing() runtime.TunnelSharing { return runtime.TunnelShareSingleton }

func (f *fakeTunnel) Open(_ context.Context, _ runtime.TunnelHost, via runtime.Tunnel) (runtime.Tunnel, error) {
	f.openCount.Add(1)
	if f.openDelay > 0 {
		time.Sleep(f.openDelay)
	}
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &fakeOpenedTunnel{parent: f, via: via}, nil
}

type fakeOpenedTunnel struct {
	parent *fakeTunnel
	via    runtime.Tunnel
}

func (t *fakeOpenedTunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	t.parent.dialCount.Add(1)
	t.parent.dialAddr = addr
	if t.parent.dialErr != nil {
		return nil, t.parent.dialErr
	}
	if t.via != nil {
		return t.via.Dial(ctx, network, addr)
	}
	a, b := net.Pipe()
	if t.parent.closePeerOnDial {
		_ = a.Close()
	} else {
		_ = a
	}
	return b, nil
}

func (t *fakeOpenedTunnel) Close() error {
	t.parent.closeCount.Add(1)
	return nil
}

// makeCompiledTunnel builds a *config.CompiledTunnel pointing at a
// fakeTunnel body. Sharing / Keepalive / Via are passed through as-is.
func makeCompiledTunnel(name string, sharing string, keepalive time.Duration, always bool, via *config.CompiledTunnel) (*config.CompiledTunnel, *fakeTunnel) {
	body := &fakeTunnel{}
	return &config.CompiledTunnel{
		Name:            name,
		Plugin:          &config.Plugin{Kind: config.KindTunnel, Type: "fake"},
		Body:            body,
		Sharing:         sharing,
		Keepalive:       keepalive,
		KeepaliveAlways: always,
		Via:             via,
	}, body
}

func makeCompiledTunnelWithFingerprint(name string, sharing string, keepalive time.Duration, always bool, via *config.CompiledTunnel, fingerprint string) (*config.CompiledTunnel, *fakeTunnel) {
	ct, fake := makeCompiledTunnel(name, sharing, keepalive, always, via)
	ct.Fingerprint = fingerprint
	return ct, fake
}

// TestManagerSingletonRefcount: two acquires share one Open; release
// of both with keepalive=0 tears it down.
func TestManagerSingletonRefcount(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ct, fake := makeCompiledTunnel("t1", runtime.TunnelShareSingleton, 0, false, nil)

	_, rel1, err := m.Acquire(context.Background(), ct, "ep1")
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	_, rel2, err := m.Acquire(context.Background(), ct, "ep2")
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}

	if got := fake.openCount.Load(); got != 1 {
		t.Errorf("openCount = %d, want 1 (singleton dedup)", got)
	}

	rel1()
	if got := fake.closeCount.Load(); got != 0 {
		t.Errorf("closeCount = %d after one release, want 0", got)
	}
	rel2()
	if got := fake.closeCount.Load(); got != 1 {
		t.Errorf("closeCount = %d after both released, want 1", got)
	}
}

// TestManagerPerEndpoint: per_endpoint sharing keys by endpoint name,
// so two endpoints get two distinct Opens.
func TestManagerPerEndpoint(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ct, fake := makeCompiledTunnel("t1", runtime.TunnelSharePerEndpoint, 0, false, nil)

	_, rel1, _ := m.Acquire(context.Background(), ct, "ep1")
	_, rel2, _ := m.Acquire(context.Background(), ct, "ep2")
	if got := fake.openCount.Load(); got != 2 {
		t.Errorf("openCount = %d, want 2 (per_endpoint)", got)
	}
	rel1()
	rel2()
	if got := fake.closeCount.Load(); got != 2 {
		t.Errorf("closeCount = %d, want 2", got)
	}
}

// TestManagerKeepaliveIdleTimer: refcount drops to 0 and the entry
// stays alive within the idle window; release-then-acquire-again
// before the timer fires reuses the same tunnel.
func TestManagerKeepaliveIdleTimer(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ct, fake := makeCompiledTunnel("t1", runtime.TunnelShareSingleton, 50*time.Millisecond, false, nil)

	_, rel1, _ := m.Acquire(context.Background(), ct, "ep")
	rel1()
	// Within the idle window — re-acquire should reuse.
	_, rel2, _ := m.Acquire(context.Background(), ct, "ep")
	if got := fake.openCount.Load(); got != 1 {
		t.Errorf("openCount = %d after refcount drop+regain, want 1 (idle reuse)", got)
	}
	rel2()
	// Wait for idle timer to expire.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if fake.closeCount.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := fake.closeCount.Load(); got != 1 {
		t.Errorf("closeCount = %d after idle elapse, want 1", got)
	}
}

// TestManagerOpenError: Open failure cleans up the entry so a retry
// behaves like a first-acquire.
func TestManagerOpenError(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ct, fake := makeCompiledTunnel("t1", runtime.TunnelShareSingleton, 0, false, nil)
	fake.openErr = errors.New("nope")

	_, _, err := m.Acquire(context.Background(), ct, "ep")
	if err == nil {
		t.Fatal("acquire succeeded with openErr set, want error")
	}

	// Clear the error and retry — should be a fresh first-acquire.
	fake.openErr = nil
	_, rel, err := m.Acquire(context.Background(), ct, "ep")
	if err != nil {
		t.Fatalf("retry acquire: %v", err)
	}
	if got := fake.openCount.Load(); got != 2 {
		t.Errorf("openCount = %d, want 2 (one failed + one success)", got)
	}
	rel()
}

// TestManagerViaChain: a child tunnel acquires its parent on first-
// open and releases it on teardown, recursively.
func TestManagerViaChain(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	parent, parentFake := makeCompiledTunnel("p", runtime.TunnelShareSingleton, 0, false, nil)
	child, childFake := makeCompiledTunnel("c", runtime.TunnelShareSingleton, 0, false, parent)

	_, rel, err := m.Acquire(context.Background(), child, "ep")
	if err != nil {
		t.Fatalf("acquire child: %v", err)
	}
	if got := parentFake.openCount.Load(); got != 1 {
		t.Errorf("parent openCount = %d, want 1 (via chain)", got)
	}
	if got := childFake.openCount.Load(); got != 1 {
		t.Errorf("child openCount = %d, want 1", got)
	}

	rel()
	if got := childFake.closeCount.Load(); got != 1 {
		t.Errorf("child closeCount = %d, want 1", got)
	}
	if got := parentFake.closeCount.Load(); got != 1 {
		t.Errorf("parent closeCount = %d, want 1 (cascade)", got)
	}
}

// TestManagerKeepaliveAlways: the manager pins a +1 refcount so the
// tunnel stays up after every dispatcher Release. SetPolicy with the
// tunnel removed drops the pin and tears it down.
func TestManagerKeepaliveAlways(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ct, fake := makeCompiledTunnel("t1", runtime.TunnelShareSingleton, 0, true, nil)

	policy := &config.CompiledPolicy{Tunnels: map[string]*config.CompiledTunnel{"t1": ct}}
	m.SetPolicy(context.Background(), policy)

	if got := fake.openCount.Load(); got != 1 {
		t.Errorf("openCount = %d after pin, want 1", got)
	}
	// A dispatcher acquire + release must not tear down.
	_, rel, _ := m.Acquire(context.Background(), ct, "ep")
	rel()
	if got := fake.closeCount.Load(); got != 0 {
		t.Errorf("closeCount = %d while pinned, want 0", got)
	}
	// Drop the pin via SetPolicy with no tunnels.
	m.SetPolicy(context.Background(), &config.CompiledPolicy{Tunnels: map[string]*config.CompiledTunnel{}})
	if got := fake.closeCount.Load(); got != 1 {
		t.Errorf("closeCount = %d after pin drop, want 1", got)
	}
}

func TestManagerKeepaliveAlwaysReopensWhenFingerprintChanges(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	oldCT, oldFake := makeCompiledTunnelWithFingerprint("t1", runtime.TunnelShareSingleton, 0, true, nil, "old-config")
	newCT, newFake := makeCompiledTunnelWithFingerprint("t1", runtime.TunnelShareSingleton, 0, true, nil, "new-config")

	m.SetPolicy(context.Background(), &config.CompiledPolicy{Tunnels: map[string]*config.CompiledTunnel{"t1": oldCT}})
	if got := oldFake.openCount.Load(); got != 1 {
		t.Fatalf("old openCount after initial pin = %d, want 1", got)
	}

	m.SetPolicy(context.Background(), &config.CompiledPolicy{Tunnels: map[string]*config.CompiledTunnel{"t1": newCT}})

	if got := oldFake.closeCount.Load(); got != 1 {
		t.Errorf("old closeCount after same-name config change = %d, want 1", got)
	}
	if got := newFake.openCount.Load(); got != 1 {
		t.Errorf("new openCount after same-name config change = %d, want 1", got)
	}
}

func TestManagerKeepaliveAlwaysFingerprintChangeDoesNotStealInFlightOldTunnel(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	oldCT, oldFake := makeCompiledTunnelWithFingerprint("t1", runtime.TunnelShareSingleton, 0, true, nil, "old-config")
	newCT, newFake := makeCompiledTunnelWithFingerprint("t1", runtime.TunnelShareSingleton, 0, true, nil, "new-config")

	m.SetPolicy(context.Background(), &config.CompiledPolicy{Tunnels: map[string]*config.CompiledTunnel{"t1": oldCT}})
	_, oldDispatcherRel, err := m.Acquire(context.Background(), oldCT, "ep")
	if err != nil {
		t.Fatalf("old dispatcher acquire: %v", err)
	}

	m.SetPolicy(context.Background(), &config.CompiledPolicy{Tunnels: map[string]*config.CompiledTunnel{"t1": newCT}})

	if got := oldFake.closeCount.Load(); got != 0 {
		t.Errorf("old closeCount while dispatcher still holds old tunnel = %d, want 0", got)
	}
	if got := newFake.openCount.Load(); got != 1 {
		t.Fatalf("new openCount after same-name config change = %d, want 1", got)
	}
	oldDispatcherRel()
	if got := oldFake.closeCount.Load(); got != 1 {
		t.Errorf("old closeCount after old dispatcher release = %d, want 1", got)
	}
}

// TestManagerConcurrentAcquire: many goroutines acquiring the same
// singleton tunnel still produce exactly one Open.
func TestManagerConcurrentAcquire(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ct, fake := makeCompiledTunnel("t1", runtime.TunnelShareSingleton, 100*time.Millisecond, false, nil)
	fake.openDelay = 20 * time.Millisecond

	var wg sync.WaitGroup
	rels := make([]func(), 16)
	for i := range rels {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, rel, err := m.Acquire(context.Background(), ct, "ep")
			if err != nil {
				t.Errorf("acquire %d: %v", i, err)
				return
			}
			rels[i] = rel
		}()
	}
	wg.Wait()
	if got := fake.openCount.Load(); got != 1 {
		t.Errorf("openCount = %d under concurrent acquire, want 1", got)
	}
	for _, r := range rels {
		if r != nil {
			r()
		}
	}
}

// credTunnel is a fakeTunnel variant whose opened handle satisfies
// runtime.TunnelCredentialNamer + runtime.TunnelDisconnector, so the
// manager's DisconnectCredential path is exercised end-to-end.
type credTunnel struct {
	fakeTunnel
	credential   string
	disconnectCt atomic.Int32
	disconnectEr error
}

func (c *credTunnel) Open(_ context.Context, _ runtime.TunnelHost, via runtime.Tunnel) (runtime.Tunnel, error) {
	c.openCount.Add(1)
	if c.openErr != nil {
		return nil, c.openErr
	}
	return &credOpenedTunnel{parent: c, via: via}, nil
}

type credOpenedTunnel struct {
	parent *credTunnel
	via    runtime.Tunnel
}

func (t *credOpenedTunnel) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	t.parent.dialCount.Add(1)
	_, b := net.Pipe()
	return b, nil
}

func (t *credOpenedTunnel) Close() error {
	t.parent.closeCount.Add(1)
	return nil
}

func (t *credOpenedTunnel) CredentialName() string { return t.parent.credential }

func (t *credOpenedTunnel) Disconnect(_ context.Context) error {
	t.parent.disconnectCt.Add(1)
	return t.parent.disconnectEr
}

func makeCredTunnel(name, credential string) (*config.CompiledTunnel, *credTunnel) {
	body := &credTunnel{credential: credential}
	return &config.CompiledTunnel{
		Name:    name,
		Plugin:  &config.Plugin{Kind: config.KindTunnel, Type: "fake_cred"},
		Body:    body,
		Sharing: runtime.TunnelShareSingleton,
	}, body
}

// TestDisconnectCredential: matching entries get Disconnect-then-Close,
// non-matching entries are untouched, and the next Acquire on the
// evicted name builds a fresh runtime.
func TestDisconnectCredential(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ctA, fakeA := makeCredTunnel("tnA", "credX")
	ctB, fakeB := makeCredTunnel("tnB", "credY")

	_, relA, err := m.Acquire(context.Background(), ctA, "ep")
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer relA()
	_, relB, err := m.Acquire(context.Background(), ctB, "ep")
	if err != nil {
		t.Fatalf("acquire B: %v", err)
	}
	defer relB()

	if err := m.DisconnectCredential(context.Background(), "credX"); err != nil {
		t.Fatalf("DisconnectCredential: %v", err)
	}
	if got := fakeA.disconnectCt.Load(); got != 1 {
		t.Errorf("credX disconnect count = %d, want 1", got)
	}
	if got := fakeA.closeCount.Load(); got != 1 {
		t.Errorf("credX close count = %d, want 1", got)
	}
	if got := fakeB.disconnectCt.Load(); got != 0 {
		t.Errorf("credY disconnect count = %d, want 0 (non-matching)", got)
	}
	if got := fakeB.closeCount.Load(); got != 0 {
		t.Errorf("credY close count = %d, want 0 (non-matching)", got)
	}

	// Re-Acquire on the evicted tunnel runs Open again — proves the
	// entry was force-evicted regardless of the lingering release
	// closure held by relA.
	_, rel2, err := m.Acquire(context.Background(), ctA, "ep")
	if err != nil {
		t.Fatalf("re-acquire A: %v", err)
	}
	defer rel2()
	if got := fakeA.openCount.Load(); got != 2 {
		t.Errorf("credX openCount after evict+re-acquire = %d, want 2", got)
	}
}

// TestDisconnectCredentialUnknown: a credential with no matching live
// runtime is a silent no-op (no error, no Close calls).
func TestDisconnectCredentialUnknown(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ct, fake := makeCredTunnel("tn", "credX")
	_, rel, err := m.Acquire(context.Background(), ct, "ep")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer rel()
	if err := m.DisconnectCredential(context.Background(), "nope"); err != nil {
		t.Fatalf("DisconnectCredential: %v", err)
	}
	if got := fake.disconnectCt.Load(); got != 0 {
		t.Errorf("disconnect count = %d, want 0", got)
	}
	if got := fake.closeCount.Load(); got != 0 {
		t.Errorf("close count = %d, want 0", got)
	}
}

// TestDisconnectCredentialErrorIsNonFatal: a Disconnect error surfaces
// from the manager but eviction still completes — Close still ran.
func TestDisconnectCredentialErrorIsNonFatal(t *testing.T) {
	m := NewTunnelManager(runtime.EnvSecretStore{}, "")
	ct, fake := makeCredTunnel("tn", "credX")
	fake.disconnectEr = errors.New("boom")
	_, rel, err := m.Acquire(context.Background(), ct, "ep")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer rel()
	err = m.DisconnectCredential(context.Background(), "credX")
	if err == nil || err.Error() != "boom" {
		t.Fatalf("DisconnectCredential err = %v, want boom", err)
	}
	if got := fake.closeCount.Load(); got != 1 {
		t.Errorf("close count = %d, want 1 (evict proceeds past logout error)", got)
	}
}
