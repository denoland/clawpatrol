package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
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
