package tunnels

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	cruntime "github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestLocalCommandSpawn verifies Open spawns the configured argv,
// the readiness probe waits for the listen socket to accept, Dial
// routes to the configured listen address, and Close kills the
// child. The "real" listener is the test process itself, so the
// command we spawn is just a long sleep — we're testing the
// plugin's lifecycle, not the proxy semantics.
func TestLocalCommandSpawn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Setpgid pattern is unix-only")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	listenAddr := l.Addr().String()

	// Accept-and-discard in the background so Dial succeeds.
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	tn := &LocalCommandTunnel{
		Command:      []string{"sleep", "30"},
		Listen:       listenAddr,
		ReadyProbe:   "tcp",
		ReadyTimeout: "3s",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := cruntime.TunnelHost{Name: "test"}
	rt, err := tn.Open(ctx, host, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Dial should connect to our in-process listener regardless
	// of what addr we pass.
	conn, err := rt.Dial(ctx, "tcp", "ignored:9999")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()

	// Close terminates the spawned `sleep`; the test would hang
	// for 30s if SIGTERM weren't routed to the process group.
	if err := rt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestLocalCommandReadinessTimeout: the configured command does
// nothing, so the probe times out and Open errors.
func TestLocalCommandReadinessTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only")
	}
	tn := &LocalCommandTunnel{
		Command:      []string{"sleep", "5"},
		Listen:       "127.0.0.1:1", // nothing listens
		ReadyProbe:   "tcp",
		ReadyTimeout: "200ms",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := tn.Open(ctx, cruntime.TunnelHost{Name: "test"}, nil)
	if err == nil {
		t.Fatal("Open succeeded with non-listening command, want timeout")
	}
}
