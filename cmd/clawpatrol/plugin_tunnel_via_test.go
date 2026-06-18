package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestPluginTunnelViaCompiles proves the `via` attribute on an EXTERNAL
// (plugin) tunnel block is peeled and resolved: example_passthrough chains
// through example_socks, and the compiled tunnel's Via pointer is wired —
// the same as a built-in tunnel. (Plugin tunnel bodies decode the common
// via/share/keepalive/credential attrs themselves, since tunnels skip the
// loader's frameworkAttrsByKind extraction.)
func TestPluginTunnelViaCompiles(t *testing.T) {
	pluginPath := buildSharedExamplePlugin(t)
	mgr := sharedExampleManager()
	config.SetPluginLoader(mgr)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	gw, diags := config.LoadBytes([]byte(fmt.Sprintf(`
plugin "example" {
  source  = %q
  network = "none"
}
gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
tunnel "example_socks" "corp" {
  proxy     = "10.0.0.9:1080"
  share     = "per_conn"
  keepalive = "5m"
}
tunnel "example_passthrough" "chained" {
  via = example_socks.corp
}
profile "default" { credentials = [] }
`, pluginPath)), "plugin-tunnel-via.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	chained, corp := policy.Tunnels["chained"], policy.Tunnels["corp"]
	if chained == nil || corp == nil {
		t.Fatalf("missing compiled tunnels (have %v)", keysOfTunnels(policy.Tunnels))
	}
	if chained.Via != corp {
		t.Fatalf("via not wired on plugin tunnel: chained.Via = %v, want corp", chained.Via)
	}
	// share / keepalive on a plugin tunnel are peeled + compiled too.
	if corp.Sharing != "per_conn" {
		t.Errorf("share not wired: corp.Sharing = %q, want per_conn", corp.Sharing)
	}
	if corp.Keepalive != 5*time.Minute {
		t.Errorf("keepalive not wired: corp.Keepalive = %v, want 5m", corp.Keepalive)
	}
}

// TestPluginTunnelViaUnknownFails proves a `via` naming an undeclared
// tunnel is caught (rather than silently dropped).
func TestPluginTunnelViaUnknownFails(t *testing.T) {
	pluginPath := buildSharedExamplePlugin(t)
	mgr := sharedExampleManager()
	config.SetPluginLoader(mgr)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	gw, diags := config.LoadBytes([]byte(fmt.Sprintf(`
plugin "example" { source = %q, network = "none" }
gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
tunnel "example_socks" "corp"    { proxy = "10.0.0.9:1080" }
tunnel "example_passthrough" "x" { via   = example_socks.nope }
profile "default" { credentials = [] }
`, pluginPath)), "plugin-tunnel-via-bad.hcl")
	// An undeclared `via` target is rejected — either at load (the
	// bare-name ref doesn't resolve) or at compile (link pass).
	if diags.HasErrors() {
		return
	}
	if _, err := config.Compile(gw); err == nil {
		t.Fatal("expected an error for via referencing an undeclared tunnel")
	} else if !strings.Contains(err.Error(), "via") && !strings.Contains(err.Error(), "nope") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPluginTunnelViaE2E dials a target through a chain of two PLUGIN
// tunnels wired entirely in HCL: example_passthrough `via` example_socks.
// The gateway routes passthrough's transport through the socks parent,
// which CONNECTs to the target via an in-test SOCKS5 proxy — proving the
// HCL `via` on a plugin tunnel works end to end (sandbox on), not just at
// compile time.
func TestPluginTunnelViaE2E(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello-through-chained-plugin-tunnels")
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")
	socksAddr := startTestSocks5(t)

	pluginPath := buildSharedExamplePlugin(t)
	mgr := sharedExampleManager()
	config.SetPluginLoader(mgr)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	gw, diags := config.LoadBytes([]byte(fmt.Sprintf(`
plugin "example" {
  source  = %q
  network = "none"
}
gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
tunnel "example_socks" "corp" {
  proxy = %q
}
tunnel "example_passthrough" "chained" {
  via = example_socks.corp
}
profile "default" { credentials = [] }
`, pluginPath, socksAddr)), "plugin-tunnel-via-e2e.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ct := policy.Tunnels["chained"]
	if ct == nil || ct.Via == nil {
		t.Fatalf("chained tunnel or its via not compiled: %+v", ct)
	}

	tm := NewTunnelManager(runtime.EnvSecretStore{}, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tun, release, err := tm.Acquire(ctx, ct, "demo")
	if err != nil {
		t.Fatalf("acquire chained tunnel: %v", err)
	}
	defer release()

	conn, err := tun.Dial(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial through chain: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", targetAddr); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "hello-through-chained-plugin-tunnels") {
		t.Fatalf("got status %d body %q", resp.StatusCode, body)
	}
}

func keysOfTunnels(m map[string]*config.CompiledTunnel) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
