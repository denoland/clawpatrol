//go:build linux

package main

// Live end-to-end driver for the plugin-tunnel via+UDP spike. Gated by
// CLAWPATROL_VIA_E2E so it never runs in normal CI. It builds the real
// socks + wireguard plugin binaries, loads a config with a wireguard
// tunnel (optionally `via` a socks tunnel), acquires it through the
// gateway's TunnelManager, dials a target over the WG netstack, and
// checks the HTTP response.
//
// Run (against a live WireGuard server + SOCKS proxy + target):
//
//	CLAWPATROL_VIA_E2E=1 VIA=1 \
//	WG_ENDPOINT=host:51820 WG_PRIV=... WG_PEERPUB=... WG_ADDR=10.9.0.2 \
//	SOCKS_PROXY=host:1080 TARGET=10.9.0.1:8080 \
//	go test ./cmd/clawpatrol -run TestTunnelViaE2E -count=1 -v

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func buildTunnelPlugin(t *testing.T, pkg, name string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	return out
}

func TestTunnelViaE2E(t *testing.T) {
	if os.Getenv("CLAWPATROL_VIA_E2E") == "" {
		t.Skip("set CLAWPATROL_VIA_E2E=1 (plus WG_*/SOCKS_PROXY/TARGET) to run the live spike")
	}
	wgEndpoint := os.Getenv("WG_ENDPOINT")
	wgPriv := os.Getenv("WG_PRIV")
	wgPeerPub := os.Getenv("WG_PEERPUB")
	wgAddr := envOr("WG_ADDR", "10.9.0.2")
	socksProxy := os.Getenv("SOCKS_PROXY")
	target := envOr("TARGET", "10.9.0.1:8080")
	useVia := os.Getenv("VIA") == "1"
	if wgEndpoint == "" || wgPriv == "" || wgPeerPub == "" || (useVia && socksProxy == "") {
		t.Fatal("need WG_ENDPOINT, WG_PRIV, WG_PEERPUB (and SOCKS_PROXY when VIA=1)")
	}

	socksBin := buildTunnelPlugin(t, "./pluginsdk/socks", "socks-tunnel")
	wgBin := buildTunnelPlugin(t, "./pluginsdk/wireguard", "wireguard-tunnel")

	stateDir := t.TempDir()
	mgr := extplugin.New(log.New(os.Stderr, "", 0))
	config.SetPluginLoader(mgr)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	socksBlock := ""
	if useVia {
		socksBlock = fmt.Sprintf(`
plugin "socks_tunnel" {
  source  = %q
  network = "outbound"
  sandbox = "off"
}
tunnel "socks_proxy" "corp" {
  proxy = %q
}
`, socksBin, socksProxy)
	}

	// NOTE: the HCL `via` attribute on a *plugin* tunnel block is a separate,
	// unfinished config-layer gap (plugin tunnel bodies don't yet peel the
	// common via/keepalive/share attrs the way built-in tunnels do via
	// TunnelCommonRead). To exercise the runtime via path here we wire Via
	// directly on the compiled tunnel below.
	hcl := fmt.Sprintf(`
plugin "wireguard_tunnel" {
  source  = %q
  network = "outbound"
  sandbox = "off"
}
%s
gateway {
  state_dir  = %q
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
tunnel "wireguard" "vpn" {
  endpoint        = %q
  private_key     = %q
  peer_public_key = %q
  address         = %q
}
endpoint "https" "via-target" {
  hosts  = ["target.invalid"]
  tunnel = wireguard.vpn
}
profile "default" { credentials = [] }
`, wgBin, socksBlock, stateDir, wgEndpoint, wgPriv, wgPeerPub, wgAddr)

	gw, diags := config.LoadBytes([]byte(hcl), "via-e2e.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ct := policy.Tunnels["vpn"]
	if ct == nil {
		t.Fatalf("no compiled tunnel 'vpn' (have %v)", keysOf(policy.Tunnels))
	}
	if useVia {
		corp := policy.Tunnels["corp"]
		if corp == nil {
			t.Fatalf("no compiled tunnel 'corp' (have %v)", keysOf(policy.Tunnels))
		}
		ct.Via = corp // wire the via chain at runtime (HCL via is a separate gap)
	}

	tm := NewTunnelManager(runtime.EnvSecretStore{}, stateDir)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	t.Logf("acquiring wireguard tunnel (via=%v) -> %s", useVia, wgEndpoint)
	tun, release, err := tm.Acquire(ctx, ct, "via-target")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	// Dial the target over the WG netstack and do a plain HTTP GET.
	t.Logf("dialing %s through the tunnel", target)
	conn, err := tun.Dial(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", target); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	t.Logf("RESPONSE %d: %q", resp.StatusCode, body[:n])
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
}

func keysOf(m map[string]*config.CompiledTunnel) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
