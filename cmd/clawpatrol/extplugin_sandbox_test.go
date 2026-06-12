package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
	"github.com/denoland/clawpatrol/internal/sandbox"
	"github.com/denoland/clawpatrol/internal/sandbox/sandboxtest"
)

// nosyReport mirrors the probeResult the nosy plugin reports in its
// manifest Version field.
type nosyReport struct {
	SecretRead bool `json:"secret_read"`
	HostHome   bool `json:"host_home_read"`
	OutboundOK bool `json:"outbound_ok"`
	LoopbackOK bool `json:"loopback_ok"`
	ProcInitOK bool `json:"proc_init_read"`
}

// nosyInstance gives each nosy-plugin load a unique manifest name and
// credential type. The global plugin registry has no deregistration,
// so two loads sharing a type name collide.
var nosyInstance atomic.Uint64

// buildNosyPlugin compiles the nosy probe plugin with the probe
// targets and a unique manifest name baked in via -ldflags (the
// environment is scrubbed, so the plugin can't receive them at
// runtime). Returns the binary path and the unique plugin name.
func buildNosyPlugin(t *testing.T, secretPath, hostHomeFile, loopbackAddr string) (string, string) {
	t.Helper()
	moduleRoot := moduleRootForTest(t)
	out := filepath.Join(t.TempDir(), "nosy")
	name := fmt.Sprintf("nosyplugin%d", nosyInstance.Add(1))
	ldflags := fmt.Sprintf(
		"-X main.secretPath=%s -X main.hostHomeFile=%s -X main.loopbackAddr=%s -X main.pluginName=%s -X main.credType=%s_noop",
		secretPath, hostHomeFile, loopbackAddr, name, name)
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", out, "./cmd/clawpatrol/testdata/nosyplugin")
	cmd.Dir = moduleRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build nosy plugin: %v\n%s", err, b)
	}
	return out, name
}

// runNosyProbe loads the nosy plugin under the given backend/network
// grants and returns what it observed. The loopback listener stands
// in for "a gateway-side socket on the host network".
func runNosyProbe(t *testing.T, sandboxMode, network string, extraGrants string) (nosyReport, string) {
	t.Helper()

	// A secret the gateway user can read but the plugin must not.
	secretPath := filepath.Join(t.TempDir(), "secret-marker")
	if err := os.WriteFile(secretPath, []byte("top-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	hostHomeFile := filepath.Join(home, ".clawpatrol")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	pluginPath, pluginName := buildNosyPlugin(t, secretPath, hostHomeFile, ln.Addr().String())

	mgr := extplugin.New(nil)
	config.SetPluginLoader(mgr)
	t.Cleanup(func() {
		mgr.Stop()
		config.SetPluginLoader(nil)
	})

	hcl := fmt.Sprintf(`
plugin %q {
  source  = %q
  sandbox = %q
  network = %q
  %s
}

gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
`, pluginName, pluginPath, sandboxMode, network, extraGrants)

	_, diags := config.LoadBytes([]byte(hcl), "nosy-sandbox-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	plugins := mgr.Plugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	mf := plugins[0].Manifest()
	var r nosyReport
	if err := json.Unmarshal([]byte(mf.Version), &r); err != nil {
		t.Fatalf("decode probe report %q: %v", mf.Version, err)
	}
	return r, plugins[0].SandboxMode()
}

// TestNosyPluginBlockedUnderSandbox runs the probe plugin under every
// available backend and asserts the sandbox blocked each boundary
// crossing.
func TestNosyPluginBlockedUnderSandbox(t *testing.T) {
	av := sandboxtest.RequireBackend(t)

	backends := []string{""} // "" = whatever Probe picks by default
	if runtime.GOOS == "linux" && av.Mode == sandbox.ModeNamespaces {
		// Also force the Landlock fallback when the kernel supports it.
		if forced, err := func() (sandbox.Availability, error) {
			t.Setenv(sandbox.EnvBackend, "landlock")
			return sandbox.Probe()
		}(); err == nil && forced.Mode == sandbox.ModeLandlock {
			backends = append(backends, "landlock")
		}
		_ = os.Unsetenv(sandbox.EnvBackend)
	}

	for _, backend := range backends {
		name := backend
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			if backend != "" {
				t.Setenv(sandbox.EnvBackend, backend)
			}
			r, mode := runNosyProbe(t, "enforce", "none", "")
			t.Logf("backend=%s report=%+v", mode, r)
			if r.SecretRead {
				t.Error("plugin read the gateway's secret-marker file")
			}
			if r.HostHome {
				t.Error("plugin read the host home directory")
			}
			if r.OutboundOK {
				t.Error("plugin made an outbound connection under network=none")
			}
			if r.LoopbackOK {
				t.Error("plugin reached a host-network loopback listener under network=none")
			}
			// Landlock can restrict TCP only at ABI >= 4; below that
			// the dial probes may succeed. The filesystem assertions
			// above always hold.
			if mode == string(sandbox.ModeLandlock) && av.LandlockABI < 4 {
				t.Logf("Landlock ABI %d < 4: network restriction not asserted", av.LandlockABI)
			}
		})
	}
}

// TestNosyPluginUnsandboxedProbesSucceed guards against vacuous
// passes: with sandbox = "off" the probes must actually succeed, so a
// blocked result under enforcement is meaningful.
func TestNosyPluginUnsandboxedProbesSucceed(t *testing.T) {
	r, mode := runNosyProbe(t, "off", "outbound", "")
	if mode != string(sandbox.ModeOff) {
		t.Fatalf("sandbox mode = %q, want off", mode)
	}
	if !r.SecretRead {
		t.Error("unsandboxed plugin could not read the secret file (probe is broken)")
	}
	if !r.HostHome {
		t.Log("host home marker absent; skipping host-home positive assertion")
	}
}

// TestNosyPluginReadPathGrant proves an explicit read_paths grant
// flips the secret-marker read to allowed under the sandbox.
func TestNosyPluginReadPathGrant(t *testing.T) {
	sandboxtest.RequireBackend(t)
	// Grant the whole temp root so the per-run secret-marker path is
	// covered (its exact path is allocated inside runNosyProbe).
	r, mode := runNosyProbe(t, "enforce", "none", fmt.Sprintf("read_paths = [%q]", os.TempDir()))
	t.Logf("backend=%s report=%+v", mode, r)
	if !r.SecretRead {
		t.Error("read_paths grant did not allow reading the secret file")
	}
	// Network is still denied even with the read grant.
	if r.OutboundOK {
		t.Error("read_paths grant unexpectedly allowed outbound network")
	}
}
