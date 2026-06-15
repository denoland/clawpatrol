package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/extplugin"
	"github.com/denoland/clawpatrol/internal/sandbox/sandboxtest"
)

// capInstance gives each test a unique plugin name + credential type
// (the global plugin registry has no deregistration).
var capInstance atomic.Uint64

// buildCapPlugin compiles the capability test plugin with its name,
// credential type, and declared network baked in via -ldflags.
func buildCapPlugin(t *testing.T, out, name, network string) {
	t.Helper()
	ldflags := fmt.Sprintf("-X main.pluginName=%s -X main.credType=%s_noop -X main.network=%s",
		name, name, network)
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", out, "./cmd/clawpatrol/testdata/capplugin")
	cmd.Dir = moduleRootForTest(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cap plugin (%s): %v\n%s", network, err, b)
	}
}

func capPluginHCL(name, source string) string {
	return fmt.Sprintf(`
plugin %q { source = %q }

gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
`, name, source)
}

// TestPluginPermissionTOFUAndEscalation is the security crux: a
// plugin's manifest-declared network is trusted on first use and
// recorded in the lockfile; an upgrade that escalates it fails config
// load until re-approved.
func TestPluginPermissionTOFUAndEscalation(t *testing.T) {
	sandboxtest.RequireBackend(t)
	name := fmt.Sprintf("captest%d", capInstance.Add(1))
	dir := t.TempDir()
	binPath := filepath.Join(dir, "plug")
	lockPath := filepath.Join(dir, extplugin.LockfileName)
	hcl := capPluginHCL(name, binPath)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	// v1 declares network=none. First load => trust on first use:
	// records none in the lockfile and loads.
	buildCapPlugin(t, binPath, name, "none")
	mgr := extplugin.New(nil)
	mgr.SetLockfile(lockPath, false)
	config.SetPluginLoader(mgr)
	if _, diags := config.LoadBytes([]byte(hcl), "perm-test.hcl"); diags.HasErrors() {
		t.Fatalf("v1 load: %v", diags)
	}
	mgr.Stop()
	if lf := readFileString(t, lockPath); !strings.Contains(lf, `network = "none"`) {
		t.Fatalf("lockfile did not record network=none after first load:\n%s", lf)
	}

	// v2 keeps the same name but declares network=outbound. Rebuilt at
	// the same path so the hash changes (an "upgrade"). Load must fail
	// closed with an escalation diagnostic.
	buildCapPlugin(t, binPath, name, "outbound")
	mgr2 := extplugin.New(nil)
	mgr2.SetLockfile(lockPath, false)
	config.SetPluginLoader(mgr2)
	_, diags := config.LoadBytes([]byte(hcl), "perm-test.hcl")
	if !diags.HasErrors() {
		t.Fatal("v2 escalation (none -> outbound) was not blocked")
	}
	msg := diags.Error()
	for _, want := range []string{"escalates permissions", `network="outbound"`, "approve"} {
		if !strings.Contains(msg, want) {
			t.Errorf("escalation diagnostic %q missing %q", msg, want)
		}
	}
	mgr2.Stop()
	// The lockfile must still record the old (none) approval — the
	// escalation must not have been silently written.
	if lf := readFileString(t, lockPath); !strings.Contains(lf, `network = "none"`) {
		t.Fatalf("lockfile changed despite blocked escalation:\n%s", lf)
	}

	// Operator re-approves the upgrade: records outbound + the new hash.
	mgr3 := extplugin.New(nil)
	mgr3.SetLockfile(lockPath, false)
	approved, err := mgr3.Approve(context.Background(),
		[]config.PluginSource{{Name: name, Source: binPath}}, []string{name})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	mgr3.Stop()
	if len(approved) != 1 || approved[0].Network != "outbound" {
		t.Fatalf("approve result = %+v, want one outbound entry", approved)
	}
	if lf := readFileString(t, lockPath); !strings.Contains(lf, `network = "outbound"`) {
		t.Fatalf("lockfile not updated to outbound after approve:\n%s", lf)
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
