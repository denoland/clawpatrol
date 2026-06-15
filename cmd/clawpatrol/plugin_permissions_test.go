package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	// The blocked plugin must surface in PluginInfos (the dashboard
	// /api/plugins feed) with its reason, even though it never loaded.
	var blocked *extplugin.PluginInfo
	for _, info := range mgr2.PluginInfos() {
		if info.Name == name {
			blocked = &info
			break
		}
	}
	if blocked == nil || !blocked.Blocked {
		t.Fatalf("escalation-blocked plugin not surfaced in PluginInfos: %+v", blocked)
	}
	if !strings.Contains(blocked.Reason, "escalates permissions") {
		t.Errorf("blocked reason %q missing escalation text", blocked.Reason)
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

// TestPluginApproveUnblocksLoad covers the dashboard's approve-then-load
// path: a plugin held back by an escalation is blocked on load, and
// after Approve records the new permission a reload on the same manager
// loads it cleanly (the blocked attempt never registered its types, so
// the reload is the first registration — no global-registry collision).
func TestPluginApproveUnblocksLoad(t *testing.T) {
	sandboxtest.RequireBackend(t)
	name := fmt.Sprintf("captest%d", capInstance.Add(1))
	dir := t.TempDir()
	binPath := filepath.Join(dir, "plug")
	lockPath := filepath.Join(dir, extplugin.LockfileName)
	hcl := capPluginHCL(name, binPath)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	// Seed the lockfile with a prior network=none approval (a stand-in
	// hash) so the outbound binary reads as an escalation on first load.
	seed := fmt.Sprintf("plugin %q {\n  network = \"none\"\n  hashes = [\"sha256:0000\"]\n}\n", name)
	if err := os.WriteFile(lockPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	buildCapPlugin(t, binPath, name, "outbound")
	mgr := extplugin.New(nil)
	mgr.SetLockfile(lockPath, false)
	config.SetPluginLoader(mgr)
	defer mgr.Stop()

	// Load 1: blocked by the escalation; types are not registered.
	if _, diags := config.LoadBytes([]byte(hcl), "h2.hcl"); !diags.HasErrors() {
		t.Fatal("outbound binary over a none approval was not blocked")
	}
	if info := pluginInfoByName(mgr, name); info == nil || !info.Blocked {
		t.Fatalf("plugin not surfaced as blocked: %+v", info)
	}

	// Operator approves the current binary (records outbound + its hash).
	if _, err := mgr.Approve(context.Background(),
		[]config.PluginSource{{Name: name, Source: binPath}}, []string{name}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Load 2 (the reload apiPluginApprove triggers): the fast path now
	// approves the hash, so the plugin loads and registers.
	if _, diags := config.LoadBytes([]byte(hcl), "h2.hcl"); diags.HasErrors() {
		t.Fatalf("post-approve load failed: %v", diags)
	}
	info := pluginInfoByName(mgr, name)
	if info == nil || info.Blocked {
		t.Fatalf("plugin still blocked after approve: %+v", info)
	}
	if info.Network != "outbound" {
		t.Errorf("post-approve network = %q, want outbound", info.Network)
	}
}

// TestApiPluginApproveEndpoint drives the dashboard's POST
// /api/plugins/approve handler: it approves a plugin held back by an
// escalation and reloads, so the blocked plugin ends up loaded.
func TestApiPluginApproveEndpoint(t *testing.T) {
	sandboxtest.RequireBackend(t)
	name := fmt.Sprintf("captest%d", capInstance.Add(1))
	dir := t.TempDir()
	binPath := filepath.Join(dir, "plug")
	cfgPath := filepath.Join(dir, "gateway.hcl")
	lockPath := filepath.Join(dir, extplugin.LockfileName)
	hcl := capPluginHCL(name, binPath)
	t.Cleanup(func() { config.SetPluginLoader(nil) })

	if err := os.WriteFile(cfgPath, []byte(hcl), 0o644); err != nil {
		t.Fatal(err)
	}
	// Seed a prior network=none approval so the outbound binary loads
	// blocked until the handler re-approves it.
	seed := fmt.Sprintf("plugin %q {\n  network = \"none\"\n  hashes = [\"sha256:0000\"]\n}\n", name)
	if err := os.WriteFile(lockPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	buildCapPlugin(t, binPath, name, "outbound")

	mgr := extplugin.New(nil)
	mgr.SetLockfile(lockPath, false)
	config.SetPluginLoader(mgr)
	defer mgr.Stop()
	if _, diags := config.LoadBytes([]byte(hcl), cfgPath); !diags.HasErrors() {
		t.Fatal("outbound binary over a none approval was not blocked")
	}

	db := openOnboardAuthTestDB(t)
	g := &Gateway{db: db, cfgPath: cfgPath, pluginMgr: mgr}
	g.cfg.Store(&config.Gateway{
		Plugins: []config.PluginSource{{Name: name, Source: binPath}},
	})
	w := &webMux{g: g}

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/approve",
		strings.NewReader(fmt.Sprintf(`{"name":%q}`, name)))
	rw := httptest.NewRecorder()
	w.apiPluginApprove(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Fatalf("approve endpoint = %d, want 204; body=%s", rw.Code, rw.Body.String())
	}
	if lf := readFileString(t, lockPath); !strings.Contains(lf, `network = "outbound"`) {
		t.Fatalf("lockfile not updated to outbound after approve:\n%s", lf)
	}
	info := pluginInfoByName(mgr, name)
	if info == nil || info.Blocked {
		t.Fatalf("plugin still blocked after approve endpoint: %+v", info)
	}

	// Bad request: a missing name is a 400.
	rw = httptest.NewRecorder()
	w.apiPluginApprove(rw, httptest.NewRequest(http.MethodPost,
		"/api/plugins/approve", strings.NewReader(`{}`)))
	if rw.Code != http.StatusBadRequest {
		t.Errorf("empty-name approve = %d, want 400", rw.Code)
	}
}

func pluginInfoByName(mgr *extplugin.Manager, name string) *extplugin.PluginInfo {
	for _, info := range mgr.PluginInfos() {
		if info.Name == name {
			return &info
		}
	}
	return nil
}

// TestPluginInfosShape checks the data the dashboard's /api/plugins
// endpoint serves, loading the real example plugin.
func TestPluginInfosShape(t *testing.T) {
	sandboxtest.RequireBackend(t)
	loadDemoPluginPolicy(t, `dial = ["127.0.0.1:8000"]`)

	var ex *extplugin.PluginInfo
	for _, info := range sharedExampleManager().PluginInfos() {
		if info.Name == "example" {
			ex = &info
			break
		}
	}
	if ex == nil {
		t.Fatal("example plugin missing from PluginInfos")
	}
	if ex.Network != "none" { // forced by the loadDemoPluginPolicy override
		t.Errorf("network = %q, want none", ex.Network)
	}
	if ex.SandboxMode == "" {
		t.Error("empty sandbox mode")
	}
	if len(ex.Credentials) == 0 || len(ex.Tunnels) == 0 || len(ex.Endpoints) == 0 || len(ex.Facets) == 0 {
		t.Errorf("missing declared types: %+v", ex)
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
