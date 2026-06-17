package extplugin

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

// mkRelease builds a release spec with one archive per platform plus a
// SHA256SUMS asset, mirroring the documented goreleaser layout.
func mkRelease(t *testing.T, repo, ver string, plats []string) relSpec {
	t.Helper()
	assets := map[string][]byte{}
	var sums strings.Builder
	for _, pl := range plats {
		name := fmt.Sprintf("%s_%s_%s.tar.gz", repo, ver, pl)
		content := tarGz(t, map[string][]byte{repo: []byte(ver + "-" + pl)}, repo)
		assets[name] = content
		fmt.Fprintf(&sums, "%s  %s\n", sha256hex(content), name)
	}
	assets[fmt.Sprintf("%s_%s_SHA256SUMS", repo, ver)] = []byte(sums.String())
	return relSpec{tag: "v" + ver, assets: assets}
}

func TestInstallUpdateLock(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plats := []string{"linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"}
	if !slices.Contains(plats, platformToken()) {
		plats = append(plats, platformToken()) // ensure the host build exists
	}
	srv := newReleaseServer(t, owner, repo, []relSpec{
		mkRelease(t, repo, "1.2.0", plats),
		mkRelease(t, repo, "1.3.0", plats),
	})

	m, _ := newFetchTestManager(t, srv.URL)
	// network override => Install records it without spawning the plugin.
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin", Version: "~> 1.2", Network: "outbound"}
	specs := []config.PluginSource{sp}
	ctx := context.Background()

	// Seed a pin at v1.2.0 on disk; install (no upgrade) must keep it.
	m.lock.setSource(repo, "github.com/acme/myplugin", "v1.2.0", "~> 1.2", "", false)
	if err := m.lock.save(); err != nil {
		t.Fatal(err)
	}
	res, err := m.Install(ctx, specs, nil, false)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(res) != 1 || res[0].Version != "v1.2.0" || res[0].Updated {
		t.Fatalf("install kept-pin = %+v, want v1.2.0 not updated", res)
	}
	if e, _ := m.lock.get(repo); e.Network != "outbound" || len(e.Hashes) != 1 {
		t.Fatalf("after install entry = %+v, want network=outbound and one hash", e)
	}

	// update re-resolves ~> 1.2 to the newest tag v1.3.0 and re-pins.
	res, err = m.Install(ctx, specs, nil, true)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if res[0].Version != "v1.3.0" || !res[0].Updated || res[0].WasLocked != "v1.2.0" {
		t.Fatalf("update = %+v, want v1.2.0 -> v1.3.0 updated", res[0])
	}
	e, _ := m.lock.get(repo)
	if e.Version != "v1.3.0" {
		t.Fatalf("locked version = %q, want v1.3.0", e.Version)
	}

	// lock records every platform build's hash for the pinned version.
	if _, err := m.LockPlatforms(ctx, specs, nil); err != nil {
		t.Fatalf("lock: %v", err)
	}
	e, _ = m.lock.get(repo)
	if len(e.Hashes) != len(plats) {
		t.Fatalf("locked %d platform hashes, want %d (%v)", len(e.Hashes), len(plats), plats)
	}
}

// TestInstallUpgradeClearsPrivileged is the regression test for the
// silent-privilege-grant bypass: a manifest-less UPGRADE of a
// previously-privileged-approved plugin must not let the new binary inherit
// the old version's privileged grant. install can't read a manifest-less
// release's declaration (it doesn't spawn), so it must clear the grant —
// the new version then fails closed at load until `plugins approve` re-grants
// it. Without the fix, the upgraded binary would silently run unsandboxed.
func TestInstallUpgradeClearsPrivileged(t *testing.T) {
	repo := "ssh_tools"
	plats := []string{platformToken()}
	srv := newReleaseServer(t, "o", repo, []relSpec{
		mkRelease(t, repo, "1.2.0", plats),
		mkRelease(t, repo, "1.3.0", plats),
	})
	m, _ := newFetchTestManager(t, srv.URL)
	// Network override => install records without spawning the fake binary.
	sp := config.PluginSource{Name: repo, Source: "github.com/o/ssh_tools", Version: "~> 1.2", Network: "outbound"}
	specs := []config.PluginSource{sp}
	ctx := context.Background()

	// Seed a pin at v1.2.0 so the first install keeps it (rather than
	// resolving ~> 1.2 to the newest in range).
	m.lock.setSource(repo, "github.com/o/ssh_tools", "v1.2.0", "~> 1.2", "", false)
	if err := m.lock.save(); err != nil {
		t.Fatal(err)
	}
	// Install v1.2.0, then simulate the operator approving it as privileged
	// (what `plugins approve` records for a manifest-less release after
	// probing the binary).
	if _, err := m.Install(ctx, specs, nil, false); err != nil {
		t.Fatalf("install v1.2.0: %v", err)
	}
	m.lock.setPrivileged(repo, true)
	if err := m.lock.save(); err != nil {
		t.Fatal(err)
	}
	if e, _ := m.lock.get(repo); !e.Privileged || e.Version != "v1.2.0" {
		t.Fatalf("precondition: entry = %+v, want privileged v1.2.0", e)
	}

	// Upgrade to the manifest-less v1.3.0. The stale grant must be dropped.
	if _, err := m.Install(ctx, specs, nil, true); err != nil {
		t.Fatalf("update v1.3.0: %v", err)
	}
	e, _ := m.lock.get(repo)
	if e.Version != "v1.3.0" {
		t.Fatalf("version = %q, want v1.3.0", e.Version)
	}
	if e.Privileged {
		t.Fatalf("BYPASS: upgraded binary inherited privileged grant: %+v", e)
	}

	// Re-load the lockfile from disk to confirm it was persisted, not just
	// the in-memory view.
	if err := m.lock.load(); err != nil {
		t.Fatal(err)
	}
	if e, _ := m.lock.get(repo); e.Privileged {
		t.Fatalf("BYPASS persisted on disk: %+v", e)
	}
}

func TestInstallFirstUsePicksNewest(t *testing.T) {
	repo := "p"
	plats := []string{platformToken()}
	srv := newReleaseServer(t, "o", repo, []relSpec{
		mkRelease(t, repo, "1.0.0", plats),
		mkRelease(t, repo, "1.5.0", plats),
		mkRelease(t, repo, "2.0.0", plats),
	})
	m, _ := newFetchTestManager(t, srv.URL)
	sp := config.PluginSource{Name: repo, Source: "github.com/o/p", Version: "~> 1.0", Network: "none"}

	res, err := m.Install(context.Background(), []config.PluginSource{sp}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Version != "v1.5.0" || res[0].WasLocked != "" {
		t.Fatalf("first install = %+v, want newest-in-range v1.5.0", res[0])
	}
}

func TestCheckUpdates(t *testing.T) {
	repo := "p"
	plats := []string{platformToken()}
	srv := newReleaseServer(t, "o", repo, []relSpec{
		mkRelease(t, repo, "1.2.0", plats),
		mkRelease(t, repo, "1.4.0", plats),
		mkRelease(t, repo, "2.0.0", plats), // outside ~> 1.2, must be ignored
	})
	m, _ := newFetchTestManager(t, srv.URL)
	sp := config.PluginSource{Name: repo, Source: "github.com/o/p", Version: "~> 1.2", Network: "none"}
	specs := []config.PluginSource{sp}

	// Pin v1.2.0, then check: the newest in-range is v1.4.0.
	m.lock.setSource(repo, "github.com/o/p", "v1.2.0", "~> 1.2", "", false)
	if err := m.lock.save(); err != nil {
		t.Fatal(err)
	}
	m.CheckUpdates(context.Background(), specs)
	infos := m.PluginInfos()
	// No loaded plugins, but CheckUpdates keyed by source; assert via the map.
	m.mu.Lock()
	got := m.updates[sp.Source]
	m.mu.Unlock()
	if got != "v1.4.0" {
		t.Fatalf("update available = %q, want v1.4.0 (2.0.0 is out of range)", got)
	}
	_ = infos

	// Pin to the newest in range: no update reported.
	m.lock.setSource(repo, "github.com/o/p", "v1.4.0", "~> 1.2", "", false)
	if err := m.lock.save(); err != nil {
		t.Fatal(err)
	}
	m.CheckUpdates(context.Background(), specs)
	m.mu.Lock()
	got = m.updates[sp.Source]
	m.mu.Unlock()
	if got != "" {
		t.Fatalf("update available = %q, want none", got)
	}
}

func TestInstallSkipsLocalAndUnknownName(t *testing.T) {
	m, _ := newFetchTestManager(t, "")
	specs := []config.PluginSource{{Name: "loc", Source: "/local/bin"}}
	// Local-only config: install is a no-op, no error.
	if res, err := m.Install(context.Background(), specs, nil, false); err != nil || len(res) != 0 {
		t.Fatalf("install local = %v %+v, want no-op", err, res)
	}
	// Naming a plugin that isn't in the config errors.
	if _, err := m.Install(context.Background(), specs, []string{"ghost"}, false); err == nil ||
		!strings.Contains(err.Error(), `no plugin "ghost"`) {
		t.Fatalf("want unknown-name error, got %v", err)
	}
}
