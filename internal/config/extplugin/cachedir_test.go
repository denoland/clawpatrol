package extplugin

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

// TestCacheDirLocked covers the cache-root selection: cacheDir when set,
// otherwise stateDir. stateDir itself (the secret-store / sandbox
// read_paths boundary) is unaffected by a cache override.
func TestCacheDirLocked(t *testing.T) {
	m := New(nil)
	m.setStateDir("/state")
	if got := m.cacheDirLocked(); got != "/state" {
		t.Errorf("unset cacheDir = %q, want /state", got)
	}
	m.SetCacheDir("/cache")
	if got := m.cacheDirLocked(); got != "/cache" {
		t.Errorf("set cacheDir = %q, want /cache", got)
	}
	if got := m.stateDirLocked(); got != "/state" {
		t.Errorf("stateDirLocked = %q, want /state (cache override must not move it)", got)
	}
}

// TestResolvePluginBinaryCacheDirOverride checks that SetCacheDir (the seam
// behind --plugin-cache-dir) directs the fetched binary to that dir and
// leaves the secret-store stateDir untouched — this is what lets the
// verification commands cache somewhere writable instead of a production
// state_dir.
func TestResolvePluginBinaryCacheDirOverride(t *testing.T) {
	srv, sp, payload := newCacheTestRelease(t)
	m, stateDir := newFetchTestManager(t, srv.URL)
	cacheDir := t.TempDir()
	m.SetCacheDir(cacheDir)

	path, _, err := m.resolvePluginBinary(context.Background(), sp, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.HasPrefix(path, cacheDir) {
		t.Errorf("binary cached at %q, want under cacheDir %q", path, cacheDir)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, payload) {
		t.Errorf("cached binary content = %q, want payload", got)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "plugins")); !os.IsNotExist(err) {
		t.Errorf("stateDir/plugins exists (err=%v); cache leaked into the secret-store dir", err)
	}
}

// newCacheTestRelease stands up a release server serving a single tagged
// build of github.com/acme/myplugin and returns it with a matching source
// spec and the binary payload.
func newCacheTestRelease(t *testing.T) (*httptest.Server, config.PluginSource, []byte) {
	t.Helper()
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	payload := []byte("plugin-cachedir-payload")
	archive := tarGz(t, map[string][]byte{repo: payload}, repo)
	archiveName := fmt.Sprintf("%s_1.2.0_%s.tar.gz", repo, plat)
	sumsName := fmt.Sprintf("%s_1.2.0_SHA256SUMS", repo)
	sums := fmt.Sprintf("%s  %s\n", sha256hex(archive), archiveName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.2.0",
		assets: map[string][]byte{archiveName: archive, sumsName: []byte(sums)},
	}})
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin", Version: "~> 1.2"}
	return srv, sp, payload
}
