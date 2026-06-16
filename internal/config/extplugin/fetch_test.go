package extplugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// tarGz builds a gzip-compressed tar with the given files; execName is
// given mode 0755, the rest 0644.
func tarGz(t *testing.T, files map[string][]byte, execName string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		mode := int64(0o644)
		if name == execName {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type relSpec struct {
	tag    string
	assets map[string][]byte // name -> bytes
}

// newReleaseServer serves the subset of the GitHub releases API that the
// fetcher uses, plus asset downloads at /dl/<name>.
func newReleaseServer(t *testing.T, owner, repo string, rels []relSpec) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	relJSON := func(r relSpec) map[string]any {
		var assets []map[string]any
		for name := range r.assets {
			assets = append(assets, map[string]any{
				"name":                 name,
				"browser_download_url": srv.URL + "/dl/" + name,
				"size":                 len(r.assets[name]),
			})
		}
		return map[string]any{"tag_name": r.tag, "assets": assets}
	}
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/releases", owner, repo), func(w http.ResponseWriter, _ *http.Request) {
		var out []map[string]any
		for _, r := range rels {
			out = append(out, relJSON(r))
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	for _, r := range rels {
		r := r
		mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/releases/tags/%s", owner, repo, r.tag), func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(relJSON(r))
		})
	}
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/dl/")
		for _, rel := range rels {
			if b, ok := rel.assets[name]; ok {
				_, _ = w.Write(b)
				return
			}
		}
		http.Error(w, "no asset", http.StatusNotFound)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestParseShaSumsAndPickAsset(t *testing.T) {
	raw := "aaaa  myplugin_1.2.0_linux_amd64.tar.gz\n" +
		strings.Repeat("b", 64) + "  myplugin_1.2.0_linux_arm64.tar.gz\n" +
		strings.Repeat("c", 64) + " *myplugin_1.2.0_darwin_arm64.tar.gz\n" +
		"# a comment line\n"
	sums, err := parseShaSums([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	// "aaaa" is too short (not 64) and is dropped.
	if _, ok := sums["myplugin_1.2.0_linux_amd64.tar.gz"]; ok {
		t.Error("short hash should have been skipped")
	}
	// linux_arm must not match linux_arm64.
	if got, _ := sums.pickAsset("linux_arm64"); got != "myplugin_1.2.0_linux_arm64.tar.gz" {
		t.Errorf("pickAsset(linux_arm64) = %q", got)
	}
	if _, err := sums.pickAsset("linux_arm"); err == nil {
		t.Error("pickAsset(linux_arm) should not match the arm64 archive")
	}
	if got, _ := sums.pickAsset("darwin_arm64"); got != "myplugin_1.2.0_darwin_arm64.tar.gz" {
		t.Errorf("pickAsset(darwin_arm64) = %q (the * binary marker should be stripped)", got)
	}
}

func TestExtractBinary(t *testing.T) {
	payload := []byte("\x7fELF fake binary contents")
	archive := tarGz(t, map[string][]byte{
		"README":   []byte("docs"),
		"myplugin": payload,
	}, "myplugin")
	dir := t.TempDir()
	src := filepath.Join(dir, "a.tar.gz")
	if err := os.WriteFile(src, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "out")
	if err := extractBinary(src, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("extracted %q (err %v), want the executable file", got, err)
	}
	if fi, _ := os.Stat(dest); fi.Mode()&0o100 == 0 {
		t.Error("extracted binary is not executable")
	}
}

// newFetchTestManager wires a Manager with a temp state dir + lockfile
// pointed at the given GitHub API base.
func newFetchTestManager(t *testing.T, ghBase string) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	m := New(nil)
	m.SetLockfile(filepath.Join(dir, LockfileName), false)
	if err := m.lock.load(); err != nil {
		t.Fatal(err)
	}
	m.setStateDir(dir)
	m.ghBase = ghBase
	return m, dir
}

func TestResolvePluginBinaryDownloadCacheAndPin(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	payload := []byte("plugin-v1.2.0-payload")
	archive := tarGz(t, map[string][]byte{repo: payload}, repo)
	archiveName := fmt.Sprintf("%s_1.2.0_%s.tar.gz", repo, plat)
	sumsName := fmt.Sprintf("%s_1.2.0_SHA256SUMS", repo)
	sums := fmt.Sprintf("%s  %s\n", sha256hex(archive), archiveName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.2.0",
		assets: map[string][]byte{archiveName: archive, sumsName: []byte(sums)},
	}})

	m, dir := newFetchTestManager(t, srv.URL)
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin", Version: "~> 1.2"}

	// First use: resolves ~> 1.2 -> v1.2.0, downloads, caches, TOFU-records.
	path, err := m.resolvePluginBinary(context.Background(), sp)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	wantPath := filepath.Join(dir, "plugins", "github.com", owner, repo, "v1.2.0", plat, repo)
	if path != wantPath {
		t.Errorf("cache path = %q, want %q", path, wantPath)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, payload) {
		t.Errorf("cached binary content = %q, want payload", got)
	}
	e, ok := m.lock.get(repo)
	if !ok || e.Source != "github.com/acme/myplugin" || e.Version != "v1.2.0" || e.Constraints != "~> 1.2" {
		t.Fatalf("lockfile not TOFU-recorded: %+v ok=%v", e, ok)
	}

	// Second resolve is offline (cache hit): close the server first.
	srv.Close()
	path2, err := m.resolvePluginBinary(context.Background(), sp)
	if err != nil || path2 != wantPath {
		t.Fatalf("cache-hit resolve failed: %v (path %q)", err, path2)
	}
}

func TestResolvePluginBinaryConstraintDriftFailsClosed(t *testing.T) {
	m, dir := newFetchTestManager(t, "http://127.0.0.1:0") // never dialed
	// Seed a lock entry pinned to v1.2.0.
	m.lock.setSource("p", "github.com/acme/myplugin", "v1.2.0", "~> 1.2")
	// Pretend the binary is cached so a cache hit would otherwise return.
	plat := platformToken()
	cached := filepath.Join(dir, "plugins", "github.com", "acme", "myplugin", "v1.2.0", plat, "myplugin")
	if err := os.MkdirAll(filepath.Dir(cached), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Operator tightened the constraint so the locked version no longer fits.
	sp := config.PluginSource{Name: "p", Source: "github.com/acme/myplugin", Version: "~> 2.0"}
	_, err := m.resolvePluginBinary(context.Background(), sp)
	if err == nil || !strings.Contains(err.Error(), "no longer satisfies") {
		t.Fatalf("want constraint-drift fail-closed, got %v", err)
	}

	// The matching constraint takes the offline cache hit.
	sp.Version = "~> 1.2"
	if got, err := m.resolvePluginBinary(context.Background(), sp); err != nil || got != cached {
		t.Fatalf("pinned cache hit failed: %v (got %q)", err, got)
	}
}

func TestResolvePluginBinaryTamperRejected(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	archive := tarGz(t, map[string][]byte{repo: []byte("real")}, repo)
	archiveName := fmt.Sprintf("%s_1.0.0_%s.tar.gz", repo, plat)
	sumsName := fmt.Sprintf("%s_1.0.0_SHA256SUMS", repo)
	// SHA256SUMS advertises a hash that does NOT match the served archive.
	sums := fmt.Sprintf("%s  %s\n", strings.Repeat("0", 64), archiveName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.0.0",
		assets: map[string][]byte{archiveName: archive, sumsName: []byte(sums)},
	}})
	m, _ := newFetchTestManager(t, srv.URL)
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin"}
	_, err := m.resolvePluginBinary(context.Background(), sp)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha256 mismatch rejection, got %v", err)
	}
}

func TestResolvePluginBinaryLocalPassThrough(t *testing.T) {
	m, _ := newFetchTestManager(t, "")
	sp := config.PluginSource{Name: "p", Source: "/abs/local/plugin"}
	got, err := m.resolvePluginBinary(context.Background(), sp)
	if err != nil || got != "/abs/local/plugin" {
		t.Fatalf("local source should pass through unchanged: %q err=%v", got, err)
	}
}
