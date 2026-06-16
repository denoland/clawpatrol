package extplugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

// staticManifestJSON builds the protojson a plugin's --print-manifest
// mode emits and a release publishes as <repo>_<version>_manifest.json.
func staticManifestJSON(t *testing.T, name, version string, net pb.NetworkAccess) []byte {
	t.Helper()
	b, err := protojson.Marshal(&pb.ManifestResponse{
		Name:         name,
		Version:      version,
		Capabilities: &pb.PluginCapabilities{Network: net},
		Credentials:  []*pb.CredentialDecl{{TypeName: name + "_token"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPreviewSourceReadsStaticManifest(t *testing.T) {
	owner, repo := "acme", "myplugin"
	mfName := fmt.Sprintf("%s_1.2.0_manifest.json", repo)
	mf := staticManifestJSON(t, "myplugin", "1.2.0", pb.NetworkAccess_NETWORK_OUTBOUND)
	// A release whose only assets are the manifest + SHA256SUMS (no
	// binary) — preview must work without any binary download.
	sums := fmt.Sprintf("%s  %s\n", sha256hex(mf), mfName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.2.0",
		assets: map[string][]byte{mfName: mf, repo + "_1.2.0_SHA256SUMS": []byte(sums)},
	}})

	m, _ := newFetchTestManager(t, srv.URL)
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin", Version: "~> 1.0"}

	pv, err := m.PreviewSource(context.Background(), sp)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if pv.Version != "v1.2.0" || pv.Network != "outbound" {
		t.Fatalf("preview = %+v, want v1.2.0 / outbound", pv)
	}
	if len(pv.Credentials) != 1 || pv.Credentials[0] != "myplugin_token" {
		t.Fatalf("credentials = %v, want [myplugin_token]", pv.Credentials)
	}

	// A tampered manifest (sha doesn't match SHA256SUMS) is rejected.
	badName := fmt.Sprintf("%s_1.3.0_manifest.json", repo)
	badSums := fmt.Sprintf("%s  %s\n", strings.Repeat("0", 64), badName)
	srv2 := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.3.0",
		assets: map[string][]byte{badName: mf, repo + "_1.3.0_SHA256SUMS": []byte(badSums)},
	}})
	m2, _ := newFetchTestManager(t, srv2.URL)
	sp.Version = "~> 1.3"
	if _, err := m2.PreviewSource(context.Background(), sp); err == nil ||
		!strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("tampered manifest should be rejected, got: %v", err)
	}
}

// TestStaticManifestDrivesNetworkWithoutProbe proves that when a release
// ships a signed static manifest, the network grant comes from it with no
// probe spawn: the "binary" here is not a runnable plugin, so a probe
// would fail — install succeeding with the manifest's grant means none
// happened.
func TestStaticManifestDrivesNetworkWithoutProbe(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	archive := tarGz(t, map[string][]byte{repo: []byte("not-a-runnable-plugin")}, repo)
	archiveName := fmt.Sprintf("%s_1.0.0_%s.tar.gz", repo, plat)
	mfName := fmt.Sprintf("%s_1.0.0_manifest.json", repo)
	mf := staticManifestJSON(t, repo, "1.0.0", pb.NetworkAccess_NETWORK_OUTBOUND)
	sums := fmt.Sprintf("%s  %s\n%s  %s\n", sha256hex(archive), archiveName, sha256hex(mf), mfName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.0.0",
		assets: map[string][]byte{archiveName: archive, mfName: mf, repo + "_1.0.0_SHA256SUMS": []byte(sums)},
	}})
	m, _ := newFetchTestManager(t, srv.URL)
	// No Network override: the grant must come from the signed manifest.
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin"}
	res, err := m.Install(context.Background(), []config.PluginSource{sp}, nil, false)
	if err != nil {
		t.Fatalf("install via static manifest (no probe) failed: %v", err)
	}
	if res[0].Network != "outbound" {
		t.Fatalf("network = %q, want outbound (from the static manifest)", res[0].Network)
	}
}

func TestCheckManifestConsistency(t *testing.T) {
	mk := func(net pb.NetworkAccess, cred string) *pb.ManifestResponse {
		return &pb.ManifestResponse{
			Name:         "p",
			Capabilities: &pb.PluginCapabilities{Network: net},
			Credentials:  []*pb.CredentialDecl{{TypeName: cred}},
		}
	}
	stat := mk(pb.NetworkAccess_NETWORK_OUTBOUND, "p_token")
	// nil static manifest -> check skipped.
	if err := checkManifestConsistency("p", nil, mk(pb.NetworkAccess_NETWORK_NONE, "x")); err != nil {
		t.Fatalf("nil static should skip: %v", err)
	}
	// Exact match -> ok.
	if err := checkManifestConsistency("p", stat, mk(pb.NetworkAccess_NETWORK_OUTBOUND, "p_token")); err != nil {
		t.Fatalf("matching manifests: %v", err)
	}
	// Network mismatch -> fail closed.
	if err := checkManifestConsistency("p", stat, mk(pb.NetworkAccess_NETWORK_NONE, "p_token")); err == nil ||
		!strings.Contains(err.Error(), "network") {
		t.Fatalf("network mismatch should fail: %v", err)
	}
	// Declared types differ -> fail closed.
	if err := checkManifestConsistency("p", stat, mk(pb.NetworkAccess_NETWORK_OUTBOUND, "other_token")); err == nil {
		t.Fatal("type mismatch should fail closed")
	}

	// Egress mismatch between the signed static manifest and the running
	// binary -> fail closed.
	withEgress := func(egress ...string) *pb.ManifestResponse {
		return &pb.ManifestResponse{
			Name:         "p",
			Capabilities: &pb.PluginCapabilities{Network: pb.NetworkAccess_NETWORK_OUTBOUND, Egress: egress},
			Credentials:  []*pb.CredentialDecl{{TypeName: "p_token"}},
		}
	}
	statEgress := withEgress("*.foo.com:443")
	if err := checkManifestConsistency("p", statEgress, withEgress("*.foo.com:443")); err != nil {
		t.Fatalf("matching egress: %v", err)
	}
	if err := checkManifestConsistency("p", statEgress, withEgress("*.foo.com:443", "evil.com:443")); err == nil ||
		!strings.Contains(err.Error(), "egress") {
		t.Fatalf("egress mismatch should fail: %v", err)
	}
}

func TestPluginInfosSurfacesRequested(t *testing.T) {
	m := New(nil)
	m.mu.Lock()
	m.blocked = map[string]blockedRecord{
		"p": {
			source: "github.com/o/p",
			reason: "upgrade escalates permissions",
			requested: &ManifestPreview{
				Version:     "v2.0.0",
				Network:     "outbound",
				Credentials: []string{"p_token"},
			},
		},
	}
	m.mu.Unlock()

	var pi *PluginInfo
	for _, info := range m.PluginInfos() {
		if info.Name == "p" {
			i := info
			pi = &i
		}
	}
	if pi == nil || !pi.Blocked || pi.Requested == nil {
		t.Fatalf("blocked plugin missing requested privileges: %+v", pi)
	}
	if pi.Requested.Network != "outbound" || pi.Requested.Version != "v2.0.0" ||
		len(pi.Requested.Credentials) != 1 {
		t.Fatalf("requested = %+v, want outbound/v2.0.0/[p_token]", pi.Requested)
	}
}

func TestPreviewSourceNoManifest(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	archive := tarGz(t, map[string][]byte{repo: []byte("bin")}, repo)
	archiveName := fmt.Sprintf("%s_1.0.0_%s.tar.gz", repo, plat)
	sums := fmt.Sprintf("%s  %s\n", sha256hex(archive), archiveName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.0.0",
		assets: map[string][]byte{archiveName: archive, repo + "_1.0.0_SHA256SUMS": []byte(sums)},
	}})
	m, _ := newFetchTestManager(t, srv.URL)
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin"}
	if _, err := m.PreviewSource(context.Background(), sp); !errors.Is(err, errNoManifest) {
		t.Fatalf("want errNoManifest, got: %v", err)
	}
}
