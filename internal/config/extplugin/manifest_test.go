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
