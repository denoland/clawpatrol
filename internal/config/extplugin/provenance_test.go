package extplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/denoland/clawpatrol/internal/config"
)

// inTotoStatement builds the DSSE payload a build-provenance attestation
// signs: an in-toto statement whose subject digest is the artifact's.
func inTotoStatement(t *testing.T, name, sha256hex string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject":       []map[string]any{{"name": name, "digest": map[string]string{"sha256": sha256hex}}},
		"predicate":     map[string]any{"buildType": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckProvenanceIdentityAndDigest(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	v, err := verify.NewVerifier(vs, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}

	const digest = "1111111111111111111111111111111111111111111111111111111111111111"
	identity := "https://github.com/acme/myplugin/.github/workflows/release.yml@refs/tags/v1.0.0"
	entity, err := vs.Attest(identity, githubActionsOIDCIssuer, inTotoStatement(t, "myplugin_1.0.0_linux_amd64.tar.gz", digest))
	if err != nil {
		t.Fatal(err)
	}

	// Correct repo identity + matching artifact digest -> verified.
	if err := checkProvenance(v, entity, "acme", "myplugin", digest); err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
	// Wrong repo: the SAN identity policy must reject it.
	if err := checkProvenance(v, entity, "evil", "myplugin", digest); err == nil {
		t.Error("attestation from a different repo identity was accepted")
	}
	// Wrong artifact digest: the artifact policy must reject it.
	const other = "2222222222222222222222222222222222222222222222222222222222222222"
	if err := checkProvenance(v, entity, "acme", "myplugin", other); err == nil {
		t.Error("attestation for a different artifact digest was accepted")
	}
	// Wrong OIDC issuer is rejected too: re-attest under a bogus issuer.
	bad, err := vs.Attest("https://github.com/acme/myplugin/.github/workflows/release.yml@refs/tags/v1.0.0",
		"https://accounts.google.com", inTotoStatement(t, "x", digest))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkProvenance(v, bad, "acme", "myplugin", digest); err == nil {
		t.Error("attestation from a non-GitHub-Actions issuer was accepted")
	}
}

func TestAttestationsAPIParsing(t *testing.T) {
	// 404 => no attestation (soft miss).
	srv404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}))
	defer srv404.Close()
	c := &ghClient{http: srv404.Client(), base: srv404.URL}
	bundles, err := c.attestations(context.Background(), "o", "r", "sha256:abc")
	if err != nil || bundles != nil {
		t.Fatalf("404 should be a soft miss: bundles=%v err=%v", bundles, err)
	}

	// A malformed bundle payload is a hard error.
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"attestations":[{"bundle":{"not":"a real bundle"}}]}`))
	}))
	defer srvBad.Close()
	c = &ghClient{http: srvBad.Client(), base: srvBad.URL}
	if _, err := c.attestations(context.Background(), "o", "r", "sha256:abc"); err == nil {
		t.Error("malformed bundle should error")
	}
}

// TestProvenanceVerifyIfPresentFallback checks the fetcher behavior: a
// repo with no attestation installs (warn), a present-but-bad one fails.
func TestProvenanceVerifyIfPresentFallback(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	archive := tarGz(t, map[string][]byte{repo: []byte("payload")}, repo)
	archiveName := fmt.Sprintf("%s_1.0.0_%s.tar.gz", repo, plat)
	sumsName := fmt.Sprintf("%s_1.0.0_SHA256SUMS", repo)
	sums := fmt.Sprintf("%s  %s\n", sha256hex(archive), archiveName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.0.0",
		assets: map[string][]byte{archiveName: archive, sumsName: []byte(sums)},
	}})
	m, _ := newFetchTestManager(t, srv.URL)
	sp := config.PluginSource{Name: "p", Source: "github.com/acme/myplugin"}

	// no-attestation verifier -> soft miss -> install proceeds.
	m.prov = stubProv{err: errNoAttestation}
	if _, err := m.resolvePluginBinary(context.Background(), sp); err != nil {
		t.Fatalf("no-attestation should fall back to checksum, got: %v", err)
	}

	// present-but-invalid attestation -> hard fail. Use a fresh manager so
	// the cache miss forces a re-download (and the verifier runs).
	m2, _ := newFetchTestManager(t, srv.URL)
	m2.prov = stubProv{err: errors.New("bad attestation")}
	if _, err := m2.resolvePluginBinary(context.Background(), sp); err == nil ||
		!strings.Contains(err.Error(), "provenance verification failed") {
		t.Fatalf("invalid attestation should fail closed, got: %v", err)
	}
}

type stubProv struct{ err error }

func (s stubProv) verify(_ context.Context, _, _, _, _ string) error { return s.err }
