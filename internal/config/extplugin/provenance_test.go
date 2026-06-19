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

const testGitCommit = "2a6fb83e91633ab8a606f306f609f2fbfc8154f4"

// inTotoStatement builds the DSSE payload a build-provenance attestation
// signs: an in-toto SLSA statement whose subject digest is the artifact's
// and whose buildDefinition resolves a source commit (as GitHub's
// attestations do).
func inTotoStatement(t *testing.T, name, sha256hex string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject":       []map[string]any{{"name": name, "digest": map[string]string{"sha256": sha256hex}}},
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"resolvedDependencies": []map[string]any{
					{"uri": "git+https://github.com/acme/myplugin@refs/tags/v1.0.0",
						"digest": map[string]any{"gitCommit": testGitCommit}},
				},
			},
		},
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

	// Correct repo identity + matching artifact digest -> verified, and
	// the verified statement yields the attested source commit.
	res, err := checkProvenance(v, entity, "acme", "myplugin", digest)
	if err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
	if got := sourceCommit(res); got != testGitCommit {
		t.Errorf("sourceCommit = %q, want %q", got, testGitCommit)
	}
	// Wrong repo: the SAN identity policy must reject it.
	if _, err := checkProvenance(v, entity, "evil", "myplugin", digest); err == nil {
		t.Error("attestation from a different repo identity was accepted")
	}
	// Wrong artifact digest: the artifact policy must reject it.
	const other = "2222222222222222222222222222222222222222222222222222222222222222"
	if _, err := checkProvenance(v, entity, "acme", "myplugin", other); err == nil {
		t.Error("attestation for a different artifact digest was accepted")
	}
	// Wrong OIDC issuer is rejected too: re-attest under a bogus issuer.
	bad, err := vs.Attest("https://github.com/acme/myplugin/.github/workflows/release.yml@refs/tags/v1.0.0",
		"https://accounts.google.com", inTotoStatement(t, "x", digest))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkProvenance(v, bad, "acme", "myplugin", digest); err == nil {
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
	if _, _, err := m.resolvePluginBinary(context.Background(), sp, false); err != nil {
		t.Fatalf("no-attestation should fall back to checksum, got: %v", err)
	}

	// present-but-invalid attestation -> hard fail. Use a fresh manager so
	// the cache miss forces a re-download (and the verifier runs).
	m2, _ := newFetchTestManager(t, srv.URL)
	m2.prov = stubProv{err: errors.New("bad attestation")}
	if _, _, err := m2.resolvePluginBinary(context.Background(), sp, false); err == nil ||
		!strings.Contains(err.Error(), "provenance verification failed") {
		t.Fatalf("invalid attestation should fail closed, got: %v", err)
	}
}

// TestProvenanceRecordsAndPinsCommit covers recording the attested source
// commit and rejecting a pinned re-download whose attestation names a
// different commit (a re-pointed tag).
func TestProvenanceRecordsAndPinsCommit(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	payload := []byte("payload")
	archive := tarGz(t, map[string][]byte{repo: payload}, repo)
	archiveName := fmt.Sprintf("%s_1.0.0_%s.tar.gz", repo, plat)
	sumsName := fmt.Sprintf("%s_1.0.0_SHA256SUMS", repo)
	sums := fmt.Sprintf("%s  %s\n", sha256hex(archive), archiveName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.0.0",
		assets: map[string][]byte{archiveName: archive, sumsName: []byte(sums)},
	}})
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin"}
	binSHA := "sha256:" + sha256hex(payload) // extracted binary's hash

	// First use records the attested commit in the lockfile.
	m, _ := newFetchTestManager(t, srv.URL)
	m.prov = stubProv{commit: "commit-aaa"}
	if _, _, err := m.resolvePluginBinary(context.Background(), sp, false); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if e, _ := m.lock.get(repo); e.Commit != "commit-aaa" {
		t.Fatalf("lockfile commit = %q, want commit-aaa", e.Commit)
	}

	// Fresh host (no cache), lock pinned to commit-aaa + the real hash, but
	// the attestation now vouches a different commit -> fail closed.
	m2, _ := newFetchTestManager(t, srv.URL)
	m2.prov = stubProv{commit: "commit-bbb"}
	m2.lock.setSource(repo, "github.com/acme/myplugin", "v1.0.0", "", "commit-aaa", false)
	m2.lock.addHash(repo, binSHA, "none")
	_, _, err := m2.resolvePluginBinary(context.Background(), sp, false)
	if err == nil || !strings.Contains(err.Error(), "does not match the locked commit") {
		t.Fatalf("commit mismatch should fail closed, got: %v", err)
	}
}

// TestProvenanceCommitCheckIsVersionAware covers that the re-pointed-tag
// guard fires only for a re-download of the *same* version, not for an
// explicit upgrade to a *new* version (whose commit legitimately differs).
// Without this distinction `clawpatrol plugins update` to a newer attested
// release is wrongly blocked.
func TestProvenanceCommitCheckIsVersionAware(t *testing.T) {
	entry := lockEntry{Version: "v1.0.0", Commit: "commit-aaa", Attested: true}
	res := fetchResult{commit: "commit-bbb", attested: true}

	// Same tag, different commit: the tag was re-pointed -> blocked.
	if err := checkProvenanceNotDowngraded("p", provWarn, entry, res, "v1.0.0"); err == nil ||
		!strings.Contains(err.Error(), "re-pointed") {
		t.Fatalf("same-version commit change should be blocked, got: %v", err)
	}
	// Newer version, different commit: a legitimate upgrade -> accepted.
	if err := checkProvenanceNotDowngraded("p", provWarn, entry, res, "v1.1.0"); err != nil {
		t.Fatalf("upgrade to a new version must not be blocked, got: %v", err)
	}
	// A lost attestation still blocks, regardless of the version change.
	if err := checkProvenanceNotDowngraded("p", provWarn, entry, fetchResult{}, "v1.1.0"); err == nil ||
		!strings.Contains(err.Error(), "lost its build-provenance") {
		t.Fatalf("lost attestation should block, got: %v", err)
	}
	// provenance = "off" disables every check.
	if err := checkProvenanceNotDowngraded("p", provOff, entry, fetchResult{}, "v1.0.0"); err != nil {
		t.Fatalf("provOff should skip checks, got: %v", err)
	}
}

// TestProvenanceDowngradeBlockedUntilApproved covers the TOFU model: a
// plugin recorded as attested that loses provenance is blocked on load
// until Approve (accept=true) re-records the lower level.
func TestProvenanceDowngradeBlockedUntilApproved(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	payload := []byte("payload")
	archive := tarGz(t, map[string][]byte{repo: payload}, repo)
	archiveName := fmt.Sprintf("%s_1.0.0_%s.tar.gz", repo, plat)
	sumsName := fmt.Sprintf("%s_1.0.0_SHA256SUMS", repo)
	sums := fmt.Sprintf("%s  %s\n", sha256hex(archive), archiveName)
	srv := newReleaseServer(t, owner, repo, []relSpec{{
		tag:    "v1.0.0",
		assets: map[string][]byte{archiveName: archive, sumsName: []byte(sums)},
	}})
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin"}
	binSHA := "sha256:" + sha256hex(payload)

	// Pinned as ATTESTED with the real hash, but the binary now has no
	// attestation -> load fails closed.
	m, _ := newFetchTestManager(t, srv.URL)
	m.prov = stubProv{err: errNoAttestation}
	m.lock.setSource(repo, "github.com/acme/myplugin", "v1.0.0", "", "commit-aaa", true)
	m.lock.addHash(repo, binSHA, "none")
	if _, _, err := m.resolvePluginBinary(context.Background(), sp, false); err == nil ||
		!strings.Contains(err.Error(), "lost its build-provenance") {
		t.Fatalf("provenance downgrade should fail closed, got: %v", err)
	}

	// Approve (accept=true) accepts it, re-recording attested=false.
	if _, _, err := m.resolvePluginBinary(context.Background(), sp, true); err != nil {
		t.Fatalf("approve should accept the downgrade: %v", err)
	}
	if e, _ := m.lock.get(repo); e.Attested {
		t.Fatalf("approve should have recorded attested=false, got %+v", e)
	}
	// Load now succeeds (cache hit, no downgrade).
	if _, _, err := m.resolvePluginBinary(context.Background(), sp, false); err != nil {
		t.Fatalf("load after approve failed: %v", err)
	}
}

// TestProvenanceModes covers the per-plugin `provenance` policy: require
// fails closed on a missing attestation; off skips the check entirely.
func TestProvenanceModes(t *testing.T) {
	owner, repo := "acme", "myplugin"
	plat := platformToken()
	archive := tarGz(t, map[string][]byte{repo: []byte("payload")}, repo)
	archiveName := fmt.Sprintf("%s_1.0.0_%s.tar.gz", repo, plat)
	sumsName := fmt.Sprintf("%s_1.0.0_SHA256SUMS", repo)
	sums := fmt.Sprintf("%s  %s\n", sha256hex(archive), archiveName)
	mkSrv := func() string {
		return newReleaseServer(t, owner, repo, []relSpec{{
			tag:    "v1.0.0",
			assets: map[string][]byte{archiveName: archive, sumsName: []byte(sums)},
		}}).URL
	}

	// require + no attestation -> fail closed.
	m, _ := newFetchTestManager(t, mkSrv())
	m.prov = stubProv{err: errNoAttestation}
	sp := config.PluginSource{Name: repo, Source: "github.com/acme/myplugin", Provenance: "require"}
	if _, _, err := m.resolvePluginBinary(context.Background(), sp, false); err == nil ||
		!strings.Contains(err.Error(), "provenance is required") {
		t.Fatalf("require + no attestation should fail closed, got: %v", err)
	}

	// off + an erroring verifier -> the verifier is never consulted, install ok.
	m2, _ := newFetchTestManager(t, mkSrv())
	m2.prov = stubProv{err: errors.New("should not be called")}
	sp.Provenance = "off"
	if _, _, err := m2.resolvePluginBinary(context.Background(), sp, false); err != nil {
		t.Fatalf("off should skip provenance entirely, got: %v", err)
	}
}

type stubProv struct {
	commit string
	err    error
}

func (s stubProv) verify(_ context.Context, _, _, _, _ string) (string, error) {
	return s.commit, s.err
}
