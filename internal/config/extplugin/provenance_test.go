package extplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/snappy"
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

// minimalBundleJSON is the smallest bundle JSON that survives both
// protojson decoding and bundle.NewBundle validation: a v0.3 media type,
// a public-key verification material, a message signature, and no tlog
// entries (so no inclusion proof is required). It would never verify
// cryptographically — these tests stop at the parsing layer.
const minimalBundleJSON = `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",` +
	`"verificationMaterial":{"publicKey":{"hint":"test"}},` +
	`"messageSignature":{"messageDigest":{"algorithm":"SHA2_256",` +
	`"digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"signature":"c2ln"}}`

// bundleURLServers fakes the two hosts involved in a by-reference
// attestation: a blob host serving blobBody with blobStatus, and a
// GitHub API host answering the attestations endpoint with apiJSON
// (a fmt template whose single %s receives the blob URL). The returned
// client carries a token so tests can prove it reaches the API host but
// never the blob host. blobAuth records the Authorization header the
// blob host received; blobHits counts its requests.
func bundleURLServers(t *testing.T, blobStatus int, blobBody []byte, apiJSON string) (c *ghClient, blobAuth *string, blobHits *int) {
	t.Helper()
	blobAuth, blobHits = new(string), new(int)
	blob := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*blobAuth = r.Header.Get("Authorization")
		*blobHits++
		w.Header().Set("Content-Type", "application/x-snappy")
		w.WriteHeader(blobStatus)
		_, _ = w.Write(blobBody)
	}))
	t.Cleanup(blob.Close)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("API host got Authorization %q, want \"Bearer tok\"", got)
		}
		_, _ = fmt.Fprintf(w, apiJSON, blob.URL+"/attestations/1234.json.sn")
	}))
	t.Cleanup(api.Close)
	return &ghClient{http: api.Client(), base: api.URL, token: "tok"}, blobAuth, blobHits
}

// TestAttestationsBundleURL covers attestations delivered by reference:
// GitHub now returns "bundle": null plus a bundle_url pointing at blob
// storage, where the bundle is served snappy-compressed (issue #769).
func TestAttestationsBundleURL(t *testing.T) {
	ctx := context.Background()
	const nullWithURL = `{"attestations":[{"bundle":null,"bundle_url":"%s"}]}`

	t.Run("snappy_block", func(t *testing.T) {
		// What GitHub serves today. Also the token-leak guard: the blob
		// host is a pre-signed third-party URL and must not receive the
		// GitHub token (the API-host assertion in the helper proves the
		// client does send it where it belongs).
		body := snappy.Encode(nil, []byte(minimalBundleJSON))
		c, blobAuth, _ := bundleURLServers(t, http.StatusOK, body, nullWithURL)
		bundles, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err != nil || len(bundles) != 1 {
			t.Fatalf("bundles=%d err=%v, want 1 bundle", len(bundles), err)
		}
		if *blobAuth != "" {
			t.Errorf("blob host got Authorization %q; the GitHub token must not leak to blob storage", *blobAuth)
		}
	})

	t.Run("snappy_framed", func(t *testing.T) {
		var buf bytes.Buffer
		w := snappy.NewBufferedWriter(&buf)
		if _, err := w.Write([]byte(minimalBundleJSON)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		c, _, _ := bundleURLServers(t, http.StatusOK, buf.Bytes(), nullWithURL)
		bundles, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err != nil || len(bundles) != 1 {
			t.Fatalf("bundles=%d err=%v, want 1 bundle", len(bundles), err)
		}
	})

	t.Run("uncompressed_json", func(t *testing.T) {
		c, _, _ := bundleURLServers(t, http.StatusOK, []byte(minimalBundleJSON), nullWithURL)
		bundles, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err != nil || len(bundles) != 1 {
			t.Fatalf("bundles=%d err=%v, want 1 bundle", len(bundles), err)
		}
	})

	t.Run("null_bundle_no_url", func(t *testing.T) {
		// A degenerate entry with neither field carries nothing to
		// verify: skip it, so verify() reports errNoAttestation (soft
		// miss) rather than a hard decode failure.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"attestations":[{"bundle":null}]}`))
		}))
		t.Cleanup(srv.Close)
		c := &ghClient{http: srv.Client(), base: srv.URL}
		bundles, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err != nil || bundles != nil {
			t.Fatalf("null bundle without bundle_url should be skipped: bundles=%v err=%v", bundles, err)
		}
	})

	t.Run("bundle_url_http_error", func(t *testing.T) {
		// The attestation exists but its bundle is unretrievable (e.g.
		// an expired SAS URL): fail closed, not a soft miss — otherwise
		// blocking the blob path would downgrade verification.
		c, _, _ := bundleURLServers(t, http.StatusForbidden, []byte("gone"), nullWithURL)
		_, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("blob HTTP error should be a hard error naming the status, got: %v", err)
		}
		if errors.Is(err, errNoAttestation) {
			t.Error("blob fetch failure must not be classified as a soft miss")
		}
	})

	t.Run("block_bomb_rejected", func(t *testing.T) {
		body := snappy.Encode(nil, make([]byte, 17<<20))
		c, _, _ := bundleURLServers(t, http.StatusOK, body, nullWithURL)
		_, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("oversized block bundle should be rejected before allocation, got: %v", err)
		}
	})

	t.Run("framed_bomb_rejected", func(t *testing.T) {
		var buf bytes.Buffer
		w := snappy.NewBufferedWriter(&buf)
		if _, err := w.Write(make([]byte, 17<<20)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		c, _, _ := bundleURLServers(t, http.StatusOK, buf.Bytes(), nullWithURL)
		_, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("oversized framed bundle should be rejected, got: %v", err)
		}
	})

	t.Run("inline_preferred_over_url", func(t *testing.T) {
		apiJSON := `{"attestations":[{"bundle":` + minimalBundleJSON + `,"bundle_url":"%s"}]}`
		c, _, blobHits := bundleURLServers(t, http.StatusOK, []byte("garbage"), apiJSON)
		bundles, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err != nil || len(bundles) != 1 {
			t.Fatalf("bundles=%d err=%v, want 1 bundle", len(bundles), err)
		}
		if *blobHits != 0 {
			t.Errorf("blob host was hit %d times; an inline bundle must not trigger a fetch", *blobHits)
		}
	})

	t.Run("valid_inline_then_unreachable_url", func(t *testing.T) {
		// A loadable bundle must survive a sibling entry whose blob is
		// temporarily unavailable: verify() applies its one-valid-
		// attestation-is-enough policy, so dropping everything over one
		// unreachable entry is an availability failure that buys no
		// authenticity.
		apiJSON := `{"attestations":[{"bundle":` + minimalBundleJSON + `},{"bundle":null,"bundle_url":"%s"}]}`
		c, _, _ := bundleURLServers(t, http.StatusForbidden, []byte("gone"), apiJSON)
		bundles, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err != nil || len(bundles) != 1 {
			t.Fatalf("bundles=%d err=%v, want the valid inline bundle despite the unreachable sibling", len(bundles), err)
		}
	})

	t.Run("unreachable_url_then_valid_inline", func(t *testing.T) {
		// Same as above with the entry order flipped: the failing
		// entry comes first and must not short-circuit the loop.
		apiJSON := `{"attestations":[{"bundle":null,"bundle_url":"%s"},{"bundle":` + minimalBundleJSON + `}]}`
		c, _, _ := bundleURLServers(t, http.StatusForbidden, []byte("gone"), apiJSON)
		bundles, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err != nil || len(bundles) != 1 {
			t.Fatalf("bundles=%d err=%v, want the valid inline bundle despite the unreachable sibling", len(bundles), err)
		}
	})

	t.Run("mixed_inline_and_by_reference", func(t *testing.T) {
		apiJSON := `{"attestations":[{"bundle":null,"bundle_url":"%s"},{"bundle":` + minimalBundleJSON + `}]}`
		body := snappy.Encode(nil, []byte(minimalBundleJSON))
		c, _, _ := bundleURLServers(t, http.StatusOK, body, apiJSON)
		bundles, err := c.attestations(ctx, "o", "r", "sha256:abc")
		if err != nil || len(bundles) != 2 {
			t.Fatalf("bundles=%d err=%v, want 2 bundles", len(bundles), err)
		}
	})
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
