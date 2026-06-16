package extplugin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// This file verifies a release archive's GitHub build-provenance
// attestation: proof, via Sigstore, that the artifact was built by the
// named repo's GitHub Actions workflow. The source address already names
// owner/repo, so that identity is the trust anchor — no key to pin. This
// closes the trust-on-first-use gap that checksums alone leave open.

// githubActionsOIDCIssuer is the OIDC issuer GitHub Actions signs with.
const githubActionsOIDCIssuer = "https://token.actions.githubusercontent.com"

// errNoAttestation means the repo published no build-provenance
// attestation for the artifact. The fetcher treats this as a soft miss
// (warn, fall back to checksum + lockfile TOFU) so plugins that have not
// adopted attestations yet still install.
var errNoAttestation = errors.New("no build-provenance attestation found")

// githubProvenance is the production provenanceVerifier. It fetches the
// attestation bundle GitHub holds for an artifact digest and verifies it
// with sigstore-go against the repo's GitHub Actions identity.
type githubProvenance struct {
	gh *ghClient

	mu sync.Mutex
	tm root.TrustedMaterial // lazily fetched public-good trust root; injectable in tests
}

func newGitHubProvenance(gh *ghClient, tm root.TrustedMaterial) *githubProvenance {
	return &githubProvenance{gh: gh, tm: tm}
}

func (g *githubProvenance) trustedMaterial() (root.TrustedMaterial, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tm != nil {
		return g.tm, nil
	}
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, err
	}
	g.tm = tr
	return tr, nil
}

// verify checks that the archive with sha256 archiveSHA256 is covered by
// a build-provenance attestation from owner/repo's GitHub Actions
// workflow, and returns the source commit the attestation vouches the
// binary was built from (empty if the predicate omits it). Returns
// errNoAttestation when the repo published none, or a verification error
// when an attestation exists but does not validate.
func (g *githubProvenance) verify(ctx context.Context, owner, repo, tag, archiveSHA256 string) (string, error) {
	bundles, err := g.gh.attestations(ctx, owner, repo, "sha256:"+archiveSHA256)
	if err != nil {
		return "", err
	}
	if len(bundles) == 0 {
		return "", errNoAttestation
	}

	tm, err := g.trustedMaterial()
	if err != nil {
		return "", fmt.Errorf("load sigstore trust root: %w", err)
	}
	v, err := verify.NewVerifier(tm, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return "", err
	}

	var lastErr error
	for _, b := range bundles {
		res, err := checkProvenance(v, b, owner, repo, archiveSHA256)
		if err == nil {
			return sourceCommit(res), nil // one valid attestation is enough
		}
		lastErr = err
	}
	return "", fmt.Errorf("attestation present but unverified for %s/%s@%s: %w", owner, repo, tag, lastErr)
}

// checkProvenance verifies a single signed entity (a parsed bundle, or a
// test entity) against the policy: the artifact digest must match and the
// signing identity must be a GitHub Actions workflow in owner/repo.
func checkProvenance(v *verify.Verifier, entity verify.SignedEntity, owner, repo, archiveSHA256 string) (*verify.VerificationResult, error) {
	digest, err := hex.DecodeString(archiveSHA256)
	if err != nil {
		return nil, fmt.Errorf("bad artifact digest: %w", err)
	}
	// The signing certificate's SAN must be a GitHub Actions workflow in
	// this exact repo; the issuer must be GitHub's Actions OIDC. The ref
	// in the SAN is deliberately not pinned — it reflects the triggering
	// event (a tag push, a release, or workflow_dispatch), which varies
	// by plugin; the source commit is bound separately, below.
	sanRegex := fmt.Sprintf(`^https://github\.com/%s/%s/\.github/workflows/.+`,
		regexp.QuoteMeta(owner), regexp.QuoteMeta(repo))
	certID, err := verify.NewShortCertificateIdentity(githubActionsOIDCIssuer, "", "", sanRegex)
	if err != nil {
		return nil, err
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(certID))
	return v.Verify(entity, policy)
}

// sourceCommit pulls the git commit the build-provenance predicate
// records as the build's source — buildDefinition.resolvedDependencies[]
// .digest.gitCommit in the SLSA v1 predicate. Empty if absent.
func sourceCommit(res *verify.VerificationResult) string {
	if res == nil || res.Statement == nil || res.Statement.Predicate == nil {
		return ""
	}
	m := res.Statement.Predicate.AsMap()
	bd, _ := m["buildDefinition"].(map[string]any)
	deps, _ := bd["resolvedDependencies"].([]any)
	for _, d := range deps {
		dm, _ := d.(map[string]any)
		dig, _ := dm["digest"].(map[string]any)
		if gc, ok := dig["gitCommit"].(string); ok && gc != "" {
			return gc
		}
	}
	return ""
}

// attestations fetches the Sigstore build-provenance bundles GitHub
// stores for an artifact's subject digest ("sha256:<hex>"). A 404 means
// no attestation exists (returns nil, nil).
func (c *ghClient) attestations(ctx context.Context, owner, repo, digest string) ([]*bundle.Bundle, error) {
	u := fmt.Sprintf("%s/repos/%s/%s/attestations/%s", c.base, owner, repo, digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.authHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: fetch attestations for %s/%s: %w", owner, repo, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: fetch attestations for %s/%s: HTTP %d: %s",
			owner, repo, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("github: decode attestations: %w", err)
	}
	var out []*bundle.Bundle
	for _, a := range payload.Attestations {
		if len(a.Bundle) == 0 {
			continue
		}
		var pb protobundle.Bundle
		if err := protojson.Unmarshal(a.Bundle, &pb); err != nil {
			return nil, fmt.Errorf("github: decode attestation bundle: %w", err)
		}
		b, err := bundle.NewBundle(&pb)
		if err != nil {
			return nil, fmt.Errorf("github: load attestation bundle: %w", err)
		}
		out = append(out, b)
	}
	return out, nil
}
