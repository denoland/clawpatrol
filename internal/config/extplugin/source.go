package extplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	version "github.com/hashicorp/go-version"

	"github.com/denoland/clawpatrol/internal/config"
)

// A plugin `source` is either a local filesystem path or a GitHub repo
// reference. This file classifies the source, lists the repo's release
// tags, and selects the newest tag satisfying the operator's version
// constraint (hashicorp/go-version, the same engine and semantics
// Terraform uses for provider version constraints).

// githubHost is the only remote host clawpatrol fetches plugins from in
// v1. A source qualified with it is a repo reference; anything else is a
// local path (preserving the pre-distribution behavior).
const githubHost = "github.com"

// sourceKind classifies a plugin's `source`.
type sourceKind int

const (
	sourceLocal sourceKind = iota
	sourceGitHub
)

// parsedSource is a validated, classified plugin source.
type parsedSource struct {
	Kind  sourceKind
	Raw   string
	Owner string // github only
	Repo  string // github only
}

// IsRemote reports whether the source is fetched (vs a local path).
func (p parsedSource) IsRemote() bool { return p.Kind == sourceGitHub }

// slug is "github.com/<owner>/<repo>" — the canonical source string and
// the value recorded as `source` in the lockfile.
func (p parsedSource) slug() string {
	return githubHost + "/" + p.Owner + "/" + p.Repo
}

// parseSource classifies a `source` string. A value qualified with the
// github.com host is a GitHub repo reference (exactly owner/repo); every
// other string is treated as a local filesystem path.
func parseSource(s string) (parsedSource, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return parsedSource{}, fmt.Errorf("source is empty")
	}
	rest, ok := strings.CutPrefix(raw, githubHost+"/")
	if !ok {
		// Not host-qualified: a local path (/abs, ./rel, ~/p, bare).
		return parsedSource{Kind: sourceLocal, Raw: raw}, nil
	}
	rest = strings.TrimSuffix(rest, "/")
	rest = strings.TrimSuffix(rest, ".git")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return parsedSource{}, fmt.Errorf(
			"github source %q must be of the form github.com/<owner>/<repo>", raw)
	}
	return parsedSource{Kind: sourceGitHub, Raw: raw, Owner: parts[0], Repo: parts[1]}, nil
}

// provenanceMode is how a GitHub release's build-provenance attestation
// is enforced (the HCL `provenance` field).
type provenanceMode int

const (
	provWarn    provenanceMode = iota // verify when present, else warn (default)
	provRequire                       // an attestation is mandatory
	provOff                           // skip the attestation check entirely
)

// parseProvenanceMode validates the HCL `provenance` value.
func parseProvenanceMode(s string) (provenanceMode, error) {
	switch strings.TrimSpace(s) {
	case "", "warn":
		return provWarn, nil
	case "require":
		return provRequire, nil
	case "off":
		return provOff, nil
	default:
		return 0, fmt.Errorf("invalid provenance %q: expected \"warn\", \"require\", or \"off\"", s)
	}
}

// provenanceModeOf returns the validated provenance mode for sp; callers
// reach it only after pluginSourceFor has already validated the value.
func provenanceModeOf(sp config.PluginSource) provenanceMode {
	m, _ := parseProvenanceMode(sp.Provenance)
	return m
}

// pluginSourceFor classifies sp.Source and enforces that the version
// constraint and provenance mode are only set on a remote (GitHub)
// source — either on a local path is a config error.
func pluginSourceFor(sp config.PluginSource) (parsedSource, error) {
	p, err := parseSource(sp.Source)
	if err != nil {
		return parsedSource{}, err
	}
	if strings.TrimSpace(sp.Version) != "" && !p.IsRemote() {
		return parsedSource{}, fmt.Errorf(
			"version constraint %q is only valid for a github.com/<owner>/<repo> source, not a local path %q",
			sp.Version, sp.Source)
	}
	if _, err := parseProvenanceMode(sp.Provenance); err != nil {
		return parsedSource{}, err
	}
	if strings.TrimSpace(sp.Provenance) != "" && !p.IsRemote() {
		return parsedSource{}, fmt.Errorf(
			"provenance %q is only valid for a github.com/<owner>/<repo> source, not a local path %q",
			sp.Provenance, sp.Source)
	}
	return p, nil
}

// ghAsset is the subset of a GitHub release asset we consume.
type ghAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	// APIURL is the asset's api.github.com URL; downloading it with an
	// Accept: application/octet-stream header works for private repos
	// where browser_download_url would 404 without a session.
	APIURL string `json:"url"`
	Size   int64  `json:"size"`
}

// ghRelease is the subset of a GitHub release we consume.
type ghRelease struct {
	TagName    string    `json:"tag_name"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Assets     []ghAsset `json:"assets"`
}

// asset returns the named release asset, or false.
func (r ghRelease) asset(name string) (ghAsset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return ghAsset{}, false
}

// ghClient lists releases and downloads assets from the GitHub REST API.
// base defaults to https://api.github.com (overridden in tests); token,
// when set from $GITHUB_TOKEN, authenticates for private repos and
// lifts the unauthenticated rate limit.
type ghClient struct {
	http  *http.Client
	base  string
	token string
}

func newGHClient() *ghClient {
	return &ghClient{
		http:  &http.Client{Timeout: 30 * time.Second},
		base:  "https://api.github.com",
		token: strings.TrimSpace(os.Getenv("GITHUB_TOKEN")),
	}
}

func (c *ghClient) authHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// listReleases returns every (non-draft handling left to the caller)
// release for owner/repo, following pagination up to a sane cap.
func (c *ghClient) listReleases(ctx context.Context, owner, repo string) ([]ghRelease, error) {
	var out []ghRelease
	for pg := 1; pg <= 20; pg++ {
		u := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100&page=%d",
			c.base, url.PathEscape(owner), url.PathEscape(repo), pg)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		c.authHeaders(req)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github: list releases for %s/%s: %w", owner, repo, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("github: list releases for %s/%s: HTTP %d: %s",
				owner, repo, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var batch []ghRelease
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("github: decode releases for %s/%s: %w", owner, repo, err)
		}
		out = append(out, batch...)
		if len(batch) < 100 {
			break // last page
		}
	}
	return out, nil
}

// resolveRelease picks the newest release whose tag satisfies the
// constraint. Drafts are skipped and non-semver tags ignored.
// Pre-releases are excluded unless the constraint pins one (go-version's
// Check enforces that for a non-empty constraint); an empty constraint
// selects the newest non-prerelease tag.
func resolveRelease(releases []ghRelease, constraint string) (ghRelease, *version.Version, error) {
	var cons version.Constraints
	if c := strings.TrimSpace(constraint); c != "" {
		var err error
		cons, err = version.NewConstraint(c)
		if err != nil {
			return ghRelease{}, nil, fmt.Errorf("invalid version constraint %q: %w", constraint, err)
		}
	}
	var bestRel ghRelease
	var bestVer *version.Version
	for _, r := range releases {
		if r.Draft {
			continue
		}
		v, err := version.NewVersion(r.TagName)
		if err != nil {
			continue // not a semver tag
		}
		if cons == nil {
			if v.Prerelease() != "" {
				continue
			}
		} else if !cons.Check(v) {
			continue
		}
		if bestVer == nil || v.GreaterThan(bestVer) {
			bestVer, bestRel = v, r
		}
	}
	if bestVer == nil {
		want := strings.TrimSpace(constraint)
		if want == "" {
			want = "(newest stable)"
		}
		return ghRelease{}, nil, fmt.Errorf("no release tag satisfies version constraint %s", want)
	}
	return bestRel, bestVer, nil
}

// resolveVersion lists the repo's releases and returns the newest
// release satisfying the constraint.
func (c *ghClient) resolveVersion(ctx context.Context, p parsedSource, constraint string) (ghRelease, *version.Version, error) {
	releases, err := c.listReleases(ctx, p.Owner, p.Repo)
	if err != nil {
		return ghRelease{}, nil, err
	}
	return resolveRelease(releases, constraint)
}
