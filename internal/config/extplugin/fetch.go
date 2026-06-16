package extplugin

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/hashicorp/go-hclog"
	version "github.com/hashicorp/go-version"

	"github.com/denoland/clawpatrol/internal/config"
)

// This file downloads a plugin binary from a GitHub release, verifies it
// against the release's SHA256SUMS (and, when configured, its build-
// provenance attestation), extracts it, and caches it under the state
// dir. The cache layout mirrors Terraform's provider cache:
//
//	<state_dir>/plugins/github.com/<owner>/<repo>/<tag>/<os>_<arch>/<repo>

const (
	maxArchiveBytes      = 256 << 20 // ceiling on a downloaded release archive
	maxSumsBytes         = 1 << 20   // ceiling on a SHA256SUMS / metadata file
	maxReleaseJSONBytes  = 16 << 20  // ceiling on a release's JSON (many assets)
	maxDecompressedBytes = 512 << 20 // ceiling on total inflated archive bytes
	maxArchiveEntries    = 4096      // ceiling on tar entries (decompression bomb)
)

// platformToken is "<goos>_<goarch>" for the running host — the token a
// release archive's name must carry (e.g. "linux_amd64", "darwin_arm64").
func platformToken() string { return runtime.GOOS + "_" + runtime.GOARCH }

// provenanceVerifier asserts that the archive with the given sha256 was
// built by owner/repo at tag, per its GitHub build-provenance
// attestation, and returns the source commit it vouches for ("" if the
// predicate omits it). nil verifier means "skip".
type provenanceVerifier interface {
	verify(ctx context.Context, owner, repo, tag, archiveSHA256 string) (commit string, err error)
}

// fetchResult is the outcome of downloading + extracting one platform's
// plugin binary.
type fetchResult struct {
	path     string // extracted binary path
	binSHA   string // "sha256:..." of the extracted binary (load-time identity)
	commit   string // attested source commit ("" when unattested)
	attested bool   // a build-provenance attestation verified
}

// shaSums maps an asset filename to its lowercase-hex sha256, parsed
// from a SHA256SUMS file.
type shaSums map[string]string

func parseShaSums(b []byte) (shaSums, error) {
	out := shaSums{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}
		sum := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[1], "*") // coreutils binary marker
		if len(sum) != 64 {
			continue
		}
		out[name] = sum
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no SHA256SUMS entries parsed")
	}
	return out, nil
}

func isTarGz(name string) bool {
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz")
}

// pickAsset returns the archive filename for the given "<os>_<arch>"
// token. The convention is "..._<os>_<arch>.tar.gz", matched on the full
// token suffix so "linux_arm" never matches "linux_arm64". Exactly one
// archive must match.
func (s shaSums) pickAsset(plat string) (string, error) {
	var matches []string
	for name := range s {
		if isTarGz(name) && (strings.HasSuffix(name, "_"+plat+".tar.gz") || strings.HasSuffix(name, "_"+plat+".tgz")) {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no release archive named *_%s.tar.gz in SHA256SUMS", plat)
	default:
		return "", fmt.Errorf("ambiguous release archives for %s: %s", plat, strings.Join(matches, ", "))
	}
}

// findSumsAsset returns the release's SHA256SUMS asset.
func findSumsAsset(r ghRelease) (ghAsset, bool) {
	for _, a := range r.Assets {
		if strings.HasSuffix(a.Name, "SHA256SUMS") {
			return a, true
		}
	}
	return ghAsset{}, false
}

// releaseByTag fetches a single release by its tag (used to re-download a
// lockfile-pinned version without listing every release).
func (c *ghClient) releaseByTag(ctx context.Context, owner, repo, tag string) (ghRelease, error) {
	u := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s",
		c.base, url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ghRelease{}, err
	}
	c.authHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return ghRelease{}, fmt.Errorf("github: get release %s/%s@%s: %w", owner, repo, tag, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseJSONBytes))
	_ = resp.Body.Close()
	if err != nil {
		return ghRelease{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return ghRelease{}, fmt.Errorf("github: get release %s/%s@%s: HTTP %d: %s",
			owner, repo, tag, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var r ghRelease
	if err := json.Unmarshal(body, &r); err != nil {
		return ghRelease{}, fmt.Errorf("github: decode release %s/%s@%s: %w", owner, repo, tag, err)
	}
	return r, nil
}

// assetURL chooses the download URL for an asset: the api.github.com
// asset URL when authenticated (works for private repos), else the
// public browser_download_url.
func (c *ghClient) assetURL(a ghAsset) string {
	if c.token != "" && a.APIURL != "" {
		return a.APIURL
	}
	return a.DownloadURL
}

// getBytes fetches a small asset/file entirely into memory.
func (c *ghClient) getBytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	return body, nil
}

// downloadToTemp streams url into a temp file in dir, enforcing a byte
// ceiling, and returns the temp path plus the content's hex sha256.
func (c *ghClient) downloadToTemp(ctx context.Context, url, dir string) (path, sum string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/octet-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, "dl-*")
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxArchiveBytes+1))
	cerr := tmp.Close()
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", "", err
	}
	if cerr != nil {
		_ = os.Remove(tmp.Name())
		return "", "", cerr
	}
	if n > maxArchiveBytes {
		_ = os.Remove(tmp.Name())
		return "", "", fmt.Errorf("download %s exceeds %d bytes", url, maxArchiveBytes)
	}
	return tmp.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// extractBinary unpacks the single executable from a .tar.gz at src and
// writes it to dest (0700). Output goes to a fixed path, not a tar entry
// name, so there is no path-traversal surface; a regular file is chosen
// (preferring the executable one when several exist).
func extractBinary(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	// Bound total inflated bytes so a decompression bomb (the on-disk
	// archive is only capped while compressed) can't exhaust CPU/disk as
	// the tar reader advances through entries.
	tr := tar.NewReader(io.LimitReader(gz, maxDecompressedBytes))

	tmp, err := os.CreateTemp(filepath.Dir(dest), "ex-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	found, executable := false, false
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = tmp.Close()
			return fmt.Errorf("read archive: %w", err)
		}
		if entries++; entries > maxArchiveEntries {
			_ = tmp.Close()
			return fmt.Errorf("archive %s has too many entries (>%d)", filepath.Base(src), maxArchiveEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		isExec := hdr.Mode&0o111 != 0
		// Keep the first regular file; upgrade to an executable one if a
		// non-exec was kept first. Reject two executables (ambiguous).
		if found && executable && isExec {
			_ = tmp.Close()
			return fmt.Errorf("archive %s contains multiple executables; expected one plugin binary", filepath.Base(src))
		}
		if found && !isExec {
			continue // already have a candidate, this one is no better
		}
		if found && isExec && executable {
			continue
		}
		// (Re)write the candidate.
		if err := tmp.Truncate(0); err != nil {
			_ = tmp.Close()
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			_ = tmp.Close()
			return err
		}
		if _, err := io.Copy(tmp, io.LimitReader(tr, maxArchiveBytes+1)); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("extract %s: %w", hdr.Name, err)
		}
		found, executable = true, isExec
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("archive %s contains no regular file", filepath.Base(src))
	}
	if err := os.Chmod(tmpName, 0o700); err != nil {
		return err
	}
	return os.Rename(tmpName, dest)
}

// fetcher downloads and caches GitHub-release plugin binaries.
type fetcher struct {
	gh     *ghClient
	cache  string // <state_dir>/plugins
	prov   provenanceVerifier
	logger hclog.Logger
}

func newFetcher(stateDir, ghBase string, prov provenanceVerifier, logger hclog.Logger) *fetcher {
	c := newGHClient()
	if ghBase != "" {
		c.base = ghBase
	}
	return &fetcher{gh: c, cache: filepath.Join(stateDir, "plugins"), prov: prov, logger: logger}
}

func (f *fetcher) platDir(p parsedSource, tag string) string {
	return filepath.Join(f.cache, githubHost, p.Owner, p.Repo, tag, platformToken())
}

// binPath is the cached host-platform binary path for a given tag.
func (f *fetcher) binPath(p parsedSource, tag string) string {
	return filepath.Join(f.platDir(p, tag), p.Repo)
}

// ensure downloads (if not already cached) the host-platform binary for
// release r, verifying the archive against SHA256SUMS and the provenance
// attestation, and returns the cached binary path and its "sha256:..."
// (the extracted binary's hash — the lockfile load-time identity).
func (f *fetcher) ensure(ctx context.Context, p parsedSource, r ghRelease, mode provenanceMode) (fetchResult, error) {
	return f.fetchTo(ctx, p, r, platformToken(), f.platDir(p, r.TagName), p.Repo, mode)
}

// fetchTo downloads the archive for the given platform token from release
// r, verifies it against SHA256SUMS (and the provenance attestation when
// configured), and extracts the binary to destDir/destName. ensure
// caches at the host platform path; the lock command points it at a temp
// dir to hash other platforms' builds without caching them.
func (f *fetcher) fetchTo(ctx context.Context, p parsedSource, r ghRelease, plat, destDir, destName string, mode provenanceMode) (fetchResult, error) {
	var zero fetchResult
	sumsAsset, ok := findSumsAsset(r)
	if !ok {
		return zero, fmt.Errorf("release %s of %s has no SHA256SUMS asset", r.TagName, p.slug())
	}
	sumsBytes, err := f.gh.getBytes(ctx, f.gh.assetURL(sumsAsset), maxSumsBytes)
	if err != nil {
		return zero, err
	}
	sums, err := parseShaSums(sumsBytes)
	if err != nil {
		return zero, err
	}
	archiveName, err := sums.pickAsset(plat)
	if err != nil {
		return zero, err
	}
	wantSHA := sums[archiveName]
	archive, ok := r.asset(archiveName)
	if !ok {
		return zero, fmt.Errorf("SHA256SUMS lists %q but the release has no such asset", archiveName)
	}

	// Provenance gate: the archive's sha256 must be covered by a build-
	// provenance attestation from owner/repo (which also vouches the
	// source commit), governed by the per-plugin `mode`. See
	// gateProvenance.
	attested, commit, err := f.gateProvenance(ctx, p, r.TagName, wantSHA, mode)
	if err != nil {
		return zero, err
	}
	if attested && commit == "" && f.logger != nil {
		f.logger.Warn("plugin attestation verified but names no source commit; commit pinning disabled",
			"plugin", p.slug(), "version", r.TagName)
	}

	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return zero, err
	}
	tmpArchive, gotSHA, err := f.gh.downloadToTemp(ctx, f.gh.assetURL(archive), destDir)
	if err != nil {
		return zero, err
	}
	defer func() { _ = os.Remove(tmpArchive) }()
	if gotSHA != wantSHA {
		return zero, fmt.Errorf("archive %s sha256 mismatch: got %s, SHA256SUMS says %s", archiveName, gotSHA, wantSHA)
	}
	dest := filepath.Join(destDir, destName)
	if err := extractBinary(tmpArchive, dest); err != nil {
		return zero, err
	}
	binSHA, err := hashFile(dest)
	if err != nil {
		return zero, err
	}
	return fetchResult{path: dest, binSHA: binSHA, commit: commit, attested: attested}, nil
}

// platformsInRelease lists the "<os>_<arch>" tokens for every archive in
// the release's SHA256SUMS — the set a cross-platform `plugins lock`
// records hashes for.
func (f *fetcher) platformsInRelease(ctx context.Context, p parsedSource, r ghRelease) ([]string, error) {
	sumsAsset, ok := findSumsAsset(r)
	if !ok {
		return nil, fmt.Errorf("release %s of %s has no SHA256SUMS asset", r.TagName, p.slug())
	}
	sumsBytes, err := f.gh.getBytes(ctx, f.gh.assetURL(sumsAsset), maxSumsBytes)
	if err != nil {
		return nil, err
	}
	sums, err := parseShaSums(sumsBytes)
	if err != nil {
		return nil, err
	}
	var plats []string
	for name := range sums {
		if tok := platformFromArchive(name); tok != "" {
			plats = append(plats, tok)
		}
	}
	sort.Strings(plats)
	return plats, nil
}

// platformFromArchive extracts the "<os>_<arch>" token from an archive
// filename "..._<os>_<arch>.tar.gz", or "" if it isn't a platform
// archive. The os/arch are the last two underscore-separated fields
// before the extension.
func platformFromArchive(name string) string {
	base := strings.TrimSuffix(strings.TrimSuffix(name, ".tar.gz"), ".tgz")
	if base == name {
		return "" // not a tar.gz
	}
	fields := strings.Split(base, "_")
	if len(fields) < 2 {
		return ""
	}
	return fields[len(fields)-2] + "_" + fields[len(fields)-1]
}

// resolvePluginBinary turns a plugin source into a local binary path. A
// local-path source is returned unchanged. A GitHub source resolves to
// the lockfile's pinned version, downloading it to the cache on a miss;
// the first time a plugin is seen it resolves the operator's constraint
// to the newest release, downloads it, and records the source + resolved
// version in the lockfile (trust on first use). It never silently moves
// to a newer version once pinned — that is `clawpatrol plugins update`.
//
// accept distinguishes the two callers: the gateway load (accept=false)
// enforces the pinned hashes, the attested commit, and the provenance
// level — a re-download that loses provenance fails closed. Approve
// (accept=true) instead re-records the binary's current provenance level,
// the operator deliberately accepting it (e.g. a downgrade).
func (m *Manager) resolvePluginBinary(ctx context.Context, sp config.PluginSource, accept bool) (string, error) {
	p, err := pluginSourceFor(sp)
	if err != nil {
		return "", err
	}
	if !p.IsRemote() {
		return sp.Source, nil // local path: existing behavior
	}
	mode := provenanceModeOf(sp)
	f := newFetcher(m.stateDirLocked(), m.ghBase, m.prov, m.logger)

	entry, have := m.lock.get(sp.Name)

	// The pinned (enforcing) path applies to a normal gateway load of an
	// already-locked plugin. Approve (accept=true) skips it: it re-resolves
	// the constraint's newest release and re-records, deliberately
	// accepting the result.
	pinned := !accept && have && entry.Source != "" && entry.Version != ""

	// A lockfile entry that names a version but no source is malformed (a
	// hand-edit or a partial write). Refuse it rather than fall through to
	// the first-use branch, which would silently re-resolve the constraint
	// and auto-upgrade — the one thing the running gateway must never do.
	if !accept && have && entry.Version != "" && entry.Source == "" {
		return "", fmt.Errorf(
			"lockfile entry for %q has a version but no source; fix or remove it, then run `clawpatrol plugins install`",
			sp.Name)
	}

	if pinned {
		if entry.Source != p.slug() {
			return "", fmt.Errorf(
				"source changed from %q to %q since it was locked; run `clawpatrol plugins update %s`",
				entry.Source, p.slug(), sp.Name)
		}
		if err := constraintHolds(sp.Version, entry.Version); err != nil {
			return "", fmt.Errorf(
				"locked version %s no longer satisfies %q; run `clawpatrol plugins update %s` (%w)",
				entry.Version, sp.Version, sp.Name, err)
		}
		// Offline fast path: trust the cache only when the lockfile records
		// at least one approved hash AND the cached binary matches it. An
		// entry with no hashes was never fully verified (e.g. a first-load
		// probe failed after the source/version was recorded), so fall
		// through to a fresh, provenance- and checksum-verified download
		// rather than load an unchecked binary.
		path := f.binPath(p, entry.Version)
		if len(entry.Hashes) > 0 && fileExists(path) {
			if h, err := hashFile(path); err == nil && entry.hasHash(h) {
				return path, nil
			}
			// Hash mismatch or unreadable: re-download and re-verify below.
		}
		r, err := f.gh.releaseByTag(ctx, p.Owner, p.Repo, entry.Version)
		if err != nil {
			return "", err
		}
		res, err := f.ensure(ctx, p, r, mode)
		if err != nil {
			return "", err
		}
		if len(entry.Hashes) > 0 && !entry.hasHash(res.binSHA) {
			_ = os.Remove(res.path)
			return "", fmt.Errorf(
				"downloaded binary hash %s is not in the lockfile (expected one of %v); refusing", res.binSHA, entry.Hashes)
		}
		if err := checkProvenanceNotDowngraded(sp.Name, mode, entry, res); err != nil {
			_ = os.Remove(res.path)
			return "", err
		}
		return res.path, nil
	}

	// First use, or Approve: resolve the constraint to the newest release,
	// download, and (trust-on-first-use / operator-accept) record the
	// source + resolved tag + attested commit + provenance level. The
	// binary hash + network grant are recorded by the resolveNetwork pass
	// that runs next.
	r, _, err := f.gh.resolveVersion(ctx, p, sp.Version)
	if err != nil {
		return "", err
	}
	res, err := f.ensure(ctx, p, r, mode)
	if err != nil {
		return "", err
	}
	m.lock.setSource(sp.Name, p.slug(), r.TagName, strings.TrimSpace(sp.Version), res.commit, res.attested)
	return res.path, nil
}

// checkProvenanceNotDowngraded fails closed when a freshly-fetched binary
// has weaker provenance than the lockfile recorded: it lost the
// attestation entirely, or its attestation now names a different source
// commit (a re-pointed tag). Skipped when the operator set provenance =
// "off". The fix is `clawpatrol plugins approve`.
func checkProvenanceNotDowngraded(name string, mode provenanceMode, entry lockEntry, res fetchResult) error {
	if mode == provOff {
		return nil
	}
	if entry.Attested && !res.attested {
		return fmt.Errorf(
			"plugin %q lost its build-provenance attestation since it was approved; "+
				"a benign plugin's build dropping provenance looks exactly like this. "+
				"If you trust it, re-approve: clawpatrol plugins approve %s", name, name)
	}
	if entry.Commit != "" && res.commit != "" && res.commit != entry.Commit {
		return fmt.Errorf(
			"plugin %q: attested source commit %s does not match the locked commit %s (a re-pointed tag); "+
				"run `clawpatrol plugins update %s` or re-approve it", name, res.commit, entry.Commit, name)
	}
	return nil
}

// constraintHolds reports whether the locked tag still satisfies the
// operator's constraint. An empty constraint accepts any pinned version.
func constraintHolds(constraint, tag string) error {
	c := strings.TrimSpace(constraint)
	if c == "" {
		return nil
	}
	cons, err := version.NewConstraint(c)
	if err != nil {
		return fmt.Errorf("invalid version constraint %q: %w", constraint, err)
	}
	v, err := version.NewVersion(tag)
	if err != nil {
		return fmt.Errorf("locked version %q is not valid semver: %w", tag, err)
	}
	if !cons.Check(v) {
		return fmt.Errorf("%s does not satisfy %s", tag, c)
	}
	return nil
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}
