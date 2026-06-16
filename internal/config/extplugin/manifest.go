package extplugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/denoland/clawpatrol/internal/config"
	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

// A plugin release may publish a static manifest asset
// (<repo>_<version>_manifest.json) — the same manifest the plugin serves
// over gRPC, emitted by its `--print-manifest` mode. It is listed in
// SHA256SUMS and covered by the build-provenance attestation, so the
// gateway can read a plugin's metadata and required privileges, verified,
// *before* downloading or running the binary.

// errNoManifest means the release publishes no static manifest asset.
var errNoManifest = errors.New("release has no static manifest asset")

// gateProvenance applies the per-plugin provenance policy to one asset's
// sha256 and reports whether an attestation verified plus the attested
// source commit. Under "require" a missing attestation fails closed;
// under "warn" it warns and returns (false, "", nil); a present-but-
// invalid attestation always fails; "off"/no-verifier skips.
func (f *fetcher) gateProvenance(ctx context.Context, p parsedSource, tag, assetSHA256 string, mode provenanceMode) (attested bool, commit string, err error) {
	if f.prov == nil || mode == provOff {
		return false, "", nil
	}
	c, verr := f.prov.verify(ctx, p.Owner, p.Repo, tag, assetSHA256)
	switch {
	case verr == nil:
		return true, c, nil
	case errors.Is(verr, errNoAttestation):
		if mode == provRequire {
			return false, "", fmt.Errorf(
				"%s %s has no build-provenance attestation but provenance is required; "+
					"set provenance = \"warn\" to allow checksum-only, or have the plugin publish one",
				p.slug(), tag)
		}
		if f.logger != nil {
			f.logger.Warn("plugin has no build-provenance attestation; verified by checksum only",
				"plugin", p.slug(), "version", tag)
		}
		return false, "", nil
	default:
		return false, "", fmt.Errorf("provenance verification failed for %s %s: %w", p.slug(), tag, verr)
	}
}

// manifestAsset returns the SHA256SUMS entry for the static manifest
// (a "*manifest.json" filename), or false.
func (s shaSums) manifestAsset() (name, sum string, ok bool) {
	var names []string
	for n := range s {
		if strings.HasSuffix(n, "manifest.json") {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "", "", false
	}
	sort.Strings(names)
	return names[0], s[names[0]], true
}

// fetchManifest downloads and verifies the release's static manifest
// asset (checksum + provenance, per mode) and parses it. No binary is
// downloaded. Returns errNoManifest when the release has none.
func (f *fetcher) fetchManifest(ctx context.Context, p parsedSource, r ghRelease, mode provenanceMode) (*pb.ManifestResponse, error) {
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
	name, wantSHA, ok := sums.manifestAsset()
	if !ok {
		return nil, errNoManifest
	}
	asset, ok := r.asset(name)
	if !ok {
		return nil, fmt.Errorf("SHA256SUMS lists %q but the release has no such asset", name)
	}
	if _, _, err := f.gateProvenance(ctx, p, r.TagName, wantSHA, mode); err != nil {
		return nil, err
	}
	body, err := f.gh.getBytes(ctx, f.gh.assetURL(asset), maxSumsBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		return nil, fmt.Errorf("manifest %s sha256 mismatch: got %s, SHA256SUMS says %s", name, got, wantSHA)
	}
	var mf pb.ManifestResponse
	if err := protojson.Unmarshal(body, &mf); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", name, err)
	}
	return &mf, nil
}

// ManifestPreview is a plugin version's metadata and required privileges,
// read from its static manifest with no binary download.
type ManifestPreview struct {
	Name        string   `json:"name"`
	Source      string   `json:"source"`
	Version     string   `json:"version"` // resolved release tag
	Locked      string   `json:"locked,omitempty"`
	Network     string   `json:"network"`          // required network grant
	Egress      []string `json:"egress,omitempty"` // required brokered-dial targets
	Credentials []string `json:"credentials,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty"`
	Tunnels     []string `json:"tunnels,omitempty"`
	Facets      []string `json:"facets,omitempty"`
}

// PreviewSource resolves the constraint to the newest release and reads
// its static manifest (no binary download), returning the plugin's
// metadata and required privileges. The locked version, if any, is
// included so a caller can show what an upgrade would change. Returns
// errNoManifest when the release publishes no static manifest.
func (m *Manager) PreviewSource(ctx context.Context, sp config.PluginSource) (ManifestPreview, error) {
	if err := m.lock.load(); err != nil {
		return ManifestPreview{}, err
	}
	return m.previewManifest(ctx, sp)
}

// previewManifest is PreviewSource without reloading the lockfile — for
// callers (LoadPlugins) that already hold a loaded lock pass.
func (m *Manager) previewManifest(ctx context.Context, sp config.PluginSource) (ManifestPreview, error) {
	p, err := pluginSourceFor(sp)
	if err != nil {
		return ManifestPreview{}, err
	}
	if !p.IsRemote() {
		return ManifestPreview{}, fmt.Errorf("plugin %q has a local source; nothing to preview", sp.Name)
	}
	locked := ""
	if e, ok := m.lock.get(sp.Name); ok {
		locked = e.Version
	}
	f := newFetcher(m.stateDirLocked(), m.ghBase, m.prov, m.logger)
	r, _, err := f.gh.resolveVersion(ctx, p, sp.Version)
	if err != nil {
		return ManifestPreview{}, err
	}
	mf, err := f.fetchManifest(ctx, p, r, provenanceModeOf(sp))
	if err != nil {
		return ManifestPreview{}, err
	}
	return previewFromManifest(sp.Name, p.slug(), r.TagName, locked, mf), nil
}

func previewFromManifest(name, source, version, locked string, mf *pb.ManifestResponse) ManifestPreview {
	pv := ManifestPreview{
		Name: name, Source: source, Version: version, Locked: locked,
		Network: string(networkFromManifest(mf)),
		Egress:  egressFromManifest(mf),
	}
	for _, c := range mf.GetCredentials() {
		pv.Credentials = append(pv.Credentials, c.GetTypeName())
	}
	for _, e := range mf.GetEndpoints() {
		pv.Endpoints = append(pv.Endpoints, e.GetTypeName())
	}
	for _, t := range mf.GetTunnels() {
		pv.Tunnels = append(pv.Tunnels, t.GetTypeName())
	}
	for _, fa := range mf.GetFacets() {
		pv.Facets = append(pv.Facets, fa.GetName())
	}
	return pv
}
