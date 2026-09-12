package endpoints_test

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/facet"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const remoteMCPGatewayPrefix = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

`

func loadRemoteMCP(t *testing.T, src string) (*config.CompiledPolicy, error) {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(remoteMCPGatewayPrefix+src), "in.hcl")
	if diags.HasErrors() {
		return nil, diags
	}
	return config.Compile(gw)
}

func mustLoadRemoteMCP(t *testing.T, src string) *config.CompiledPolicy {
	t.Helper()
	cp, err := loadRemoteMCP(t, src)
	if err != nil {
		t.Fatalf("load/compile: %v", err)
	}
	return cp
}

// TestRemoteMCPEndpointHostsFromURL: the compiled endpoint derives its
// host from the URL and carries family "mcp".
func TestRemoteMCPEndpointHostsFromURL(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "grain" {
  url = "https://api.grain.com/_/mcp"
}
credential "bearer_token" "tok" { endpoint = remote_mcp.grain }
profile "default" { credentials = [bearer_token.tok] }
`)
	ep := cp.Endpoints["grain"]
	if ep == nil {
		t.Fatal("endpoint grain not compiled")
	}
	if ep.Family != "mcp" {
		t.Errorf("family = %q, want mcp", ep.Family)
	}
	found := false
	for _, h := range ep.Hosts {
		if h == "api.grain.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("hosts = %v, want to include api.grain.com", ep.Hosts)
	}
	if ep.PathConstraint != "/_/mcp" || ep.PathPrefix {
		t.Errorf("path constraint = %q prefix=%v, want /_/mcp exact", ep.PathConstraint, ep.PathPrefix)
	}
}

// TestRemoteMCPEndpointRejectsHTTPURL: a non-https url is a config error.
func TestRemoteMCPEndpointRejectsHTTPURL(t *testing.T) {
	_, err := loadRemoteMCP(t, `
endpoint "remote_mcp" "insecure" {
  url = "http://mcp.example.com/mcp"
}
credential "bearer_token" "tok" { endpoint = remote_mcp.insecure }
profile "default" { credentials = [bearer_token.tok] }
`)
	if err == nil {
		t.Fatal("expected error for http url, got nil")
	}
}

// TestRemoteMCPEndpointRejectsMissingHost: a url without a host fails.
func TestRemoteMCPEndpointRejectsMissingHost(t *testing.T) {
	_, err := loadRemoteMCP(t, `
endpoint "remote_mcp" "nohost" {
  url = "https:///mcp"
}
credential "bearer_token" "tok" { endpoint = remote_mcp.nohost }
profile "default" { credentials = [bearer_token.tok] }
`)
	if err == nil {
		t.Fatal("expected error for missing host, got nil")
	}
}

// TestRemoteMCPEndpointRejectsUnknownTransport: transport is only an
// advisory hint today, but unsupported spellings should fail config
// validation instead of silently documenting a fake mode.
func TestRemoteMCPEndpointRejectsUnknownTransport(t *testing.T) {
	_, err := loadRemoteMCP(t, `
endpoint "remote_mcp" "bad_transport" {
  url       = "https://mcp.example.com/mcp"
  transport = "websocket"
}
credential "bearer_token" "tok" { endpoint = remote_mcp.bad_transport }
profile "default" { credentials = [bearer_token.tok] }
`)
	if err == nil {
		t.Fatal("expected error for unknown transport, got nil")
	}
}

// TestRemoteMCPRootURLIsHostWide: an empty/root URL path should behave
// like a host-wide endpoint rather than a path-scoped endpoint to "/".
func TestRemoteMCPRootURLIsHostWide(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "root" {
  url = "https://mcp-root.example.com/"
}
credential "bearer_token" "tok" { endpoint = remote_mcp.root }
profile "default" { credentials = [bearer_token.tok] }
`)
	ep := cp.Endpoints["root"]
	if ep == nil {
		t.Fatal("endpoint root not compiled")
	}
	if ep.PathConstraint != "" || ep.PathPrefix {
		t.Errorf("path constraint = %q prefix=%v, want host-wide empty constraint", ep.PathConstraint, ep.PathPrefix)
	}
	cands := runtime.HostCandidates(cp, "default", "mcp-root.example.com")
	if got := runtime.SelectEndpointForPath(cands, "/v1/anything"); got == nil || got.Name != "root" {
		t.Errorf("/v1/anything → %v, want root host-wide endpoint", got)
	}
}

// TestRemoteMCPEndpointKeepsExplicitAdditionalHosts: explicit hosts are
// merged with the URL-derived host; the URL host is never dropped.
func TestRemoteMCPEndpointKeepsExplicitAdditionalHosts(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "multi" {
  url   = "https://mcp.example.com/mcp"
  hosts = ["mcp-alt.example.com"]
}
credential "bearer_token" "tok" { endpoint = remote_mcp.multi }
profile "default" { credentials = [bearer_token.tok] }
`)
	ep := cp.Endpoints["multi"]
	if ep == nil {
		t.Fatal("endpoint multi not compiled")
	}
	var haveURL, haveExtra bool
	for _, h := range ep.Hosts {
		switch h {
		case "mcp.example.com":
			haveURL = true
		case "mcp-alt.example.com":
			haveExtra = true
		}
	}
	if !haveURL || !haveExtra {
		t.Errorf("hosts = %v, want both mcp.example.com and mcp-alt.example.com", ep.Hosts)
	}
}

// TestRemoteMCPFamilyUsesHTTPSMITMTransport: the mcp facet rides the
// https-mitm transport.
func TestRemoteMCPFamilyUsesHTTPSMITMTransport(t *testing.T) {
	if !facet.IsHTTPSMITMFamily("mcp") {
		t.Fatal("mcp family should use https-mitm transport")
	}
}

// TestRemoteMCPDispatchMatchesConfiguredPathOnly: a request to the
// configured MCP path lands on the MCP endpoint, while another path on
// the same host does not.
func TestRemoteMCPDispatchMatchesConfiguredPathOnly(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "grain" {
  url = "https://api.grain.com/_/mcp"
}
credential "bearer_token" "tok" { endpoint = remote_mcp.grain }
profile "default" { credentials = [bearer_token.tok] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.grain.com")
	if got := runtime.SelectEndpointForPath(cands, "/_/mcp"); got == nil || got.Name != "grain" {
		t.Errorf("/_/mcp → %v, want grain", got)
	}
	if got := runtime.SelectEndpointForPath(cands, "/v1/users"); got != nil {
		t.Errorf("/v1/users → %v, want nil (not the MCP endpoint)", got.Name)
	}
}

// TestRemoteMCPDispatchUsesPathSegmentBoundary: an exact path
// constraint does not match a sibling path that shares a prefix.
func TestRemoteMCPDispatchUsesPathSegmentBoundary(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "m" {
  url = "https://mcp.example.com/mcp"
}
credential "bearer_token" "tok" { endpoint = remote_mcp.m }
profile "default" { credentials = [bearer_token.tok] }
`)
	cands := runtime.HostCandidates(cp, "default", "mcp.example.com")
	if got := runtime.SelectEndpointForPath(cands, "/mcp"); got == nil {
		t.Error("/mcp should match exact constraint /mcp")
	}
	if got := runtime.SelectEndpointForPath(cands, "/mcp2"); got != nil {
		t.Errorf("/mcp2 → %v, want nil (segment boundary)", got.Name)
	}
	if got := runtime.SelectEndpointForPath(cands, "/mcp/sub"); got != nil {
		t.Errorf("/mcp/sub → %v, want nil (exact only)", got.Name)
	}
}

// TestRemoteMCPSharedHostRequiresPathAwareDispatch: an MCP endpoint and
// a generic https endpoint can share a host; the path-specific endpoint
// wins on its path while the rest of the host routes to the host-wide
// https endpoint.
func TestRemoteMCPSharedHostRequiresPathAwareDispatch(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "mcp" {
  url = "https://api.shared.com/_/mcp"
}
endpoint "https" "rest" {
  hosts = ["api.shared.com"]
}
credential "bearer_token" "a" { endpoint = remote_mcp.mcp }
credential "bearer_token" "b" { endpoint = https.rest }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.shared.com")
	if len(cands) < 2 {
		t.Fatalf("expected both endpoints as candidates, got %d", len(cands))
	}
	if got := runtime.SelectEndpointForPath(cands, "/_/mcp"); got == nil || got.Name != "mcp" {
		t.Errorf("/_/mcp → %v, want mcp", got)
	}
	if got := runtime.SelectEndpointForPath(cands, "/v1/users"); got == nil || got.Name != "rest" {
		t.Errorf("/v1/users → %v, want rest (host-wide https)", got)
	}
	// HostEndpoint (single) still resolves to the host-wide https
	// endpoint, not the path-scoped MCP one.
	if got := runtime.HostEndpoint(cp, "default", "api.shared.com"); got == nil || got.Name != "rest" {
		t.Errorf("HostEndpoint → %v, want host-wide rest", got)
	}
}

// TestRemoteMCPDispatchMostSpecificEndpointWins: the longest matching
// path constraint wins among path-scoped candidates.
func TestRemoteMCPSharedHostFallsBackToWildcardHTTPS(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "mcp" {
  url = "https://api.shared-wildcard.com/_/mcp"
}
endpoint "https" "wildcard" {
  hosts = ["*.shared-wildcard.com"]
}
credential "bearer_token" "a" { endpoint = remote_mcp.mcp }
credential "bearer_token" "b" { endpoint = https.wildcard }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.shared-wildcard.com")
	if got := runtime.SelectEndpointForPath(cands, "/_/mcp"); got == nil || got.Name != "mcp" {
		t.Errorf("/_/mcp → %v, want mcp", got)
	}
	if got := runtime.SelectEndpointForPath(cands, "/v1/users"); got == nil || got.Name != "wildcard" {
		t.Errorf("/v1/users → %v, want wildcard fallback", got)
	}
}

func TestRemoteMCPWildcardSharedHostFallsBackToWildcardHTTPS(t *testing.T) {
	cases := map[string]string{
		"mcp first": `
endpoint "remote_mcp" "mcp" {
  url = "https://mcp.shared-wildcard-order.com/_/mcp"
  hosts = ["*.shared-wildcard-order.com"]
}
endpoint "https" "rest" {
  hosts = ["*.shared-wildcard-order.com"]
}
credential "bearer_token" "a" { endpoint = remote_mcp.mcp }
credential "bearer_token" "b" { endpoint = https.rest }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`,
		"https first": `
endpoint "https" "rest" {
  hosts = ["*.shared-wildcard-order.com"]
}
endpoint "remote_mcp" "mcp" {
  url = "https://mcp.shared-wildcard-order.com/_/mcp"
  hosts = ["*.shared-wildcard-order.com"]
}
credential "bearer_token" "a" { endpoint = remote_mcp.mcp }
credential "bearer_token" "b" { endpoint = https.rest }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`,
	}
	for name, hcl := range cases {
		t.Run(name, func(t *testing.T) {
			cp := mustLoadRemoteMCP(t, hcl)
			cands := runtime.HostCandidates(cp, "default", "api.shared-wildcard-order.com")
			if got := runtime.SelectEndpointForPath(cands, "/_/mcp"); got == nil || got.Name != "mcp" {
				t.Errorf("/_/mcp → %v, want mcp", got)
			}
			if got := runtime.SelectEndpointForPath(cands, "/v1/users"); got == nil || got.Name != "rest" {
				t.Errorf("/v1/users → %v, want rest wildcard fallback", got)
			}
		})
	}
}

func TestRemoteMCPExactHostWideBeatsWildcardPathScoped(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "https" "api" {
  hosts = ["api.exact-beats-wild.example"]
}
endpoint "remote_mcp" "wild" {
  url = "https://mcp.exact-beats-wild.example/_/mcp"
  hosts = ["*.exact-beats-wild.example"]
}
credential "bearer_token" "a" { endpoint = https.api }
credential "bearer_token" "b" { endpoint = remote_mcp.wild }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.exact-beats-wild.example")
	if got := runtime.SelectEndpointForPath(cands, "/_/mcp"); got == nil || got.Name != "api" {
		t.Errorf("/_/mcp → %v, want exact host-wide api", got)
	}
	if got := runtime.SelectEndpointForPath(cands, "/v1/users"); got == nil || got.Name != "api" {
		t.Errorf("/v1/users → %v, want exact host-wide api", got)
	}
}

func TestRemoteMCPExactHostWideBeatsWildcardHostWide(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "https" "api" {
  hosts = ["api.exact-hostwide.example"]
}
endpoint "https" "wild" {
  hosts = ["*.exact-hostwide.example"]
}
credential "bearer_token" "a" { endpoint = https.api }
credential "bearer_token" "b" { endpoint = https.wild }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.exact-hostwide.example")
	if got := runtime.SelectEndpointForPath(cands, "/v1/users"); got == nil || got.Name != "api" {
		t.Errorf("/v1/users → %v, want exact host-wide api", got)
	}
}

func TestRemoteMCPExactHostWideDuplicatesKeepLastWins(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "https" "first" {
  hosts = ["api.duplicate-exact.example"]
}
endpoint "https" "second" {
  hosts = ["api.duplicate-exact.example"]
}
credential "bearer_token" "a" { endpoint = https.first }
credential "bearer_token" "b" { endpoint = https.second }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.duplicate-exact.example")
	if got := runtime.SelectEndpointForPath(cands, "/v1/users"); got == nil || got.Name != "second" {
		t.Errorf("/v1/users → %v, want duplicate exact host-wide last-wins endpoint second", got)
	}
	if got := runtime.HostEndpoint(cp, "default", "api.duplicate-exact.example"); got == nil || got.Name != "second" {
		t.Errorf("HostEndpoint → %v, want second", got)
	}
}

func TestRemoteMCPMostSpecificWildcardHostWideWins(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "https" "broad" {
  hosts = ["*.wild-specific.example"]
}
endpoint "https" "specific" {
  hosts = ["*.api.wild-specific.example"]
}
credential "bearer_token" "a" { endpoint = https.broad }
credential "bearer_token" "b" { endpoint = https.specific }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "foo.api.wild-specific.example")
	if got := runtime.SelectEndpointForPath(cands, "/v1/users"); got == nil || got.Name != "specific" {
		t.Errorf("/v1/users → %v, want most-specific wildcard host-wide", got)
	}
}

func TestRemoteMCPExactPathScopedFallsBackToWildcardPathScoped(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "exact" {
  url = "https://api.path-fallback.example/_/mcp"
}
endpoint "remote_mcp" "wild" {
  url = "https://mcp.path-fallback.example/common-mcp"
  hosts = ["*.path-fallback.example"]
}
credential "bearer_token" "a" { endpoint = remote_mcp.exact }
credential "bearer_token" "b" { endpoint = remote_mcp.wild }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.path-fallback.example")
	if got := runtime.SelectEndpointForPath(cands, "/_/mcp"); got == nil || got.Name != "exact" {
		t.Errorf("/_/mcp → %v, want exact", got)
	}
	if got := runtime.SelectEndpointForPath(cands, "/common-mcp"); got == nil || got.Name != "wild" {
		t.Errorf("/common-mcp → %v, want wildcard path-scoped fallback", got)
	}
}

func TestRemoteMCPExactPathScopedBeatsWildcardPathScoped(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "exact" {
  url = "https://api.path-precedence.example/_/mcp/"
}
endpoint "remote_mcp" "wild" {
  url = "https://mcp.path-precedence.example/_/mcp/deeper"
  hosts = ["*.path-precedence.example"]
}
credential "bearer_token" "a" { endpoint = remote_mcp.exact }
credential "bearer_token" "b" { endpoint = remote_mcp.wild }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.path-precedence.example")
	if got := runtime.SelectEndpointForPath(cands, "/_/mcp/deeper"); got == nil || got.Name != "exact" {
		t.Errorf("/_/mcp/deeper → %v, want exact path-scoped endpoint", got)
	}
}

func TestRemoteMCPDispatchMostSpecificEndpointWins(t *testing.T) {
	cp := mustLoadRemoteMCP(t, `
endpoint "remote_mcp" "deep" {
  url = "https://api.shared2.com/_/mcp/v2"
}
endpoint "remote_mcp" "shallow" {
  url = "https://api.shared2.com/_/"
}
credential "bearer_token" "a" { endpoint = remote_mcp.deep }
credential "bearer_token" "b" { endpoint = remote_mcp.shallow }
profile "default" { credentials = [bearer_token.a, bearer_token.b] }
`)
	cands := runtime.HostCandidates(cp, "default", "api.shared2.com")
	if got := runtime.SelectEndpointForPath(cands, "/_/mcp/v2"); got == nil || got.Name != "deep" {
		t.Errorf("/_/mcp/v2 → %v, want deep (most specific)", got)
	}
	if got := runtime.SelectEndpointForPath(cands, "/_/other"); got == nil || got.Name != "shallow" {
		t.Errorf("/_/other → %v, want shallow (prefix)", got)
	}
}
