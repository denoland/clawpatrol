package config_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestCompile loads testdata/feature_minimal.hcl, lowers it via
// config.Compile, and exercises the resulting CompiledPolicy end-to-
// end: priority sort, host indexing, credential resolution, and
// matcher dispatch on synthetic requests.
func TestCompile(t *testing.T) {
	gw, diags := config.Load(filepath.Join("testdata", "feature_minimal.hcl"))
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Profile shape.
	prof, ok := cp.Profiles["default"]
	if !ok {
		t.Fatalf("missing default profile")
	}
	if len(prof.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(prof.Endpoints))
	}
	ep := prof.Endpoints["github"]
	if ep == nil {
		t.Fatal("expected github endpoint")
	}

	// Host index.
	for _, want := range []string{"api.github.com", "github.com"} {
		if prof.HostIndex[want] != ep {
			t.Errorf("HostIndex[%q] missing or wrong", want)
		}
	}

	// Credentials resolved.
	if len(ep.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(ep.Credentials))
	}
	if ep.Credentials[0].Credential == nil ||
		ep.Credentials[0].Credential.Symbol.Name != "github-pat" {
		t.Errorf("credential resolution wrong: %+v", ep.Credentials[0])
	}

	// Rule order: github-reads (priority 0), github-writes (priority 0).
	// Both 0 → declaration order, but the fixture declares reads first.
	if len(ep.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(ep.Rules))
	}
	names := []string{ep.Rules[0].Name, ep.Rules[1].Name}
	// Stable sort; rule order in cp.Endpoints map vs. iteration is
	// non-deterministic upstream, so we just check both rules landed.
	got := map[string]bool{names[0]: true, names[1]: true}
	for _, want := range []string{"github-reads", "github-writes"} {
		if !got[want] {
			t.Errorf("missing rule %q in compiled set %v", want, names)
		}
	}

	// Matcher dispatch — find each rule by name and run a request.
	var reads, writes *config.CompiledRule
	for _, r := range ep.Rules {
		switch r.Name {
		case "github-reads":
			reads = r
		case "github-writes":
			writes = r
		}
	}
	getReq := &match.Request{Family: "http", Method: "GET"}
	postReq := &match.Request{Family: "http", Method: "POST"}
	if !reads.Matcher.Match(getReq) {
		t.Errorf("github-reads should match GET")
	}
	if reads.Matcher.Match(postReq) {
		t.Errorf("github-reads should NOT match POST")
	}
	if !writes.Matcher.Match(postReq) {
		t.Errorf("github-writes should match POST")
	}
	if writes.Matcher.Match(getReq) {
		t.Errorf("github-writes should NOT match GET")
	}

	// Outcomes wired correctly.
	if reads.Outcome.Verdict != "allow" {
		t.Errorf("github-reads verdict=%q want allow", reads.Outcome.Verdict)
	}
	if len(writes.Outcome.Approve) != 1 || writes.Outcome.Approve[0].Name != "ops" {
		t.Errorf("github-writes approve=%+v", writes.Outcome.Approve)
	}
}

// TestCompileWildcardHosts verifies that wildcard hosts are accepted,
// land in HostPatterns (not HostIndex), and that malformed wildcards
// or within-endpoint duplicates are rejected at load time.
func TestCompileWildcardHosts(t *testing.T) {
	src := `
credential "bearer_token" "tok" {}
endpoint "https" "aws" {
  hosts      = ["*.amazonaws.com", "*.us-east-1.amazonaws.com:443"]
  credential = tok
}
profile "p" { endpoints = [aws] }
`
	gw, diags := config.LoadBytes([]byte(src), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	prof := cp.Profiles["p"]
	if prof == nil {
		t.Fatalf("missing profile p")
	}
	if got := len(prof.HostPatterns); got != 2 {
		t.Fatalf("HostPatterns count = %d, want 2 (entries: %+v)", got, prof.HostPatterns)
	}
	// Longest first: *.us-east-1.amazonaws.com before *.amazonaws.com.
	if prof.HostPatterns[0].Pattern != "*.us-east-1.amazonaws.com" {
		t.Errorf("HostPatterns[0]=%q, want *.us-east-1.amazonaws.com", prof.HostPatterns[0].Pattern)
	}
	if prof.HostPatterns[1].Pattern != "*.amazonaws.com" {
		t.Errorf("HostPatterns[1]=%q, want *.amazonaws.com", prof.HostPatterns[1].Pattern)
	}
	// Wildcards must not leak into HostIndex.
	for k := range prof.HostIndex {
		if strings.HasPrefix(k, "*.") {
			t.Errorf("HostIndex leaked wildcard %q", k)
		}
	}
}

func TestCompileRejectsBadHosts(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "malformed wildcard - empty suffix",
			src: `
credential "bearer_token" "tok" {}
endpoint "https" "bad" {
  hosts = ["*."]
  credential = tok
}
profile "p" { endpoints = [bad] }
`,
		},
		{
			name: "wildcard with bare TLD",
			src: `
credential "bearer_token" "tok" {}
endpoint "https" "bad" {
  hosts = ["*.com"]
  credential = tok
}
profile "p" { endpoints = [bad] }
`,
		},
		{
			name: "wildcard not at leftmost label",
			src: `
credential "bearer_token" "tok" {}
endpoint "https" "bad" {
  hosts = ["api.*.foo.com"]
  credential = tok
}
profile "p" { endpoints = [bad] }
`,
		},
		{
			name: "duplicate hosts",
			src: `
credential "bearer_token" "tok" {}
endpoint "https" "bad" {
  hosts = ["api.foo.com", "api.foo.com"]
  credential = tok
}
profile "p" { endpoints = [bad] }
`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, diags := config.LoadBytes([]byte(c.src), "in.hcl")
			if !diags.HasErrors() {
				t.Fatalf("load accepted bad hosts; want diagnostic")
			}
		})
	}
}

// TestCompilePrioritySort verifies that rules with mixed priorities
// land in descending priority order, matching the v14 first-match-
// wins evaluation. Tied priorities preserve declaration order.
func TestCompilePrioritySort(t *testing.T) {
	src := `
credential "bearer_token" "pat" {}
endpoint "https" "ep" {
  hosts      = ["x.example.com"]
  credential = pat
}
profile "p" { endpoints = [ep] }

rule "fallback" {
  endpoint  = ep
  priority  = -100
  condition = "http.method == 'POST'"
  verdict   = "deny"
}
rule "specific" {
  endpoint  = ep
  priority  = 100
  condition = "http.method == 'POST' && http.path == '/v1/refunds'"
  verdict   = "deny"
}
rule "general" {
  endpoint  = ep
  condition = "http.method == 'POST'"
  verdict   = "allow"
}
`
	gw, diags := config.LoadBytes([]byte(src), "in.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules := cp.Endpoints["ep"].Rules
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	want := []string{"specific", "general", "fallback"}
	for i, r := range rules {
		if r.Name != want[i] {
			t.Errorf("rules[%d]=%q want %q (priorities %v)",
				i, r.Name, want[i], priorities(rules))
		}
	}
}

func priorities(rules []*config.CompiledRule) []int {
	out := make([]int, len(rules))
	for i, r := range rules {
		out[i] = r.Priority
	}
	return out
}

// TestCompileTunnel exercises the tunnel-specific bits of Compile:
// CompiledTunnel population, endpoint→tunnel ref resolution, the
// VIP forcing for tunneled endpoints, and skipping ConnRouter
// indexing for the same.
func TestCompileTunnel(t *testing.T) {
	gw, diags := config.Load(filepath.Join("testdata", "feature_tunnel.hcl"))
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	ct, ok := cp.Tunnels["csql-prod"]
	if !ok {
		t.Fatal("missing csql-prod tunnel in CompiledPolicy")
	}
	if ct.Sharing != "singleton" {
		t.Errorf("Sharing = %q, want singleton", ct.Sharing)
	}
	if ct.Keepalive != 5*time.Minute {
		t.Errorf("Keepalive = %v, want 5m", ct.Keepalive)
	}
	if ct.KeepaliveAlways {
		t.Error("KeepaliveAlways = true, want false")
	}

	ep, ok := cp.Endpoints["deploy-classic"]
	if !ok {
		t.Fatal("missing deploy-classic endpoint")
	}
	if ep.Tunnel != ct {
		t.Errorf("ep.Tunnel = %p, want %p (csql-prod)", ep.Tunnel, ct)
	}
	if !ep.RequiresVIP() {
		t.Error("tunneled endpoint must opt into VIP, got RequiresVIP() = false")
	}
}

func TestCompileTunnelFingerprintTracksConfig(t *testing.T) {
	base := `
credential "bearer_token" "tok" {}
tunnel "local_command" "t" {
  command    = ["ssh", "old-bastion"]
  listen     = "127.0.0.1:1001"
  keepalive  = "always"
  credential = tok
}
`
	same := `
credential "bearer_token" "tok" {}
tunnel "local_command" "t" {
  command    = ["ssh", "old-bastion"]
  listen     = "127.0.0.1:1001"
  keepalive  = "always"
  credential = tok
}
`
	commandChanged := `
credential "bearer_token" "tok" {}
tunnel "local_command" "t" {
  command    = ["ssh", "new-bastion"]
  listen     = "127.0.0.1:1001"
  keepalive  = "always"
  credential = tok
}
`
	credentialChanged := `
credential "bearer_token" "tok" { idempotency_key = true }
tunnel "local_command" "t" {
  command    = ["ssh", "old-bastion"]
  listen     = "127.0.0.1:1001"
  keepalive  = "always"
  credential = tok
}
`

	baseFP := compileTunnelFingerprint(t, base, "t")
	if baseFP == "" {
		t.Fatal("Fingerprint is empty")
	}
	if sameFP := compileTunnelFingerprint(t, same, "t"); sameFP != baseFP {
		t.Fatalf("same config fingerprint = %q, want %q", sameFP, baseFP)
	}
	if changedFP := compileTunnelFingerprint(t, commandChanged, "t"); changedFP == baseFP {
		t.Fatal("command change did not change tunnel fingerprint")
	}
	if changedFP := compileTunnelFingerprint(t, credentialChanged, "t"); changedFP == baseFP {
		t.Fatal("credential change did not change tunnel fingerprint")
	}
}

func TestCompileTunnelFingerprintTracksViaChain(t *testing.T) {
	base := `
tunnel "local_command" "base" {
  command = ["ssh", "old-jump"]
  listen  = "127.0.0.1:1001"
}
tunnel "local_command" "child" {
  command = ["ssh", "child"]
  listen  = "127.0.0.1:1002"
  via     = base
}
`
	viaChanged := `
tunnel "local_command" "base" {
  command = ["ssh", "new-jump"]
  listen  = "127.0.0.1:1001"
}
tunnel "local_command" "child" {
  command = ["ssh", "child"]
  listen  = "127.0.0.1:1002"
  via     = base
}
`

	baseChildFP := compileTunnelFingerprint(t, base, "child")
	if baseChildFP == "" {
		t.Fatal("child Fingerprint is empty")
	}
	if changedChildFP := compileTunnelFingerprint(t, viaChanged, "child"); changedChildFP == baseChildFP {
		t.Fatal("via tunnel config change did not change child tunnel fingerprint")
	}
}

func compileTunnelFingerprint(t *testing.T, src string, name string) string {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(src), "fingerprint.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ct := cp.Tunnels[name]
	if ct == nil {
		t.Fatalf("missing tunnel %q", name)
	}
	return ct.Fingerprint
}

// TestCompileTunnelViaCycle: a → b → a fails to compile with a
// diagnostic that names the cycle.
func TestCompileTunnelViaCycle(t *testing.T) {
	src := []byte(`
tunnel "local_command" "a" {
  command = ["true"]
  listen  = "127.0.0.1:1"
  via     = b
}
tunnel "local_command" "b" {
  command = ["true"]
  listen  = "127.0.0.1:2"
  via     = a
}
`)
	gw, diags := config.LoadBytes(src, "cycle.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	_, err := config.Compile(gw)
	if err == nil {
		t.Fatal("Compile succeeded on via cycle, want error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error %q does not mention cycle", err)
	}
}

// TestCompileTunnelIPLiteralOnly rejects a tunneled endpoint whose
// hosts are all IP literals — DNS-VIP needs a name to intercept.
func TestCompileTunnelIPLiteralOnly(t *testing.T) {
	src := []byte(`
tunnel "local_command" "t" {
  command = ["true"]
  listen  = "127.0.0.1:1"
}
endpoint "postgres" "ipliteral" {
  host   = "10.0.0.5:5432"
  tunnel = t
}
`)
	gw, diags := config.LoadBytes(src, "ipliteral.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	_, err := config.Compile(gw)
	if err == nil {
		t.Fatal("Compile succeeded on tunneled IP-literal endpoint, want error")
	}
	if !strings.Contains(err.Error(), "no hostnames") {
		t.Errorf("error %q does not mention hostnames", err)
	}
}

// TestCompileFullSpec confirms the verbatim v14 fixture compiles
// without errors after Load — every rule's match map produces a
// valid matcher, every endpoint resolves its credentials, every
// profile resolves its endpoints.
func TestCompileFullSpec(t *testing.T) {
	gw, diags := config.Load(filepath.Join("testdata", "full.hcl"))
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cp.Profiles) != 3 {
		t.Errorf("expected 3 profiles, got %d", len(cp.Profiles))
	}
	if len(cp.Endpoints) < 20 {
		t.Errorf("expected ~30 endpoints, got %d", len(cp.Endpoints))
	}
	totalRules := 0
	for _, ep := range cp.Endpoints {
		totalRules += len(ep.Rules)
	}
	if totalRules < 50 {
		t.Errorf("expected ~50+ rule attachments, got %d", totalRules)
	}
}
