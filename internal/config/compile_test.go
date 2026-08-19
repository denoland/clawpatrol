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

// testGatewayPrefix wraps inline test fixtures with a minimal valid
// `gateway {}` block so loader-level operational validation passes;
// these tests care only about the policy blocks they declare.
const testGatewayPrefix = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

`

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
	if ep.Credentials[0] == nil ||
		ep.Credentials[0].Symbol.Name != "github" {
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
	if reads.Matcher.Match(getReq).Result != match.Matched {
		t.Errorf("github-reads should match GET")
	}
	if got := reads.Matcher.Match(postReq).Result; got != match.NoMatch {
		t.Errorf("github-reads should NOT match POST, got %v", got)
	}
	if writes.Matcher.Match(postReq).Result != match.Matched {
		t.Errorf("github-writes should match POST")
	}
	if got := writes.Matcher.Match(getReq).Result; got != match.NoMatch {
		t.Errorf("github-writes should NOT match GET, got %v", got)
	}

	// Outcomes wired correctly.
	if reads.Outcome.Verdict != "allow" {
		t.Errorf("github-reads verdict=%q want allow", reads.Outcome.Verdict)
	}
	if len(writes.Outcome.Approve) != 1 || writes.Outcome.Approve[0].Name != "ops" {
		t.Errorf("github-writes approve=%+v", writes.Outcome.Approve)
	}
}

func TestEnrollmentConfigValidation(t *testing.T) {
	// Enrollment is a top-level block (sibling of profile/credential), not
	// nested in gateway { ... }.
	const enrollBlock = `enrollment "kubernetes_token_review" "agents" {
  audience = "clawpatrol"

  match {
    namespace       = "agents"
    service_account = "agent-runner"
    profile_label   = "clawpatrol.dev/profile"
    profiles        = ["default"]
  }

  keepalive_interval = "20s"
  keepalive_reap_count = 6
}
`
	valid := `gateway {
  state_dir = "/opt/clawpatrol"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "clawpatrol-wg.clawpatrol.svc:51820"
  }
}

` + enrollBlock + `
profile "default" { credentials = [] }
`
	gw, diags := config.LoadBytes([]byte(valid), "k8s.hcl")
	if diags.HasErrors() {
		t.Fatalf("valid config diagnostics: %v", diags)
	}
	if !gw.IsEnrollmentEnabled() {
		t.Fatal("enrollment should be enabled")
	}
	ent, ok := gw.Policy.Enrollments["agents"]
	if !ok {
		t.Fatalf("enrollment %q not loaded; have %v", "agents", gw.Policy.Enrollments)
	}
	if ent.Plugin.Type != "kubernetes_token_review" {
		t.Fatalf("enrollment type = %q, want kubernetes_token_review", ent.Plugin.Type)
	}
	ke, ok := ent.Body.(*config.K8sEnrollment)
	if !ok {
		t.Fatalf("enrollment body = %T, want *config.K8sEnrollment", ent.Body)
	}
	if ke.KeepaliveInterval != "20s" || ke.KeepaliveReapCount == nil || *ke.KeepaliveReapCount != 6 {
		t.Fatalf("keepalive/reap = %q/%v, want 20s/6", ke.KeepaliveInterval, ke.KeepaliveReapCount)
	}
	if len(ke.Matches) != 1 || ke.Matches[0].ProfileLabel != "clawpatrol.dev/profile" {
		t.Fatalf("unexpected matches: %+v", ke.Matches)
	}

	// The compiled policy exposes the parsed, profile-resolved form.
	cp, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	enrollment := cp.EnrollmentsByName["agents"]
	if enrollment == nil {
		t.Fatalf("compiled enrollment %q missing", "agents")
	}
	if enrollment.Type != "kubernetes_token_review" {
		t.Fatalf("compiled enrollment type = %q, want kubernetes_token_review", enrollment.Type)
	}
	enr, ok := enrollment.Body.(*config.CompiledK8sEnrollment)
	if !ok {
		t.Fatalf("compiled enrollment body = %T, want *config.CompiledK8sEnrollment", enrollment.Body)
	}
	if enr.Audience != "clawpatrol" || len(enr.Matches) != 1 {
		t.Fatalf("unexpected compiled enrollment body: %+v", enr)
	}
	// Liveness is derived and shared: keepalive_interval × keepalive_reap_count = 20s×6 = 2m.
	l := enrollment.Liveness
	if l.KeepaliveInterval != 20*time.Second || l.ReapCount != 6 || l.LivenessWindow() != 2*time.Minute {
		t.Fatalf("compiled keepalive/reap/liveness = %s/%d/%s, want 20s/6/2m",
			l.KeepaliveInterval, l.ReapCount, l.LivenessWindow())
	}

	dump, err := gw.Dump()
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if !strings.Contains(string(dump), `"enrollments"`) {
		t.Fatalf("dump does not use enrollment shape:\n%s", dump)
	}

	// profile_label defaults to clawpatrol.dev/profile when omitted.
	noLabel := strings.Replace(valid, `    profile_label   = "clawpatrol.dev/profile"`+"\n", "", 1)
	gw2, diags := config.LoadBytes([]byte(noLabel), "k8s-nolabel.hcl")
	if diags.HasErrors() {
		t.Fatalf("no-label config diagnostics: %v", diags)
	}
	ke2 := gw2.Policy.Enrollments["agents"].Body.(*config.K8sEnrollment)
	if ke2.Matches[0].ProfileLabel != config.K8sDefaultProfileLabel {
		t.Fatalf("default profile_label = %q, want %q", ke2.Matches[0].ProfileLabel, config.K8sDefaultProfileLabel)
	}

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing audience",
			body: strings.Replace(valid, `  audience = "clawpatrol"`+"\n", "", 1),
			want: `The argument "audience" is required`,
		},
		{
			name: "keepalive_interval below minimum",
			body: strings.Replace(valid, `keepalive_interval = "20s"`, `keepalive_interval = "5s"`, 1),
			want: "Invalid enrollment keepalive_interval",
		},
		{
			name: "keepalive_reap_count of 1 rejected",
			body: strings.Replace(valid, `keepalive_reap_count = 6`, `keepalive_reap_count = 1`, 1),
			want: "Invalid enrollment keepalive_reap_count",
		},
		{
			name: "missing match",
			body: strings.Replace(valid, `  match {
    namespace       = "agents"
    service_account = "agent-runner"
    profile_label   = "clawpatrol.dev/profile"
    profiles        = ["default"]
  }
`, "", 1),
			want: "Missing enrollment match",
		},
		{
			name: "match missing profiles",
			body: strings.Replace(valid, `    profiles        = ["default"]`+"\n", "", 1),
			want: `The argument "profiles" is required`,
		},
		{
			name: "unknown profile",
			body: strings.Replace(valid, `profiles        = ["default"]`, `profiles        = ["ghost"]`, 1),
			want: "Unknown enrollment profile",
		},
		{
			name: "no wireguard",
			body: strings.Replace(valid, `  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "clawpatrol-wg.clawpatrol.svc:51820"
  }
`, "", 1),
			want: "enrollment requires a wireguard block",
		},
		{
			name: "duplicate enrollment",
			body: strings.Replace(valid, enrollBlock, enrollBlock+enrollBlock, 1),
			want: "Duplicate enrollment name",
		},
		{
			name: "unsupported type",
			body: strings.Replace(valid, `enrollment "kubernetes_token_review" "agents"`, `enrollment "oidc_jwt" "agents"`, 1),
			want: "Unknown enrollment type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, diags := config.LoadBytes([]byte(tc.body), tc.name+".hcl")
			if !diags.HasErrors() {
				t.Fatalf("expected diagnostics")
			}
			found := false
			for _, d := range diags {
				if strings.Contains(d.Summary, tc.want) || strings.Contains(d.Detail, tc.want) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("diagnostics = %v, want %q", diags, tc.want)
			}
		})
	}
}

// TestCompileWildcardHosts verifies that wildcard hosts are accepted,
// land in HostPatterns (not HostIndex), and that malformed wildcards
// or within-endpoint duplicates are rejected at load time.
func TestCompileWildcardHosts(t *testing.T) {
	src := `
endpoint "https" "aws" {
  hosts = ["*.amazonaws.com", "*.us-east-1.amazonaws.com:443"]
}
credential "bearer_token" "tok" {
  endpoint = https.aws
}
profile "p" { credentials = [bearer_token.tok] }
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
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
endpoint "https" "bad" {
  hosts = ["*."]
}
credential "bearer_token" "tok" {
  endpoint = https.bad
}
profile "p" { credentials = [bearer_token.tok] }
`,
		},
		{
			name: "wildcard with bare TLD",
			src: `
endpoint "https" "bad" {
  hosts = ["*.com"]
}
credential "bearer_token" "tok" {
  endpoint = https.bad
}
profile "p" { credentials = [bearer_token.tok] }
`,
		},
		{
			name: "wildcard not at leftmost label",
			src: `
endpoint "https" "bad" {
  hosts = ["api.*.foo.com"]
}
credential "bearer_token" "tok" {
  endpoint = https.bad
}
profile "p" { credentials = [bearer_token.tok] }
`,
		},
		{
			name: "duplicate hosts",
			src: `
endpoint "https" "bad" {
  hosts = ["api.foo.com", "api.foo.com"]
}
credential "bearer_token" "tok" {
  endpoint = https.bad
}
profile "p" { credentials = [bearer_token.tok] }
`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, diags := config.LoadBytes([]byte(testGatewayPrefix+c.src), "in.hcl")
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
endpoint "https" "ep" {
  hosts = ["x.example.com"]
}
credential "bearer_token" "pat" {
  endpoint = https.ep
}
profile "p" { credentials = [bearer_token.pat] }

rule "fallback" {
  endpoint  = https.ep
  priority  = -100
  condition = "http.method == 'POST'"
  verdict   = "deny"
}
rule "specific" {
  endpoint  = https.ep
  priority  = 100
  condition = "http.method == 'POST' && http.path == '/v1/refunds'"
  verdict   = "deny"
}
rule "general" {
  endpoint  = https.ep
  condition = "http.method == 'POST'"
  verdict   = "allow"
}
`
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
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
  credential = bearer_token.tok
}
`
	same := `
credential "bearer_token" "tok" {}
tunnel "local_command" "t" {
  command    = ["ssh", "old-bastion"]
  listen     = "127.0.0.1:1001"
  keepalive  = "always"
  credential = bearer_token.tok
}
`
	commandChanged := `
credential "bearer_token" "tok" {}
tunnel "local_command" "t" {
  command    = ["ssh", "new-bastion"]
  listen     = "127.0.0.1:1001"
  keepalive  = "always"
  credential = bearer_token.tok
}
`
	credentialChanged := `
credential "bearer_token" "tok" { idempotency_key = true }
tunnel "local_command" "t" {
  command    = ["ssh", "old-bastion"]
  listen     = "127.0.0.1:1001"
  keepalive  = "always"
  credential = bearer_token.tok
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
  via     = local_command.base
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
  via     = local_command.base
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
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "fingerprint.hcl")
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
  via     = local_command.b
}
tunnel "local_command" "b" {
  command = ["true"]
  listen  = "127.0.0.1:2"
  via     = local_command.a
}
`)
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+string(src)), "cycle.hcl")
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
  tunnel = local_command.t
}
`)
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+string(src)), "ipliteral.hcl")
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

// TestEnrollmentLivenessDerivation covers the derived liveness window:
// defaults when the knobs are omitted, and keepalive_reap_count = 0 disabling
// reaping (LivenessWindow() == 0).
func TestEnrollmentLivenessDerivation(t *testing.T) {
	base := func(knobs string) string {
		return `gateway {
  state_dir = "/opt/clawpatrol"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint    = "clawpatrol-wg.clawpatrol.svc:51820"
  }
}

enrollment "kubernetes_token_review" "agents" {
  audience = "clawpatrol"
  match {
    namespace       = "agents"
    service_account = "agent-runner"
    profiles        = ["default"]
  }
` + knobs + `}

profile "default" { credentials = [] }
`
	}

	cases := []struct {
		name           string
		knobs          string
		wantKeepalive  time.Duration
		wantMultiplier int
		wantLiveness   time.Duration
	}{
		{
			name:           "defaults",
			knobs:          "",
			wantKeepalive:  config.EnrollmentDefaultKeepalive,
			wantMultiplier: config.EnrollmentDefaultReapCount,
			wantLiveness:   config.EnrollmentDefaultKeepalive * config.EnrollmentDefaultReapCount,
		},
		{
			name:           "explicit",
			knobs:          "  keepalive_interval = \"20s\"\n  keepalive_reap_count = 5\n",
			wantKeepalive:  20 * time.Second,
			wantMultiplier: 5,
			wantLiveness:   100 * time.Second,
		},
		{
			name:           "disabled",
			knobs:          "  keepalive_reap_count = 0\n",
			wantKeepalive:  config.EnrollmentDefaultKeepalive,
			wantMultiplier: 0,
			wantLiveness:   0, // reaping disabled
		},
		{
			// No upper bound on keepalive_interval: a long interval is accepted
			// (the 25s rekey-safety ceiling was lifted once the sidecar became
			// the sole keepalive sender + ICMP-probe liveness).
			name:           "long keepalive allowed",
			knobs:          "  keepalive_interval = \"120s\"\n  keepalive_reap_count = 3\n",
			wantKeepalive:  120 * time.Second,
			wantMultiplier: 3,
			wantLiveness:   6 * time.Minute,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw, diags := config.LoadBytes([]byte(base(tc.knobs)), "k8s.hcl")
			if diags.HasErrors() {
				t.Fatalf("diagnostics: %v", diags)
			}
			cp, err := config.Compile(gw)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			enrollment := cp.EnrollmentsByName["agents"]
			if enrollment == nil {
				t.Fatal("compiled enrollment liveness missing")
			}
			l := enrollment.Liveness
			if l.KeepaliveInterval != tc.wantKeepalive || l.ReapCount != tc.wantMultiplier || l.LivenessWindow() != tc.wantLiveness {
				t.Fatalf("keepalive/reap/liveness = %s/%d/%s, want %s/%d/%s",
					l.KeepaliveInterval, l.ReapCount, l.LivenessWindow(),
					tc.wantKeepalive, tc.wantMultiplier, tc.wantLiveness)
			}
		})
	}
}
