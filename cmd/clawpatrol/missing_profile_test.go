package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// missingProfileBaseHCL declares three single-credential endpoints.
// Each test appends the profiles it wants.
const missingProfileBaseHCL = `
endpoint "https" "alpha" { hosts = ["alpha.example.com"] }
endpoint "https" "beta"  { hosts = ["beta.example.com"] }
endpoint "postgres" "db" { host = "db.example.com:5432" }

credential "bearer_token" "alpha-tok"      { endpoint = https.alpha }
credential "bearer_token" "beta-tok"       { endpoint = https.beta }
credential "postgres_credential" "db-cred" { endpoint = postgres.db }
`

const (
	missingProfileKept = `
profile "default" { credentials = [bearer_token.alpha-tok] }
profile "other"   { credentials = [bearer_token.beta-tok, postgres_credential.db-cred] }
`
	missingProfileRemoved = `
profile "removed" { credentials = [bearer_token.alpha-tok] }
`
)

// loadMissingProfilePolicy swaps a freshly loaded config into g the way
// a config reload does: both the raw config and the compiled policy.
func loadMissingProfilePolicy(t *testing.T, g *Gateway, profiles string) *config.CompiledPolicy {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(testGatewayPrefix+missingProfileBaseHCL+profiles), "missing-profile-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	return policy
}

// reachable lists what a peer served under profile gets from policy:
// the endpoints it resolves by host and by connection index, and the
// credentials dispatch would inject there.
func reachable(policy *config.CompiledPolicy, profile string) (endpoints, credentials []string) {
	httpReq := &match.Request{Family: "http", Headers: http.Header{}}
	for _, host := range []string{"alpha.example.com", "beta.example.com"} {
		if ep := runtime.HostEndpoint(policy, profile, host); ep != nil {
			endpoints = append(endpoints, ep.Name)
		}
	}
	// The connection-index paths (postgres, VIP, direct IP) hand every
	// endpoint that claims the destination to pickEndpointForProfile.
	db := policy.Endpoints["db"]
	if ep := pickEndpointForProfile([]*config.CompiledEndpoint{db}, policy, profile); ep != nil {
		endpoints = append(endpoints, ep.Name)
	}
	for _, name := range []string{"alpha", "beta", "db"} {
		req := httpReq
		if name == "db" {
			req = &match.Request{Family: "sql"}
		}
		if cc := runtime.ResolveCredential(policy, profile, policy.Endpoints[name], req); cc != nil {
			credentials = append(credentials, cc.Credential.Symbol.Name)
		}
	}
	return endpoints, credentials
}

// A device whose row names a profile the config no longer declares is
// served nothing: not what the removed profile carried, not the default
// profile, and not the sole credential of every single-credential
// endpoint. Devices on declared profiles and devices with no profile on
// their row are untouched.
func TestProfileForMissingProfileFailsClosed(t *testing.T) {
	const (
		orphanIP  = "100.1.1.1"
		orphanULA = "fd7a:115c:a1e0::1"
		otherIP   = "100.1.1.2"
		blankIP   = "100.1.1.3"
	)
	r := newOnboardRegistry()
	r.AssignProfile(orphanIP, "removed")
	r.RegisterIPAlias(orphanULA, orphanIP)
	r.AssignProfile(otherIP, "other")
	r.knownDeviceIPs[blankIP] = true // a row with a NULL profile
	r.hostnameByIP[orphanIP] = "build-box"
	g := &Gateway{onboard: r}
	logged := captureLog(t)

	// While the profile is declared the device is served under it.
	policy := loadMissingProfilePolicy(t, g, missingProfileKept+missingProfileRemoved)
	if got := g.profileFor(orphanIP); got != "removed" {
		t.Fatalf("profileFor(%s) = %q while the profile is declared, want removed", orphanIP, got)
	}
	if eps, creds := reachable(policy, g.profileFor(orphanIP)); strings.Join(eps, ",") != "alpha" || strings.Join(creds, ",") != "alpha-tok" {
		t.Fatalf("declared profile reaches endpoints %v credentials %v, want alpha / alpha-tok", eps, creds)
	}
	if logged.Len() != 0 {
		t.Fatalf("logged while the profile is declared: %q", logged.String())
	}

	// A reload drops the profile block; the devices row still names it.
	policy = loadMissingProfilePolicy(t, g, missingProfileKept)
	for _, ip := range []string{orphanIP, orphanULA} {
		profile := g.profileFor(ip)
		if profile != config.UnknownPeerEmptyProfile {
			t.Fatalf("profileFor(%s) = %q after the profile was removed, want the reserved empty profile", ip, profile)
		}
		if eps, creds := reachable(policy, profile); len(eps) != 0 || len(creds) != 0 {
			t.Fatalf("%s on a removed profile reaches endpoints %v credentials %v, want none", ip, eps, creds)
		}
	}
	// The raw name must not open anything either, for a caller that
	// holds it from before the reload (a parked HITL operation).
	if eps, creds := reachable(policy, "removed"); len(eps) != 0 || len(creds) != 0 {
		t.Fatalf("undeclared name reaches endpoints %v credentials %v, want none", eps, creds)
	}

	// Everyone else is served as before.
	if got := g.profileFor(otherIP); got != "other" {
		t.Fatalf("profileFor(%s) = %q, want other", otherIP, got)
	}
	if eps, creds := reachable(policy, "other"); strings.Join(eps, ",") != "beta,db" || strings.Join(creds, ",") != "beta-tok,db-cred" {
		t.Fatalf("profile other reaches endpoints %v credentials %v", eps, creds)
	}
	if got := g.profileFor(blankIP); got != "default" {
		t.Fatalf("profileFor(%s) = %q for a row with no profile, want default", blankIP, got)
	}
	if got := g.profileFor("100.9.9.9"); got != "default" {
		t.Fatalf("profileFor of a peer with no row = %q, want default", got)
	}

	// One line for the device, however many connections it makes.
	for range 5 {
		g.profileFor(orphanIP)
	}
	out := logged.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("logged %d lines, want 1:\n%s", n, out)
	}
	for _, want := range []string{"build-box", orphanIP, `"removed"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log line %q does not mention %s", out, want)
		}
	}

	// Restoring the block restores the device, with no restart.
	loadMissingProfilePolicy(t, g, missingProfileKept+missingProfileRemoved)
	if got := g.profileFor(orphanIP); got != "removed" {
		t.Fatalf("profileFor(%s) = %q after the profile came back, want removed", orphanIP, got)
	}
}

// The log line is repeated once the interval has passed, and at once
// when the device is moved to a different undeclared profile.
func TestLogMissingProfileRateLimit(t *testing.T) {
	const ip = "100.1.1.1"
	r := newOnboardRegistry()
	r.AssignProfile(ip, "removed")
	g := &Gateway{onboard: r}
	loadMissingProfilePolicy(t, g, missingProfileKept)
	logged := captureLog(t)
	lines := func() int { return strings.Count(logged.String(), "\n") }

	g.profileFor(ip)
	g.profileFor(ip)
	if lines() != 1 {
		t.Fatalf("logged %d lines, want 1", lines())
	}
	note := g.missingProfileLogged[ip]
	note.at = note.at.Add(-missingProfileLogInterval - 1)
	g.missingProfileLogged[ip] = note
	g.profileFor(ip)
	if lines() != 2 {
		t.Fatalf("logged %d lines after the interval, want 2", lines())
	}
	r.AssignProfile(ip, "also-removed")
	g.profileFor(ip)
	if lines() != 3 || !strings.Contains(logged.String(), `"also-removed"`) {
		t.Fatalf("no fresh line for a different missing profile:\n%s", logged.String())
	}
}

// A config that declares no profile at all is single-tenant, and the
// name on a device row scopes nothing there: onboarding stores a
// `join --profile` suggestion verbatim because it has nothing to check
// it against. Such a device is served like one with no profile on its
// row, and is not reported as missing its profile.
func TestProfileForNoProfilesDeclared(t *testing.T) {
	const blankIP = "100.1.1.1"
	const namedIP = "100.1.1.2"
	r := newOnboardRegistry()
	r.knownDeviceIPs[blankIP] = true
	r.AssignProfile(namedIP, "suggested")
	g := &Gateway{onboard: r, agents: NewAgentRegistry()}
	g.agents.onboard = r
	g.agents.Seed(namedIP)
	policy := loadMissingProfilePolicy(t, g, "")
	logged := captureLog(t)

	for ip, want := range map[string]string{blankIP: "", "100.9.9.9": "", namedIP: "suggested"} {
		profile := g.profileFor(ip)
		if profile != want {
			t.Fatalf("profileFor(%s) = %q under a profile-less config, want %q", ip, profile, want)
		}
		eps, creds := reachable(policy, profile)
		if strings.Join(eps, ",") != "db" || !strings.Contains(strings.Join(creds, ","), "db-cred") {
			t.Fatalf("%s reaches endpoints %v credentials %v, want db / db-cred", ip, eps, creds)
		}
	}
	if logged.Len() != 0 {
		t.Fatalf("logged under a profile-less config: %q", logged.String())
	}
	w := &webMux{g: g, onboard: r}
	for _, a := range w.agentsList() {
		if a.ProfileMissing {
			t.Fatalf("%s flagged as missing its profile under a profile-less config", a.IP)
		}
	}
}

// The device list flags a device whose profile is not declared.
func TestAgentsListFlagsMissingProfile(t *testing.T) {
	const orphanIP = "100.1.1.1"
	const otherIP = "100.1.1.2"
	r := newOnboardRegistry()
	r.AssignProfile(orphanIP, "removed")
	r.AssignProfile(otherIP, "other")
	g := &Gateway{onboard: r, agents: NewAgentRegistry()}
	g.agents.onboard = r
	g.agents.Seed(orphanIP)
	g.agents.Seed(otherIP)
	loadMissingProfilePolicy(t, g, missingProfileKept)
	w := &webMux{g: g, onboard: r}

	got := map[string]*Agent{}
	for _, a := range w.agentsList() {
		got[a.IP] = a
	}
	if a := got[orphanIP]; a == nil || !a.ProfileMissing || a.Profile != "removed" || len(a.Integrations) != 0 {
		t.Fatalf("orphan row = %+v, want profile removed flagged missing with no credentials", a)
	}
	if a := got[otherIP]; a == nil || a.ProfileMissing {
		t.Fatalf("declared-profile row = %+v, want it not flagged", a)
	}
}
