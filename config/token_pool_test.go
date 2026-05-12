package config_test

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

func loadAndCompile(t *testing.T, src string) (*config.CompiledPolicy, error) {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(src), "in.hcl")
	if diags.HasErrors() {
		return nil, diags
	}
	return config.Compile(gw)
}

const poolFixture = `
admin_email = "you@example.com"

credential "anthropic_oauth_subscription" "alice" {}
credential "anthropic_oauth_subscription" "bob"   {}
credential "anthropic_oauth_subscription" "carol" {}

token_pool "team" {
  credentials = [alice, bob, carol]
  strategy    = "round_robin"
}

endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  credential = team
}

profile "default" { endpoints = [anthropic] }
`

func TestTokenPoolCompiles(t *testing.T) {
	cp, err := loadAndCompile(t, poolFixture)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pool, ok := cp.TokenPools["team"]
	if !ok {
		t.Fatalf("expected pool 'team' in CompiledPolicy.TokenPools")
	}
	if pool.Strategy != config.PoolStrategyRoundRobin {
		t.Errorf("strategy = %q, want %q", pool.Strategy, config.PoolStrategyRoundRobin)
	}
	if got := len(pool.Members); got != 3 {
		t.Errorf("member count = %d, want 3", got)
	}
	if pool.PluginType != "anthropic_oauth_subscription" {
		t.Errorf("plugin type = %q, want anthropic_oauth_subscription", pool.PluginType)
	}

	ep, ok := cp.Endpoints["anthropic"]
	if !ok {
		t.Fatalf("expected endpoint 'anthropic'")
	}
	if got := len(ep.Credentials); got != 1 {
		t.Fatalf("endpoint credential bindings = %d, want 1", got)
	}
	cc := ep.Credentials[0]
	if cc.Pool == nil {
		t.Errorf("expected pool binding on endpoint, got Credential=%v", cc.Credential)
	}
	if cc.Credential != nil {
		t.Errorf("expected Credential to be nil for pool binding")
	}
}

func TestTokenPoolDefaultStrategy(t *testing.T) {
	src := strings.Replace(poolFixture, `strategy    = "round_robin"`, "", 1)
	cp, err := loadAndCompile(t, src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pool := cp.TokenPools["team"]
	if pool.Strategy != config.DefaultPoolStrategy {
		t.Errorf("default strategy = %q, want %q", pool.Strategy, config.DefaultPoolStrategy)
	}
}

func TestTokenPoolRoundRobinPicksInOrder(t *testing.T) {
	cp, err := loadAndCompile(t, poolFixture)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pool := cp.TokenPools["team"]
	want := []string{"alice", "bob", "carol", "alice", "bob", "carol", "alice"}
	for i, w := range want {
		got := pool.Pick(nil)
		if got == nil {
			t.Fatalf("pick %d returned nil", i)
		}
		if got.Symbol.Name != w {
			t.Errorf("pick %d: got %q, want %q", i, got.Symbol.Name, w)
		}
	}
}

func TestTokenPoolLeastLoaded(t *testing.T) {
	src := strings.Replace(poolFixture, `"round_robin"`, `"least_loaded"`, 1)
	cp, err := loadAndCompile(t, src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pool := cp.TokenPools["team"]

	// First pick: tie at 0, picks index 0 (alice).
	picks := []string{}
	for i := 0; i < 9; i++ {
		picks = append(picks, pool.Pick(nil).Symbol.Name)
	}
	// After 9 picks, all members should have been chosen 3 times each
	// for least_loaded with starting tie at 0 → repeating 0,1,2,...
	count := map[string]int{}
	for _, p := range picks {
		count[p]++
	}
	if count["alice"] != 3 || count["bob"] != 3 || count["carol"] != 3 {
		t.Errorf("least_loaded distribution off: %v", count)
	}
}

func TestTokenPoolRejectsMixedTypes(t *testing.T) {
	src := `
admin_email = "you@example.com"

credential "anthropic_oauth_subscription" "alice"  {}
credential "openai_codex_oauth"            "bob"   {}

token_pool "team" {
  credentials = [alice, bob]
}

profile "default" { endpoints = [] }
`
	_, err := loadAndCompile(t, src)
	if err == nil {
		t.Fatalf("expected compile to reject mixed-type pool")
	}
	if !strings.Contains(err.Error(), "single-provider") {
		t.Errorf("error %v, want mention of single-provider constraint", err)
	}
}

func TestTokenPoolRejectsSingleMember(t *testing.T) {
	src := `
admin_email = "you@example.com"

credential "anthropic_oauth_subscription" "alice" {}

token_pool "solo" {
  credentials = [alice]
}

profile "default" { endpoints = [] }
`
	_, err := loadAndCompile(t, src)
	if err == nil {
		t.Fatalf("expected compile to reject single-member pool")
	}
}

func TestTokenPoolRejectsExhaustFirst(t *testing.T) {
	src := strings.Replace(poolFixture, `"round_robin"`, `"exhaust_first"`, 1)
	_, err := loadAndCompile(t, src)
	if err == nil {
		t.Fatalf("expected compile to reject exhaust_first (not implemented in v1)")
	}
}

func TestTokenPoolRejectsUnknownStrategy(t *testing.T) {
	src := strings.Replace(poolFixture, `"round_robin"`, `"random"`, 1)
	_, err := loadAndCompile(t, src)
	if err == nil {
		t.Fatalf("expected compile to reject unknown strategy")
	}
}

func TestTokenPoolRejectsUnknownMember(t *testing.T) {
	src := `
admin_email = "you@example.com"

credential "anthropic_oauth_subscription" "alice" {}
credential "anthropic_oauth_subscription" "bob"   {}

token_pool "team" {
  credentials = [alice, ghost, bob]
}

profile "default" { endpoints = [] }
`
	_, diagsErr := loadAndCompile(t, src)
	if diagsErr == nil {
		t.Fatalf("expected error for unknown pool member")
	}
}

func TestTokenPoolEndpointResolveDelegatesToMember(t *testing.T) {
	cp, err := loadAndCompile(t, poolFixture)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := cp.Endpoints["anthropic"]
	cc := ep.Credentials[0]

	// Resolve picks via round-robin; first pick is alice.
	first := cc.Resolve(nil)
	if first == nil || first.Symbol.Name != "alice" {
		t.Errorf("first Resolve = %v, want alice", first)
	}
	second := cc.Resolve(nil)
	if second == nil || second.Symbol.Name != "bob" {
		t.Errorf("second Resolve = %v, want bob", second)
	}
}

func TestTokenPoolStats(t *testing.T) {
	cp, err := loadAndCompile(t, poolFixture)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pool := cp.TokenPools["team"]
	pool.Pick(nil)
	pool.Pick(nil)
	pool.Pick(nil)
	pool.Pick(nil) // wraps to alice
	stats := pool.Stats()
	if got := len(stats); got != 3 {
		t.Fatalf("stats len = %d, want 3", got)
	}
	if stats[0].Name != "alice" || stats[0].Requests != 2 {
		t.Errorf("alice stats = %+v, want 2 requests", stats[0])
	}
	if stats[1].Name != "bob" || stats[1].Requests != 1 {
		t.Errorf("bob stats = %+v, want 1 request", stats[1])
	}
}

func TestEndpointSingularBindingStillWorks(t *testing.T) {
	src := `
admin_email = "you@example.com"

credential "anthropic_oauth_subscription" "alice" {}

endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  credential = alice
}

profile "default" { endpoints = [anthropic] }
`
	cp, err := loadAndCompile(t, src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := cp.Endpoints["anthropic"]
	cc := ep.Credentials[0]
	if cc.Pool != nil {
		t.Errorf("expected non-pool binding")
	}
	if cc.Credential == nil || cc.Credential.Symbol.Name != "alice" {
		t.Errorf("expected Credential=alice")
	}
	if got := cc.Resolve(nil); got == nil || got.Symbol.Name != "alice" {
		t.Errorf("Resolve = %v, want alice", got)
	}
}
