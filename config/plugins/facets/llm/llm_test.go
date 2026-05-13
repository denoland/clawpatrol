package llm_test

import (
	"testing"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
	llmfacet "github.com/denoland/clawpatrol/config/plugins/facets/llm"
)

// TestLLMMatcherModelGlob pins the headline use case operators care
// about: gating which model a credential is allowed to call. The CEL
// runtime exposes llm.model so .matches() / startsWith / == all work.
func TestLLMMatcherModelGlob(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		model     string
		want      bool
	}{
		{"opus-prefix matches opus-4-7", `llm.model.matches("^claude-opus-")`, "claude-opus-4-7-20251001", true},
		{"opus-prefix misses sonnet", `llm.model.matches("^claude-opus-")`, "claude-3-5-sonnet-20240620", false},
		{"openrouter provider prefix", `llm.model.matches("^anthropic/")`, "anthropic/claude-3-5-sonnet-20240620", true},
		{"exact-match miss", `llm.model == "gpt-5"`, "gpt-4o", false},
		{"exact-match hit", `llm.model == "gpt-5"`, "gpt-5", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := facet.NewMatcher("llm", tc.condition)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			req := &match.Request{Families: []string{"http", "llm"}}
			req.SetMeta("llm", &llmfacet.Meta{Provider: "openai", Model: tc.model})
			if got := m.Match(req); got != tc.want {
				t.Errorf("Match=%v want %v", got, tc.want)
			}
		})
	}
}

// TestLLMMatcherProviderGate pins the secondary use case: gating by
// provider name so an operator can write "anthropic only via the
// anthropic endpoint" rules without redoing the model glob.
func TestLLMMatcherProviderGate(t *testing.T) {
	m, err := facet.NewMatcher("llm", `llm.provider == "anthropic" && llm.stream == true`)
	if err != nil {
		t.Fatal(err)
	}
	req := &match.Request{Families: []string{"http", "llm"}}
	req.SetMeta("llm", &llmfacet.Meta{Provider: "anthropic", Model: "claude-opus-4-7", Stream: true})
	if !m.Match(req) {
		t.Errorf("expected streaming anthropic call to match")
	}

	req2 := &match.Request{Families: []string{"http", "llm"}}
	req2.SetMeta("llm", &llmfacet.Meta{Provider: "openrouter", Model: "anthropic/claude-3-5-sonnet"})
	if m.Match(req2) {
		t.Errorf("expected openrouter call to miss provider gate")
	}
}

// TestLLMMatcherEmptyMetaIsNoMatch pins fail-soft on requests that
// never reached an LLM-parsing endpoint plugin. Missing slot must
// behave like "no match" rather than panic.
func TestLLMMatcherEmptyMetaIsNoMatch(t *testing.T) {
	m, err := facet.NewMatcher("llm", `llm.model == "anything"`)
	if err != nil {
		t.Fatal(err)
	}
	req := &match.Request{Families: []string{"http"}}
	if m.Match(req) {
		t.Errorf("expected no match on request without llm slot")
	}
}

// TestLLMReportFieldsCoverMeta keeps the ReportFields declaration in
// sync with what Report actually emits. If a future contributor adds
// a Meta field, they must update Report and this test breaks until
// they update ReportFields.
func TestLLMReportFieldsCoverMeta(t *testing.T) {
	f := llmfacet.Facet{}
	req := &match.Request{Families: []string{"llm"}}
	req.SetMeta("llm", &llmfacet.Meta{
		Provider: "anthropic", Model: "claude-opus-4-7", Stream: true,
		InputTokens: 100, OutputTokens: 20,
		CacheReadTokens: 50, CacheWriteTokens: 10, StopReason: "end_turn",
	})
	report := f.Report(req)
	declared := f.ReportFields()
	for _, spec := range declared {
		if _, ok := report[spec.Name]; !ok {
			t.Errorf("ReportFields declares %q but Report omits it", spec.Name)
		}
	}
	for k := range report {
		found := false
		for _, spec := range declared {
			if spec.Name == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Report emits %q but ReportFields doesn't declare it", k)
		}
	}
}
