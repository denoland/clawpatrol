package main

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestResolveUndecidedVerdict(t *testing.T) {
	cases := []struct {
		name         string
		policy       *config.CompiledPolicy
		approverType string
		in           runtime.ApproveVerdict
		wantDecision string
		wantReason   string
	}{
		{
			name:         "llm open allows and keeps the failure reason",
			policy:       &config.CompiledPolicy{LLMFailMode: "open"},
			approverType: "llm_approver",
			in:           runtime.ApproveVerdict{Reason: "llm call: dial tcp: i/o timeout"},
			wantDecision: "allow",
			wantReason:   "llm_fail_mode = open: llm call: dial tcp: i/o timeout",
		},
		{
			name:         "llm closed denies",
			policy:       &config.CompiledPolicy{LLMFailMode: "closed"},
			approverType: "llm_approver",
			in:           runtime.ApproveVerdict{Reason: "llm http 503: overloaded"},
			wantDecision: "deny",
			wantReason:   "llm http 503: overloaded",
		},
		{
			name:         "llm default (unset) denies",
			policy:       &config.CompiledPolicy{},
			approverType: "llm_approver",
			in:           runtime.ApproveVerdict{Reason: "secret fetch: no such secret"},
			wantDecision: "deny",
			wantReason:   "secret fetch: no such secret",
		},
		{
			name:         "open does not apply to human approvers",
			policy:       &config.CompiledPolicy{LLMFailMode: "open"},
			approverType: "human_approver",
			in:           runtime.ApproveVerdict{},
			wantDecision: "deny",
			wantReason:   "approver ops timed out",
		},
		{
			name:         "nil policy denies",
			policy:       nil,
			approverType: "llm_approver",
			in:           runtime.ApproveVerdict{Reason: "llm call: eof"},
			wantDecision: "deny",
			wantReason:   "llm call: eof",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveUndecidedVerdict(c.policy, "ops", c.approverType, c.in)
			if got.Decision != c.wantDecision {
				t.Fatalf("Decision = %q, want %q", got.Decision, c.wantDecision)
			}
			if got.Reason != c.wantReason {
				t.Fatalf("Reason = %q, want %q", got.Reason, c.wantReason)
			}
		})
	}
}
