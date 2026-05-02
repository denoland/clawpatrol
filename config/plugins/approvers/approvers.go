// Package approvers registers the two approver kinds: an LLM proctor
// (claude / gpt) for fast / repeatable checks, and a human-in-Slack
// approver for high-blast-radius operations.
package approvers

import (
	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol-go/config"
)

// LLMApprover only carries the model — the prompt itself comes from
// the per-rule `policy = ...` reference, so the same approver instance
// can be reused across many rules with different prompts.
type LLMApprover struct {
	Model string `hcl:"model"`
}

// HumanApprover targets one Slack channel. Timeout / require_approvers
// override the global defaults block on a per-approver basis.
type HumanApprover struct {
	Channel          string `hcl:"channel"`
	Timeout          int    `hcl:"timeout,optional"`
	RequireApprovers int    `hcl:"require_approvers,optional"`
}

func init() {
	config.Register(&config.Plugin{
		Kind:  config.KindApprover,
		Type:  "llm_approver",
		New:   func() any { return &LLMApprover{} },
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
	})
	config.Register(&config.Plugin{
		Kind:  config.KindApprover,
		Type:  "human_approver",
		New:   func() any { return &HumanApprover{} },
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
	})
}
