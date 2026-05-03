// Package approvers registers the two approver kinds: an LLM proctor
// (claude / gpt) for fast / repeatable checks, and a human-in-Slack
// approver for high-blast-radius operations.
package approvers

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol-go/config"
)

// LLMApprover carries the model + the credential used to authenticate
// the call to the model API. The prompt comes from the per-rule
// `policy = ...` reference, so the same approver can be reused across
// many rules with different prompts.
//
// Credential resolves at load time against the symbol table — the
// runtime fetches its access token via the SecretStore at call time,
// so OAuth refresh / per-profile token rotation works the same way it
// does for credential injection on endpoint requests.
type LLMApprover struct {
	Model      string `hcl:"model"`
	Credential string `hcl:"credential"`
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
		Kind: config.KindApprover,
		Type: "llm_approver",
		New:  func() any { return &LLMApprover{} },
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential},
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			a := body.(*LLMApprover)
			b.SetAttributeValue("model", cty.StringVal(a.Model))
			config.SetIdent(b, "credential", a.Credential)
		},
	})
	config.Register(&config.Plugin{
		Kind:  config.KindApprover,
		Type:  "human_approver",
		New:   func() any { return &HumanApprover{} },
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			a := body.(*HumanApprover)
			b.SetAttributeValue("channel", cty.StringVal(a.Channel))
			if a.Timeout != 0 {
				b.SetAttributeValue("timeout", cty.NumberIntVal(int64(a.Timeout)))
			}
			if a.RequireApprovers != 0 {
				b.SetAttributeValue("require_approvers", cty.NumberIntVal(int64(a.RequireApprovers)))
			}
		},
	})
}
