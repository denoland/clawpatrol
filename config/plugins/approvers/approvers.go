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
// the call to the model API + the policy text the model judges
// against. Inline `policy` is a bare-name reference to a `policy
// "<name>" { text = ... }` block — operator declares the prompt once
// and reuses across multiple judges. The use site stays a single
// bare name: `approve = [claude-judge]`.
//
// Credential resolves at load time against the symbol table — the
// runtime fetches its access token via the SecretStore at call time,
// so OAuth refresh / per-profile token rotation works the same way it
// does for credential injection on endpoint requests.
type LLMApprover struct {
	Model      string `hcl:"model"`
	Credential string `hcl:"credential"`
	Policy     string `hcl:"policy,optional"`
}

// HumanApprover targets one Slack channel. Timeout / require_approvers
// override the global defaults block on a per-approver basis.
//
// Credential references a slack_tokens credential — the bot token
// from that credential's `bot` slot is what the gateway uses to
// chat.postMessage into Channel. Leave empty for a dashboard-only
// approver (no Slack notification; operator clicks approve/deny on
// the dashboard).
type HumanApprover struct {
	Channel          string `hcl:"channel"`
	Credential       string `hcl:"credential,optional"`
	Timeout          int    `hcl:"timeout,optional"`
	RequireApprovers int    `hcl:"require_approvers,optional"`
	// Interactive toggles in-Slack approve/deny buttons. Requires the
	// referenced credential's signing_secret slot pasted via the
	// dashboard AND Slack's Interactivity URL pointed at the gateway.
	// Default false: message includes only an "Open dashboard" link
	// — operator decides on the dashboard.
	Interactive bool `hcl:"interactive,optional"`
}

// HumanApproverChannel + HumanApproverCredential expose the fields
// the gateway's HITL wiring needs without main importing this
// package — main does an anonymous-interface type-assert on
// ent.Body.
func (h *HumanApprover) HumanApproverChannel() string    { return h.Channel }
func (h *HumanApprover) HumanApproverCredential() string { return h.Credential }
func (h *HumanApprover) HumanApproverInteractive() bool  { return h.Interactive }

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindApprover,
		Type:    "llm_approver",
		New:     func() any { return &LLMApprover{} },
		Runtime: (*LLMApprover)(nil),
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential},
			{Path: "Policy", Kind: config.KindPolicy, Optional: true},
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			a := body.(*LLMApprover)
			b.SetAttributeValue("model", cty.StringVal(a.Model))
			config.SetIdent(b, "credential", a.Credential)
			if a.Policy != "" {
				config.SetIdent(b, "policy", a.Policy)
			}
		},
	})
	config.Register(&config.Plugin{
		Kind:    config.KindApprover,
		Type:    "human_approver",
		New:     func() any { return &HumanApprover{} },
		Runtime: (*HumanApprover)(nil),
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential, Optional: true},
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			a := body.(*HumanApprover)
			b.SetAttributeValue("channel", cty.StringVal(a.Channel))
			if a.Credential != "" {
				config.SetIdent(b, "credential", a.Credential)
			}
			if a.Timeout != 0 {
				b.SetAttributeValue("timeout", cty.NumberIntVal(int64(a.Timeout)))
			}
			if a.RequireApprovers != 0 {
				b.SetAttributeValue("require_approvers", cty.NumberIntVal(int64(a.RequireApprovers)))
			}
			if a.Interactive {
				b.SetAttributeValue("interactive", cty.True)
			}
		},
	})
}
