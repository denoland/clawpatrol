package approvers

// human_approver: targets one channel via a credential's HITLNotifier
// (Slack chat.postMessage, Discord webhook, Telegram sendMessage,
// etc.). The credential plugin owns the channel-specific wire shape;
// this approver just publishes to the dashboard pool and dispatches
// the prompt. First operator to act — pool decide via dashboard or
// channel-side action — wins.
//
// Empty Channel / Credential → falls through to dashboard-only.

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// HumanApprover targets one channel. Timeout / require_approvers
// override the global defaults block on a per-approver basis.
//
// Credential references a credential whose body satisfies HITLNotifier
// (slack_tokens today; future Discord / Telegram / SMTP credentials).
// Leave empty for a dashboard-only approver (no channel notification;
// operator clicks approve/deny on the dashboard).
type HumanApprover struct {
	Channel          string `hcl:"channel"`
	Credential       string `hcl:"credential,optional"`
	Timeout          int    `hcl:"timeout,optional"`
	RequireApprovers int    `hcl:"require_approvers,optional"`
	// Interactive toggles in-channel approve/deny buttons. Requires the
	// referenced credential's signing_secret slot pasted via the
	// dashboard AND Slack's Interactivity URL pointed at the gateway.
	// Default false: message includes only an "Open dashboard" link.
	Interactive bool `hcl:"interactive,optional"`
	// Classifier optionally references an llm_approver by name. When set,
	// the approver calls the classifier's Summarize method before posting
	// the HITL notification, enriching the Slack card with classification
	// metadata. Classifier failures are non-fatal — the generic card is
	// used as fallback.
	Classifier string `hcl:"classifier,optional"`
	// Message is an optional Go-template-style string with {{var}}
	// placeholders. When set, the expanded text replaces the default
	// section body in the Slack (or other notifier) card. Supported
	// vars mirror the CEL facet namespace: {{http.method}},
	// {{http.path}}, {{k8s.verb}}, {{sql.tables}}, {{body_json.ticket}},
	// {{profile}}, {{endpoint}}, {{reason}}, etc.
	// Classifier (if also set) still runs; Message takes display precedence.
	Message string `hcl:"message,optional"`
}

// HumanApproverChannel + HumanApproverCredential expose the fields
// the gateway's HITL wiring needs without main importing this package
// — main does an anonymous-interface type-assert on ent.Body.
func (h *HumanApprover) HumanApproverChannel() string { return h.Channel }

// HumanApproverCredential is part of the clawpatrol plugin API.
func (h *HumanApprover) HumanApproverCredential() string { return h.Credential }

// HumanApproverInteractive is part of the clawpatrol plugin API.
func (h *HumanApprover) HumanApproverInteractive() bool { return h.Interactive }

// Approve is part of the clawpatrol plugin API.
func (h *HumanApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if req.Pool == nil {
		return runtime.ApproveVerdict{}, fmt.Errorf("human approver %q: no pool", req.ApproverName)
	}
	pending := buildPending(req)
	id, ch := req.Pool.Add(pending)
	defer req.Pool.Discard(id)

	var summary *runtime.HITLSummary
	if h.Classifier != "" && req.Policy != nil {
		if ent, ok := req.Policy.Approvers[h.Classifier]; ok {
			if clf, ok := ent.Body.(runtime.HITLClassifier); ok {
				if s, err := clf.Summarize(ctx, req); err == nil {
					summary = s
				} else {
					log.Printf("human approver %s: classifier %q: %v", req.ApproverName, h.Classifier, err)
				}
			}
		}
	}

	if h.Channel != "" && h.Credential != "" && req.Policy != nil {
		ent, ok := req.Policy.Credentials[h.Credential]
		if ok {
			if notifier, ok := ent.Body.(runtime.HITLNotifier); ok {
				var msg string
				if h.Message != "" {
					msg = expandMessage(h.Message, req)
				}
				target := runtime.HITLTarget{
					CredentialName: h.Credential,
					Channel:        h.Channel,
					Interactive:    h.Interactive,
					PendingID:      id,
					DashboardURL:   req.DashboardURL,
					ThreadTS:       req.ThreadTS,
					Summary:        summary,
					Message:        msg,
				}
				go func() {
					if err := notifier.NotifyHITL(ctx, req, target); err != nil {
						log.Printf("human approver %s: notify: %v", req.ApproverName, err)
					}
				}()
			} else {
				log.Printf("human approver %s: credential %q does not implement HITLNotifier", req.ApproverName, h.Credential)
			}
		} else {
			log.Printf("human approver %s: credential %q not declared", req.ApproverName, h.Credential)
		}
	}

	timeout := time.Duration(h.Timeout) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(req.Policy.HumanTimeout) * time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case d := <-ch:
		return runtime.ApproveVerdict{
			Decision: decision(d.Allow),
			Reason:   d.Reason,
			By:       d.By,
		}, nil
	case <-timer.C:
		return runtime.ApproveVerdict{
			Reason: fmt.Sprintf("approver %q timed out after %s", req.ApproverName, timeout),
		}, nil
	case <-ctx.Done():
		return runtime.ApproveVerdict{}, ctx.Err()
	}
}

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindApprover,
		Type:    "human_approver",
		New:     func() any { return &HumanApprover{} },
		Runtime: (*HumanApprover)(nil),
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential, Optional: true},
			{Path: "Classifier", Kind: config.KindApprover, Optional: true},
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
			if a.Classifier != "" {
				config.SetIdent(b, "classifier", a.Classifier)
			}
			if a.Message != "" {
				b.SetAttributeValue("message", cty.StringVal(a.Message))
			}
		},
	})
}
