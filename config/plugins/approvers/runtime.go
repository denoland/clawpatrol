package approvers

// Approver runtimes — every approver plugin's body satisfies
// runtime.ApproverRuntime so the gateway dispatcher can call
// .Approve(ctx, req) without knowing the plugin's specific shape.
//
// DashboardApprover (built-in) is registered programmatically (not
// from HCL) so `approve = [dashboard]` works without an explicit
// block. HumanApprover delegates the actual notification to its
// configured credential's runtime.HITLNotifier — Slack, Discord,
// Telegram, etc. live in the credential plugin, not here.

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/denoland/clawpatrol-go/config/runtime"
)

// DashboardApprover: pool.Add → wait for the dashboard's PUT
// /api/hitl/decide. No external notification — operator sees the
// pending entry on the dashboard's HITL panel directly.
type DashboardApprover struct{}

func (DashboardApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if req.Pool == nil {
		return runtime.ApproveVerdict{}, fmt.Errorf("dashboard approver: no pool")
	}
	pending := buildPending(req)
	id, ch := req.Pool.Add(pending)
	defer req.Pool.Discard(id)
	select {
	case d := <-ch:
		return runtime.ApproveVerdict{
			Decision: decision(d.Allow),
			Reason:   d.Reason,
			By:       d.By,
		}, nil
	case <-ctx.Done():
		return runtime.ApproveVerdict{}, ctx.Err()
	}
}

// Approve on HumanApprover: publish to the dashboard pool, then
// dispatch the prompt to the configured credential's HITLNotifier
// (Slack chat.postMessage, Discord webhook, Telegram sendMessage,
// etc.) so the credential plugin owns the channel-specific wire
// shape. First operator to act — pool decide via dashboard or
// channel-side action — wins.
//
// Empty Channel / Credential → falls through to dashboard-only.
func (h *HumanApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if req.Pool == nil {
		return runtime.ApproveVerdict{}, fmt.Errorf("human approver %q: no pool", req.ApproverName)
	}
	pending := buildPending(req)
	id, ch := req.Pool.Add(pending)
	defer req.Pool.Discard(id)

	if h.Channel != "" && h.Credential != "" && req.Policy != nil {
		ent, ok := req.Policy.Credentials[h.Credential]
		if ok {
			if notifier, ok := ent.Body.(runtime.HITLNotifier); ok {
				target := runtime.HITLTarget{
					CredentialName: h.Credential,
					Channel:        h.Channel,
					Interactive:    h.Interactive,
					PendingID:      id,
					DashboardURL:   req.DashboardURL,
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
		timeout = time.Duration(req.Defaults.HumanTimeout) * time.Second
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

func buildPending(req runtime.ApproveRequest) runtime.HITLPending {
	now := time.Now()
	return runtime.HITLPending{
		AgentIP:    req.Profile,
		Host:       req.Host,
		Method:     req.Method,
		Path:       req.Path,
		UA:         req.UA,
		BodySample: req.BodySample,
		Reason:     req.Reason,
		Approvers:  []string{req.ApproverName},
		CreatedAt:  now,
	}
}

func decision(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}
