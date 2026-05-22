package main

// Approve-chain dispatcher. Rules in the compiled policy can list a
// chain of approver stages (`approve = [...]`); mitmHTTPS and the
// connection-oriented endpoint dispatchers all defer to
// runApproveChain when they need a verdict from those stages before
// they forward upstream. The chain is all-must-allow — first
// non-allow verdict short-circuits — and dashboard is handled
// inline so policy doesn't have to declare it as an entity.

import (
	"context"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/plugins/approvers"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// runApproveCtx is the context blob the dispatcher passes per stage —
// HITL prompt fields + the matching rule + the device's profile.
type runApproveCtx struct {
	AgentIP                   string
	Host                      string
	Method                    string
	Path                      string
	UA                        string
	BodySample                string
	Reason                    string
	ThreadTS                  string
	Endpoint                  *config.CompiledEndpoint
	Rule                      *config.CompiledRule
	Profile                   string
	Request                   *match.Request
	AsyncOperationID          string
	AsyncPendingOnSyncTimeout bool
	AsyncSyncWaitTimeout      time.Duration
}

// runApproveChain dispatches each stage of an approve = [...] list to
// the matching approver entity's runtime. All-must-allow semantics —
// the first non-allow verdict short-circuits and is returned. Built-in
// `dashboard` is handled inline (no policy entity needed).
func (g *Gateway) runApproveChain(ctx context.Context, stages []config.ApproveStage, c runApproveCtx) runtime.ApproveVerdict {
	policy := g.Policy()
	for _, st := range stages {
		var ar runtime.ApproverRuntime
		approverType := ""
		if st.Name == "dashboard" {
			ar = approvers.DashboardApprover{}
			approverType = "dashboard"
		} else if policy != nil {
			if ent, ok := policy.Approvers[st.Name]; ok {
				if rt, ok := ent.Body.(runtime.ApproverRuntime); ok {
					ar = rt
				}
				if ent.Plugin != nil {
					approverType = ent.Plugin.Type
				}
			}
		}
		if ar == nil {
			return runtime.ApproveVerdict{Decision: "deny", Reason: "approver " + st.Name + " not found", By: "gateway", ApproverName: st.Name}
		}
		if c.AsyncPendingOnSyncTimeout && c.AsyncSyncWaitTimeout > 0 && c.AsyncOperationID != "" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, c.AsyncSyncWaitTimeout)
			defer cancel()
		}
		req := runtime.ApproveRequest{
			Stage:                     st,
			Endpoint:                  c.Endpoint,
			Rule:                      c.Rule,
			Request:                   c.Request,
			ApproverName:              st.Name,
			AgentIP:                   c.AgentIP,
			Profile:                   c.Profile,
			Method:                    c.Method,
			Host:                      c.Host,
			Path:                      c.Path,
			UA:                        c.UA,
			BodySample:                c.BodySample,
			Reason:                    c.Reason,
			ThreadTS:                  c.ThreadTS,
			AsyncOperationID:          c.AsyncOperationID,
			AsyncPendingOnSyncTimeout: c.AsyncPendingOnSyncTimeout,
			Pool:                      g.hitl,
			Secrets:                   g.secrets,
			DashboardURL:              g.cfg.PublicURL(),
			Policy:                    policy,
			MessageUpdateSink:         g.recordHITLOperationMessageRef,
			PendingMessageUpdateSink:  g.hitl.RecordMessageRef,
		}
		v, err := ar.Approve(ctx, req)
		// Stamp the entity name + plugin type on every verdict so the
		// dispatcher labels its `approved` / `denied` events with the
		// deciding approver — runtimes don't have to remember.
		if v.ApproverName == "" {
			v.ApproverName = st.Name
		}
		if v.ApproverType == "" {
			v.ApproverType = approverType
		}
		if err != nil {
			return runtime.ApproveVerdict{Decision: "deny", Reason: err.Error(), By: "gateway", ApproverName: v.ApproverName, ApproverType: v.ApproverType}
		}
		if v.Decision != "allow" {
			if v.Decision == "" {
				v.Decision = "deny"
				if v.Reason == "" {
					v.Reason = "approver " + st.Name + " timed out"
				}
			}
			return v
		}
	}
	return runtime.ApproveVerdict{Decision: "allow"}
}

// ifNotEmpty returns f(v) when v != nil, else "".
func ifNotEmpty(r *config.CompiledRule, f func(*config.CompiledRule) string) string {
	if r == nil {
		return ""
	}
	return f(r)
}
