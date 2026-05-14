// Package approvers registers every built-in approver kind. Per-
// approver files (dashboard.go, human.go, llm.go) carry the struct +
// every interface impl + the init() that registers the plugin. This
// file is the cross-cutting helpers shared between them.
package approvers

import (
	"context"
	"errors"
	"time"

	"github.com/denoland/clawpatrol/config/runtime"
)

// buildPending lifts an ApproveRequest into the dashboard-pool's
// HITLPending shape. Used by every approver that publishes to the
// pool (dashboard, human).
func buildPending(req runtime.ApproveRequest) runtime.HITLPending {
	now := time.Now()
	family := ""
	if req.Endpoint != nil {
		family = req.Endpoint.Family
	}
	return runtime.HITLPending{
		AgentIP:    req.AgentIP,
		Host:       req.Host,
		Method:     req.Method,
		Path:       req.Path,
		Endpoint:   runtime.HITLEndpointLabel(req),
		Family:     family,
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

func verdictFromDecision(d runtime.HITLDecision) runtime.ApproveVerdict {
	return runtime.ApproveVerdict{
		Decision: decision(d.Allow),
		Reason:   d.Reason,
		By:       d.By,
	}
}

func cancelPending(pool runtime.HITLPool, id string, state runtime.HITLState, reason string) runtime.HITLResolveResult {
	if canceler, ok := pool.(runtime.HITLPoolCanceler); ok {
		return canceler.Cancel(id, state, reason)
	}
	pool.Discard(id)
	return runtime.HITLResolveResult{OK: true, State: state, Reason: reason}
}

func terminalDecisionVerdict(result runtime.HITLResolveResult, ch <-chan runtime.HITLDecision) (runtime.ApproveVerdict, bool) {
	switch result.State {
	case runtime.HITLStateApproved, runtime.HITLStateDenied:
		select {
		case d := <-ch:
			return verdictFromDecision(d), true
		default:
		}
		return runtime.ApproveVerdict{
			Decision: decision(result.State == runtime.HITLStateApproved),
			Reason:   result.Reason,
		}, true
	default:
		return runtime.ApproveVerdict{}, false
	}
}

func hitlCancelStateForContext(err error) (runtime.HITLState, string) {
	if errors.Is(err, context.Canceled) {
		return runtime.HITLStateClientDisconnected, "original client connection closed before approval; upstream request was not sent"
	}
	if err != nil {
		return runtime.HITLStateCanceled, err.Error()
	}
	return runtime.HITLStateCanceled, "approval canceled before a decision; upstream request was not sent"
}
