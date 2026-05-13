// Package approvers registers every built-in approver kind. Per-
// approver files (dashboard.go, human.go, llm.go) carry the struct +
// every interface impl + the init() that registers the plugin. This
// file is the cross-cutting helpers shared between them.
package approvers

import (
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
