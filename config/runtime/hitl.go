package runtime

import (
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
)

// Shared HITL prompt formatting helpers. Used by both the Slack
// notifier (config/plugins/credentials/slack.go) and the dashboard
// pending-approvals widget (via buildPending → /api/hitl/pending)
// so the labelling is consistent across surfaces.

// HITLEndpointLabel returns the most concrete endpoint identifier
// for a HITL prompt. Whether the request's Host is informative on
// its own (HTTPS hostname like api.anthropic.com) or merely a wire
// address (SQL / k8s VIP) is a per-facet property: the facet
// runtime declares HostIsResource() and the dashboard / Slack
// renderer asks instead of carving out family strings here.
func HITLEndpointLabel(req ApproveRequest) string {
	ep := req.Endpoint
	if ep != nil && req.Host != "" {
		if f := facet.Lookup(ep.Family); f != nil && f.HostIsResource() {
			return req.Host
		}
	}
	if ep != nil && ep.Name != "" {
		return ep.Name
	}
	return req.Host
}

// HITLQueryLabel picks a family-appropriate label for the body of a
// HITL prompt by asking the facet that owns the endpoint's family.
// Falls back to "Path" for unknown families or endpoints without
// a registered facet.
func HITLQueryLabel(ep *config.CompiledEndpoint) string {
	if ep != nil {
		if f := facet.Lookup(ep.Family); f != nil {
			if label := f.HITLQueryLabel(); label != "" {
				return label
			}
		}
	}
	return "Path"
}

// HITLTitle builds the Slack header / dashboard title:
// "Approve <verb> · <endpoint>". Either half may be empty; an empty
// input is dropped so we never emit "Approve  ·  ".
func HITLTitle(method, endpoint string) string {
	method = strings.TrimSpace(method)
	endpoint = strings.TrimSpace(endpoint)
	switch {
	case method != "" && endpoint != "":
		return "Approve " + method + " · " + endpoint
	case endpoint != "":
		return "Approve " + endpoint
	case method != "":
		return "Approve " + method
	}
	return "Approve"
}
