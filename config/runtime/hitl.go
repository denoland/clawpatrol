package runtime

import (
	"strings"

	"github.com/denoland/clawpatrol/config"
)

// Shared HITL prompt formatting helpers. Used by both the Slack
// notifier (config/plugins/credentials/slack.go) and the dashboard
// pending-approvals widget (via buildPending → /api/hitl/pending)
// so the labelling is consistent across surfaces.

// HITLEndpointLabel returns the most concrete endpoint identifier
// for a HITL prompt. For HTTPS the request's Host is a real
// hostname (api.anthropic.com), so we use it. For SQL / k8s the
// Host is typically a virtual IP, so we prefer the operator-defined
// endpoint resource name (e.g. "users-db") and only fall back to
// Host when no endpoint metadata is available.
func HITLEndpointLabel(req ApproveRequest) string {
	ep := req.Endpoint
	if ep != nil && ep.Family == "https" && req.Host != "" {
		return req.Host
	}
	if ep != nil && ep.Name != "" {
		return ep.Name
	}
	return req.Host
}

// HITLQueryLabel picks a family-appropriate label for the body of a
// HITL prompt: "Query" for SQL, "Resource" for k8s, "Path" for
// HTTPS or unknown families.
func HITLQueryLabel(ep *config.CompiledEndpoint) string {
	if ep == nil {
		return "Path"
	}
	switch ep.Family {
	case "sql":
		return "Query"
	case "k8s":
		return "Resource"
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
