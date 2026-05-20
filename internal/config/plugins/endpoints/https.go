package endpoints

// https endpoint: anything that speaks TLS-wrapped HTTP. Covers most
// API-style upstreams. The kubernetes endpoint is HTTPS underneath
// too but ships as its own type because it carries server / ca_cert
// metadata HTTPS doesn't.

import (
	"encoding/base64"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// HTTPSEndpoint is part of the clawpatrol plugin API.
type HTTPSEndpoint struct {
	// Hosts is the set of HTTPS hostnames or host:port pairs this
	// endpoint intercepts.
	Hosts []string `hcl:"hosts"`
}

// EndpointHosts is part of the clawpatrol plugin API.
func (e *HTTPSEndpoint) EndpointHosts() []string { return e.Hosts }

// HTTPSEndpointRuntime detects placeholders in an HTTP request's
// Authorization header. Plain-substring scan rather than strict
// equality because agents send placeholders embedded in
// `Bearer <PH>` or `Basic <base64(user:<PH>)>` shapes; we only need to
// recognize that the agent picked one of our placeholders, not parse
// the auth scheme beyond safe Basic decoding.
type HTTPSEndpointRuntime struct{}

// DetectPlaceholder is part of the clawpatrol plugin API.
func (HTTPSEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.Headers == nil {
		return ""
	}
	hay := req.Headers.Get("Authorization") +
		"\x00" + basicAuthPayload(req.Headers.Get("Authorization")) +
		"\x00" + req.Headers.Get("Cookie")
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

func basicAuthPayload(authz string) string {
	scheme, payload, ok := strings.Cut(authz, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return ""
	}
	return string(decoded)
}

func init() {
	var _ runtime.PlaceholderDetector = HTTPSEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "https",
		Family:   "http",
		New:      func() any { return &HTTPSEndpoint{} },
		Runtime:  HTTPSEndpointRuntime{},
		Validate: hostsValidate,
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*HTTPSEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
		},
	})
}
