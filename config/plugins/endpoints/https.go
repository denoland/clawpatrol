package endpoints

// https endpoint: anything that speaks TLS-wrapped HTTP. Covers most
// API-style upstreams. The kubernetes endpoint is HTTPS underneath
// too but ships as its own type because it carries server / ca_cert
// metadata HTTPS doesn't.

import (
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

type HTTPSEndpoint struct {
	Hosts          []string  `hcl:"hosts"`
	Credential     string    `hcl:"credential,optional"`
	CredentialsRaw cty.Value `hcl:"credentials,optional" json:"-"`

	// Credentials is populated by Validate from CredentialsRaw. Stable
	// JSON shape for goldens.
	Credentials []CredentialEntry `json:"Credentials,omitempty"`
}

func (e *HTTPSEndpoint) EndpointHosts() []string { return e.Hosts }
func (e *HTTPSEndpoint) EndpointCredentials() []config.CredBinding {
	return bindings(e.Credential, e.Credentials)
}

func (e *HTTPSEndpoint) credentialAndRaw() (string, cty.Value) {
	return e.Credential, e.CredentialsRaw
}
func (e *HTTPSEndpoint) setCredentialEntries(es []CredentialEntry) { e.Credentials = es }

// HTTPSEndpointRuntime detects placeholders in an HTTP request's
// Authorization header. Plain-substring scan rather than strict
// equality because agents send placeholders embedded in
// `Bearer <PH>` or `Basic <base64(<PH>:)>` shapes; we only need to
// recognize that the agent picked one of our placeholders, not parse
// the auth scheme.
type HTTPSEndpointRuntime struct{}

func (HTTPSEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.Headers == nil {
		return ""
	}
	hay := req.Headers.Get("Authorization") + "\x00" + req.Headers.Get("Cookie")
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

func init() {
	var _ runtime.PlaceholderDetector = HTTPSEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "https",
		Family:   "https",
		New:      func() any { return &HTTPSEndpoint{} },
		Refs:     singularRef,
		Validate: multiCredValidate,
		Runtime:  HTTPSEndpointRuntime{},
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*HTTPSEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			emitCredentialBinding(b, e.Credential, e.Credentials)
		},
	})
}
