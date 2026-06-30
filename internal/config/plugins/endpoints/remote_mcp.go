package endpoints

// remote_mcp endpoint: a hosted Model Context Protocol server reached
// over HTTPS (Streamable HTTP or legacy HTTP+SSE). It carries the full
// MCP endpoint URL so the gateway can both index its host and scope
// dispatch to the endpoint's path — a configured URL such as
// `https://api.grain.com/_/mcp` must not capture every request to
// `api.grain.com`. The mcp facet (family "mcp") composes the http
// facet, so rules can match MCP semantics (mcp.kind, mcp.method,
// mcp.tool_name) alongside http.* fields.

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// RemoteMCPEndpoint is part of the clawpatrol plugin API.
type RemoteMCPEndpoint struct {
	// URL is the full MCP endpoint URL (absolute https). Its host is
	// indexed for SNI dispatch and its path scopes which requests on
	// that host run the MCP facet.
	URL string `hcl:"url"`
	// Transport is an advisory hint about the MCP transport the agent
	// uses (auto | streamable_http | sse). The gateway never rewrites
	// the agent's transport; this is reserved for future reporting.
	Transport string `hcl:"transport,optional"`
	// ProtocolVersion optionally pins the MCP protocol version for
	// reporting / documentation.
	ProtocolVersion string `hcl:"protocol_version,optional"`
	// Hosts are additional hostnames (or host:port pairs) this endpoint
	// also intercepts beyond the URL host — an advanced override.
	Hosts []string `hcl:"hosts,optional"`
}

// RemoteMCPURL returns the configured resource URL for generic remote
// MCP OAuth discovery.
func (e *RemoteMCPEndpoint) RemoteMCPURL() string { return e.URL }

// EndpointHosts is part of the clawpatrol plugin API. It returns the
// URL-derived host first, then any explicit additional hosts. Explicit
// hosts never remove the URL host.
func (e *RemoteMCPEndpoint) EndpointHosts() []string {
	var hosts []string
	if h := mcpURLHost(e.URL); h != "" {
		hosts = append(hosts, h)
	}
	hosts = append(hosts, e.Hosts...)
	return hosts
}

// EndpointPathConstraint is part of the clawpatrol plugin API. It
// reports the URL path the endpoint is scoped to for path-aware HTTPS
// dispatch. An empty path (or "/") means the endpoint serves the whole
// host. A path ending in "/" matches that prefix and its path-segment
// children; any other path matches exactly.
func (e *RemoteMCPEndpoint) EndpointPathConstraint() (path string, prefix bool) {
	u, err := url.Parse(strings.TrimSpace(e.URL))
	if err != nil {
		return "", false
	}
	p := u.Path
	if p == "" || p == "/" {
		return "", false
	}
	if strings.HasSuffix(p, "/") {
		return p, true
	}
	return p, false
}

// mcpURLHost returns the host[:port] of a remote MCP URL, or "" when
// the URL doesn't parse or carries no host.
func mcpURLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Host
}

// RemoteMCPEndpointRuntime detects placeholders in a remote MCP
// request. Remote MCP is TLS-wrapped HTTP, so the placeholder shapes
// are identical to the https endpoint (Authorization / decoded Basic /
// Cookie); reuse that detector directly rather than duplicating it.
type RemoteMCPEndpointRuntime struct{}

// DetectPlaceholder is part of the clawpatrol plugin API.
func (RemoteMCPEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	return HTTPSEndpointRuntime{}.DetectPlaceholder(req, candidates)
}

// remoteMCPValidate checks the URL is an absolute https URL with a
// host, validates the transport hint, and chains the shared host
// validation.
func remoteMCPValidate(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	e := d.(*RemoteMCPEndpoint)
	defRange := ctx.Block.DefRange
	var diags hcl.Diagnostics
	raw := strings.TrimSpace(e.URL)
	if raw == "" {
		return append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Missing url on remote_mcp endpoint %q", name),
			Detail:   `remote_mcp endpoints require an absolute https url, e.g. url = "https://mcp.example.com/mcp"`,
			Subject:  &defRange,
		})
	}
	u, err := url.Parse(raw)
	if err != nil {
		return append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Malformed url on remote_mcp endpoint %q", name),
			Detail:   fmt.Sprintf("url %q: %v", raw, err),
			Subject:  &defRange,
		})
	}
	if u.Scheme != "https" {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("remote_mcp endpoint %q url must be https", name),
			Detail:   fmt.Sprintf("url %q has scheme %q; remote MCP requires https", raw, u.Scheme),
			Subject:  &defRange,
		})
	}
	if u.Hostname() == "" {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("remote_mcp endpoint %q url is missing a host", name),
			Detail:   fmt.Sprintf("url %q must include a host, e.g. https://mcp.example.com/mcp", raw),
			Subject:  &defRange,
		})
	}
	switch e.Transport {
	case "", "auto", "streamable_http", "sse":
	default:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("remote_mcp endpoint %q has an unknown transport", name),
			Detail:   fmt.Sprintf("transport %q must be one of: auto, streamable_http, sse", e.Transport),
			Subject:  &defRange,
		})
	}
	return append(diags, validateHosts(e, name, defRange)...)
}

func init() {
	var _ runtime.PlaceholderDetector = RemoteMCPEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "remote_mcp",
		Family:   "mcp",
		New:      func() any { return &RemoteMCPEndpoint{} },
		Runtime:  RemoteMCPEndpointRuntime{},
		Validate: remoteMCPValidate,
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*RemoteMCPEndpoint)
			b.SetAttributeValue("url", cty.StringVal(e.URL))
			if e.Transport != "" {
				b.SetAttributeValue("transport", cty.StringVal(e.Transport))
			}
			if e.ProtocolVersion != "" {
				b.SetAttributeValue("protocol_version", cty.StringVal(e.ProtocolVersion))
			}
			if len(e.Hosts) > 0 {
				b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
			}
		},
	})
}
