// Package pluginsdk is the author-facing SDK for clawpatrol's
// Terraform-style external plugins.
//
// A plugin is an ordinary Go program whose main() builds a *Plugin
// describing the credential / tunnel / endpoint types it provides and
// hands it to Run. Run starts the gRPC server the gateway will
// connect to via hashicorp/go-plugin's handshake.
//
// Minimal example:
//
//	func main() {
//		pluginsdk.Run(&pluginsdk.Plugin{
//			Name: "example", Version: "0.1",
//			Endpoints: []pluginsdk.EndpointDef{...},
//		})
//	}
package pluginsdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

// Plugin is the top-level declaration a plugin's main() builds and
// hands to Run. Name is the registered plugin name (used to namespace
// types as <name>.<type> when the gateway registers them); Version
// is informational, surfaced in startup logs.
type Plugin struct {
	Name        string
	Version     string
	Credentials []CredentialDef
	Tunnels     []TunnelDef
	Endpoints   []EndpointDef

	// Capabilities declares the low-risk permissions this plugin
	// needs. The gateway records the approved set in its lockfile on
	// first load (the operator no longer hand-writes them) and fails
	// closed with a loud warning if a later version of the plugin
	// asks for more. Today the only capability is Network: set it to
	// NetworkOutbound if the plugin dials out itself (a tunnel
	// transport, or a credential plugin doing its own token
	// exchange). High-risk grants — host filesystem access,
	// sandbox = "off" — are operator-only and are NOT declarable
	// here.
	Capabilities Capabilities
	// Facets is the per-plugin schema list for protocol families the
	// plugin's endpoints emit actions against. The gateway registers
	// one facet.Runtime per FacetDef so the dashboard's /api/facets
	// surfaces the schema and rules can compile CEL conditions
	// against it (e.g. `smtp.verb == "MAIL"`). Names are auto-
	// namespaced to "<plugin>.<facet>".
	Facets []FacetDef
}

// Capabilities is the set of low-risk, plugin-declarable permissions
// in Plugin.Capabilities.
type Capabilities struct {
	// Network is the plugin's network requirement. Defaults to
	// NetworkNone (the plugin only talks to the gateway over its
	// socket).
	Network NetworkAccess

	// Egress is the set of upstream targets this plugin needs to reach
	// through the gateway's brokered dial (conn.DialUpstream), each
	// "host:port" or "*.suffix.tld:port" (port required). Declaring it
	// lets a plugin run with Network = NetworkNone — no raw sockets,
	// every connection gateway-validated and audited — instead of the
	// coarse NetworkOutbound. The gateway records the approved set in its
	// lockfile (trust-on-first-use) and blocks an upgrade that broadens
	// it, the same model as Network; the operator never hand-writes it.
	Egress []string
}

// NetworkAccess is a plugin's declared network requirement.
type NetworkAccess int

const (
	// NetworkNone confines the plugin to its gateway socket; upstream
	// connections go through the gateway's brokered dial.
	NetworkNone NetworkAccess = iota
	// NetworkOutbound lets the plugin dial out itself.
	NetworkOutbound
)

// FacetDef declares one protocol-family schema. Endpoints bind to a
// declared facet by setting EndpointDef.Family to the facet's short
// name; the SDK auto-namespaces it before forwarding to the gateway.
type FacetDef struct {
	Name   string
	Fields []FacetField
}

// FacetField declares one column in the facet's schema. Kind tells
// the dashboard how to format the value (single string, list of
// strings, key/value map, integer, or lazy byte stream); Label is
// the optional human-readable column header (defaults to a
// title-cased Name).
//
// Optional fields may be omitted from the action map passed to
// Conn.Evaluate; the gateway substitutes a kind-zero value before
// CEL evaluation so rule conditions can reference them without
// `has()` guards.
type FacetField struct {
	Name     string
	Kind     FacetKind
	Label    string
	Optional bool
}

// FacetKind mirrors pb.FacetKind.
type FacetKind int

const (
	// FacetString is a scalar string facet field.
	FacetString FacetKind = 0
	// FacetStringList is a repeated string facet field.
	FacetStringList FacetKind = 1
	// FacetStringMap is a string-to-string map facet field.
	FacetStringMap FacetKind = 2
	// FacetInt is an integer facet field.
	FacetInt FacetKind = 3
	// FacetStream is a lazy bytes value the plugin offers via
	// pluginsdk.Stream(io.Reader) in the action map. The gateway
	// pulls chunks on demand — the full payload (up to a cap) when
	// any rule references the field, otherwise just enough to log
	// a prefix — and cancels the stream when it has what it needs.
	FacetStream FacetKind = 4
)

// Stream wraps an io.Reader so it can be passed as a value in the
// action map of Conn.Evaluate. The SDK detects Stream values, swaps
// them for handle markers in the JSON payload sent to the gateway,
// and serves the gateway's StreamRead requests by reading from r in
// the background. On StreamCancel (or conn shutdown) the SDK stops
// reading; the plugin can use that as a hint to drop its own
// upstream copy.
//
// Plugin authors who want to "rewind" a stream should buffer it
// themselves (bytes.NewReader) before passing it here.
func Stream(r io.Reader) StreamValue { return StreamValue{R: r} }

// StreamValue is the wrapper returned by Stream. Exported so plugin
// code can construct it directly when convenient.
type StreamValue struct {
	R io.Reader
}

// SecretSlot describes one dashboard secret input an external
// credential type exposes to operators.
type SecretSlot struct {
	Name        string
	Label       string
	Multiline   bool
	Description string
}

// EnvVar is one environment variable pushed to agent processes. The
// Value should be a placeholder, not a real secret.
type EnvVar struct {
	Name        string
	Value       string
	Description string
}

// OptionalScopeGroup is one dashboard OAuth scope-picker section.
type OptionalScopeGroup struct {
	Title  string
	Scopes []OptionalScope
}

// OptionalScope is one toggleable OAuth scope.
type OptionalScope struct {
	ID    string
	Label string
}

// OAuthConfig describes the OAuth client/endpoint configuration for
// an external credential's gateway-owned OAuth flow.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	DeviceURL    string
	RegisterURL  string
	RedirectURI  string
	Scopes       []string
	RefreshToken string
}

// OAuthIntegration describes how an OAuth access token is acquired and
// injected for an external credential.
type OAuthIntegration struct {
	Type           string
	Header         string
	Prefix         string
	Flow           string
	OAuth          OAuthConfig
	OptionalScopes []OptionalScopeGroup
}

// CredentialMetadata is the instance-specific metadata a credential
// Build callback may return alongside its canonical config.
type CredentialMetadata struct {
	Disambiguators []string
	SecretSlots    []SecretSlot
	EnvVars        []EnvVar
	OAuth          *OAuthIntegration
	HTTPInject     bool
	// HTTPTransform mirrors CredentialDef.HTTPTransform (the credential
	// rewrites method/URL/body via TransformHTTP). Registration-time only.
	HTTPTransform bool
}

// CredentialBuildResult lets a Build callback return both canonical
// config and instance-specific metadata. Returning a plain value keeps
// the legacy behavior and treats that value as canonical config.
type CredentialBuildResult struct {
	Canonical any
	Metadata  CredentialMetadata
}

// HeaderMutationOp is a request-header operation returned by an
// external credential InjectHTTP callback.
type HeaderMutationOp string

const (
	// HeaderSet replaces all existing values for the named request header.
	HeaderSet HeaderMutationOp = "set"
	// HeaderAdd appends values to the named request header. Use HeaderSet for
	// Authorization and other replacement-style auth headers so the agent's
	// placeholder header is removed before the real value is forwarded.
	HeaderAdd HeaderMutationOp = "add"
	// HeaderDel removes the named request header.
	HeaderDel HeaderMutationOp = "del"
)

// HeaderMutation mutates an outbound HTTP request header.
type HeaderMutation struct {
	Op     HeaderMutationOp
	Name   string
	Values []string
}

// HTTPInjectRequest is sent to an external credential just before the
// built-in HTTPS endpoint forwards a request upstream.
type HTTPInjectRequest struct {
	CredentialTypeName        string
	CredentialInstance        string
	CredentialCanonicalConfig []byte
	CredentialSecret          []byte
	CredentialExtras          map[string]string

	Method  string
	URL     string
	Host    string
	Headers http.Header

	BodyPrefix    []byte
	BodyTruncated bool
}

// HTTPInjectResponse is the header-only mutation set returned by an
// external credential InjectHTTP callback.
type HTTPInjectResponse struct {
	Headers []HeaderMutation
	// Redactions lists exact derived secret strings the gateway should mask from
	// audit samples. Include any exchanged JWTs, HMAC signatures, or other values
	// derived from CredentialSecret that are injected into non-sensitive headers.
	Redactions []string
}

// CredentialDef declares one credential type. The plugin's endpoints
// still receive the credential's secret bytes via Conn.CredentialSecret,
// and credentials with HTTPInject=true can also participate in the
// built-in HTTPS endpoint's request-time injection path.
type CredentialDef struct {
	TypeName string
	Schema   Schema

	// Disambiguators names registration-time supported dispatch
	// discriminator fields, e.g. "placeholder" for HTTP bearer-style
	// credentials. The gateway validates credential/profile HCL against
	// this list.
	Disambiguators []string

	// HTTPInject declares that this credential can inject into the
	// built-in HTTPS endpoint via InjectHTTP.
	HTTPInject bool

	// Build is optional. When set, the gateway invokes it once per
	// HCL block at config-load time. The plugin can validate the
	// decoded body, fill defaults, and return either a canonical form
	// or CredentialBuildResult. When nil, the SDK echoes the request
	// body unchanged.
	Build func(req BuildRequest) (any, error)

	// InjectHTTP is called for credentials bound to a built-in HTTPS
	// endpoint when HTTPInject is true. Header-only: the request body does
	// not flow through the plugin.
	InjectHTTP func(ctx context.Context, req HTTPInjectRequest) (*HTTPInjectResponse, error)

	// HTTPTransform declares that this credential rewrites more than
	// headers — the request method / URL / body — via TransformHTTP.
	// Implies HTTPInject. Use for credentials that sign over the body (AWS
	// SigV4) or carry the secret in the URL/body (telegram, discord).
	HTTPTransform bool

	// TransformHTTP is called for HTTPTransform credentials. It receives
	// the request body as a stream (req.Body) and returns the mutations
	// plus the transformed body. Buffering is the plugin's choice: read
	// only what you need and stream the rest, or read it all to sign. See
	// HTTPTransformRequest / HTTPTransformResponse.
	TransformHTTP func(ctx context.Context, req HTTPTransformRequest) (*HTTPTransformResponse, error)
}

// HTTPTransformRequest is delivered to a credential's TransformHTTP
// callback before the built-in HTTPS endpoint forwards a request upstream.
type HTTPTransformRequest struct {
	CredentialTypeName        string
	CredentialInstance        string
	CredentialCanonicalConfig []byte
	CredentialSecret          []byte
	CredentialExtras          map[string]string

	Method  string
	URL     string
	Host    string
	Headers http.Header

	// Body is the request body, streamed from the gateway. Read as much
	// as you need — the plugin controls buffering. Reading to EOF is fine
	// (the gateway streams the whole body); reading a prefix and returning
	// a Body that copies the rest through is also fine.
	Body io.Reader
}

// HTTPTransformResponse is what a TransformHTTP callback returns.
type HTTPTransformResponse struct {
	// Headers / Method / URL rewrite the request line and headers; applied
	// by the gateway before the request is forwarded. A credential that
	// signs over the body sets the signature header here (and a
	// Content-Length header if it changed the body length).
	Headers []HeaderMutation
	Method  string
	URL     string
	// Redactions are exact derived secret strings to mask from audit
	// samples (a computed signature, an exchanged token).
	Redactions []string

	// Body is the outgoing request body the gateway forwards upstream. To
	// pass the input through unchanged, set Body = req.Body. To replace it,
	// return any io.Reader (e.g. bytes.NewReader). nil sends an empty body.
	//
	// HTTP trailers that follow the request body (e.g. gRPC's) are
	// preserved by the gateway across the transform; the plugin does not
	// handle them.
	Body io.Reader
}

// TunnelDef declares one tunnel type. Open returns an opaque handle
// the gateway can later use to Dial through. Dial takes ownership of
// the connection and should write/read until either side closes.
type TunnelDef struct {
	TypeName string
	Schema   Schema
	Build    func(req BuildRequest) (any, error)
	// Open is invoked on the first Acquire of a tunnel instance. It
	// returns the handle the SDK passes back to Dial / Close. Open is
	// optional for stateless tunnels; the SDK supplies a no-op default
	// returning the instance name as the handle.
	Open func(ctx context.Context, req TunnelOpenRequest) (any, error)
	// Dial opens one upstream connection through the tunnel handle.
	// The SDK exposes a duplex net.Conn-like upstream object the
	// plugin reads from / writes to as if it were the upstream socket.
	Dial func(ctx context.Context, req TunnelDialRequest, upstream net.Conn) error
	// Close tears down the handle. May be nil for stateless tunnels.
	Close func(ctx context.Context, handle any) error
}

// EndpointDef declares one endpoint type. HandleConn owns the agent
// connection from start to finish.
type EndpointDef struct {
	TypeName string
	// Family is forwarded to *config.Plugin.Family. Use "stream" so
	// CEL rules can't accidentally try to match http.* / sql.*
	// against this endpoint.
	Family      string
	TLSMode     TLSMode
	RequiresVIP bool
	Schema      Schema
	Build       func(req BuildRequest) (any, error)
	// HandleConn owns the agent connection. The SDK has already (a)
	// terminated TLS for TLSMode=TLSTerminate and (b) populated
	// conn.* with the per-conn context. Return nil for a clean close,
	// or any error to log + close.
	HandleConn func(ctx context.Context, conn *Conn) error
}

// TLSMode mirrors pb.TLSMode so plugin code can stay decoupled from
// the generated proto package.
type TLSMode int

const (
	// TLSNone leaves the agent connection raw (plain TCP).
	TLSNone TLSMode = TLSMode(pb.TLSMode_TLS_NONE)
	// TLSTerminate makes the gateway terminate TLS (using its CA)
	// before handing the conn to HandleConn.
	TLSTerminate TLSMode = TLSMode(pb.TLSMode_TLS_TERMINATE)
)

// Schema is a flat list of the HCL attributes the type accepts.
type Schema struct {
	Fields []SchemaField
}

// SchemaField names one attribute. TypeString is a go-cty type
// string ("string", "bool", "number", "list(string)", etc.).
type SchemaField struct {
	Name       string
	TypeString string
	Required   bool
}

// BuildRequest is what Build callbacks receive at config-load time.
type BuildRequest struct {
	// Kind is "credential", "tunnel", or "endpoint".
	Kind         string
	TypeName     string
	InstanceName string
	// ConfigJSON is the HCL block body decoded against the declared
	// Schema and marshaled as a JSON object. Decode it into your
	// plugin-native struct via Decode.
	ConfigJSON []byte
}

// Decode unmarshals ConfigJSON into v.
func (r BuildRequest) Decode(v any) error {
	if len(r.ConfigJSON) == 0 {
		return nil
	}
	return json.Unmarshal(r.ConfigJSON, v)
}

// ConnCredential is one credential bound to a plugin endpoint, as
// delivered on Conn.Credentials. Mirrors the singular Conn.Credential*
// fields; carried as a list so an endpoint can offer several and the
// plugin picks which to use per connection.
type ConnCredential struct {
	TypeName        string
	Instance        string
	Secret          []byte
	Extras          map[string]string
	CanonicalConfig []byte
}

// Conn is the per-inbound-conn handle a plugin's HandleConn receives.
// Reading / writing the underlying agent connection is done through
// the embedded net.Conn (which is a TLS-terminated *tls.Conn for
// TLSMode=TLSTerminate, or a raw stream-backed conn otherwise).
type Conn struct {
	net.Conn

	EndpointTypeName        string
	EndpointInstance        string
	EndpointCanonicalConfig []byte // canonical JSON the endpoint Build returned

	Profile      string
	PeerIP       string
	UpstreamHost string
	DstPort      uint16

	CredentialTypeName        string
	CredentialInstance        string
	CredentialSecret          []byte
	CredentialExtras          map[string]string
	CredentialCanonicalConfig []byte

	// Credentials is every credential bound to this endpoint, in
	// declaration order, for plugins that support multi-credential
	// endpoints (e.g. a base key per account). The singular Credential*
	// fields above mirror Credentials[0]. On single-credential endpoints
	// it holds that one credential; on older gateways that don't send the
	// set it is nil (read the singular fields instead).
	Credentials []ConnCredential

	TunnelTypeName string
	TunnelInstance string

	emit         func(ConnEvent)
	evaluate     func(ctx context.Context, facet string, action map[string]any, summary string) (Verdict, error)
	dialUpstream func(ctx context.Context, network, addr string, opts *DialUpstreamOptions) (net.Conn, error)
}

// DialUpstreamOptions controls gateway-side TLS for a brokered dial.
type DialUpstreamOptions struct {
	// TLS asks the gateway to terminate upstream TLS: the gateway
	// performs real certificate verification (system roots plus the
	// endpoint's TLS configuration and any mTLS credential) and the
	// plugin exchanges plaintext over the brokered pipe. Preferred
	// over running tls.Client inside the plugin — sandboxed plugins
	// may not even have a CA bundle mounted.
	TLS bool
	// TLSServerName overrides the SNI / verification name. Defaults
	// to the host part of addr.
	TLSServerName string
}

// ErrDialUpstreamUnsupported is returned by Conn.DialUpstream when
// the gateway predates the brokered-dial protocol. Such gateways
// silently drop the request frame, so the SDK fails fast instead of
// hanging; plugins that must support them need their own net.Dial
// and an operator-granted network = "outbound".
var ErrDialUpstreamUnsupported = errors.New(
	"pluginsdk: gateway does not support brokered dial (upgrade clawpatrol, or grant the plugin network = \"outbound\" and dial directly)")

// DialUpstream asks the gateway to open an upstream connection on
// the plugin's behalf. The gateway only dials targets the operator's
// HCL sanctions for this endpoint instance (the agent's original
// target, the endpoint's `hosts`, or its `dial` allow-list), routes
// through the endpoint's bound tunnel when one is configured, and
// audits every attempt. This is how endpoint plugins reach their
// upstream while running with no network access of their own.
//
// network must be "tcp". Safe for concurrent use; each call opens an
// independent upstream connection.
func (c *Conn) DialUpstream(ctx context.Context, network, addr string, opts *DialUpstreamOptions) (net.Conn, error) {
	if c.dialUpstream == nil {
		return nil, errors.New("pluginsdk: Conn.DialUpstream not wired (running without a gateway?)")
	}
	return c.dialUpstream(ctx, network, addr, opts)
}

// Emit hands an audit event to the gateway. The gateway funnels it
// through its existing event sink (dashboard SSE + JSONL log).
//
// Emit is for *non-policy* events only — operational failures,
// session-level milestones (connect / disconnect), out-of-band
// notices the dashboard should surface but that don't correspond
// to a request the plugin asked the gateway to rule on. Use
// Conn.Evaluate for anything where the verdict matters; the
// gateway emits a derived ConnEvent for every Evaluate so plugins
// don't double-log.
//
// In particular, do not call Emit with a hardcoded Action of
// "allow" or "deny" — that fabricates a verdict no rule produced.
//
// No-op when emit is nil (e.g. in unit tests).
func (c *Conn) Emit(ev ConnEvent) {
	if c.emit != nil {
		c.emit(ev)
	}
}

// Evaluate asks the gateway to rule on one structured action against
// the endpoint's compiled rule list, walking any approve = [...]
// chain along the way. The gateway also logs the action onto its
// event stream with the action map as the facet payload, so plugin
// authors don't need to call Emit separately.
//
// facet is the short facet name as declared in Plugin.Facets (the
// SDK auto-namespaces it). action is a JSON-serializable map whose
// keys match the facet's declared fields. summary is the one-liner
// rendered on dashboard / HITL prompts.
//
// Safe to call concurrently from multiple goroutines on the same
// Conn — the SDK matches verdicts to in-flight calls by call_id.
func (c *Conn) Evaluate(ctx context.Context, facet string, action map[string]any, summary string) (Verdict, error) {
	if c.evaluate == nil {
		return Verdict{}, errors.New("pluginsdk: Conn.Evaluate not wired (running without a gateway?)")
	}
	return c.evaluate(ctx, facet, action, summary)
}

// Verdict is the gateway's decision on one EvaluateAction call.
type Verdict struct {
	// Action is "allow" | "deny" | "hitl_allow" | "hitl_deny" |
	// "error". The plugin maps this onto whatever protocol-level
	// response code makes sense (250/535 for SMTP, etc.).
	Action string
	Reason string
	// Rule is the matched CompiledRule.Name, or "" when no rule
	// matched (the gateway's default-deny took effect).
	Rule string
}

// ConnEvent is the runtime.ConnEvent shape exposed to plugin code.
type ConnEvent struct {
	Action  string // "allow" | "deny" | "hitl_allow" | "hitl_deny" | "error"
	Reason  string
	Verb    string
	Summary string
	Bytes   int64
	Facets  map[string]any
	Rule    string
}

// TunnelOpenRequest is what Open callbacks receive when the gateway
// brings up a tunnel instance.
type TunnelOpenRequest struct {
	TunnelTypeName   string
	TunnelInstance   string
	CanonicalConfig  []byte
	CredentialSecret []byte
	CredentialExtras map[string]string
}

// TunnelDialRequest is what Dial callbacks receive when the gateway
// dials through an open tunnel handle.
type TunnelDialRequest struct {
	Handle  any
	Network string
	Addr    string
}

// ErrNoSuchType is returned by the SDK when the gateway invokes a
// (kind, type) the plugin did not register. Surfaces as a gRPC error
// to the gateway, which converts it to an HCL diagnostic.
var ErrNoSuchType = errors.New("plugin: no such type registered")
