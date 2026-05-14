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

	pb "github.com/denoland/clawpatrol/config/extplugin/proto"
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
	// Facets is the per-plugin schema list for protocol families the
	// plugin's endpoints emit actions against. The gateway registers
	// one facet.Runtime per FacetDef so the dashboard's /api/facets
	// surfaces the schema and rules can compile CEL conditions
	// against it (e.g. `smtp.verb == "MAIL"`). Names are auto-
	// namespaced to "<plugin>.<facet>".
	Facets []FacetDef
}

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

// CredentialDef declares one credential type. The plugin's endpoints
// receive the credential's secret bytes via Conn.CredentialSecret;
// there is no per-request RPC for credential injection in v1, since
// "plugin owns the whole conn" means the plugin's endpoint code
// applies the credential however the protocol requires.
type CredentialDef struct {
	TypeName string
	Schema   Schema
	// Build is optional. When set, the gateway invokes it once per
	// HCL block at config-load time. The plugin can validate the
	// decoded body, fill defaults, and return a canonical form that
	// later rides on Conn.CredentialCanonicalJSON. When nil, the
	// SDK echoes the request body unchanged.
	Build func(req BuildRequest) (any, error)
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

	TunnelTypeName string
	TunnelInstance string

	emit     func(ConnEvent)
	evaluate func(ctx context.Context, facet string, action map[string]any, summary string) (Verdict, error)
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
