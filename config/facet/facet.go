// Package facet is the registry for protocol-family plugins.
//
// A facet owns end-to-end per-family behaviour: which keys a rule's
// match{} block may use, how those keys compile into a Matcher, how
// per-request metadata is derived from the request snapshot, and which
// fields the family contributes to the event/log reporting layer.
//
// Built-in facets (https, sql, k8s) live under config/plugins/facets/;
// each registers itself at init() via facet.Register. The rules
// plugin (config/plugins/rules) and the request handler look facets up
// by name through this registry rather than switching on family
// strings, so adding a new protocol is a single new package — no
// edits in match.go, rules.go, or the gateway runtime.
//
// The contract is deliberately serialisable (MatchKeySpec,
// ReportFieldSpec, and Report's map[string]any output all round-trip
// through JSON) so a later out-of-process / Terraform-style provider
// model can wrap the same Runtime interface over RPC without
// re-architecting the host side.
package facet

import (
	"fmt"
	"sort"
	"sync"

	"github.com/denoland/clawpatrol/config/match"
)

// Runtime is the per-facet contract. Implementations live in their
// own packages under config/plugins/facets/ and register a singleton
// at init() time. The same Runtime instance is shared across every
// request handled by the gateway, so implementations must be
// goroutine-safe (which is trivial when they hold no mutable state).
type Runtime interface {
	// Name returns the family identifier — "https", "sql", "k8s",
	// and so on. Must match the Type used at registration and the
	// `family` string carried on endpoints and rules.
	Name() string

	// RuleType is the HCL block label used for rules targeting this
	// facet ("http_rule", "sql_rule", "k8s_rule"). The rules plugin
	// registers one config.KindRule entry per facet using this name.
	RuleType() string

	// EndpointFamilies lists the endpoint families a rule of this
	// facet is allowed to attach to. Almost always a single entry
	// equal to Name(); kept as a slice because the existing
	// RefSpec.FamilyConstraint takes a slice.
	EndpointFamilies() []string

	// Transport names the gateway-side handler that owns the wire
	// for endpoints of this family. "https-mitm" → SNI peek + TLS
	// terminate + HTTP request loop (used by https and kubernetes
	// endpoints alike). "" → no MITM-port-443 dispatch; the
	// endpoint plugin's own runtime drives the wire (postgres /
	// clickhouse / future native protocols). Lets the gateway
	// decide where to route a TLS connection without switching on
	// family strings.
	Transport() string

	// HITLQueryLabel is the human-readable label the dashboard /
	// Slack approval card uses for the body of a HITL prompt
	// ("Path" for HTTPS, "Query" for SQL, "Resource" for k8s, etc.).
	// Empty falls back to "Path".
	HITLQueryLabel() string

	// HostIsResource reports whether the request's Host field is a
	// meaningful label on its own (e.g. an HTTPS hostname like
	// `api.anthropic.com`) or merely a wire-level address (a SQL
	// virtual IP, a k8s cluster IP) that the dashboard should
	// substitute with the operator-defined endpoint name. Replaces
	// the old `Family == "https"` carve-out in HITLEndpointLabel.
	HostIsResource() bool

	// MatchKeys returns the keys a rule's match{} block may contain
	// for this facet. The loader uses these to reject typos before
	// the matcher ever sees the raw map.
	MatchKeys() []MatchKeySpec

	// NewMatcher compiles a raw match map (already validated against
	// MatchKeys) into a runtime Matcher. The returned Matcher reads
	// from match.Request — typically by type-asserting Request.Meta
	// to the facet's own Meta type, set by PrepareRequest or by the
	// protocol's wire-frame frontend.
	NewMatcher(raw map[string]any) (match.Matcher, error)

	// PrepareRequest is called by the gateway after building the
	// request snapshot and before any matcher runs. The facet
	// derives its Meta value from the request's existing fields
	// (URL, method, headers, body) and stashes it on req.Meta.
	// Implementations that don't need pre-matching derivation
	// (https, sql — sql endpoints populate Meta inline from the
	// wire frame) leave req.Meta untouched.
	PrepareRequest(req *match.Request)

	// ReportFields declares the per-family fields the facet emits
	// onto an event for logging, persistence, and dashboard
	// rendering. The names must match the keys Report returns.
	ReportFields() []ReportFieldSpec

	// Report extracts the per-family fields from a request snapshot
	// into a flat map keyed by ReportField.Name. Called once per
	// request, after the verdict is known, to populate the event's
	// per-family facets payload.
	Report(req *match.Request) map[string]any
}

// MatchValueKind tags the shape a single match-key value may take in
// HCL. The loader uses it to provide better diagnostics; downstream
// matchers are still free to coerce flexibly via match.stringList /
// match.parseGlobs as they always have.
type MatchValueKind int

const (
	// MatchString is a single bare string ("verb = \"select\"").
	MatchString MatchValueKind = iota
	// MatchStringList accepts a string or list-of-strings; used by
	// list-shaped facets like SQL `tables`.
	MatchStringList
	// MatchGlobList is a list-of-globs with optional "!" negation
	// (paths, k8s resource names).
	MatchGlobList
	// MatchStringMap is a key→value map ("query = { foo = \"bar\" }",
	// "headers = { ... }", "params = { ... }").
	MatchStringMap
	// MatchRegex is a regex pattern string (sql `statement_regex`).
	MatchRegex
	// MatchObject is a free-form nested object (http `body_json`).
	MatchObject
	// MatchCredentialRef is a bare-name reference to a credential
	// block; handled specially by the rule build path.
	MatchCredentialRef
)

// MatchKeySpec declares one valid key inside a rule's match{} body.
type MatchKeySpec struct {
	Name string
	Kind MatchValueKind
}

// ReportValueKind tags the runtime shape of a per-family report
// field so the dashboard can format consistently and so a future
// schema-driven persistence layer can choose the right column type.
type ReportValueKind int

const (
	// ReportString is a single string (method, verb, resource).
	ReportString ReportValueKind = iota
	// ReportStringList is a slice of strings (sql tables, functions).
	ReportStringList
	// ReportStringMap is a key→string map (k8s params, http headers).
	ReportStringMap
	// ReportInt is a signed integer (http status).
	ReportInt
)

// ReportFieldSpec declares one per-family reporting field. Label is
// the human-readable column header the dashboard renders; if empty,
// the dashboard falls back to Name with cosmetic title-casing.
type ReportFieldSpec struct {
	Name  string
	Kind  ReportValueKind
	Label string
}

// registry holds every facet registered at init time. The blank-
// import chain rooted at config/plugins/all/all.go pulls in every
// built-in facet package so its init() runs before main().
var registry struct {
	sync.RWMutex
	byName map[string]Runtime
}

// Register installs r in the registry. Called from each facet
// package's init(). Duplicate names panic — they always indicate a
// build-time mistake (two packages registering the same family).
func Register(r Runtime) {
	if r == nil {
		panic("facet.Register: nil Runtime")
	}
	name := r.Name()
	if name == "" {
		panic("facet.Register: empty Name")
	}
	if r.RuleType() == "" {
		panic(fmt.Sprintf("facet.Register(%s): empty RuleType", name))
	}
	registry.Lock()
	defer registry.Unlock()
	if registry.byName == nil {
		registry.byName = make(map[string]Runtime)
	}
	if _, dup := registry.byName[name]; dup {
		panic(fmt.Sprintf("facet.Register: duplicate facet %q", name))
	}
	registry.byName[name] = r
}

// Lookup returns the facet registered under name, or nil if none is.
// The rule loader uses this both to validate match-key sets and to
// compile match maps into Matchers.
func Lookup(name string) Runtime {
	registry.RLock()
	defer registry.RUnlock()
	return registry.byName[name]
}

// All returns every registered facet, sorted by Name. Stable order
// matters for golden tests and for deterministic config dumps.
func All() []Runtime {
	registry.RLock()
	defer registry.RUnlock()
	out := make([]Runtime, 0, len(registry.byName))
	for _, r := range registry.byName {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Names returns every registered facet name, sorted. Used to render
// "unknown family X — known: ..." diagnostics.
func Names() []string {
	registry.RLock()
	defer registry.RUnlock()
	out := make([]string, 0, len(registry.byName))
	for n := range registry.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// NewMatcher dispatches to the named facet's NewMatcher.
// Replaces the per-family switch in match.New. Returns an error
// when the family is unknown so the rule loader can surface a clean
// diagnostic against the user's HCL.
func NewMatcher(family string, raw map[string]any) (match.Matcher, error) {
	r := Lookup(family)
	if r == nil {
		return nil, fmt.Errorf("unknown family %q (known: %v)", family, Names())
	}
	return r.NewMatcher(raw)
}

// KnownKeys returns the match-block keys allowed for family, or nil
// when the family isn't registered. Replaces the per-family switch
// in match.KnownKeys; same contract — the rule loader feeds the
// result to its typo-check pass.
func KnownKeys(family string) []string {
	r := Lookup(family)
	if r == nil {
		return nil
	}
	specs := r.MatchKeys()
	out := make([]string, len(specs))
	for i, s := range specs {
		out[i] = s.Name
	}
	return out
}
