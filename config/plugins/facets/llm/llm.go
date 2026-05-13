// Package llm is the LLM protocol-family facet. It rides alongside
// the http facet on per-provider endpoints (`anthropic`, `openrouter`,
// `openai_codex_https`) so a single action carries both HTTP fields
// (method / path / status) and LLM fields (provider / model / token
// counts).
//
// The facet exposes a narrow CEL surface in v1 — only the request-
// extractable fields (provider / model / stream) are reachable from
// rule conditions; token counts and stop_reason ship in the Report
// payload for dashboard visibility but aren't matchable yet. v2 will
// widen the CEL env to expose post-flight fields plus a streaming-
// cancellation hook.
//
// The provider endpoint plugin populates req.Metas["llm"] with a
// *Meta in two phases: provider / model / stream from the request
// body before forwarding, and the token counts / stop_reason after
// the response stream completes. The HTTPS MITM dispatcher calls the
// endpoint plugin's optional LLMResponseParser between trackBuf
// extraction and emitEnd so the end-event carries the token-rich
// facets the dashboard renders.
package llm

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/match"
)

// Meta carries the per-request LLM fields the matcher reads. Provider
// endpoint plugins build one of these from the request body and the
// (streamed or non-streamed) response body and assign it via
// req.SetMeta("llm", …).
//
// Pre-flight fields (Provider / Model / Stream) are populated before
// the request forwards upstream. Post-flight fields (token counts /
// StopReason) populate after the response completes. The facet's
// Report emits every field; the CEL env intentionally hides post-
// flight fields in v1 so a rule that references them fails at
// compile time instead of pretending to match on bytes that haven't
// arrived yet.
type Meta struct {
	Provider         string // "anthropic" | "openai" | "openrouter"
	Model            string // e.g. "claude-opus-4-7" or "anthropic/claude-3-5-sonnet"
	Stream           bool   // request had stream:true
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	StopReason       string // "end_turn" / "stop_sequence" / "tool_use" / provider-specific
}

// LLMFields is the CEL-facing view exposed to rule conditions. Only
// the pre-flight subset lands here in v1; v2 widens.
type LLMFields struct {
	Provider string `cel:"provider"`
	Model    string `cel:"model"`
	Stream   bool   `cel:"stream"`
}

// Facet is the LLM facet Runtime. Singleton; held by the registry.
type Facet struct{}

// Name reports the family identifier this facet handles.
func (Facet) Name() string { return "llm" }

// EndpointFamilies enumerates the endpoint families an llm rule may
// attach to. LLM-bearing endpoints declare Families ["http", "llm"]
// (the wire is HTTPS); a bare llm-only endpoint would also be
// allowed.
func (Facet) EndpointFamilies() []string { return []string{"llm"} }

// Transport returns "" because llm-family endpoints share the
// HTTPS-MITM dispatch path with their http facet — the underlying
// wire is TLS-wrapped HTTP. The "http" facet's Transport() of
// "https-mitm" handles routing; the llm facet is reporting-only at
// the dispatch layer.
func (Facet) Transport() string { return "" }

// HITLQueryLabel is the dashboard / Slack label for an LLM call.
// Reuses "Path" since the underlying request is HTTP — the
// dashboard renders the LLM-specific fields (model / tokens) in the
// per-facet report block, not the HITL prompt body.
func (Facet) HITLQueryLabel() string { return "Path" }

// HostIsResource reports that an LLM endpoint's Host is the
// provider's API surface (api.anthropic.com etc.) and meaningful on
// its own.
func (Facet) HostIsResource() bool { return true }

// ReportFields declares the per-family columns the LLM facet emits.
// Token fields are ints (CEL natively supports comparison /
// arithmetic) per the design doc §3.5. Cache write tokens stay zero
// for providers that don't surface a write/read split.
func (Facet) ReportFields() []facet.ReportFieldSpec {
	return []facet.ReportFieldSpec{
		{Name: "provider", Kind: facet.ReportString, Label: "Provider"},
		{Name: "model", Kind: facet.ReportString, Label: "Model"},
		{Name: "stream", Kind: facet.ReportString, Label: "Stream"},
		{Name: "input_tokens", Kind: facet.ReportInt, Label: "Input tokens"},
		{Name: "output_tokens", Kind: facet.ReportInt, Label: "Output tokens"},
		{Name: "cache_read_tokens", Kind: facet.ReportInt, Label: "Cache read tokens"},
		{Name: "cache_write_tokens", Kind: facet.ReportInt, Label: "Cache write tokens"},
		{Name: "stop_reason", Kind: facet.ReportString, Label: "Stop reason"},
	}
}

// PrepareRequest is a no-op: the provider endpoint plugin populates
// req.Metas["llm"] from the parsed request body (and, post-stream,
// from the response body via LLMResponseParser). The facet itself
// owns no derivation step beyond the CEL surface and Report.
func (Facet) PrepareRequest(*match.Request) {}

// Report extracts the LLM report fields from a request. Token counts
// land on the action even though they're not CEL-matchable in v1 —
// the dashboard renders them in the request detail page so operators
// can audit usage without round-tripping through the legacy /api/llm
// path.
func (Facet) Report(req *match.Request) map[string]any {
	m, _ := req.Meta("llm").(*Meta)
	if m == nil {
		return nil
	}
	streamStr := "false"
	if m.Stream {
		streamStr = "true"
	}
	return map[string]any{
		"provider":           m.Provider,
		"model":              m.Model,
		"stream":             streamStr,
		"input_tokens":       m.InputTokens,
		"output_tokens":      m.OutputTokens,
		"cache_read_tokens":  m.CacheReadTokens,
		"cache_write_tokens": m.CacheWriteTokens,
		"stop_reason":        m.StopReason,
	}
}

// celEnv is the LLM CEL environment. Built once at init.
var celEnv *cel.Env

func init() {
	env, err := cel.NewEnv(
		ext.Sets(),
		ext.NativeTypes(
			reflect.TypeFor[LLMFields](),
			ext.ParseStructTags(true),
		),
		cel.Variable("llm", cel.ObjectType("llm.LLMFields")),
	)
	if err != nil {
		panic(fmt.Sprintf("llm facet: cel env: %v", err))
	}
	celEnv = env

	facet.Register(Facet{})
}

// LLM facets read no truncatable bytes: provider / model / stream are
// extracted from the request body the gateway already buffered (and
// the truncation gate on the http facet covers body overflow), and
// token / stop_reason fields aren't reachable from CEL in v1.
var truncatablePaths []string

// NewMatcher compiles a CEL condition into a Matcher. An empty
// condition is the catch-all match-everything case.
func (Facet) NewMatcher(condition string) (match.Matcher, error) {
	if condition == "" {
		return match.PassThrough{}, nil
	}
	return match.CompileCondition(celEnv, condition, buildActivation, nil, truncatablePaths)
}

func buildActivation(req *match.Request) map[string]any {
	if req == nil {
		return nil
	}
	meta, _ := req.Meta("llm").(*Meta)
	if meta == nil {
		return nil
	}
	return map[string]any{
		"llm": &LLMFields{
			Provider: meta.Provider,
			Model:    meta.Model,
			Stream:   meta.Stream,
		},
	}
}
