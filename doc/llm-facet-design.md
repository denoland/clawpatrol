# `llm` facet family + per-provider LLM endpoint plugins — design

Status: proposed. This doc is the design proposal for adding an `llm`
facet family alongside `http` / `sql` / `k8s`, and shipping three
per-provider HTTPS endpoint plugins (`anthropic`, `openai`,
`openrouter`) whose actions carry both HTTP facets and LLM facets so
existing HTTP rules keep firing and a new `llm`-family rule can match
on provider / model / stream / tokens.

The structural decision in [§3.1](#31-multi-family-per-action) is
load-bearing. Sign-off on that section before implementation lands.

---

## 1. Goal

LLM endpoint plugins should emit action events that carry **token-rich
LLM metadata** (model, input / output tokens, cache read / write
tokens) in addition to the HTTP facets they already emit. Three
coordinated changes:

1. A new facet family `llm` registered alongside the existing
   `http` / `sql` / `k8s` facets.
2. Action records that can carry **multiple** facet families on the
   same request — an LLM endpoint's action carries both `http` and
   `llm` facets, so existing HTTP rules keep matching and new LLM
   rules become matchable.
3. Three per-provider HTTPS endpoint plugins: `anthropic`, `openai`,
   `openrouter`. Each parses the response (streaming + non-streaming)
   to extract usage and populates the `llm` facet.

---

## 2. What's there today

Captured during investigation; everything below is the state of
`origin/main` at the time of writing.

- **Per-family model.** `config/match/match.go`'s `Request` carries a
  single `Family string` and a single opaque `Meta any`. Per-family
  fields (verb / tables / functions / statement for SQL; resource /
  verb / params for k8s) live in family-owned `Meta` types; the
  facet's matcher type-asserts. `Truncated bool` and the
  `InspectsTruncatableFacet()` plumbing fails closed on rules that
  read body bytes that didn't fit the inspection cap.

- **Rule binding.** `config/plugins/rules/rules.go` registers a
  single `rule` block. Family is **inferred** from each rule's
  resolved endpoint set; mixed-family endpoint sets are rejected at
  validate time. A rule's CEL condition is compiled against the
  facet's `*cel.Env`, so each rule sees exactly one family's
  variables (`http.*` or `sql.*` or `k8s.*`).

- **Facet registry.** `config/facet/facet.go` exposes a `Runtime`
  contract: `Name()`, `EndpointFamilies()`, `Transport()`,
  `NewMatcher(condition)`, `PrepareRequest(req)`, plus the reporting
  pair `ReportFields()` / `Report(req)`. The HTTPS-MITM dispatcher in
  `main.go` looks up the endpoint's family in the registry, calls
  `PrepareRequest`, populates `Event.Family` and `Event.Facets`, then
  matches against rules.

- **HTTPS endpoint plugins.** `config/plugins/endpoints/https.go` is
  the canonical baseline (hosts + credential plumbing only). Two
  HTTPS-shaped variants already exist:
  - `kubernetes` — k8s family, owns server / ca_cert decoration.
  - `openai_codex_https` — http family, ships a synthetic Agent
    Identity JWT pushdown plus a synthetic responder for the JWKS
    and per-task registration POST so codex's chatgpt.com flow runs
    against clawpatrol-controlled state.

- **Existing LLM tracking (out of band).** `main.go` already has a
  parallel observability path:
  `trackKindFor(host)` → `preCreateLLMSession` (request body, seeds
  session row) → `trackLLMUsage` (response body, fills token counts)
  → `g.agents.recordLLMUsage`. It runs alongside the policy
  dispatcher but doesn't feed `Event.Facets`, doesn't show up on the
  action record, isn't matchable by policy. The provider parsers
  (`parseClaudeRequest`, `parseClaudeResponse`, `parseOpenAIResponse`,
  `codexResponsesRequestTitle`) already cover Anthropic +
  OpenAI-shaped streaming and non-streaming usage; the new facet
  reuses those parsers rather than rewriting them.

- **Event shape.** `web.go`'s `Event` already supports two-phase
  emission: `Phase = "start"` is emitted at request open (HTTP facets
  + endpoint + rule populated, no response data) and `Phase = "end"`
  is emitted after `resp.Write` completes (status, response sample,
  duration). LLM facets land naturally on the end event because the
  current `trackBuf` parse already happens between response write and
  `emitEnd`.

---

## 3. Open design questions

### 3.1 Multi-family-per-action

**Three shapes the bead lays out:**

a. `Families []string` (a *set* of families on the request) plus per-
   family `Meta` slots. Each facet has first-class status; rule
   dispatch walks every rule whose family is in the set.
b. Primary family + auxiliary facets bag.
c. Type-assertion / bitmask over a `MultiFacetRequest` interface.

**Proposal: take option (a), shaped concretely as:**

1. Add `Metas map[string]any` to `match.Request` (or, equivalently, a
   per-family struct holding `HTTP`, `SQL`, `K8s`, `LLM` pointer
   fields — same effect, less reflection). The existing `Meta any`
   field is removed; every site that reads `req.Meta.(*sql.Meta)`
   becomes `req.Metas["sql"].(*sql.Meta)`. The change is mechanical
   and contained — three call sites total (sql facet matcher, k8s
   facet matcher, postgres/clickhouse runtimes that *set* Meta).
2. Drop the single `Family string` field. Replace with the same set
   of family slots — presence of a slot ≡ membership in the family
   set. (Equivalent option: keep `Family` for the *primary* protocol
   family, used for dashboard column selection and HITL labelling,
   and treat the slot-presence set as the matcher set.)
3. Endpoint plugins gain an optional `ExtraFamilies []string` field
   on `config.Plugin`. The `anthropic` / `openai` / `openrouter`
   plugins set `Family = "http"` and `ExtraFamilies = []string{"llm"}`.
   The `https`, `kubernetes`, postgres, clickhouse endpoints keep
   `ExtraFamilies` empty.
4. `rules.go` family inference walks `Family ∪ ExtraFamilies` per
   endpoint and intersects across the rule's endpoint set. A rule
   whose endpoints all support family `X` is family-`X`. Ambiguity
   (a rule attached only to LLM-bearing endpoints could be either
   `http` or `llm`) is resolved by an explicit `family = "llm"`
   attribute on the rule. Rules without `family` default to the
   primary `Family` of the endpoint (so the existing fleet of HTTP
   rules attached to a future `anthropic` endpoint continues to read
   as HTTP without edits).
5. `MatchRequest` is unchanged: each rule's matcher already type-
   asserts against its own meta slot, so a rule whose family isn't
   represented on the request will return `false` cleanly. (We could
   add an early continue keyed on rule family ∉ request families set
   as a perf optim, but it's not correctness-load-bearing.)

**Why (a) over (b) / (c).** `llm_rule` gets first-class status, the
CEL env stays per-family (single variable per facet — `http`, `sql`,
`k8s`, `llm`), no special-cased aux bag, no reflection-heavy
type-assertion dispatch. The cost is a single field rename
(`Meta any` → `Metas map[string]any`) touching ~6 sites.

**Rejected: option (b)** would keep `Family string` singular and
hide LLM facets behind `AuxFacets map[string]any`. That makes LLM
rules second-class — their CEL would have to read from a generic
map instead of the typed `llm.*` variable, and the rule plugin would
need a special case for them. Not worth it.

**Rejected: option (c)** is an over-engineered variant of (a). Same
end state, more reflection.

### 3.2 When LLM facets land on the action

Two options:

- **Two-phase emission.** Emit start with HTTP facets only, then
  emit end (or a synthetic update) with HTTP **plus** LLM facets.
- **Single emission post-stream.** Wait until the response completes
  before emitting anything. Loses in-flight visibility.

**Proposal: two-phase, riding the existing `Phase = "start"` →
`Phase = "end"` channel.** The dashboard SSE protocol already
correlates start/end events by `ID`. The current MITM handler
collects the streamed response into `trackBuf` and reads it
*before* `emitEnd` — that's exactly where the LLM facet's response
parser runs and populates the LLM-family slot on `Event.Facets`.
The start event carries HTTP facets only; the end event carries
HTTP + LLM. No new `Phase` value is needed.

This matches the existing `parseClaudeResponse` /
`parseOpenAIResponse` runtime model and means the dashboard's
request detail page renders LLM facets on the end-of-row state
without any new SSE protocol concept.

### 3.3 Pre-flight vs post-flight rule semantics

`http_rule` matches **pre-flight**. The LLM-family fields split:

- **Pre-flight matchable** (extractable from the request body before
  forwarding): `model`, `provider`, `stream`.
- **Post-flight only** (need the response): `input_tokens`,
  `output_tokens`, `cache_read_tokens`, `cache_write_tokens`,
  `stop_reason`.

**Proposal: v1 supports pre-flight LLM facets only.** Per the bead:

- The `llm` CEL env exposes only pre-flight fields (`llm.model`,
  `llm.provider`, `llm.stream`). Rule conditions that read a post-
  flight field fail at compile time with "unknown field".
- Post-flight token counts are emitted on the action via
  `Report(req)` for visibility / dashboard rendering, but **not**
  reachable from CEL.
- v2 adds post-flight CEL fields plus a streaming-cancellation hook
  for providers that support it (Anthropic streaming can be
  cancelled mid-flight). Out of scope for v1 — documented in §5.

Pre-flight model gates (`llm.model.matches("^claude-opus-")`,
`llm.model == "gpt-5"`) cover the common case operators care about
("don't let codex use opus-class models"). Token-budget gating waits
for the identity layer (cl-6hk) anyway, so blocking post-flight
rules on v2 doesn't move the budget-enforcement timeline.

### 3.4 Per-provider plugin scope

Each of `anthropic` / `openai` / `openrouter` is HTTPS underneath.
Three shapes:

- Sibling plugins (each a top-level endpoint type alongside `https`).
- Subtype of `https` that delegates to an embedded HTTPSEndpoint.
- A single `llm_endpoint` plugin parameterized by provider name.

**Proposal: sibling plugins.** Matches the existing
`openai_codex_https` precedent (sibling of `https`, with its own
`Runtime` for synthetic JWKS responses and `EnvVars` for codex JWT
pushdown). Each provider plugin reuses the placeholder-detection
behaviour of `HTTPSEndpointRuntime` (cred placeholder in
`Authorization` header) by either embedding it or shipping an
identical method.

The actual provider-specific work — parsing the response stream for
usage — lives behind a new optional interface on the endpoint
plugin's `Runtime`:

```go
// In config/runtime, alongside PlaceholderDetector / HTTPSyntheticResponder:
type LLMResponseParser interface {
    ParseLLMResponse(reqBody, respBody []byte) llm.Meta
}
```

The MITM dispatcher (`main.go`) type-asserts `ep.Plugin.Runtime` for
this interface (in the same pattern as `HTTPSyntheticResponder`) and,
when present, calls it with the collected request + response bytes
between `trackBuf` extraction and `emitEnd`. The parser populates the
`llm` slot in `req.Metas` and the `Event.Facets["llm"]` map.

The default `Hosts` for each plugin:
- `anthropic` → `["api.anthropic.com"]`
- `openai` → `["api.openai.com"]`
- `openrouter` → `["openrouter.ai"]`

Hosts can still be overridden in HCL; defaults exist so the common
case is one-line:

```hcl
endpoint "anthropic" "claude" {
  credential = anthropic
}
```

### 3.4.1 Naming: `codex` vs `openai`

The bead names the OpenAI plugin `codex` but flags that the broader
scope (OpenAI's responses/completions API, which also serves the
OpenAI Codex CLI, gh Copilot, and custom OpenAI clients) is the
defensible choice.

**Proposal: name it `openai`, not `codex`.** Reasoning:

- `codex` already exists as `openai_codex_https`, scoped to the
  *chatgpt.com* path that codex CLI uses under subscription auth.
  Reusing the name for a *different* provider scope (api.openai.com)
  would be confusing.
- The new plugin's host is `api.openai.com` — naming it `openai`
  matches the host and the credential family.
- The existing `openai_codex_https` plugin stays as-is for the
  chatgpt.com subscription flow. It can grow `LLMResponseParser`
  later for consistency.

If reviewers prefer `codex` to honour the bead's literal text, the
plugin file/type name is a one-line change.

### 3.5 Facet shape for tokens (numeric vs bucketed)

Today's facets are string-typed (`sql.verb == "select"`,
`http.method == "post"`). Token counts are integers.

**Proposal: numeric.** Two reasons:

- CEL natively supports numeric comparisons and arithmetic
  (`llm.input_tokens > 10000`). No matcher refactor needed.
- The reporting layer already has `facet.ReportInt` (the HTTPS facet
  reports `status` as an int), so the dashboard rendering pathway
  already knows how to handle ints.

The bucket option (`tokens = "10k+"`) loses precision and is no
simpler when CEL handles ints directly.

(This decision only matters for the *v2* CEL exposure of token
fields — v1 doesn't expose them in CEL at all per §3.3 — but the
reporting / dashboard path uses the numeric shape from day one.)

### 3.6 Model facet

`llm.model` is a plain string (`"claude-opus-4-7"`,
`"anthropic/claude-3-5-sonnet-20240620"` for OpenRouter). Glob match
uses CEL's `.matches(regex)` for prefix patterns and `==` for exact.

No special-cased glob — operators write either:

```
llm.model == "claude-opus-4-7-20251001"
llm.model.matches("^claude-opus-")
```

OpenRouter's `provider/model` shape works as-is — the matcher
operates on the raw string.

### 3.7 Cost facet

**Out of scope for v1**, per the bead. Per-provider pricing tables
are maintenance-heavy and pricing changes more often than the
gateway ships. Documented as a v2 follow-up.

### 3.8 Cache-token facets

Anthropic distinguishes `cache_creation_input_tokens` (write, 1.25×
list price) from `cache_read_input_tokens` (read, 0.1× list price).
OpenAI exposes a read-only `cached_tokens` field via
`prompt_tokens_details`. OpenRouter is OpenAI-compatible.

**Proposal:** expose both on `LLMMeta` and on the action's `llm`
report payload, using provider-neutral names:

- `cache_read_tokens` — populated by both Anthropic and OpenAI.
- `cache_write_tokens` — Anthropic only. Stays zero for providers
  that don't surface a write-vs-read split.

In v1 neither is matchable from CEL (per §3.3) — they only appear
in `Report`.

---

## 4. Data shapes

### 4.1 `LLMMeta`

Lives in `config/plugins/facets/llm/llm.go`:

```go
type Meta struct {
    Provider         string // "anthropic" | "openai" | "openrouter"
    Model            string
    Stream           bool   // request had stream:true
    InputTokens      int64
    OutputTokens     int64
    CacheReadTokens  int64
    CacheWriteTokens int64
    StopReason       string // "end_turn" | "max_tokens" | "stop_sequence" | "tool_use" | provider-specific
}

type LLMFields struct { // CEL-facing, v1 fields only
    Provider string `cel:"provider"`
    Model    string `cel:"model"`
    Stream   bool   `cel:"stream"`
}
```

### 4.2 `ReportFields`

```go
func (Facet) ReportFields() []facet.ReportFieldSpec {
    return []facet.ReportFieldSpec{
        {Name: "provider",           Kind: facet.ReportString, Label: "Provider"},
        {Name: "model",              Kind: facet.ReportString, Label: "Model"},
        {Name: "stream",             Kind: facet.ReportString, Label: "Stream"},
        {Name: "input_tokens",       Kind: facet.ReportInt,    Label: "Input tokens"},
        {Name: "output_tokens",      Kind: facet.ReportInt,    Label: "Output tokens"},
        {Name: "cache_read_tokens",  Kind: facet.ReportInt,    Label: "Cache read tokens"},
        {Name: "cache_write_tokens", Kind: facet.ReportInt,    Label: "Cache write tokens"},
        {Name: "stop_reason",        Kind: facet.ReportString, Label: "Stop reason"},
    }
}
```

### 4.3 Endpoint plugin runtime interface

In `config/runtime/runtime.go` or a new file alongside
`PlaceholderDetector`:

```go
type LLMResponseParser interface {
    // ParseLLMResponse returns the populated llm.Meta extracted from
    // a single request/response pair. Streaming responses arrive as
    // the concatenated SSE byte stream the gateway captured into
    // trackBuf; non-streaming responses arrive as the full JSON body.
    // Implementations distinguish based on bytes, content-type, or
    // body shape — they own that detail.
    ParseLLMResponse(reqBody, respBody []byte) *llm.Meta
}
```

Each provider plugin's `Runtime` implements this. The MITM
dispatcher calls it once per request between response-write and
end-event emission.

---

## 5. Out of scope (v1)

Tracked for v2:

- **Post-flight `llm_rule` matching.** v2 widens the CEL env to
  expose token / stop_reason fields and adds a streaming-
  cancellation hook for providers that support cancellation
  (Anthropic streaming, OpenAI Responses API). Until then post-
  flight fields are emit-only.
- **Cost / pricing facets.** Per-provider pricing tables maintained
  separately.
- **Token-budget enforcement** (per-credential / per-user daily
  caps). Depends on the identity layer (cl-6hk) and on post-flight
  matching from above.
- **Provider extras**: Anthropic tools, OpenAI logprobs, Gemini
  citations. v2 (and individual additions per plugin).
- **Other providers**: Gemini, Mistral, Bedrock direct.

## 6. Acceptance criteria (re-stated from the bead)

- An action passing through an `anthropic` / `openai` / `openrouter`
  endpoint shows both HTTP facets *and* LLM facets on the dashboard
  request detail page.
- LLM facets include at minimum: provider, model, input tokens,
  output tokens, cache read tokens, cache write tokens, stop reason.
- A rule with `family = "llm"` and `condition = "llm.model.matches(...)"`
  correctly matches / denies pre-flight against an LLM endpoint.
- Existing HTTP rules attached to the same endpoint continue to fire
  correctly (multi-family compatibility).
- The PR description names the design decisions for each Phase 2
  question, especially §3.1.

---

## 7. Review focus

The structural decision in §3.1 is **load-bearing** — every other
section assumes the multi-family-per-action shape it picks. Please
sign off on §3.1 explicitly before Phase 3 commits land.

Secondary points worth explicit thumbs-up:

- §3.4.1 (`openai` vs `codex` naming)
- §3.3 (pre-flight-only v1 — confirming that token-budget
  enforcement waits for v2 is fine).
