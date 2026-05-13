# `llm` facet family + per-provider LLM endpoint plugins — design

Status: signed off. This doc is the agreed design for adding an
`llm` facet family alongside `http` / `sql` / `k8s`, and shipping
two new per-provider HTTPS endpoint plugins (`anthropic`,
`openrouter`) plus extending the existing `openai_codex_https`
plugin with LLM-family support. Actions carry both HTTP facets and
LLM facets so existing HTTP rules keep firing and a new `llm`-
family rule can match on provider / model / stream / tokens.

Sign-off notes from the reviewer (PR #305 comment):

- §3.1 multi-family shape: the request and the endpoint plugin
  carry a single `families []string` set — no separate primary
  `Family` + auxiliary `ExtraFamilies` split.
- §3.4 per-provider plugins: do **not** ship a separate `openai`
  plugin. Extend the existing `openai_codex_https` plugin so its
  action carries both HTTP and LLM facets.
- All other §3 design points are green-lit and implementation
  proceeds as proposed.

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
3. Per-provider HTTPS endpoint coverage: two new plugins
   (`anthropic`, `openrouter`) plus an LLM-family extension of the
   existing `openai_codex_https` plugin. Each parses the response
   (streaming + non-streaming) to extract usage and populates the
   `llm` facet.

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

1. Replace `Meta any` on `match.Request` with
   `Metas map[string]any`. Every site that reads
   `req.Meta.(*sql.Meta)` becomes `req.Metas["sql"].(*sql.Meta)`;
   every site that sets `req.Meta = m` becomes
   `req.Metas["sql"] = m`. The change is mechanical and contained.
2. Replace `Family string` on `match.Request` with
   `Families []string`. Presence in the set ≡ that family carries
   metadata on the request. The HTTP-shaped fields (Method, URL,
   Headers, Body) stay common-shared regardless of whether the
   request is HTTP-only, LLM-bearing, or pure SQL.
3. Replace `Family string` on `config.Plugin` with
   `Families []string`. The `https`, `kubernetes`, `postgres`,
   `clickhouse_native`, `clickhouse_https` endpoints declare a
   single family in the slice. The `anthropic` / `openrouter`
   plugins and the existing `openai_codex_https` plugin declare
   `Families = []string{"http", "llm"}`. Endpoints that today
   register `Family = "http"` migrate to
   `Families = []string{"http"}` mechanically.
4. `rules.go` family inference walks each endpoint's `Families`
   and intersects across the rule's endpoint set. A rule whose
   endpoints all support family `X` is family-`X`. Ambiguity (a
   rule attached only to LLM-bearing endpoints could match `http`
   or `llm`) is resolved by an explicit `family = "llm"` attribute
   on the rule. Rules without `family` resolve to the unique
   common family across the endpoint set; if more than one is
   common and the rule omits `family`, validation rejects the
   config with a diagnostic naming the candidate families.
5. `MatchRequest` is unchanged: each rule's matcher already type-
   asserts against its own meta slot, so a rule whose family isn't
   represented on the request will return `false` cleanly. (An
   early-continue keyed on rule family ∉ request `Families` is an
   optional perf optim, not correctness-load-bearing.)

**Why (a) over (b) / (c).** `llm_rule` gets first-class status, the
CEL env stays per-family (single variable per facet — `http`, `sql`,
`k8s`, `llm`), no special-cased aux bag, no reflection-heavy type-
assertion dispatch. The cost is one field rename per side:
`Meta any` → `Metas map[string]any` and `Family string` →
`Families []string`, touching ~6 sites total.

**Naming note** (from the reviewer): a single `families` slice is
preferred over a primary-`Family` + auxiliary-`ExtraFamilies` split.
Both modelled the same set; the single-slice form keeps endpoint
plugins, the request snapshot, and the rule-family resolver
symmetrical and removes one degree of freedom.

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

Each LLM-bearing endpoint is HTTPS underneath. Three plugin shapes
were on the table:

- Sibling plugins (each a top-level endpoint type alongside `https`).
- Subtype of `https` that delegates to an embedded HTTPSEndpoint.
- A single `llm_endpoint` plugin parameterized by provider name.

**Proposal: sibling plugins, scoped to two new types
(`anthropic`, `openrouter`), plus an LLM-family extension to the
existing `openai_codex_https` plugin.** Matches the existing
`openai_codex_https` precedent (sibling of `https`, with its own
`Runtime` for synthetic JWKS responses and `EnvVars` for codex JWT
pushdown). Each new plugin reuses the placeholder-detection
behaviour of `HTTPSEndpointRuntime` (cred placeholder in
`Authorization` header) by either embedding it or shipping an
identical method.

The actual provider-specific work — parsing the response stream for
usage — lives behind a new optional interface on the endpoint
plugin's `Runtime`:

```go
// In config/runtime, alongside PlaceholderDetector / HTTPSyntheticResponder:
type LLMResponseParser interface {
    ParseLLMResponse(reqBody, respBody []byte) *llm.Meta
}
```

The MITM dispatcher (`main.go`) type-asserts `ep.Plugin.Runtime` for
this interface (in the same pattern as `HTTPSyntheticResponder`) and,
when present, calls it with the collected request + response bytes
between `trackBuf` extraction and `emitEnd`. The parser populates the
`llm` slot in `req.Metas` and the `Event.Facets["llm"]` map.

The default `Hosts` for each LLM-bearing plugin:
- `anthropic` → `["api.anthropic.com"]`
- `openai_codex_https` (existing) → keeps its current hosts
  (`chatgpt.com` + the codex backchannel) and additionally declares
  `Families = ["http", "llm"]` so its actions carry an `llm` slot.
- `openrouter` → `["openrouter.ai"]`

Hosts can still be overridden in HCL; defaults exist so the common
case is one-line:

```hcl
endpoint "anthropic" "claude" {
  credential = anthropic
}
```

### 3.4.1 No separate `openai` plugin

The bead originally named an `openai` plugin distinct from the
existing `openai_codex_https`. Per reviewer feedback, the OpenAI-
shaped provider work happens **inside** `openai_codex_https` rather
than in a new sibling plugin:

- `openai_codex_https` keeps its current scope (codex CLI flow
  against chatgpt.com with synthetic Agent Identity JWT pushdown)
  and additionally implements `LLMResponseParser` for the OpenAI
  responses/completions schema.
- Its `config.Plugin` registration declares
  `Families = []string{"http", "llm"}`. Actions through this
  endpoint carry both an `http` and an `llm` facet.
- No new `openai` plugin file/type is added.

If a future need arises to cover non-codex OpenAI traffic
(`api.openai.com` direct calls outside the codex subscription flow),
extending the `openai_codex_https` hosts list — or shipping a
narrower second plugin then — stays open. v1 does not introduce
that surface.

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

- An action passing through an `anthropic` / `openai_codex_https` /
  `openrouter` endpoint shows both HTTP facets *and* LLM facets on
  the dashboard request detail page.
- LLM facets include at minimum: provider, model, input tokens,
  output tokens, cache read tokens, cache write tokens, stop reason.
- A rule with `family = "llm"` and `condition = "llm.model.matches(...)"`
  correctly matches / denies pre-flight against an LLM endpoint.
- Existing HTTP rules attached to the same endpoint continue to fire
  correctly (multi-family compatibility).
- The PR description names the design decisions for each Phase 2
  question, especially §3.1.

---

## 7. Review status

Sign-off received on PR #305:

- §3.1 multi-family shape — approved with the single-`families`
  slice form (no `Family` + `ExtraFamilies` split).
- §3.4 per-provider scope — approved with the change that
  `openai_codex_https` is extended in-place rather than shipping a
  sibling `openai` plugin.
- §3.3 (pre-flight-only v1) and all other §3 points — green-lit
  as proposed.

Phase 3 implementation proceeds against this signed-off design.
