# Tool-call gating (draft)

Rules applied to a model's `tool_use` blocks before the agent ever
sees them. Three verdicts — allow, deny, human-in-the-loop (HITL) —
drive the gateway to rewrite the upstream LLM response. The
implementation lives in `internal/toolgate`; the MITM hook glue is in
`cmd/clawpatrol/toolgate.go`.

This is the exploratory draft (bead cl-umxf, PR #489). It handles
Anthropic `/v1/messages` in both response shapes: buffered JSON
(`GateAnthropicResponse`) and streaming SSE (`stream: true`,
`GateAnthropicSSE`). Most real agents stream, so the streaming path is
what makes the gate fire against typical traffic.

## Streaming (SSE)

Anthropic streams a `tool_use` incrementally — `content_block_start`
(id + name, `input: {}` placeholder) → N× `content_block_delta`
(`input_json_delta` fragments) → `content_block_stop`, with
`stop_reason` arriving later in `message_delta`. The verdict needs the
*complete* input, which isn't known until `content_block_stop`.

The implementation (`anthropic_sse.go`) uses **per-block buffering**:

- Non-`tool_use` frames (`message_start`, text blocks, `ping`, usage)
  stream straight through, preserving time-to-first-token.
- A `tool_use` block's frames are **held** from `content_block_start`
  until `content_block_stop`, accumulating the `input_json_delta`
  fragments. At stop the full input is known and the rule set runs:
  - **allow / unmatched** — held frames replayed verbatim (the stream
    is byte-identical to upstream, interleaved pings included).
  - **deny** — held frames dropped; a synthesised `text` block carries
    the reason at the same content index.
  - **hitl** — held frames dropped; the call is parked and a
    gateway-initiated follow-up LLM call picks a polling tool from the
    agent's own tools; that choice is emitted at the same index (see
    "Gateway-initiated polling-tool choice" below).
- `stop_reason` in the trailing `message_delta` is rewritten
  `tool_use` → `end_turn` iff no `tool_use` survives (every one was
  denied/blocked), matching the JSON path.

**Fail closed.** Unlike the JSON path — which forwards the original
body on a parse error so a gating bug can't brick a legitimate non-tool
turn — the streaming gate never forwards a `tool_use` it could not
evaluate. An unparseable `content_block_start`, a malformed delta on a
held block, an input past the 8 MB cap, or a stream truncated mid-block
all resolve to the call being **blocked** (replaced with a refusal text
block) or the stream **terminated** — never the raw tool call reaching
the agent. A held `tool_use` is emitted only after a clean *allow*.

## Verdicts and rewrites

- **allow / unmatched** — response forwarded untouched.
- **deny** — the `tool_use` block is replaced with a `text` block
  carrying the refusal reason, and `stop_reason` is flipped to
  `end_turn`. The model sees why it can't proceed and finishes the
  turn cleanly. (The alternative — synthesising a `tool_result` the
  model reads on its next turn — is deferred to v2; see "deny shape"
  below.)
- **hitl** — the `tool_use` is parked (keyed by an opaque token in the
  in-process `Store`), and the gateway runs a follow-up LLM call so the
  model picks a polling tool from the agent's *own* advertised tools.
  That choice is forwarded to the agent, which executes it to poll
  clawpatrol's approval endpoint. Once an operator decides in the
  dashboard, the long-poll wakes and returns the verdict to the agent.
  See the next section.

## Gateway-initiated polling-tool choice

The polling tool the agent calls **must be a tool the agent already
has** — its dispatcher is built from the tools *it* registered, so a
tool clawpatrol invents (the earlier draft's `clawpatrol_poll`) has no
handler and can never execute. Injecting the tool *definition* into the
request's `tools[]` wouldn't help either: dispatch is agent-local.

So the gateway lets the model choose, acting as one iteration of the
agent loop (`internal/toolgate/followup.go`):

1. Take the upstream assistant response and **remove the parked
   `tool_use`** from it (keeping any text rationale).
2. **Fabricate a user message** instructing the model to poll
   clawpatrol's approval endpoint (`POST <base>/api/approval/poll`,
   body `{"token": …}`), choosing the right tool from its own `tools[]`.
3. Make clawpatrol's **own upstream `/v1/messages` call** — reusing the
   agent's credentials and tool set (`stream: false`).
4. **Forward the follow-up response** to the agent. It names a tool the
   agent actually has, so the agent executes it and polls.

The package stays transport-agnostic: an `LLMCaller` callback (supplied
by `cmd/clawpatrol`) hides the MITM transport + credential machinery, so
the dance is unit-testable with a fake caller. The follow-up reuses the
already-credential-injected request (Anthropic uses header injection,
not body signing, so swapping the body is safe) and never re-enters the
MITM handler, so it is not itself re-gated.

**Fallback.** If the follow-up is unavailable (no caller wired, or the
original request body was too large to buffer for a faithful rebuild) or
the follow-up call fails, the HITL path degrades to a coherent "approval
pending" text block. The parked tool call is dropped either way, so the
raw call never reaches the agent.

**Configuration.** `CLAWPATROL_TOOLGATE_APPROVAL_URL` sets the base URL
the polling instruction targets (`<base>/api/approval/poll`); it must
point at clawpatrol's agent-reachable address. Unset uses a placeholder
default that will not connect.

**Known limitations (draft).** N=1 tool_use per turn is the supported
shape: when a turn mixes a HITL `tool_use` with allow/deny siblings, the
follow-up replaces the whole assistant turn and the siblings are not
independently forwarded. Each HITL block in a multi-tool stream triggers
its own follow-up call. The follow-up's chosen tool is not itself
re-gated.

The SSE (`GET /api/approval/sse`) and WS (`GET /api/approval/ws`)
endpoints are wired but degrade: SSE emits a single pending-then-
verdict event; WS returns `501` with a fallback pointer at the
long-poll path.

## Deny shape: text block vs. tool_result

Deny replaces the `tool_use` with a `text` block rather than
synthesising a `tool_result`. The text-block path is simpler: the
agent's next turn doesn't have to round-trip a fabricated result, and
`stop_reason: end_turn` ends the turn without a dangling tool call.

Round-trip preservation (the model continuing as if it received a real
`tool_result`) is the v2 alternative. It matters when an operator
wants the model to *retry* after a deny rather than stop; for that,
configure the rule as HITL instead.

## Configuration

Rules are loaded from `CLAWPATROL_TOOLGATE_RULES`, a JSON array of
`{name, tool_name, args_contains, verdict, reason}`. Empty or unset
means gating is a no-op. This env var is the draft's stand-in; the
production intent is to fold rules into the gateway HCL config via
cl-1yh's `llm_rule` plugin once that lands on `main`.

## v2 follow-ups

- Independent handling of allow/deny siblings in a HITL turn (N>1).
- Re-gate (or explicitly trust) the follow-up's chosen polling tool.
- Synth-`tool_result` deny path for round-trip preservation.
- Per-provider parsers (OpenAI/Codex/OpenRouter).
- Wire `toolgate.Rule` to cl-1yh's `llm_rule` HCL plugin.
- Dashboard UI for the approval queue.
