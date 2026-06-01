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
    `clawpatrol_poll` `tool_use` block is synthesised at the same index.
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
- **hitl** — the `tool_use` is swapped for a polling `tool_use` that
  the agent executes against clawpatrol's own approval endpoint. A
  pending entry, keyed by an opaque token, is parked in the in-process
  `Store`. Once an operator decides in the dashboard, the long-poll
  wakes and returns the verdict to the agent.

## Why long-poll only

`PollingToolName` (`anthropic.go`) is injected unconditionally as a
long-poll HTTP tool (`clawpatrol_poll` → `POST /api/approval/poll`).

The spec calls for clawpatrol to pick the polling shape (long-poll,
SSE, or WebSocket) from the tools the agent actually advertises. The
draft does not, for two reasons:

1. **Universality.** HTTP long-poll works for every agent that can
   call a tool at all. SSE and WS need transport support the agent may
   not have, and the gateway would have to introspect the original
   request's `tools[]` to know. That introspection is the v2 plan.
2. **No gateway-initiated LLM call.** The spec's richer design has
   clawpatrol make its own upstream LLM call to let the model choose
   the polling shape. That needs credential injection into a
   gateway-initiated request (re-fetching the secret out of the
   per-credential plugin), which is non-trivial. Long-poll-only
   removes the need entirely.

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

- Introspect the request's `tools[]` to pick SSE/WS when the agent
  supports them, instead of long-poll unconditionally.
- Synth-`tool_result` deny path for round-trip preservation.
- Per-provider parsers (OpenAI/Codex/OpenRouter).
- Wire `toolgate.Rule` to cl-1yh's `llm_rule` HCL plugin.
- Dashboard UI for the approval queue.
