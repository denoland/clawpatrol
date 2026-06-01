# Tool-call gating (draft)

Rules applied to a model's `tool_use` blocks before the agent ever
sees them. Three verdicts — allow, deny, human-in-the-loop (HITL) —
drive the gateway to rewrite the upstream LLM response. The
implementation lives in `internal/toolgate`; the MITM hook glue is in
`cmd/clawpatrol/toolgate.go`.

This is the exploratory draft (bead cl-umxf, PR #489). It handles
Anthropic `/v1/messages`, non-streaming JSON responses only.

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

- Streaming-response gating (Anthropic SSE, byte-by-byte rewrite). In
  a realistic deployment most `/v1/messages` traffic streams, so the
  non-streaming-only draft does not fire against typical agents — the
  streaming rewrite is the gap between this and a usable feature.
- Introspect the request's `tools[]` to pick SSE/WS when the agent
  supports them, instead of long-poll unconditionally.
- Synth-`tool_result` deny path for round-trip preservation.
- Per-provider parsers (OpenAI/Codex/OpenRouter).
- Wire `toolgate.Rule` to cl-1yh's `llm_rule` HCL plugin.
- Dashboard UI for the approval queue.
