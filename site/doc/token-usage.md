# LLM Token Usage & Session Tracking

Claw Patrol tracks LLM activity while proxying agent traffic. The current
implementation focuses on live and persisted agent sessions: model names,
request counts, input/output token totals, and context-window usage.

## What is tracked

Each detected LLM session records:

| Field | Meaning |
| --- | --- |
| `type` | Session family, currently `claude` or `codex` depending on the detected client/API shape. |
| `id` | Stable session identifier derived from provider metadata, request IDs, or request content. |
| `title` | Latest useful user prompt/tool/completion summary shown in the dashboard. |
| `model` | Model name reported by the request or response. |
| `tokens_in` | Accumulated input/prompt tokens. |
| `tokens_out` | Accumulated output/completion/reasoning tokens. |
| `ctx_used` | Tokens used by the most recent accounting update. |
| `ctx_max` | Model context-window size when known. |
| `reqs` | Session request count. |
| `first_at`, `last_at` | Session activity timestamps. |

The gateway stores these rows in the `sessions` table and reloads them on
restart so the dashboard does not lose recent agent context.

## Supported traffic shapes

The gateway extracts usage from provider response/request shapes it already
sees while proxying traffic:

- Anthropic Messages API (`/v1/messages`) JSON and SSE responses.
- OpenAI-compatible chat completions and Responses API JSON/SSE responses.
- Codex/ChatGPT Responses API frames, including streamed WebSocket/SSE events
  that report usage or tool activity.

For Anthropic, cache creation/read input tokens are counted as input tokens.
For Codex/OpenAI Responses API, cached input and reasoning output tokens are
included when the response shape reports them.

Non-LLM requests simply do not update an LLM session.

## Context-window lookup

Claw Patrol refreshes model context-window metadata from LiteLLM's public model
metadata:

```text
https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json
```

The refresh runs at gateway startup and periodically afterward. Values from
`max_input_tokens` populate `ctx_max` when the active model can be matched. If
the lookup is missing or the refresh fails, token totals still work; the
context maximum is just unknown.

## Persistence and retention

Session updates are debounced before being written to SQLite. Streaming Codex
traffic can produce many frames per second, so the in-memory state is treated as
authoritative and database writes are coalesced to avoid write amplification.

The gateway reloads session rows on boot and sweeps old rows according to
`session_keep` in `gateway.hcl`. The default keep window is 30 days; set
`session_keep = "0"` or `"off"` to disable sweeping.

## What this is not

The current public implementation does not compute per-request USD cost, and it
does not attach cost fields to every request log. Cost reporting can be layered
on top of the existing session/token accounting later, but today the source of
truth is session token usage in the gateway/dashboard.

## Key files

| File | Purpose |
| --- | --- |
| `main.go` | Parses Anthropic/OpenAI/Codex request and response usage shapes. |
| `agents.go` | Maintains in-memory agent/session state and persists session rows. |
| `integrations.go` | Refreshes LiteLLM model context-window metadata. |
| `web.go` | Serves dashboard state, analytics, events, and session-facing API data. |
| `migrations/sqlite/` | SQLite schema for persisted gateway state. |
