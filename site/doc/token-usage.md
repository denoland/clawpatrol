# LLM token tracking

When an agent's request hits a known LLM endpoint, Claw Patrol
parses the response, pulls model name + input/output token counts
off it, and stores them on the agent's session. The dashboard
shows per-session totals and a context-window progress bar.

There is no pricing, no USD cost, no OpenRouter integration —
just tokens.

## What's parsed

| Endpoint | Hosts | Parser |
|---|---|---|
| Anthropic Messages | `*.anthropic.com` `/v1/messages` | `parseClaudeResponse` |
| OpenAI Chat/Responses | `*.openai.com` `/v1/chat/completions`, `/v1/responses`, `/v1/completions` | `parseOpenAIResponse` |
| ChatGPT Codex | `chatgpt.com` `/backend-api/codex/responses` | `parseOpenAIResponse` |

Parsers handle both JSON responses and SSE streams; for streams
the token totals accumulate as deltas arrive. Anthropic's cache
tokens (`cache_creation_input_tokens`, `cache_read_input_tokens`)
are folded into the input count.

Token tracking is a pure side effect of the existing
response-body capture — adds no latency to the agent's request.

## What gets recorded

Per agent session (`AgentRegistry.recordLLMUsage` in `agents.go`):

| Field | Source |
|---|---|
| `model` | Latest model seen on the session |
| `tokens_in` | Sum of input + cache tokens across requests |
| `tokens_out` | Sum of output tokens across requests |
| `ctx_used` | `tokens_in + tokens_out` |
| `ctx_max` | Looked up from a per-model table (`agents.go:ctxMaxFor`) |
| `title` | Latest user message (lets you see what the agent is *currently* working on, not the first prompt) |

Persistence is debounced — Codex's WS frames fire `recordLLMUsage`
tens of times per second on a streaming response, so writes are
coalesced to ~1/sec/session. The in-memory state is always
authoritative.

## Source

- `main.go` — `trackLLMUsage` dispatches by endpoint kind;
  `parseClaudeResponse`, `parseOpenAIResponse` extract the fields.
- `agents.go` — `recordLLMUsage` persists; `ctxMaxFor` maps
  model → context-window size.
- `integrations.go` — `MaxInputTokens` from the upstream models
  list feeds `ctxMaxFor`.

## What's missing on purpose

- **Cost in USD.** Pricing data drifts faster than we want to
  maintain. The token counts are accurate; multiply by your own
  pricing if you need dollar figures.
- **Per-request rows.** Token usage rolls up to the agent
  session, not the individual request row in the audit log. If
  you need per-request token counts, the response body is still
  captured — re-parse downstream.
