# LLM Token Usage & Cost Tracking

## Overview

Claw Patrol extracts token usage from LLM API responses at proxy
time, estimates cost via OpenRouter pricing data, and attaches
the result to each request log. This enables cost tracking,
cache hit analysis, and model usage breakdowns without post-hoc
log parsing.

## How It Works

1. Response bodies are already captured for logging
2. `extractTokenUsage()` checks if the upstream host is a
   known LLM provider and parses the usage JSON
3. Cost is computed using cached pricing from OpenRouter
4. Token counts + cost are written to the configured
   analytics store alongside the request

Currently supported providers:
- **OpenAI** (`*.openai.com`) — `usage.prompt_tokens`,
  `completion_tokens`, `prompt_tokens_details.cached_tokens`
- **Anthropic** (`*.anthropic.com`) — `usage.input_tokens`,
  `output_tokens`, `cache_read_input_tokens`,
  `cache_creation_input_tokens`

Extraction is zero-cost for non-LLM requests (hostname check
short-circuits). Parse failures silently produce zeros.

## Pricing via OpenRouter

Pricing data is fetched from OpenRouter's public API:
```
GET https://openrouter.ai/api/v1/models
```

No authentication required. Returns model pricing as USD per
token in fields: `pricing.prompt`, `pricing.completion`,
`pricing.input_cache_read`, `pricing.input_cache_write`.

The pricing cache refreshes every hour. If the fetch fails,
the stale cache is used (or empty = $0 cost). Model lookup
tries `{provider}/{model}` first (e.g. `openai/gpt-4o`),
then the bare model name.

## Logged Fields

The following fields are attached to each request log and
persisted to the SQLite analytics store.

| Field | Description |
| ----- | ----------- |
| `LlmProvider` | `openai`, `anthropic`, or `""` |
| `LlmModel` | Model ID from the response |
| `LlmInputTokens` | Prompt / input tokens |
| `LlmOutputTokens` | Completion / output tokens |
| `LlmCacheReadTokens` | Tokens read from cache |
| `LlmCacheCreationTokens` | Tokens written to cache |
| `LlmCostUsd` | Estimated cost in USD |

See the `RequestRow` type in `src/analytics.ts` for the
canonical definition.

## Future: Plugin Response Hooks

The current implementation uses hostname-based detection in
`src/token_usage.ts`. A natural evolution is to add a
response hook to the plugin system:

```ts
// IntegrationEndpoint (future)
extractUsage?: (resp: Response, body: string) =>
  TokenUsage | null;
```

This would move OpenAI/Anthropic extraction into their
plugins and support custom/self-hosted LLMs via third-party
plugins. The `extractTokenUsage()` function serves as a
reference implementation.

## Key Files

| File | Purpose |
| ---- | ------- |
| `src/token_usage.ts` | Provider parsing + OpenRouter pricing |
| `src/proxy.ts` | WireGuard proxy — calls extractTokenUsage |
| `src/gateway.ts` | Gateway proxy — calls extractTokenUsage |
| `src/analytics.ts` | `RequestRow` type and SQLite-backed query API |
| `src/token_usage_test.ts` | Unit tests |
