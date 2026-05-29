# Claude Code OAuth & `/remote-control` env pushdown

## Problem

`/remote-control` (and other OAuth-only Claude Code features) does not
work in Claude Code sessions launched through `clawpatrol run` when
clawpatrol provides credentials via `ANTHROPIC_AUTH_TOKEN` env
pushdown. Claude Code detects the session as bearer/API-token auth and
refuses to register a remote-control session — even though the
operator's gateway-stored credential is a full-scope claude.ai
subscription OAuth token.

## How Claude Code picks its auth mode

Claude Code resolves credentials in a fixed precedence order (highest
first):

1. Cloud provider creds (`CLAUDE_CODE_USE_BEDROCK` / `_VERTEX` / `_FOUNDRY`)
2. `ANTHROPIC_AUTH_TOKEN` → `Authorization: Bearer` (LLM-gateway/proxy mode)
3. `ANTHROPIC_API_KEY` → `x-api-key`
4. `apiKeyHelper` script output
5. `CLAUDE_CODE_OAUTH_TOKEN` (long-lived `claude setup-token`, inference-only)
6. Subscription OAuth from `/login` (Pro/Max/Team) — stored in
   `.credentials.json` under a `claudeAiOauth` object

Sources:
- <https://code.claude.com/docs/en/authentication>
- <https://code.claude.com/docs/en/remote-control.md>

Modes #2–#5 put Claude Code into "API-key/bearer auth", which the
`/remote-control` feature explicitly rejects. Only mode #6 (a stored
subscription OAuth credential carrying the `user:sessions:claude_code`
scope) is eligible.

## The gate is **local**, not upstream

Verified by inspecting the shipped Claude Code binary (v2.1.156). Two
facts matter:

1. The eligibility reason-builder returns, verbatim, when
   `process.env.ANTHROPIC_AUTH_TOKEN` is set:

   > Remote Control requires claude.ai subscription auth.
   > `ANTHROPIC_AUTH_TOKEN` is set, so this session is using API-key
   > auth — unset it (or run in a shell without it) to use Remote
   > Control.

   The same builder rejects `ANTHROPIC_API_KEY` and `apiKeyHelper`
   the same way.

2. The scope check reads `scopes` off the **local** `.credentials.json`
   (`claudeAiOauth.scopes`), not the upstream `Authorization` header,
   and looks for `user:sessions:claude_code`.

Because the gate fires before any network request, a gateway that
swaps the `Authorization` header at MITM time **cannot** satisfy it:
Claude Code bails locally. This rules out the "keep pushing
`ANTHROPIC_AUTH_TOKEN`, just grant the upstream OAuth scope" approach.

Related upstream issues (all confirm bearer/long-lived tokens are
inference-only and cannot do remote control):
- anthropics/claude-code#33105 — setup-token lacks `user:sessions:claude_code`
- anthropics/claude-code#35407 — `CLAUDE_CODE_OAUTH_TOKEN` not eligible
- anthropics/claude-code#48378 — Desktop-injected token breaks `/remote-control`

## What clawpatrol does

For SDK clients (Python, Node, the raw Anthropic SDKs) the
`anthropic_oauth_subscription` plugin keeps pushing
`ANTHROPIC_AUTH_TOKEN` — that's the shape those clients expect, and the
gateway rewrites the header upstream so the placeholder never reaches
Anthropic.

For the `claude` CLI specifically, `clawpatrol run` installs a small
shim (`installClaudeCodeOAuthShim`, `cmd/clawpatrol/integrations.go`)
that runs just before the wrapped command starts:

- It synthesizes a `.credentials.json` in a `CLAUDE_CONFIG_DIR` with the
  `claudeAiOauth` shape Claude Code's `/login` writes — placeholder
  access/refresh tokens, a far-future `expiresAt` (so Claude Code never
  tries to refresh against the un-intercepted
  `console.anthropic.com`), and a `scopes` list including
  `user:sessions:claude_code`.
- It strips `ANTHROPIC_AUTH_TOKEN` from the child's environment so
  Claude Code drops out of precedence #2 and falls through to
  subscription OAuth (#6).

The gateway still rewrites the `Authorization` header at MITM time
using the operator's gateway-stored OAuth bearer, so the placeholder
bytes never reach Anthropic. That bearer must itself carry
`user:sessions:claude_code` for the upstream session-register call to
succeed — which is why `AnthropicOAuthSubscription.OAuthFlow()` requests
that scope (operators who connected the credential before the scope was
added must re-run the dashboard OAuth flow once).

### Scoping & opt-outs

- The shim only fires when the wrapped binary is `claude` and
  `ANTHROPIC_AUTH_TOKEN` is set. Non-claude clients are untouched.
- If the operator has set `CLAUDE_CONFIG_DIR`, the shim writes the
  synthesized credentials into that dir (so Claude Code keeps its
  settings/MCP/project state) instead of overriding it. A real
  `.credentials.json` already present there is left alone — dropping
  `ANTHROPIC_AUTH_TOKEN` lets that login win on its own.
- Otherwise the shim carves out a clawpatrol-managed dir
  (`~/.clawpatrol/claude-config`) and leaves the worker's `~/.claude`
  untouched.
- Set `CLAWPATROL_NO_CLAUDE_OAUTH_SHIM=1` to disable the shim entirely.

## Caveat: macOS Keychain

On macOS, an interactive `claude /login` stores credentials in the
Keychain rather than `.credentials.json`. The shim writes a file and
points `CLAUDE_CONFIG_DIR` at it, which Claude Code reads on all
platforms; clawpatrol's primary target (Linux workers) uses the file
store natively. Operators on macOS who rely on a pre-existing Keychain
login can opt out with `CLAWPATROL_NO_CLAUDE_OAUTH_SHIM=1`.
