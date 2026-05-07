# Introduction

Claw Patrol is an open-source security proxy for AI agents. It sits
between your agent and the internet, intercepting all network
traffic. Agents never touch your API keys directly — Claw Patrol
injects them into outgoing requests on the fly.

## The Problem

Your AI agent has every API key in plaintext. It talks to
GitHub, Slack, Anthropic, and dozens of other services. You
can't see what it's doing, what it costs, or where your
credentials end up. One prompt injection and your secrets
are exfiltrated.

## What Claw Patrol Does

- **Secret injection.** Agents use placeholders. Claw Patrol
  replaces them with real credentials before forwarding. Your
  agent never sees the actual key.
- **Full visibility.** Every request is logged — method, host,
  headers, body, response, latency, LLM token usage and cost.
- **Works with any agent.** Claude Code, Codex, OpenClaw, or
  your own scripts. No code changes needed.
- **Plugin system.** Built-in support for Anthropic, OpenAI,
  GitHub, Slack, and more. Write your own plugins for custom
  services.

## How It Works

Claw Patrol runs as a local proxy on your machine. On macOS, it
uses a Network Extension to transparently intercept traffic
from specific processes. On Linux, it uses a WireGuard tunnel
inside a network namespace. Either way, the agent's traffic
is routed through Claw Patrol without the agent knowing.

```
Agent  -->  Claw Patrol Proxy  -->  api.anthropic.com
              |
              +-- injects API key
              +-- logs request
              +-- tracks token usage
```

## Open Source

Claw Patrol is fully open source (MIT). You can run it locally with
no external dependencies — all data stays on your machine in
a SQLite database.

## Next Steps

- [Getting Started](/docs/02-getting-started/) — install and
  onboard in 2 minutes
- [CLI Reference](/docs/05-cli/) — all commands and options
- [Plugin System](/docs/08-plugins/) — extend Claw Patrol for custom
  services
- [Approval Rules](/docs/12-approval-rules/) — gate outbound
  actions: allow, deny, defer to a human or an LLM judge
