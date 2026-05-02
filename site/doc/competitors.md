# Competitor Analysis

Feature comparison backing the table on clawpatrol.dev.
Last updated: 2026-05-02.

These assessments are based on the versions listed below and
may become outdated as products evolve. If you maintain one of
these tools and believe a rating is incorrect or a newer version
introduces a feature we missed, please open an issue at
https://github.com/denoland/clawpatrol/issues and we will
update this page.

## Feature Definitions

- **Secret injection** — The tool stores credentials and
  injects them into outbound requests so the agent never sees
  real keys.
- **All outbound traffic** — The tool intercepts all network
  traffic from the agent, not just LLM API calls.
- **Deep packet inspection** — The tool parses
  application-level protocols beyond HTTP (e.g. Postgres wire
  protocol, Kubernetes API, ClickHouse native protocol).
- **Understands LLM traffic** — The tool parses LLM
  request/response formats (token counting, model
  identification, cost calculation).
- **Rules** — The tool has a policy/rules system for
  controlling what agents can do.
- **Analytics** — The tool provides dashboards, cost tracking,
  or usage metrics.

---

## Helicone

> AI gateway and observability
> https://helicone.ai
> Reviewed: SaaS (no public version number), May 2026

### Helicone, Secret injection: false

Helicone stores LLM provider API keys and can inject them via
its "provider keys" feature. However this is limited to LLM
provider credentials only — not arbitrary secrets like database
passwords, SaaS tokens, or SSH keys. We score this as false
because the injection scope is too narrow for general agent
security.

- https://docs.helicone.ai/getting-started/quick-start
- https://docs.helicone.ai/getting-started/integration-method/gateway

### Helicone, All outbound traffic: false

Helicone only intercepts LLM API calls. Integration works by
swapping the `baseURL` in your LLM SDK to point at Helicone's
proxy (e.g. `oai.helicone.ai/v1`). It does not function as a
forward proxy for arbitrary outbound traffic.

- https://docs.helicone.ai/getting-started/proxy-vs-async

### Helicone, Deep packet inspection: false

Operates exclusively at the HTTP layer. No support for
Postgres, Kubernetes, gRPC, or any non-HTTP protocol.
Architecture is a Cloudflare Workers-based reverse proxy for
JSON-over-HTTPS.

- https://github.com/Helicone/helicone

### Helicone, Understands LLM traffic: true

Core strength. Parses LLM request/response formats to extract
prompt content, completion text, token counts, model IDs, and
cost across 300+ models. Supports session/trace structures and
prompt versioning.

- https://docs.helicone.ai/references/how-we-calculate-cost
- https://github.com/Helicone/helicone/tree/main/costs

### Helicone, Rules: false

No general-purpose rules engine. Offers rate limiting by
request count or cost, OpenAI content moderation via header
flag, and LLM security/prompt injection detection. None of
these constitute a policy system for behavioral constraints.

- https://docs.helicone.ai/features/advanced-usage/custom-rate-limits
- https://docs.helicone.ai/features/advanced-usage/llm-security

### Helicone, Analytics: true

Comprehensive dashboards: request logging, cost tracking,
token usage, latency monitoring, user-level metrics,
session/trace visualization, custom properties, a custom
query language (HQL), alerts, and reports. Data stored in
ClickHouse.

- https://helicone.ai/pricing
- https://docs.helicone.ai/features/sessions

---

## Portkey

> AI gateway, guardrails, observability
> https://portkey.ai
> Reviewed: gateway v1.15.2

### Portkey, Secret injection: false

Portkey stores provider API keys via "Virtual Keys" and
injects them into LLM requests. But this is scoped to LLM
provider credentials only — not arbitrary secrets for
databases, SaaS APIs, etc.

- https://portkey.ai/docs/product/ai-gateway/virtual-keys

### Portkey, All outbound traffic: false

Only intercepts LLM API calls. The gateway routes requests to
250+ LLM providers using the OpenAI-compatible API format. No
general-purpose HTTP proxying or egress control.

- https://portkey.ai/docs/product/ai-gateway
- https://github.com/portkey-ai/gateway

### Portkey, Deep packet inspection: false

No support for non-HTTP protocols. Kubernetes is mentioned
only as a deployment target, not a protocol it inspects.

- https://portkey.ai/docs/product/ai-gateway

### Portkey, Understands LLM traffic: true

Core competency. Normalizes 250+ models from 45+ providers
into a unified API. Parses token counts, costs, latency, and
can apply guardrails that inspect prompt/completion content.

- https://portkey.ai/docs/introduction/what-is-portkey
- https://portkey.ai/docs/product/observability/analytics

### Portkey, Rules: true

40+ pre-built guardrail checks on inputs and outputs: regex,
JSON schema validation, code detection, PII detection, prompt
injection detection, custom webhooks. Actions include deny,
retry, fallback, and logging.

- https://portkey.ai/docs/product/guardrails

### Portkey, Analytics: true

21+ key metrics in dashboards: cost, token consumption,
latency, request volume, per-user analytics, error tracking,
cache hit rates, and metadata-based segmentation.

- https://portkey.ai/docs/product/observability
- https://portkey.ai/docs/product/observability/analytics

---

## LiteLLM

> Unified API for 100+ LLMs
> https://github.com/BerriAI/litellm
> Reviewed: v1.83.14-stable

### LiteLLM, Secret injection: false

LiteLLM stores LLM provider API keys centrally and injects
them via "virtual keys." But scope is strictly LLM provider
credentials — not general-purpose secret injection.

- https://docs.litellm.ai/docs/proxy/virtual_keys

### LiteLLM, All outbound traffic: false

LLM gateway only. Routes LLM API calls to 100+ providers.
Non-LLM traffic bypasses LiteLLM entirely.

- https://docs.litellm.ai/docs/

### LiteLLM, Deep packet inspection: false

No capability for non-HTTP protocols. Exclusively HTTP-based
LLM API traffic in OpenAI-compatible format.

### LiteLLM, Understands LLM traffic: true

Core competency. Parses messages, counts tokens, calculates
costs per model, translates between provider formats. Supports
chat completions, embeddings, image generation, audio, batches.

- https://docs.litellm.ai/docs/

### LiteLLM, Rules: true

Multi-layered: pre_call_rules and post_call_rules for request
validation, guardrails framework (Presidio PII, Azure Content
Safety, Bedrock Guardrails, OpenAI Moderation), and enterprise
guardrail policies assignable to teams/keys.

- https://docs.litellm.ai/docs/proxy/rules
- https://docs.litellm.ai/docs/proxy/guardrails/quick_start

### LiteLLM, Analytics: true

Built-in cost tracking per key/user/team/tag, Admin UI with
Usage Tab, `/spend/logs` and `/spend/report` endpoints.
Integrates with 20+ observability platforms (Langfuse,
DataDog, PostHog, etc.) and OpenTelemetry.

- https://docs.litellm.ai/docs/proxy/cost_tracking
- https://docs.litellm.ai/docs/proxy/ui

---

## agentgateway

> Agentic proxy for AI and MCP
> https://github.com/agentgateway/agentgateway
> Reviewed: v1.1.0

### agentgateway, Secret injection: false

Supports "virtual keys" for LLM providers and backend auth
policies (static keys, GCP ADC, AWS signing). But scoped to
LLM/MCP backends only — not arbitrary secrets.

- https://agentgateway.dev/docs/standalone/latest/llm/virtual-keys/
- https://agentgateway.dev/docs/standalone/latest/configuration/security/backend-authn/

### agentgateway, All outbound traffic: false

Scoped to "agent-to-LLM, agent-to-tool, and agent-to-agent
communication." Does not intercept arbitrary outbound traffic.
No transparent proxying or iptables-level interception.

- https://github.com/agentgateway/agentgateway

### agentgateway, Deep packet inspection: false

No non-HTTP protocol support. Operates at HTTP layer for LLM
calls and understands MCP/A2A as protocol abstractions.

### agentgateway, Understands LLM traffic: true

Parses LLM request/response bodies for token counts, model
names, and costs. Supports prompt enrichment via CEL
templates, content-based routing, token estimation, and budget
enforcement.

- https://agentgateway.dev/docs/standalone/latest/llm/
- https://agentgateway.dev/docs/standalone/latest/llm/spending/

### agentgateway, Rules: true

Policy system built on CEL (Common Expression Language). HTTP
authorization with allow/deny/require rules at listener,
route, or backend level. Guardrails with regex filters, OpenAI
moderation, AWS Bedrock, and Google Model Armor integration.

- https://agentgateway.dev/docs/standalone/latest/configuration/policies/
- https://agentgateway.dev/docs/standalone/latest/configuration/security/http-authz/

### agentgateway, Analytics: true

OpenTelemetry-based: metrics, distributed tracing, structured
logging. Exposes HTTP request counts, MCP tool call counts,
and LLM-specific token usage histograms. Traces export to
Jaeger or any OTel collector.

- https://agentgateway.dev/docs/standalone/latest/reference/observability/metrics/
- https://agentgateway.dev/docs/standalone/latest/llm/observability/

---

## Clawvisor

> API gateway for agent authorization
> https://github.com/clawvisor/clawvisor
> Reviewed: v0.8.16

### Clawvisor, Secret injection: true

Core design: agents never hold credentials. API keys and OAuth
tokens live in an encrypted vault. Clawvisor injects them
server-side when executing the downstream API call. Agents
send structured requests specifying service and action;
Clawvisor attaches credentials.

- https://github.com/clawvisor/clawvisor
- https://github.com/clawvisor/clawvisor/blob/main/docs/ARCHITECTURE.md

### Clawvisor, All outbound traffic: false

Not a proxy or MITM. Agents must explicitly POST to
Clawvisor's `/api/gateway/request` endpoint. Only traffic
routed through Clawvisor is governed. Architecture doc states:
"Clawvisor is not a proxy or MITM system."

- https://github.com/clawvisor/clawvisor/blob/main/docs/ARCHITECTURE.md

### Clawvisor, Deep packet inspection: false

No protocol-level inspection. Operates at the application/API
semantics layer — each service has an adapter translating
high-level actions into API calls. No Postgres, K8s, or other
wire protocol support.

### Clawvisor, Understands LLM traffic: false

Uses LLMs internally (intent verification, risk assessment)
but does not parse LLM API wire formats. Operates on
structured metadata (action names, parameters), not raw LLM
protocol payloads.

- https://github.com/clawvisor/clawvisor/blob/main/docs/ARCHITECTURE.md

### Clawvisor, Rules: true

Multi-layered authorization: restrictions (hard blocks on
service/action tuples with wildcards), task scopes
(pre-authorized action sets), and an expression runtime built
on `expr-lang/expr` for field extraction, parameter
transformation, and conditional execution.

- https://github.com/clawvisor/clawvisor/blob/main/docs/design-expr-runtime.md
- https://github.com/clawvisor/clawvisor/blob/main/docs/ARCHITECTURE.md

### Clawvisor, Analytics: true

Audit logging and web dashboard. Every request, purpose
declaration, decision, and credential injection is recorded.
Dashboard includes audit trail, approval management, and
operational overview. Primarily audit/approval UI rather than
deep metrics visualization.

- https://clawvisor.com
- https://github.com/clawvisor/clawvisor/tree/main/web/src/pages

---

## httpjail

> HTTP request filter and sandbox
> https://github.com/coder/httpjail
> Reviewed: v0.6.1

### httpjail, Secret injection: false

No mechanism for injecting credentials. Rule engines only
evaluate requests and return allow/deny decisions. Environment
variables are limited to TLS trust config and request
metadata.

- https://github.com/coder/httpjail
- https://coder.github.io/httpjail/print.html

### httpjail, All outbound traffic: false

Intercepts HTTP and HTTPS only. On Linux uses network
namespaces and iptables for ports 80/443. On macOS uses
HTTP_PROXY env vars. Non-HTTP protocols (database connections,
raw TCP, UDP) are not intercepted. Includes basic DNS
exfiltration protection on Linux.

- https://coder.github.io/httpjail/print.html

### httpjail, Deep packet inspection: false

Inspects only HTTP-level metadata: method, URL, host, scheme,
path. No body or header inspection exposed to rule engines. No
non-HTTP protocol parsing.

- https://coder.github.io/httpjail/print.html

### httpjail, Understands LLM traffic: false

No LLM-specific features. Treats all HTTP requests
identically. No awareness of LLM formats, token counting, or
model identification.

### httpjail, Rules: true

Three evaluation engines: (1) JavaScript expressions via V8
with access to request properties, supporting allow/deny with
custom messages and body size limits; (2) shell scripts using
exit codes; (3) line processor programs for stateful
filtering. Default policy is deny-all.

- https://coder.github.io/httpjail/print.html

### httpjail, Analytics: false

Basic request logging to a file (`--request-log`) in the
format `<timestamp> <+/-> <METHOD> <URL>`. No aggregation,
dashboards, metrics, or visualization.

- https://coder.github.io/httpjail/print.html

---

## Agent Vault

> Credential proxy and vault
> https://github.com/Infisical/agent-vault
> Reviewed: v0.15.0

### Agent Vault, Secret injection: true

Core purpose. Supports five auth methods: Bearer token, HTTP
Basic, API Key headers, custom header templates with
`{{ SECRET }}` placeholders, and URL path/query substitutions.
Agents make plain HTTP calls; Agent Vault transparently
authenticates them.

- https://github.com/Infisical/agent-vault
- https://github.com/Infisical/agent-vault/blob/main/docs/learn/services.mdx

### Agent Vault, All outbound traffic: false

HTTP/HTTPS proxy only (via `HTTPS_PROXY` env var on ports
14321/14322). Supports WebSocket upgrades. Does not intercept
non-HTTP protocols. Unmatched hosts can be forwarded or denied
with 403.

- https://github.com/Infisical/agent-vault

### Agent Vault, Deep packet inspection: false

Operates exclusively at the HTTP layer. No Postgres,
Kubernetes, gRPC, or other protocol parsers. Logging
intentionally excludes request bodies and headers.

- https://github.com/Infisical/agent-vault/tree/main/internal

### Agent Vault, Understands LLM traffic: false

No LLM-specific features. Designed to work with AI agents as
clients but treats their API calls as generic HTTP traffic.
WebSocket support for "OpenAI Realtime" is standard proxying,
not LLM-aware parsing.

### Agent Vault, Rules: true

Basic permission system: role-based access control (admin,
member, proxy), per-vault `unmatched_host_policy` (deny or
forward), IP-level network guards blocking cloud metadata
endpoints, and a "Proposals" approval workflow for human
review.

- https://github.com/Infisical/agent-vault/blob/main/docs/learn/permissions.mdx
- https://github.com/Infisical/agent-vault/blob/main/docs/learn/proposals.mdx

### Agent Vault, Analytics: true

Request logging to SQLite: method, host, path, status,
latency, credential key names, actor, matched service. Web UI
with a Logs tab. Basic structured log viewer — no charts or
aggregation dashboards.

- https://github.com/Infisical/agent-vault/blob/main/internal/requestlog/sink.go
- https://github.com/Infisical/agent-vault/blob/main/web/src/pages/vault/LogsTab.tsx

---

## Crab Trap

> LLM-as-judge agent proxy
> https://github.com/brexhq/CrabTrap
> Reviewed: v0.0.1

### Crab Trap, Secret injection: false

Does not inject credentials. It is a security inspection
proxy, not a credential broker. DESIGN.md states the LLM
judge receives "the full HTTP request verbatim — headers and
body are not sanitized or redacted."

- https://github.com/brexhq/CrabTrap/blob/main/DESIGN.md

### Crab Trap, All outbound traffic: false

HTTP/HTTPS forward proxy only. Agents connect via
`HTTP_PROXY`/`HTTPS_PROXY` env vars. No iptables/eBPF
capture. WebSocket frames after initial HTTP upgrade are not
inspected. Non-HTTP protocols are not handled.

- https://github.com/brexhq/CrabTrap/blob/main/README.md
- https://github.com/brexhq/CrabTrap/blob/main/DESIGN.md

### Crab Trap, Deep packet inspection: false

Operates strictly at the HTTP/HTTPS layer. No Postgres,
Kubernetes, gRPC, or other application protocol parsing.

- https://github.com/brexhq/CrabTrap/blob/main/IMPLEMENTATION.md

### Crab Trap, Understands LLM traffic: false

Does not parse LLM request/response formats. Treats all HTTP
requests generically — the same approval pipeline applies
regardless of destination. CrabTrap *uses* an LLM as a judge
but does not *understand* LLM API traffic flowing through it.

- https://github.com/brexhq/CrabTrap/blob/main/DESIGN.md

### Crab Trap, Rules: true

Two-tier policy system: static rules with deterministic URL
pattern matching (prefix, exact, glob) and HTTP method
filtering; then LLM judge evaluation against per-agent
natural-language policies. Policies are versioned and stored
in PostgreSQL. Configurable fallback mode and circuit breaker
for LLM failures.

- https://github.com/brexhq/CrabTrap/blob/main/README.md
- https://github.com/brexhq/CrabTrap/blob/main/DESIGN.md

### Crab Trap, Analytics: true

Comprehensive audit logging to PostgreSQL with full request
metadata. Web UI with audit trail viewer. Real-time SSE
streaming of events. Eval system replays historical requests
against policies. Optional OpenTelemetry/Prometheus metrics
(approval counters, judge latency, circuit breaker gauges).

- https://github.com/brexhq/CrabTrap/blob/main/docs/observability.md
- https://github.com/brexhq/CrabTrap/blob/main/DESIGN.md

---

## Claw Patrol

> Security proxy for AI agents
> https://github.com/denoland/clawpatrol

### Claw Patrol, Secret injection: true

Supports arbitrary credential injection across all protocols:
Bearer tokens, custom headers, cookies, URL path tokens,
Postgres SCRAM password substitution, Kubernetes mTLS and EKS
bearer tokens, ClickHouse credentials, OAuth token refresh,
and Slack bot/app token bundles. Agents use placeholders;
Claw Patrol swaps in real credentials at request time.

### Claw Patrol, All outbound traffic: true

Transparent forward proxy via WireGuard/Tailscale exit node.
All agent traffic routes through the gateway — HTTP, HTTPS,
Postgres, Kubernetes, ClickHouse, WebSocket. No env var
configuration needed; network-level interception.

### Claw Patrol, Deep packet inspection: true

Parses Postgres wire protocol (SQL query extraction,
verb/table/function identification, SCRAM auth interception).
Understands Kubernetes API path semantics
(verb/resource/namespace/name decomposition). ClickHouse
native protocol support. WebSocket frame parsing with
permessage-deflate decompression.

### Claw Patrol, Understands LLM traffic: true

Tracks LLM token usage and costs for Anthropic, OpenAI, and
Gemini. Parses streaming SSE responses for usage data. Records
per-session model, token counts, and estimated cost.

### Claw Patrol, Rules: true

HCL-based policy language with typed rulesets:
`http_ruleset`, `sql_ruleset`, `k8s_ruleset`. SQL rules match
on verb, tables, functions, statement patterns, and regex. K8s
rules match on verb, resource, namespace, name with glob and
negation support. HTTP rules match on method, path, query,
headers, body JSON, and body substrings. LLM and human
approvers with configurable cache TTL. Two-pass precedence:
device-scoped before global.

### Claw Patrol, Analytics: true

Dashboard with per-session request logging, LLM cost
tracking, integration status, and real-time event streaming.
SQLite-backed with configurable retention.
