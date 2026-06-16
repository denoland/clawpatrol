# External plugin protocol v2 — full parity with built-in plugins

Status: **draft / RFC** — iterating in PR comments. Nothing here is
implemented yet.

## Context

The v1 external plugin protocol (`internal/config/extplugin/proto/plugin.proto`,
landed with GitHub-based distribution) lets a third party ship a plugin
that declares **credentials, tunnels, endpoints, and facets**, runs
sandboxed in its own process, and talks to the gateway over gRPC.

A capability audit of the existing built-in plugins (22 credentials, 7
endpoints, 4 tunnels, 3 approvers, 4 facets) found that only the
*leaf* integrations extract cleanly today:

* ~10 header-injecting credentials (api-key / bearer / basic / cookie /
  OAuth-metadata) — `InjectHTTP` covers them.
* A single generic HTTPS endpoint — `TLS_TERMINATE` + `family = "http"`
  + brokered dial covers it.

Everything that makes clawpatrol a *protocol-aware* gateway stays on the
built-in side of the line:

* **Approvers** (dashboard / human / llm) and the **HITL** machinery —
  no manifest type, no protocol surface.
* **Stateful identity** — SSH host keys, Codex JWT keypairs, Tailscale
  node identity, Notion-MCP dynamic client registration — no plugin
  persistence.
* **Non-header credential injection** — telegram (URL/body), discord
  (body/WebSocket), AWS SigV4 (full-body signing), mTLS (upstream
  client cert).
* **The shared `sql` vocabulary** — the `sql.*` matcher is gateway-only,
  so an external SQL endpoint forks to a namespaced `<plugin>.<facet>`
  and operators rewrite every rule. (k8s/ssh have one implementation
  each, so a plugin-private facet is fine there — this is only a problem
  for SQL, which has many engines.)
* **Process-spawning tunnels** — `kubectl port-forward`, `local_command`
  — the sandbox forbids exec of anything but the plugin's own binary.

## Goal

Extend the protocol so that **any** built-in plugin *could* be
reimplemented as an external plugin, **without weakening the security
model**. This is about capability parity for third parties, not about
forcing the built-ins out of tree — the built-ins stay where they are.

### Non-goals

* Moving built-in plugins out of the binary.
* Exposing the gateway's core dispatch internals (TLS-MitM engine,
  DNS-VIP allocator, WireGuard) as plugin-controllable surfaces. These
  stay gateway-owned and are reached only through the existing
  mediated primitives (`TLS_TERMINATE`, `requires_vip`, brokered dial).
* A pluggable **rule/matcher** type. Rules are a policy-layer construct,
  not a plugin abstraction; see [Out of scope](#out-of-scope).

## Design principles

1. **Mirror existing gateway-side contracts.** The interfaces this
   needs already exist in `internal/config/runtime`:
   `ApproverRuntime`, `HITLPool`, `HITLNotifier`, `BlobStore`,
   `Secret{Kind,Extras}`, `facet.Runtime`. v2 is mostly *exposing those
   contracts over gRPC*, not inventing new semantics. That keeps the
   external and built-in surfaces convergent.
2. **Preserve the capability/lockfile model.** Every new power is either
   (a) **low-risk, plugin-declarable** — recorded trust-on-first-use in
   `clawpatrol.lock.hcl`, with a fail-closed escalation check on upgrade
   (the model `network` and `egress` already use), or (b) **high-risk,
   operator-only** — granted explicitly in HCL like `sandbox = "off"`,
   never silently acquired by a plugin update.
3. **Stay mediated, not raw.** A plugin keeps `network = none` by
   default. New powers are brokered by the gateway (the gateway holds
   the socket / the secret store / the webhook route), so a compromised
   plugin update can't quietly exfiltrate.
4. **Signed manifest stays authoritative; fail closed.** New declarable
   capabilities are part of the signed static manifest and the runtime
   consistency check.

## Gaps → primitives

| Gap (built-ins blocked) | New primitive | Risk tier |
|---|---|---|
| Persistent identity (ssh host key, codex jwt, tailscale, notion-mcp) | **State service** (BlobStore over gRPC) | low (quota'd) |
| URL/body/SigV4/mTLS credential injection | **TransformRequest** + typed `Secret` passthrough + brokered client cert | low |
| Approvers (dashboard/human/llm), slack notifier | **Approver service** + **HITL** (notify / decide / webhook ingress) | low (sync) / operator (webhook ingress) |
| SQL endpoints want shared `sql.*` rules | **`sql` built-in family** (opt-in); k8s/ssh/other stay plugin-defined | low |
| kubectl / local_command tunnels | **`exec` capability** | operator-only |
| Chained `via` tunnels | **`via` on tunnel dial** | low |
| Dashboard credential-location hint | **Static placeholder declaration** | low |

The rest of this doc is one section per primitive, each stating the
problem, the proposed surface, security notes, and which built-ins it
unblocks.

---

## 1. State service — persistent per-plugin bytes

**Unblocks:** ssh endpoint host keys, openai-codex JWT keypairs,
tailscale node identity, notion-mcp dynamic `client_id`.

**Problem.** Plugins run sandboxed with no writable persistent path and
no storage RPC. Anything that must survive a restart is impossible. The
gateway already has the exact contract internally — `runtime.BlobStore`
(`Get/Put(kind, name)`), backed by a sqlite table — used by the built-in
SSH and Codex endpoints. v2 exposes it.

**Proposed surface.**

```proto
service State {
  rpc Get(StateGetRequest) returns (StateGetResponse);
  rpc Put(StatePutRequest) returns (StatePutResponse);
  rpc Delete(StateDeleteRequest) returns (StateDeleteResponse);
}
message StateGetRequest  { string name = 1; }              // kind is implicit (the plugin)
message StateGetResponse { bytes value = 1; bool found = 2; }
message StatePutRequest  { string name = 1; bytes value = 2; bool secret = 3; }
```

* **Namespacing is gateway-enforced**, not plugin-chosen: the gateway
  prefixes every row with the plugin's manifest name, so one plugin can
  never address another's blobs (unlike the internal `kind` string,
  which is plugin-chosen — we do not expose `kind`).
* `secret = true` routes the value through the encrypted-at-rest secret
  table instead of the plain blob table (SSH host keys, JWT private
  keys want this).
* **Quota** (size per value + total per plugin) is a low-risk default;
  exceeding it fails the `Put`. No operator grant needed for modest
  state.

**Open question:** do we also want a list/iterate call, or is
`(name)`-addressed get/put enough for the known cases? (All four known
consumers are single-key or known-key.)

---

## 2. Generalized credential injection

**Unblocks:** telegram (token in URL path + query + body), discord
(body / WebSocket frame rewrite), aws SigV4 (full-body signing), mtls
(upstream client cert); confirms the non-HTTP credential pattern
(postgres / ssh / clickhouse).

**Problem.** v1 `InjectHTTP` returns **header mutations only** and sees
only a capped, read-only `body_prefix`. Three sub-gaps:

### 2a. Request rewriting beyond headers

Replace `InjectHTTP` with a superset `TransformRequest` whose response
can mutate method, URL (path + query), and body, not just headers:

```proto
message TransformResponse {
  repeated HeaderMutation headers = 1;
  optional string url   = 2;   // full replacement (telegram path/query)
  optional bytes  body  = 3;   // full replacement (discord, telegram body)
  repeated string redactions = 4;
}
```

`InjectHTTP` stays as the narrow, common case (header-only) so existing
plugins don't churn; `TransformRequest` is opt-in for the few that need
more.

### 2b. Full body for signing

AWS SigV4 hashes the **entire** body. The gateway buffers the request
body up to a configurable cap and passes it (or a stream handle, reusing
the existing `FACET_STREAM` chunking machinery) to `TransformRequest`.
Over the cap → fail closed, or the plugin opts into SigV4
streaming/unsigned-payload mode. **Open question:** default cap and the
large-upload story.

### 2c. Non-HTTP credentials are endpoint-coupled (no new RPC)

postgres / ssh / clickhouse / mtls auth is **not** HTTP header
injection. Once endpoints are external (§4), the credential is just a
**secret carrier**: the gateway already delivers
`Secret{Kind, Bytes, Extras}` to the endpoint via `ConnInit`
(`credential_secret` / `credential_extras`), and the endpoint plugin
performs the protocol-specific injection (postgres StartupMessage
rewrite, SSH auth, etc.). We make `Secret.Kind`/`Extras` first-class in
the proto (mirroring `runtime.Secret`) and document the pattern — no
per-protocol RPC needed.

**mTLS** is the one residual: the upstream needs a **client cert**. Add
an optional client cert/key to the brokered `DialUpstreamRequest` so the
gateway-terminated upstream TLS presents it (the cert comes from the
credential's `Secret.Extras`). The plugin can alternatively run its own
TLS over a raw brokered dial — but the brokered option keeps cert
material out of plugin memory.

---

## 3. Approver plugins + HITL

**Unblocks:** dashboard / human / llm approvers; the slack credential's
notifier + interactive-webhook role.

**Problem.** The manifest has no approver type. `ApproverRuntime`
(`Approve(ctx, ApproveRequest) (ApproveVerdict, error)`) is a built-in
Kind wired to the `HITLPool`. This is the largest sub-design; split by
difficulty.

### 3a. Synchronous approver (easy) — LLM judge

```proto
service Approver {
  rpc Approve(ApproveRequest) returns (ApproveVerdict);
}
```

`ApproveRequest` mirrors `runtime.ApproveRequest`'s plugin-relevant
fields (rule name, summary, method/host/path, body sample, profile,
stage). The LLM approver reads them, calls the model — via a **bound
credential** (`InjectHTTP`) over a **brokered dial**, so it needs no raw
network — and returns `allow`/`deny` + reason. This case is fully
expressible with the primitives above plus the new `ApproverDecl`.

### 3b. Human / HITL (hard) — dashboard + notifier + interactive callback

The human approver has three moving parts; map each to a gateway-owned
contract so the **decision authority stays in the gateway's HITLPool**,
never in the plugin:

1. **Notify** (gateway → plugin): when a HITL decision goes pending, the
   gateway pushes the prompt context to the plugin, which posts it to
   its channel (Slack `chat.postMessage`, etc.). Mirrors
   `HITLNotifier.NotifyHITL`. The plugin returns a non-secret message
   ref (Slack channel/ts) for later edits.
2. **Decide** (plugin → gateway): an interactive callback (a Slack
   button) resolves a pending id. Mirrors `HITLPool.Decide(id, d)`. The
   gateway validates the id and records the verdict in the same pool the
   dashboard writes to — so the plugin *requests* a decision, it does
   not *own* one.
3. **Webhook ingress** (the genuinely new piece): the provider's
   interactive callback is an inbound HTTP request. The plugin has no
   listener (`network = none`, and there is no inbound grant). Proposal:
   the gateway mounts a per-plugin ingress path (`/ext/<plugin>/...`),
   authenticates/normalizes the request, and forwards it to the plugin
   over a stream; the plugin returns the HTTP response and may call
   `Decide`. **Mounting a public route is operator-only** (a
   `webhook_ingress` grant) — it widens the gateway's attack surface, so
   it is not a silent plugin-declarable capability.
4. **Message update** (optional): edit the posted prompt as the
   operation resolves. Mirrors `HITLMessageUpdater.UpdateHITLMessage`.

**Open questions:** (a) webhook ingress — gateway-mounted path (above)
vs. a real `network = inbound` capability that lets the plugin own a
listener behind the gateway? The former keeps the plugin sandboxed with
no socket; the latter is simpler but a bigger trust grant. (b) Does the
LLM "classifier-before-human" composition (a human approver referencing
an llm approver) need cross-plugin approver references, or do we keep
chains gateway-resolved?

---

## 4. Shared `sql` family for external endpoints (opt-in)

**Unblocks:** external SQL endpoints (postgres / mysql / clickhouse /
cockroach / ...) reusing the operator's existing `sql.*` rules instead
of forking to a per-plugin vocabulary.

### Default: plugins define their own facet

A plugin-declared facet is already a first-class, working path —
`registerFacet` + `newPluginFacetMatcher` build the CEL env from the
declared fields, and `EvaluateAction` routes through it. So "every
plugin ships its own vocabulary" needs **no new machinery**; it is the
expected default for k8s, ssh, and any bespoke protocol.

We deliberately do **not** add shared `k8s` / `ssh` families. There is
realistically one implementation of each, so a shared vocabulary buys
nothing but a frozen compatibility surface the gateway must maintain
forever (YAGNI). A shared vocabulary does not even reduce plugin work —
the plugin still produces the parse either way; it only buys *rule
portability across multiple implementations of one family*, which those
families don't have.

### The one exception: `sql`

Unlike k8s/ssh, there are many SQL-ish engines, and the *coarse* layer
of SQL policy genuinely generalizes: `verb`, `tables`, `functions`, raw
`statement`. An operator's "no `DROP`, no unscoped `DELETE`, these
tables are off-limits" ruleset should hold against any SQL endpoint
regardless of which plugin backs it. So `sql` — and only `sql` — is
exposed as a built-in family an external endpoint may **opt into**:

* A plugin declares `family = "sql"` and emits the standard coarse
  action schema (the wire form of `sql.Meta`: verb / tables / functions
  / statement / database) in `EvaluateAction.action_json`. The gateway
  maps it onto the typed `match.Request` (extending today's http-only
  `builtinRequestFor`), so the endpoint reuses `sql.*` rules verbatim.
* Keep the shared schema **deliberately minimal** — only the fields that
  truly transfer across engines. It is a coarse guardrail surface, not a
  comprehensive one. Pretending otherwise would silently under-match
  engine-specific semantics and give operators false confidence.
* An engine that needs more (ClickHouse `SYSTEM`, BigQuery scripting,
  stored procedures) declares its own facet instead — or, phase 2,
  `extends = "sql"` to inherit the coarse fields and add its own.

This saves no *parsing* work; it buys rule portability and zero-rewrite
parity with the built-in SQL endpoints — worth it only because SQL has
many implementations, which is why the line is drawn here and nowhere
else.

**Resolved** (was an open design question): only `sql` gets a shared
built-in family; k8s, ssh, and everything else are plugin-defined.

**Open question:** version the `sql` action schema independently of the
gateway (so a plugin built against `sql/v1` keeps working across gateway
upgrades), or tie it to the protocol version?

---

## 5. `exec` capability — process-spawning tunnels

**Unblocks:** `kubernetes_port_forward` (spawns `kubectl`),
`local_command` (spawns `cloud_sql_proxy` et al.).

**Problem.** The sandbox permits `process-exec` only for the plugin's
own binary (darwin seatbelt literal; Linux via fs/namespace isolation).
Spawning `kubectl` is impossible.

**Proposal.** A **high-risk, operator-only** `exec` grant that
whitelists specific argv0 paths; the sandbox profile adds
`process-exec` for those literals only. This is **not**
plugin-declarable — spawning a host binary largely defeats the
isolation, so it must be an explicit operator decision (like
`sandbox = "off"`), recorded in the lockfile, with an optional pinned
hash of the target binary.

**Recommendation.** Prefer keeping these two tunnels built-in. The
`exec` grant exists for the operator who *must* externalize a
proxy-spawning tunnel, with eyes open. Document the trade-off loudly.

---

## 6. Tunnel chaining (`via`)

**Unblocks:** `ssh_port_forward` used as a chained/bastion tunnel.

**Problem.** A built-in tunnel can route through another (`via =
<tunnel>`). A plugin tunnel's `Dial` has no way to say "go through that
other tunnel."

**Proposal.** Add `via_tunnel_handle` to `OpenTunnelRequest` /
`DialInit`. The gateway resolves the parent tunnel (built-in or plugin)
and routes the plugin tunnel's upstream through it — the gateway owns
the composition, the plugin just names the parent. Small, additive.

---

## 7. Credential placeholder hints

**Restores:** the dashboard "where does this credential appear" hint
(`PlaceholderDetector`).

**Problem.** Built-in credentials implement `PlaceholderDetector` so the
dashboard can show where a secret surfaces (Authorization header, basic
auth, cookie, `?password`). There's no protocol surface.

**Proposal.** A **static declaration** in `CredentialMetadata` listing
placeholder locations (header names / query keys / body markers). No
runtime hook — the dashboard renders it directly. Cheapest possible fix.

---

## Security model (invariants that do not change)

* Sandbox is mandatory; `network = none` is the default; the plugin
  never receives the gateway's environment or secrets except the
  just-in-time `Secret` bound to the entity it is handling.
* The signed static manifest is authoritative; the running binary's
  manifest is consistency-checked at load; a mismatch fails closed.
* Low-risk capabilities (`network`, `egress`, `state`, `transform`,
  `approver`, built-in-family binding) are recorded trust-on-first-use;
  an upgrade that escalates beyond the recorded set fails closed until
  reapproved.
* High-risk grants (`exec`, `webhook_ingress`, `sandbox = off`) are
  operator-only, never plugin-declarable, recorded in the lockfile.

## Phasing (each milestone is a shippable PR)

1. **State service** (§1). Highest leverage, smallest surface; unblocks
   four built-ins and is a prerequisite for stateful endpoints.
2. **Generalized credential injection** (§2) — `TransformRequest`, typed
   `Secret` passthrough, brokered client cert.
3. **`sql` built-in family** (§4) — opt-in coarse SQL vocabulary, the
   only shared family. k8s/ssh/other endpoints use plugin-defined facets
   (already supported, no work).
4. **Approver plugins, synchronous** (§3a) — the LLM judge.
5. **HITL** (§3b) — notify / decide / webhook ingress. The big one;
   gated on the §3 open questions.
6. **Cleanup** — `exec` grant (§5), tunnel `via` (§6), placeholder
   hints (§7), facet `extends = "sql"` (§4 phase 2).

## Out of scope

* **Rules / matchers as plugins.** Rules are policy-layer HCL that
  reference facets and approvers; they are not a plugin Kind. A
  "matcher plugin" could be revisited later but is not part of parity
  with the built-ins (none of which are pluggable rules).
* **Replacing the core dispatch** (TLS-MitM, DNS-VIP, WireGuard). These
  remain gateway infrastructure, exposed only through the mediated
  primitives.

## Summary of new protocol surface

| Service / message | Purpose | Mirrors |
|---|---|---|
| `State.Get/Put/Delete` | persistent per-plugin bytes | `runtime.BlobStore` |
| `Credential.TransformRequest` | URL/body/header mutation, full body | `InjectHTTP` superset |
| `DialUpstreamRequest.client_cert` | upstream mTLS | `Secret.Extras` |
| `ApproverDecl` + `Approver.Approve` | approver plugins | `runtime.ApproverRuntime` |
| HITL `Notify` / `Decide` / webhook ingress | human approval | `HITLNotifier` / `HITLPool` |
| `sql` built-in family (opt-in) | reuse shared `sql.*` rules | `match.Request` mapping |
| `FacetDecl.extends = "sql"` | facet composition (phase 2) | built-in facet composition |
| `exec` capability (operator-only) | spawn host binaries | sandbox profile |
| `via_tunnel_handle` | chained tunnels | built-in `via` |
| `CredentialMetadata` placeholder decl | dashboard hint | `PlaceholderDetector` |
