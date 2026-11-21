# Design: reviewer plugins (approvers and human-in-the-loop as one shape)

Status: proposal for #703 (plugin protocol milestones M4 and M5) and
the plugin-parity goal in #833. Nothing here is built. The shape was
arrived at by putting three candidates through a two-round design
debate with a second reviewer; the alternatives and the reasons
they lost are kept below.

## Goal and constraints

Every integration that sits "in the loop" of an approval must be
expressible as an external plugin: an LLM judge, a Slack or Signal
prompt with or without buttons, a Telegram bot, and the dashboard
itself. Constraints set by the product owner:

1. One plugin shape for "LLM in the loop" and "human in the loop".
   In principle they expose the same API; the difference is who
   answers and how long it takes.
2. Every built-in must be expressible against it: `llm_approver`
   (judge and prompt summariser), `human_approver` with
   `slack_tokens` (interactive buttons via a webhook) or `signal_cli`
   (dashboard link, no buttons), and `dashboard`.
3. Async approvals (an operation that outlives the request, with
   retry grants) do not work well even for the built-ins. If
   carrying them adds a lot, leave them out of the plugin interface.
4. Elegant, simple, future-proof. Prefer adding to existing services
   over new ones. Decision authority and secrets stay in the gateway.
   No plugin-declarable public ingress without an operator grant.

## How the built-ins work today (facts the design rests on)

- A rule's `approve = [...]` chain runs synchronously in the gateway;
  each stage returns allow, deny, or undecided, and undecided goes
  through the stage's fail mode. All stages must allow.
- `dashboard` adds a pending entry to the gateway's HITL pool and
  waits. `human_approver` does the same, optionally asks an
  `llm_approver` for a summary (`HITLClassifier`), then calls
  `NotifyHITL` on a *credential* that implements `HITLNotifier`, and
  waits. On sync timeout it can park the request as an async
  operation with its own state machine and retry grants.
- `slack_tokens` posts the prompt and registers a webhook route the
  gateway mounts at a public path; the handler verifies Slack's HMAC
  with a credential slot and resolves the pending entry. `signal_cli`
  posts a dashboard link and, if configured, deletes the prompt when
  the operation is decided (`HITLMessageUpdater`).
- The pool is the record: the dashboard can decide any pending entry;
  the first accepted decision wins. `require_approvers` is parsed but
  not enforced.
- Plugins run sandboxed with no network of their own. They reach
  upstreams only through gateway-brokered dials
  (`HostTunnel.DialUpstream`, keyed by an unguessable per-tunnel
  token) with the just-in-time secret of the entity they handle. An
  approver plugin has no such path today; that is a prerequisite.

## Shapes considered

**A. Mirror the built-ins.** A plugin-served `Approver` service with
`Approve` (sync judge), `Notify` (post a prompt), `Update` (edit on
state change), plus `HostControl.Decide` for the plugin to resolve a
pending entry, plus a gateway-mounted ingress. Rejected: it is three
unrelated optional interfaces sharing a service name, keeps the
human/LLM split and the notifier-as-credential split, cannot express
the classifier summary, and `Decide` hands plugins a globally
addressable pool mutation whose caller (a Slack callback) arrives
outside any session.

**C. Pool-centric, stateless handlers.** Plugin implements only
`Notify`; it answers later through `HostControl.Decide`; the gateway
pushes state through `Update`. Rejected: the trivial judge becomes
two hops with "no answer until timeout" as its only error signal,
the classifier is still inexpressible, and the promised "async for
free" is false because durable operations need the separate SQLite
state machine regardless.

**B. One reviewer stream.** Chosen, with modifications from the
debate. The rest of this note is B.

## The shape

One plugin-served RPC:

```
service Approver { rpc Review(stream ReviewFrame) returns (stream ReviewFrame); }
```

The gateway opens one `Review` stream per approval stage (and one
per summary request). It sends `ReviewStart`; the plugin answers
with a `ReviewVote` whenever it can: immediately (an LLM), or after a
human acted (a Slack click, delivered to the plugin through ingress),
or never (Signal, which waits for the dashboard). The gateway then
sends exactly one terminal `ReviewResolution`, gives the plugin a
short window to edit or delete its message, and closes.

Gateway-owned, always:

- the pending entry (for operator-decidable reviewers), its id,
  deadline and expiry;
- resolution: the first verdict accepted atomically wins, whether it
  came from the plugin, the dashboard, or the deadline;
- ownership checks: a callback's proposed vote applies only to a
  pending entry owned by the same plugin and approver instance;
- audit of every vote, accepted or rejected;
- secrets: the bound credential's material is sent just-in-time in
  `ReviewStart` and `IngressRequest`, never stored by the plugin;
- egress: a review-scoped dial token the plugin presents to
  `HostTunnel.DialUpstream`.

Plugin-owned:

- rendering the provider message and remembering its reference for
  the life of the stream;
- talking to the provider or model over the brokered dial;
- verifying provider callbacks (HMAC, bot tokens) and mapping them to
  a proposed vote;
- editing or deleting its message when the resolution arrives.

Three decisions from the debate:

1. **Reuse `HostTunnel.DialUpstream` for egress.** It is already a
   token-scoped byte transport. The route registry generalises from
   "token → parent tunnel" to "token → dial capability" (allowed
   destinations, direct or via-tunnel routing, TLS policy, expiry,
   owning instance). `DialInit` gains `dial_token`, `tls` and
   `tls_server_name`; tunnel clients keep using `tunnel_handle`. A
   second dial stream on `HostControl` would duplicate the framing
   for nothing.
2. **No `HostControl.Decide`.** Ingress returns a *proposed* vote to
   the gateway, which validates ownership and applies it. Plugins
   never mutate the pool.
3. **Quorum is out of v1.** `ReviewVote` carries `actor_id` for
   audit; `require_approvers` other than 1 is a validation error
   rather than silently ignored. "Deny wins after allow" is not a
   coherent terminal rule without an aggregation window, so it
   waits for a real quorum design that can add tally frames without
   changing `ReviewVote`.

### Manifest and orchestration modes

```
message ApproverDecl {
  string type_name = 1; Schema schema = 2;
  bool operator_decidable = 3;      // gateway creates a dashboard-visible pending entry
  bool supports_summarize = 4;      // can serve REVIEW_SUMMARIZE
  repeated string ingress_routes = 5; // advertised only; the operator grants
}
```

One wire shape, two orchestration modes chosen by the manifest:

- **automatic** (`operator_decidable = false`, an LLM judge): no
  pending entry; the plugin's vote is the stage result. A dashboard
  operator cannot pre-empt a model, and the HITL panel is not
  polluted with machine reviews.
- **operator-decidable** (Slack, Signal, dashboard): the gateway
  creates the pending entry before opening the stream; the dashboard
  and the plugin's proposed votes race for the first accepted
  decision.

### Common attributes stay with the gateway

`credential`, `classifier`, `timeout`, `fail_mode` and
`require_approvers` are framework attributes peeled off every
`approver` block before the plugin's schema is decoded, exactly like
`via`/`share`/`credential` on tunnels. The classifier reference is an
approver instance whose plugin declares `supports_summarize`; the
gateway runs it first with `purpose = REVIEW_SUMMARIZE` and passes the
result as `input_summary`. A failed summary is a warning, never a
verdict.

### v1 proto

```
service Plugin {
  rpc Manifest(ManifestRequest) returns (ManifestResponse);
  rpc Build(BuildRequest) returns (BuildResponse);
  rpc HandleIngress(IngressRequest) returns (IngressResponse);
}
service Approver { rpc Review(stream ReviewFrame) returns (stream ReviewFrame); }

message ManifestResponse { /* existing fields 1-7 */ repeated ApproverDecl approvers = 8; }

enum ReviewPurpose  { REVIEW_DECIDE = 0; REVIEW_SUMMARIZE = 1; }
enum ReviewDecision { REVIEW_DECISION_UNSPECIFIED = 0; REVIEW_ALLOW = 1; REVIEW_DENY = 2; }
enum ReviewOutcome  { REVIEW_OUTCOME_UNSPECIFIED = 0; REVIEW_RESOLVED = 1; REVIEW_TIMED_OUT = 2; REVIEW_CANCELED = 3; }

message ReviewFrame {
  oneof frame { ReviewStart start = 1; ReviewVote vote = 2;
                ReviewSummary summary = 3; ReviewResolution resolution = 4; }
}
message ReviewStart {
  string type_name = 1; string instance = 2; bytes canonical_json = 3;
  ReviewPurpose purpose = 4; bytes action_json = 5; RequestView request = 6;
  int64 deadline_unix_ms = 7; string pending_id = 8; string dashboard_url = 9;
  ReviewSummary input_summary = 10; BoundCredential credential = 11;
  string dial_token = 12;
}
message RequestView {
  string profile = 1; string agent_ip = 2; string endpoint = 3; string family = 4;
  string rule = 5; string method = 6; string host = 7; string path = 8;
  string ua = 9; string body_sample = 10; string reason = 11;
  string thread_ts = 12; string notify_channel = 13;
}
message ReviewVote       { ReviewDecision decision = 1; string reason = 2; string actor_id = 3; }
message ReviewSummary    { string subject = 1; string label = 2; uint32 confidence = 3; string text = 4; }
message ReviewResolution { ReviewOutcome outcome = 1; ReviewDecision decision = 2; string reason = 3; string actor_id = 4; }

message IngressRequest {
  string type_name = 1; string instance = 2; bytes canonical_json = 3; string route = 4;
  string method = 5; string path = 6; map<string, HTTPHeaderValues> headers = 7;
  bytes body = 8; BoundCredential credential = 9; string dial_token = 10;
}
message IngressVote     { string pending_id = 1; ReviewVote vote = 2; }
message IngressResponse { uint32 status = 1; map<string, HTTPHeaderValues> headers = 2; bytes body = 3; IngressVote proposed_vote = 4; }

message DialInit { string tunnel_handle = 1; string network = 2; string addr = 3;
                   bool tls = 4; string tls_server_name = 5; string dial_token = 6; }
```

Direction rules are strict and enforced: the gateway sends `start`
and at most one `resolution`; the plugin sends votes (DECIDE) or one
summary (SUMMARIZE); a vote may only be ALLOW or DENY; the plugin
never treats its own vote as final, it waits for `resolution`.

### Parity: the same contract in-process

The gateway's reviewer runner drives one internal interface. The
external-plugin adapter is one implementation (it speaks `Review`
over gRPC); the built-ins are re-expressed as in-process ones. This
is the proof that every built-in could be a plugin.

```go
type Reviewer interface {
    Review(ctx context.Context, start ReviewStart, host ReviewHost) error
}
type ReviewHost interface {
    Emit(ReviewEvent) error                              // vote or summary
    Recv(ctx context.Context) (ReviewResolution, error)  // the gateway's terminal answer
    Dial(ctx context.Context, req DialRequest) (net.Conn, error)
}
type IngressReviewer interface {
    HandleIngress(ctx context.Context, req IngressRequest, dial ReviewDialer) (IngressResponse, error)
}
```

| Built-in | As a reviewer |
| --- | --- |
| `llm_approver` | dial the model; emit a vote (DECIDE) or a summary (SUMMARIZE); wait for resolution |
| `human_approver` + `slack_tokens` | post with buttons whose value is `pending_id`; keep the message ref in the stream's scope; `HandleIngress` verifies the HMAC and returns the proposed vote with Slack's user id as actor; edit the message on resolution |
| `human_approver` + `signal_cli` | post the dashboard link; wait; delete on resolution if configured; no ingress |
| `dashboard` | emit nothing; wait for resolution |

What the runner takes over from today's built-ins: the pending entry,
the classifier call, timeouts, and the message-ref sinks. Message
references become reviewer-local and live only as long as the stream.

### HCL

```hcl
plugin "slack-review" {
  source  = "github.com/example/clawpatrol-slack"
  version = "~> 1.0"
  ingress = ["ops/interactive"]        # explicit grant; advertisement alone mounts nothing
}
plugin "llm-review" {
  source  = "github.com/example/clawpatrol-llm"
  version = "~> 1.0"
}

credential "slack_tokens" "slack-bot" {}
credential "anthropic_manual_key" "judge-key" {}

approver "llm_reviewer" "risk-judge" {   # automatic
  credential = judge-key
  timeout    = "30s"
  fail_mode  = "closed"
  model      = "claude-haiku-4-5-20251001"
  policy     = "Allow routine reads; deny credential or billing changes."
}

approver "slack_reviewer" "ops" {        # operator-decidable
  credential  = slack-bot
  classifier  = risk-judge
  timeout     = "10m"
  channel     = "#agent-approvals"
  interactive = true
}

rule "sensitive-write" {
  endpoint  = production-api
  condition = "http.method in ['POST', 'PUT', 'DELETE']"
  approve   = [risk-judge, ops]
}
```

The ingress route is mounted at `/api/plugin/<plugin>/<route>` only
when the `plugin` block grants it. A Slack operator pastes that URL
into the app's interactivity settings, as with the built-in today.

### Flows

Dashboard decides first: the operator's decision is accepted as the
terminal resolution, the chain continues or stops, the plugin
receives `resolution` and edits its message, later provider votes are
stale.

Slack click: Slack posts to the granted route; the gateway forwards
the capped body, headers, approver config and the bound credential
to `HandleIngress`; the plugin verifies the HMAC and returns the
HTTP response plus `IngressVote{pending_id, vote}`; the gateway
checks ownership and replay, applies the vote if it is first, and
sends `resolution` on the open stream; the plugin edits the message.
The callback path holds no plugin state.

Telegram (long-polling `getUpdates`): polling is per approver
instance, not per review. The plugin runs one poll loop over the
brokered dial while any review for that instance is open, maps the
callback's `pending_id` to the live stream, and emits the vote
there. Its update offset can live in `HostState`. Webhook-mode
Telegram maps to `HandleIngress` like Slack.

Signal: post the dashboard link, wait, delete on resolution.

### Failure semantics (v1)

| Event | Outcome |
| --- | --- |
| plugin crashes mid-review | affected streams fail; pending entries with no accepted vote are canceled and removed; each stage applies `fail_mode`; dial tokens revoked |
| gateway restarts mid-review | reviews are not resumed; in-memory pending entries and streams are gone; client requests fail, nothing is sent upstream |
| stream closes with no vote before the deadline | immediate reviewer failure; do not wait for the deadline; cancel the entry; `fail_mode` |
| deadline passes | if it wins the atomic race: `TIMED_OUT`, entry removed, `resolution` sent within the cleanup window, `fail_mode` applied; later votes are stale |
| dashboard decides first | terminal; plugin gets `resolution` for cleanup |
| Slack click after resolution | verified and parsed; rejected as stale; the plugin's 2xx is returned so Slack does not retry; audited as `accepted=false` |
| two clicks by one user | exactly one wins; the second is stale with the same 2xx |
| callback for a `pending_id` owned by another instance | rejected before application; 403 instead of the plugin's response; audited as an ownership violation |
| SUMMARIZE fails | warning; unsummarised review proceeds; no retry |

All of these contend on the one atomic pending-entry transition the
HITL registry already has.

## v1 scope

- `ApproverDecl` in the manifest and Build support.
- Gateway-owned `credential`, `classifier`, `timeout`, `fail_mode`;
  `require_approvers` accepted only when absent or 1.
- Automatic, operator-decidable, and dashboard reviewers through one
  `Review` contract; DECIDE and SUMMARIZE purposes.
- Gateway-owned pending ids, deadlines, resolution, ownership checks
  and audit.
- Stateless ingress returning a proposed verdict, behind an explicit
  per-route operator grant on the `plugin` block.
- Brokered, allow-listed TCP/TLS egress through
  `HostTunnel.DialUpstream` with review-scoped tokens.
- Best-effort provider message cleanup while the stream is alive.
- Built-ins migrated to the same internal runner interface.

## Non-goals (v1)

- Multi-actor quorum, or deny overriding an accepted allow.
- Durable or resumable reviews across gateway or plugin restarts.
- Async retry grants and request replay; execution lifecycle states
  (executing, succeeded, failed) on the stream.
- Persisted provider message references and post-restart cleanup.
- A gateway polling API for decisions.
- Re-attaching a replacement plugin process to an existing review.
- `HostControl.Dial`, `HostControl.Decide`, or any pool-mutation RPC.

## Phasing

1. **M4a, in-process:** the reviewer runner and `Reviewer` interface;
   `llm_approver`, `human_approver`+notifiers and `dashboard`
   re-expressed against it; behaviour unchanged for operators. This
   is the parity proof and is testable without the wire.
2. **M4b, wire:** `ApproverDecl`, `Approver.Review`, review-scoped
   dial tokens on `HostTunnel.DialUpstream`, SDK `ApproverDef`; an
   external LLM reviewer as the first plugin.
3. **M5, ingress:** `plugin { ingress = [...] }`, `Plugin.HandleIngress`,
   the Slack reviewer plugin; then `slack_tokens` and `signal_cli`
   notifier code leaves core.

## Top risks and mitigations

1. **Restart loss.** Defined as v1 semantics: request-lifetime only,
   fail closed on stream loss. Resumable reviews come with the future
   durable-operation design, if ever.
2. **Ingress as a confused deputy.** Exact per-route grants; body,
   header and time limits; just-in-time credential of the instance
   only; ownership check on the proposed vote; rate limit and audit.
3. **Egress broadening `HostTunnel`.** Per-review random tokens, short
   expiry, exact destination allow-lists derived from the credential
   and approver config, gateway-side TLS verification, byte and time
   caps, no reach into another review's context.
4. **Actor identity.** Namespaced by plugin, instance and provider;
   stable provider user ids; audit-only in v1, so a forged actor gains
   nothing a plugin could not already do by voting.
5. **The stream degrading into an event bag.** A published state
   machine, enforced direction and ordering, reserved field numbers,
   and SDK conformance tests for: LLM, Slack, Signal, dashboard,
   classifier failure, timeout, callback race, duplicate click.

## Decisions for the product owner

1. `operator_decidable` as manifest metadata (proposed) versus an HCL
   attribute per approver instance.
2. Ingress grant syntax on the `plugin` block, and whether granted
   routes are listed on the dashboard.
3. Whether M4a (migrating the built-ins) ships before or together
   with M4b (the wire).
4. Where the egress allow-list for a reviewer comes from: the
   credential type's declared hosts, an explicit `plugin` grant, or
   both.
