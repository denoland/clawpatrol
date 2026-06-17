# Plugin capability bundle — design + prototype

Status: **prototype / RFC.** A working spike lives behind this doc
(`internal/config/extplugin/hostcontrol.go` + `_test.go`).

## Why

A comparison with `unclaw`'s plugin model (in-process TS) surfaced a real
smell in clawpatrol's gRPC plugin protocol: it accretes a **new bespoke
RPC + a new `*Init` message per capability**, and the plugin→gateway
*callbacks* are hand-rolled request/reply frames multiplexed inside the
`HandleConn` stream with manual correlation.

Two kinds of redundancy:

1. **Three near-identical streaming RPCs** — `Endpoint.HandleConn`,
   `Credential.TransformHTTP`, `Tunnel.Dial` — each re-inventing an init
   message, a body-chunk type, an eof/close convention, and its own
   dual-pump goroutines.
2. **Hand-rolled callback correlation.** A plugin asking the gateway to
   rule on an action sends an `EvaluateAction{call_id}` frame and later
   matches an `ActionVerdict{call_id}` reply; a brokered dial does the
   same with `dial_id`. Both sides keep an inflight map keyed by that id
   — correlation bookkeeping gRPC would do for free.

`unclaw` has neither: one `Endpoint` interface and one `EndpointFn`
**capability bundle** object the host hands the plugin (`fetch`,
`connectTcp`, `connectTls`, `session.approval`). A new capability is a
method on that object, not a new message.

clawpatrol can't *be* unclaw — its plugins are out-of-process and
sandboxed on purpose (untrusted code, secrets, provenance), so it needs a
wire protocol. But it can port the idea that survives the process
boundary: a **host-served capability bundle** reached over the same
go-plugin broker the state service (M1) already uses, where each
plugin→gateway callback is an ordinary gRPC method.

## Two directions — the framing that makes this work for every plugin type

The single most important thing to get right: there are **two distinct
call directions**, and they want different homes. Conflating them is the
trap.

| Direction | What it is | Home | Examples |
|---|---|---|---|
| **plugin → host** | the plugin calls the gateway | **host-served services** over the broker (the *capability bundle*) | `Evaluate`, brokered `Dial`, HITL `Decide`, `State` |
| **host → plugin** | the gateway calls the plugin | the plugin's **own gRPC services** | `Endpoint.HandleConn`, `Credential.TransformHTTP`, `Approver.Approve`, `Approver.Notify` |

`unclaw`'s `EndpointFn` is exactly the **plugin→host** direction. So the
capability bundle is the home for plugin→host calls — and *only* those.
The host→plugin calls are the plugin's own services; a new one there is
"add a method to the plugin's service," which gRPC also correlates for
free. The accretion this doc worries about exists in **both** directions
today (everything is multiplexed inside `HandleConn`); the fix is
**symmetric** — real gRPC methods each way — not "move everything onto
one host service."

This framing is what lets the bundle serve **multiple plugin types**: any
plugin entrypoint — an endpoint's `HandleConn`, a credential's
`TransformHTTP`, an approver's `Approve` — calls the *same* host-served
`HostControl` / `HostState` for the capabilities it needs.

### Consequence: the M4/M5 recommendation, corrected

An earlier draft said "build M4/M5 (approver + HITL) as `HostControl`
methods — `Approve(...)`, `NotifyHITL(...)`." That is **wrong by
direction.** Mapping M4/M5 onto the runtime interfaces they mirror:

| Callback | mirrors | direction | home |
|---|---|---|---|
| endpoint asks for a verdict | `match` + approve chain | plugin→host | **`HostControl.Evaluate`** |
| HITL resolve a pending id | `HITLPool.Decide` | plugin→host | **`HostControl.Decide`** |
| LLM judge | `ApproverRuntime.Approve` | **host→plugin** | plugin-served **`Approver.Approve`** |
| post the prompt (Slack) | `HITLNotifier.NotifyHITL` | **host→plugin** | plugin-served **`Approver.Notify`** |
| edit the posted prompt | `HITLMessageUpdater.UpdateHITLMessage` | **host→plugin** | plugin-served **`Approver.Update`** |

So **only `Decide` is a `HostControl` method.** `Approve` / `Notify` /
`Update` are a new **plugin-served `Approver` service**, exactly like
`Endpoint`/`Credential`. See the M4 sketch at the end.

## The design

### Control plane — the host-served bundle (`HostControl`)

A host-served gRPC service the plugin calls over the **same broker** the
state service (M1) serves on (`HostServicesBrokerID`). Each plugin→gateway
callback is an ordinary method; gRPC correlates the response, so the
`call_id`/`dial_id` inflight maps disappear.

```proto
service HostControl {
  rpc Evaluate(EvaluateRequest) returns (EvaluateVerdict);
  // grows plugin→host only:
  //   rpc Dial(stream DialChunk) returns (stream DialChunk);  // brokered dial
  //   rpc Decide(DecideRequest)  returns (DecideAck);          // HITL resolve
}
```

Two services on the one broker connection, split by responsibility — keep
it to these two; add **methods**, not services:

- **`HostState`** (M1) — plugin-lifetime persistent bytes.
- **`HostControl`** — connection-scoped control calls.

### Session scoping rides in gRPC **metadata**, not the message body

A separate channel needs the one thing a multiplexed stream got
implicitly: which **connection's** evaluation context (its rules, approve
chain, peer, secret scope) a call belongs to. The spike put a
`session_token` field on the request message. That is the ad-hoc choice;
the **standard** one is per-RPC **metadata + a server interceptor** —
session scope is a cross-cutting concern, exactly what metadata/auth
interceptors are for:

- The gateway issues an opaque, `crypto/rand` token in the connection's
  init and the plugin echoes it back as request metadata
  (`clawpatrol-session`).
- A **server interceptor** resolves the token → the connection's
  `session` object (its evaluator, and later its decide/dial context) and
  puts it in the handler's `context.Context`. A forged/expired/removed
  token is rejected (`Unauthenticated`).
- Method **messages stay payload-only.** Every *future* control method is
  scoped for free — no `session_token` to redeclare, no plugin-side field
  to remember to set. The SDK threads the token via a client interceptor,
  so the plugin author never sees it: `conn.Evaluate(...)` just works.

Per-plugin server isolation already holds (each plugin gets its own
`HostControl` instance + registry), so the token only disambiguates
**connections within one plugin** — and a token is never accepted across
plugins.

**Token lifetime:** minted per connection at `HandleConn` start,
registered in the per-plugin `sessionRegistry`, removed in its `defer` —
no dangling evaluation context.

### The registry holds a session object and returns a typed verdict

The spike's registry value was `func(...) (action, reason, rule string,
err error)` — a four-string return. Two fixes:

- The registry maps a token to a **`session` object**, not a single func.
  `Decide` and `Dial` will need the same connection context; don't
  hardcode it to "evaluate."
- `Evaluate` returns a **typed `Verdict{Action, Reason, Rule}`**
  (mirroring `runtime`/`pluginsdk.Verdict`), not a tuple.

### `action_json` stays JSON bytes

The facet payload rides as JSON bytes — the same bytes `EvaluateAction`
and M1/M2 already carry. Resist churning to `google.protobuf.Struct`
(clunky in Go, loses numeric fidelity); consistency beats novelty, and we
do not invent a new payload encoding per method.

### Data plane — defer the unification, but `Dial` is the wedge

The three streaming RPCs (`HandleConn` / `TransformHTTP` / `Tunnel.Dial`)
collapsing into one `Session` substrate is real but **high-risk,
mostly-internal** — it touches shipped, load-bearing code (#681) and every
plugin. Defer it.

But note: the *brokered upstream dial* a plugin makes is a **plugin→host**
streaming capability, so it belongs on `HostControl` as a bidi-stream
method — `rpc Dial(stream DialChunk) returns (stream DialChunk)`, scoped
by the session metadata. Moving it there kills the `dial_id` correlation
the same way `Evaluate` kills `call_id`, **and** it shrinks the data plane
to *just raw bytes per connection* — making the eventual `Session`
unification much smaller. So `HostControl.Dial` is the stepping stone, not
a separate project.

## What the spike proves

`hostcontrol.go` + `hostcontrol_test.go` implement `HostControl.Evaluate`
end to end over a **real go-plugin broker** (the M1 harness): the plugin
runs a rule evaluation with **one gRPC call**, the gateway routes it to
the connection's session via the metadata token, and a forged or removed
token is rejected. No frame, no `call_id`, no inflight map.

### Before / after (the `Evaluate` callback)

Today (`pluginsdk/server.go`), `Conn.Evaluate` allocates a `call_id`, a
reply channel, and an inflight-map entry, sends an `EvaluateAction` frame,
and `select`s on the reply channel — plus a symmetric recv-loop branch on
the gateway side matching `Verdict.CallId` back to the channel. With
`HostControl`:

```go
v, err := ctrl.Evaluate(ctx, &pb.EvaluateRequest{
    FacetName: facet, ActionJson: j, Summary: summary})   // token in metadata
```

The correlation, the channels, and both recv-loop branches are gone.

## Recommendation

**Adopt `HostControl` as the host-served (plugin→host) capability bundle
now; build the M4/M5 *host→plugin* callbacks as a plugin-served `Approver`
service; do not rewrite the shipped streaming RPCs yet.**

1. **Now:** land `HostControl` (this spike, hardened) — interceptor-based
   session scoping, typed verdict, session object, `crypto/rand` tokens —
   served on the broker next to `HostState`. Wire session
   registration into the endpoint path so `Evaluate` *can* move off the
   `HandleConn` frame at our leisure; keep the frame working meanwhile.
2. **M4/M5:** build `HostControl.Decide` (plugin→host) and the
   plugin-served `Approver` service (`Approve`/`Notify`/`Update`,
   host→plugin) — no new frames, no new correlation, in either direction.
3. **Later / optional:** move `Evaluate`/`Dial` off `HandleConn` onto
   `HostControl`, then collapse the three streaming RPCs into one
   `Session`. Pure internal cleanup, done deliberately.

This banks the architectural lesson where the next growth is, in both
directions, without destabilizing shipped, sandboxed code.

## Open questions

- `HostControl.Dial` as a bidi stream vs. keeping a raw byte stream on the
  data plane — both are gRPC streams; the bundle keeps the *correlation*
  uniform either way.
- `Evaluate`'s per-call deadline and the approve-chain (HITL) blocking
  behavior must carry over unchanged when it moves off the frame.
- Webhook ingress (M5) is host→plugin too (the gateway forwards an inbound
  HTTP request to the plugin) — a plugin-served `Approver` stream — but
  *mounting* the public route stays an operator-only grant.

## M4 / M5 sketch — both directions, end to end

Concrete proto for the next two milestones, so the corrected design is
visible end to end. **Sketch only** — not in `plugin.proto` yet; M4
implements the synchronous LLM `Approve`, M5 the human HITL
`Notify`/`Decide`/`Update`. Wire-only fields are shown; the
gateway-internal handles on the runtime structs (`Pool`, `Secrets`,
`Endpoint`, `Rule`, `*match.Request`) do **not** cross the boundary — the
plugin reaches that power through the bundle (`HostControl.Decide`) and
its bound credential, never as raw objects.

### plugin → host: `HostControl` grows methods (no new services)

```proto
service HostControl {
  rpc Evaluate(EvaluateRequest) returns (EvaluateVerdict);    // landed
  // Brokered upstream dial as a bundle method — kills the dial_id
  // inflight map the way Evaluate kills call_id, and shrinks the data
  // plane to raw bytes.
  rpc Dial(stream DialChunk) returns (stream DialChunk);      // M-later
  // HITL: a notifier (Slack button) resolves a pending decision. The
  // gateway records it in the same HITLPool the dashboard writes to, so
  // the plugin *requests* a decision, it never *owns* one.
  rpc Decide(DecideRequest) returns (DecideAck);             // M5
}
message DecideRequest {                  // mirrors HITLPool.Decide(id, d)
  string operation_id = 1;               // the pending entry id
  string decision     = 2;               // "allow" | "deny"
  string reason       = 3;
  // session token in metadata, as for every HostControl call.
}
message DecideAck { bool resolved = 1; } // false = id unknown / already decided
```

### host → plugin: a new plugin-served `Approver` service

Same shape as the existing plugin-served `Endpoint` / `Credential`
services — the gateway is the client. The proto messages mirror
`runtime.ApproveRequest` / `ApproveVerdict` / `HITLTarget` /
`HITLMessageUpdate`, minus the non-serializable handles.

```proto
service Approver {
  // M4: synchronous judge (LLM). The plugin reads the request shape,
  // calls its model via a BOUND credential over a brokered dial (so it
  // needs no network of its own), and returns a verdict.
  rpc Approve(ApproveRequest) returns (ApproveVerdict);
  // M5: post the prompt to a channel (Slack chat.postMessage). Returns a
  // non-secret message ref for later edits. Mirrors HITLNotifier.NotifyHITL.
  rpc Notify(NotifyRequest) returns (NotifyAck);
  // M5: edit the posted prompt as the operation resolves. Mirrors
  // HITLMessageUpdater.UpdateHITLMessage.
  rpc Update(UpdateRequest) returns (UpdateAck);
}

message ApproveRequest {                 // wire subset of runtime.ApproveRequest
  string stage = 1; string rule_name = 2; string approver_name = 3;
  string profile = 4; string agent_ip = 5;
  string method = 6; string host = 7; string path = 8;
  string ua = 9; string body_sample = 10; string reason = 11;
  string thread_ts = 12; string notify_channel = 13;
  string async_operation_id = 14;
  // Pool / Secrets / Endpoint / Rule / Request are NOT here — see above.
}
message ApproveVerdict { string action = 1; string reason = 2; }

message NotifyRequest {                  // wire subset of runtime.HITLTarget
  string operation_id = 1; string channel = 2; bool interactive = 3;
  string dashboard_url = 4; string thread_ts = 5;
  string method = 6; string host = 7; string path = 8; string approval_message = 9;
}
message NotifyAck { string message_ref = 1; }   // opaque channel/ts, non-secret

message UpdateRequest {                  // mirrors runtime.HITLMessageUpdate
  string message_ref = 1; string operation_id = 2; string state = 3;
  string method = 4; string host = 5; string path = 6;
  bool upstream_called = 7; string last_error = 8;
}
message UpdateAck {}
```

### Flow: LLM judge (M4, synchronous)

1. An endpoint (or the gateway) hits a rule with `approve = [llm.judge]`.
2. The gateway calls **`Approver.Approve`** (host→plugin) with the request
   shape. The plugin needs no `Pool` — it decides synchronously.
3. The plugin calls its model. It has no network; it dials the model API
   over **`HostControl.Dial`** (plugin→host, brokered) using a **bound
   credential** the gateway injected — so the key never sits in plugin
   memory unredacted and the egress is audited.
4. The plugin returns `ApproveVerdict{action,reason}`. Done — one
   host→plugin call, one plugin→host call, both ordinary gRPC.

### Flow: human approver over Slack (M5)

1. Rule hits `approve = [human.oncall]`. The gateway publishes a pending
   entry in its `HITLPool` and calls **`Approver.Notify`** (host→plugin);
   the plugin posts to Slack and returns a `message_ref`.
2. An operator clicks **Approve**. Slack delivers the interaction to the
   plugin (via webhook ingress — host→plugin, operator-granted route).
3. The plugin calls **`HostControl.Decide`** (plugin→host) with the
   `operation_id`. The gateway records it in the **same pool** the
   dashboard writes to — the decision authority never leaves the gateway.
4. As the operation resolves, the gateway calls **`Approver.Update`**
   (host→plugin) and the plugin edits the Slack message.

Every callback is a plain gRPC method on the correct side. No
`HandleConn` frame, no `call_id`, no inflight map — in either direction.
That is the whole point of the bundle, and why the direction split
matters: `Decide` belongs on `HostControl`, but `Approve`/`Notify`/
`Update` are the plugin's own service.
