# External plugin control plane

How a sandboxed external plugin and the gateway call each other, and why
the plugin→gateway callbacks are host-served gRPC methods (`HostControl`)
rather than frames multiplexed inside the connection stream.

## The problem

External plugins run out-of-process and sandboxed on purpose — they are
untrusted code that the gateway hands secrets to — so the gateway and a
plugin talk over gRPC. Two directions of call exist:

- The gateway calls the plugin: terminate this connection (`HandleConn`),
  transform this request (`TransformHTTP`), …
- The plugin calls the gateway back: rule on this action (`Evaluate`),
  open this upstream (brokered `Dial`), persist these bytes (`State`), …

The plugin→gateway callbacks started life as request/reply **frames
multiplexed inside the `HandleConn` byte stream**, each correlated by a
hand-rolled id: the plugin sends `EvaluateAction{call_id}` and later
matches an `ActionVerdict{call_id}`; a brokered dial does the same with
`dial_id`. Both sides keep an inflight map keyed by that id. Every new
capability (an approver, a HITL prompt) would add another bespoke frame
and another correlation map — bookkeeping gRPC does for free.

## Design goals

1. **Every cross-process call is an ordinary gRPC method.** gRPC
   correlates each reply to its call, so the `call_id`/`dial_id` inflight
   maps disappear and a new capability is a new *method*, not a new frame.
2. **Two clean directions, each its own gRPC surface.** plugin→host is the
   gateway's host-served control plane; host→plugin is the plugin's own
   services. Don't conflate them onto one object.
3. **Standard mechanisms over ad-hoc fields.** Cross-cutting concerns
   (which connection a call belongs to) ride in gRPC metadata resolved by
   an interceptor, not a token field repeated on every message.
4. **Mirror the gateway's in-process contracts.** The plugin-facing
   surface mirrors the interfaces the built-in plugins already use
   (`BlobStore`, the verdict/approve types, …) so the external and
   built-in paths converge instead of diverging.
5. **Works for any plugin type.** An endpoint, a credential, or an
   approver all reach the same host services for the capabilities they
   need.
6. **No weakening of the sandbox.** A plugin keeps `network = none`;
   every new power is gateway-brokered (the gateway holds the socket, the
   secret store, the rule list), so a compromised plugin can't reach past
   what it was granted.

## Two directions

| Direction | What it is | Where it lives | Examples |
|---|---|---|---|
| **plugin → host** | the plugin calls the gateway | host-served services over the broker (`HostControl`, `HostState`) | `Evaluate`, brokered `Dial`, HITL `Decide`, `State` |
| **host → plugin** | the gateway calls the plugin | the plugin's own gRPC services | `Endpoint.HandleConn`, `Credential.TransformHTTP`, `Approver.Approve`, `Approver.Notify` |

The split matters because the two directions have different homes and
both grow. A plugin→host capability is a method on `HostControl`; a
host→plugin capability is a method on a plugin-served service. Neither is
a new frame. And because the host-served side is shared, any plugin type
reaches it.

This is what makes the M4/M5 work fall out cleanly. The approver and HITL
callbacks map onto existing gateway interfaces, and the *direction* of
each decides its home:

| Callback | mirrors | direction | home |
|---|---|---|---|
| rule on an action | the match + approve chain | plugin→host | `HostControl.Evaluate` |
| resolve a pending HITL id | `HITLPool.Decide` | plugin→host | `HostControl.Decide` |
| LLM judge | `ApproverRuntime.Approve` | host→plugin | plugin-served `Approver.Approve` |
| post the prompt (Slack) | `HITLNotifier.NotifyHITL` | host→plugin | plugin-served `Approver.Notify` |
| edit the posted prompt | `HITLMessageUpdater.UpdateHITLMessage` | host→plugin | plugin-served `Approver.Update` |

So only `Decide` is a `HostControl` method; `Approve`/`Notify`/`Update`
are a separate plugin-served `Approver` service. A sketch of both is at
the end.

## How it is put together

### Host services over one broker stream

The gateway serves two host-side services over the go-plugin broker on a
single reserved stream id; the plugin dials it once and builds both stubs
over that one connection:

```proto
service HostState   { rpc Get(...); rpc Put(...); }          // persistent bytes
service HostControl {
  rpc Evaluate(EvaluateRequest) returns (EvaluateVerdict);
  // grows plugin→host only: Dial(stream) for brokered dial, Decide(...) for HITL
}
```

`HostState` is plugin-lifetime persistence; `HostControl` is
connection-scoped control. Keep it to these two services and add
*methods*, not services.

### Session scoping in metadata, resolved by an interceptor

A `HostControl` call must run against the right connection's evaluation
context (its rules, approve chain, peer). The gateway mints an opaque
`crypto/rand` token per connection, registers that context under it, and
hands the token to the plugin in `ConnInit`. The plugin echoes it back as
request **metadata** (`clawpatrol-session`), and a server interceptor
resolves it once into the handler's context:

- Messages stay payload-only; a new method is scoped for free.
- The token is minted by the gateway, never taken from the wire, and the
  registry is per-plugin — so it is unforgeable and never valid across
  plugins. A forged, unknown, or removed token is rejected
  (`Unauthenticated`) before the handler runs.
- The token is registered when the connection starts and removed when it
  ends, so no evaluation context dangles.

### One evaluate core, two callers

The legacy `EvaluateAction` frame handler and the `HostControl` session
closure run the **same** `evaluateDecoded` core (decode → match → approve
chain → emit the audit event). Verdicts are therefore identical by
construction, whichever path a call took.

### The SDK chooses the path

`Conn.Evaluate` sends the action over `HostControl` (token threaded into
metadata by the SDK; plugin authors never see it). The one case that
keeps the legacy frame is an action carrying **stream-valued fields** —
large bodies the gateway pulls lazily — since `HostControl.Evaluate`
carries no stream handles.

## Compatibility

- **Older plugins keep working** with no change: a plugin that still sends
  `EvaluateAction` frames is handled by the same frame handler (which also
  serves the stream-valued path), and it simply ignores the new
  `ConnInit.session_token`.
- **The SDK targets the current gateway.** It does not carry a fallback
  for a gateway without `HostControl`; the gateway always serves it and
  issues a token.

## Security invariants (unchanged)

- The sandbox is mandatory and `network = none` is the default; a plugin
  receives only the just-in-time secret bound to the entity it is
  handling.
- Decision authority stays in the gateway: a plugin *requests* a verdict
  or a HITL decision; the gateway's rule engine and HITL pool own it.
- High-risk powers (mounting a public webhook route for HITL, spawning a
  host binary) remain operator-only grants, never plugin-declarable.

## M4 / M5 sketch — both directions

Concrete proto for the next milestones, so the direction split is visible
end to end. **Sketch only** — not in `plugin.proto` yet. Wire-only fields
are shown; the gateway-internal handles on the runtime structs (the pool,
the secret store, the compiled endpoint/rule) do not cross the boundary —
the plugin reaches that power through `HostControl` and its bound
credential.

### plugin → host: `HostControl` grows methods

```proto
service HostControl {
  rpc Evaluate(EvaluateRequest) returns (EvaluateVerdict);    // implemented
  // Brokered upstream dial as a method — removes the dial_id inflight map
  // the way Evaluate removed call_id, and shrinks the data plane to bytes.
  rpc Dial(stream DialChunk) returns (stream DialChunk);
  // HITL: a notifier (a Slack button) resolves a pending decision. The
  // gateway records it in the same pool the dashboard writes to.
  rpc Decide(DecideRequest) returns (DecideAck);
}
message DecideRequest { string operation_id = 1; string decision = 2; string reason = 3; }
message DecideAck     { bool resolved = 1; }
```

### host → plugin: a plugin-served `Approver` service

Same shape as the existing plugin-served `Endpoint` / `Credential`
services — the gateway is the client. Messages mirror the runtime
approver / HITL types.

```proto
service Approver {
  rpc Approve(ApproveRequest) returns (ApproveVerdict);   // LLM judge (sync)
  rpc Notify(NotifyRequest)   returns (NotifyAck);        // post the prompt
  rpc Update(UpdateRequest)   returns (UpdateAck);        // edit the prompt
}

message ApproveRequest {                 // wire subset of runtime.ApproveRequest
  string stage = 1; string rule_name = 2; string approver_name = 3;
  string profile = 4; string agent_ip = 5;
  string method = 6; string host = 7; string path = 8;
  string ua = 9; string body_sample = 10; string reason = 11;
  string async_operation_id = 12;
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

### Flow: LLM judge (synchronous)

1. A rule hits `approve = [llm.judge]`. The gateway calls
   `Approver.Approve` (host→plugin) with the request shape.
2. The plugin calls its model over `HostControl.Dial` (plugin→host,
   brokered) using a bound credential — no network of its own, egress
   audited — and returns `ApproveVerdict`.

### Flow: human approver over Slack

1. Rule hits `approve = [human.oncall]`. The gateway publishes a pending
   entry and calls `Approver.Notify` (host→plugin); the plugin posts to
   Slack and returns a `message_ref`.
2. An operator clicks Approve; the provider delivers the interaction to
   the plugin (a gateway-mounted ingress route — operator-granted).
3. The plugin calls `HostControl.Decide` (plugin→host) with the
   `operation_id`; the gateway records it in the shared pool.
4. The gateway calls `Approver.Update` (host→plugin) and the plugin edits
   the Slack message as the operation resolves.

Every callback is a plain gRPC method on the correct side — no frame, no
`call_id`, no inflight map, in either direction.
