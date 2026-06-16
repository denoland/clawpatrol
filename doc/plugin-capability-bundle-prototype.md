# Plugin capability bundle — prototype + recommendation

Status: **prototype / RFC.** A working spike lives behind this doc
(`internal/config/extplugin/hostcontrol.go` + `_test.go`); it is not
wired into the live request path.

## Why

A comparison with `unclaw`'s plugin model (in-process TS) surfaced a real
smell in clawpatrol's gRPC plugin protocol: it is accreting a **new
bespoke RPC + a new `*Init` message per capability**, and the
plugin→gateway *callbacks* are hand-rolled as request/reply frames
multiplexed inside the `HandleConn` stream with manual correlation.

Concretely, two kinds of redundancy:

1. **Three near-identical streaming RPCs** — `Endpoint.HandleConn`,
   `Credential.TransformHTTP`, `Tunnel.Dial` — each re-inventing an init
   message, a body-chunk type, an eof/close convention, and (on the Go
   side) its own dual-pump goroutines.
2. **Hand-rolled callback correlation.** A plugin asking the gateway to
   rule on an action sends an `EvaluateAction{call_id}` frame and later
   matches an `ActionVerdict{call_id}` reply; a brokered dial does the
   same with `dial_id`. Both sides keep an inflight map keyed by that id.
   ~30 lines of correlation bookkeeping that gRPC would do for free.

`unclaw` has neither: one `Endpoint` interface (layered `conn`/`tls`/
`fetch` hooks over one `DuplexStream`) and one `EndpointFn` **capability
bundle** object the host hands the plugin (`fetch`, `connectTcp`,
`connectTls`, `session.approval`, `buffer`). A new capability is a method
on that object, not a new message.

clawpatrol can't *be* unclaw — its plugins are out-of-process and
sandboxed on purpose (untrusted code, secrets, provenance), so it needs a
wire protocol. But it can port the two ideas that survive the process
boundary: a **capability bundle** and a **shared session substrate**.

## The design

Split the protocol into two planes:

### Control plane — the capability bundle (`HostControl`)

A host-served gRPC service the plugin calls over the **same broker** the
state service (M1) already uses. Each plugin→gateway callback becomes an
ordinary method:

```proto
service HostControl {
  rpc Evaluate(EvaluateRequest) returns (EvaluateVerdict);
  // future: Dial(stream ...) returns (stream ...);  // brokered dial
  //         Approve(ApproveRequest) returns (ApproveVerdict);  // M4/M5
}
```

gRPC correlates the response to the call — the `call_id`/`dial_id` maps
disappear. A new capability (the M4/M5 approver, a HITL prompt) is a new
method here, **not** a new frame in `HandleConn`.

The one new thing a separate channel needs that a multiplexed stream got
implicitly: a **session token** scoping a control call to one
connection's evaluation context (its rules, approve chain, peer info).
The gateway issues it in the session init; the plugin echoes it back; a
`sessionRegistry` maps it to the connection's evaluator. A forged or
expired token is rejected, so a plugin can't evaluate against a context
it doesn't own.

### Data plane — one session substrate (later)

The three streaming RPCs collapse to one:

```proto
rpc Session(stream HostToPlugin) returns (stream PluginToHost);
// HostToPlugin = oneof { SessionInit init; ByteChunk data }
// SessionInit  = InstanceContext ctx + oneof role { Endpoint; Transform; Tunnel }
```

One init carries a shared `InstanceContext{type_name, instance,
canonical_json}` + `CredentialBinding{secret, extras}` (killing the
per-`Init` field redundancy), then raw bytes. One dual-pump
implementation instead of three. The control frames that bloat
`HandleConn` today (`EvaluateAction`, `DialUpstream`, `StreamRead`) move
to the control plane, leaving the data plane as just bytes.

## What the spike proves

`hostcontrol.go` + `hostcontrol_test.go` implement `HostControl.Evaluate`
end to end over a **real go-plugin broker** (the M1 test harness):

- The plugin runs a rule evaluation with **one gRPC call** —
  `ctrl.Evaluate(ctx, req)` — no frame, no `call_id`, no inflight map.
- The gateway routes it to the connection's evaluator by session token.
- A forged token and a removed (connection-ended) token are both
  rejected.

### Before / after (the `Evaluate` callback)

Today, on the SDK side (`pluginsdk/server.go`), `Conn.Evaluate`:

```go
callID := fmt.Sprintf("c%d", callSeq.Add(1))
ch := make(chan *pb.ActionVerdict, 1)
inflightMu.Lock(); inflight[callID] = ch; inflightMu.Unlock()
defer func() { inflightMu.Lock(); delete(inflight, callID); inflightMu.Unlock() }()
doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_Evaluate{Evaluate: &pb.EvaluateAction{
    CallId: callID, FacetName: facet, ActionJson: j, Summary: summary, ...}}})
select {
case v := <-ch: return Verdict{Action: v.Action, ...}, nil
case <-ctx.Done(): ...
case <-closed: ...
}
```

plus a recv-loop branch on the gateway side that matches `Verdict.CallId`
back to the channel, and a symmetric inflight map. With `HostControl`:

```go
v, err := ctrl.Evaluate(ctx, &pb.EvaluateRequest{
    SessionToken: tok, FacetName: facet, ActionJson: j, Summary: summary})
```

The correlation, the channels, and the recv-loop branch are gone.

## Cost / blast radius

- The **data-plane unification** touches `HandleConn` — shipped and load
  bearing (#681) — and every plugin. High risk, mostly-internal payoff.
  Not worth doing reactively.
- The **control-plane capability bundle** is incremental: it rides the
  broker M1 already established, and it does **not** require touching
  `HandleConn` — a connection can keep its existing data stream and *also*
  register a session token for control calls. The migration of the
  existing `EvaluateAction`/`DialUpstream` frames can happen later,
  opportunistically.

## Recommendation

**Adopt the capability bundle (`HostControl`) as the home for new
callbacks now; do not rewrite the shipped streaming RPCs yet.**

The accretion this whole exercise is worried about happens *next*, in
M4/M5 (approver + HITL): those are exactly plugin→gateway callbacks that,
under the current pattern, would each add new frames and new correlation.
Built on `HostControl` they are just methods — `Approve(...)`,
`NotifyHITL(...)` — reusing the broker, the session-token scoping, and
gRPC's correlation.

So:

1. **Now:** land `HostControl` as the control-plane channel (this spike,
   hardened). Wire the session-token registration into the endpoint path
   so `Evaluate` can move off the `HandleConn` frame at our leisure.
2. **M4/M5:** build the approver and HITL callbacks as `HostControl`
   methods from the start — no new frames.
3. **Later / optional:** migrate `EvaluateAction` and `DialUpstream` off
   `HandleConn` onto `HostControl`, then collapse the three streaming RPCs
   into one `Session`. Pure internal cleanup, done deliberately.

This banks the architectural lesson exactly where the next growth is,
without destabilizing shipped, sandboxed code — which is the point of
pausing to prototype before going further.

## Open questions

- Session-token issuance: random per connection, or derive from an
  existing handle? Lifetime/cleanup tie-in with the connection.
- Does `Dial` (a streaming, bidirectional capability) fit cleanly as a
  `HostControl` streaming method, or does it argue for keeping some
  callbacks on the data stream?
- For `Evaluate`, the per-call context deadline and the existing
  approve-chain blocking (HITL) behavior must carry over unchanged.
