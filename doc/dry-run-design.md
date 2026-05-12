# clawpatrol — `clawpatrol test` design proposal

> **Status:** design / discussion. No implementation yet. Open
> questions in §3 must be resolved before code lands.

## Goal

Add a CLI subcommand that runs a candidate HCL policy against a
**recorded actions file** and reports any verdicts the new policy
would change:

```
clawpatrol test --config ./candidate.hcl --actions ./actions.json
```

The actions file is a list of recorded gateway actions. Each
entry carries the request the gateway saw and the verdict it
produced — `action` (`allow` / `deny` / `approve` /
`passthrough`), the name of the matched `rule`, and the
`reason`. Nothing in the format is test-specific: it is the same
shape the gateway logs for live traffic, just persisted to a
file.

`clawpatrol test` compiles the candidate config in-process, runs
each request through `runtime.MatchRequest`, and reports any
entry whose new verdict differs from the recorded one. Exit
status is non-zero on any diff.

To keep the authoring burden low, the dashboard grows a
**"Download actions"** button on its recent-actions view. The
button emits an actions file populated from the actions the
gateway has actually seen, each carrying the verdict it produced
under the live config. Operators run that file as-is to lock in
current behaviour, or edit individual entries to drive a policy
change.

The point is iteration speed and CI: today an operator changes a
rule, pushes a full config reload, watches live traffic, and
hopes. `clawpatrol test` makes the loop a `git diff` + one
command, with no gateway involvement and no auth.

## 1. What I read

Citations are file:line in `denoland/clawpatrol@main`.

### 1.1 Single policy-dispatch point exists

`runtime.MatchRequest(ep, req)` at `config/runtime/dispatch.go:45`
walks an endpoint's priority-sorted rule list and returns the
first match. The HTTPS / K8s path calls it at `main.go:1638`,
postgres at `config/plugins/endpoints/postgres.go:432`, and
clickhouse_native at
`config/plugins/endpoints/clickhouse_native_runtime.go:692`.
That's the entire surface this subcommand needs to drive.

A `match.Request` is plain data: `Family`, `Method`, `URL`,
`Headers`, `Body`, `PeerIP`, parsed path. It serializes cleanly
to JSON, which is what the actions-file format is built on.

### 1.2 Config compile is reusable from a CLI process

`loadConfig(path)` at `main.go:92` is `config.Load() +
config.Compile()`. `Compile()` (`config/compile.go:194`) returns
a fresh `*CompiledPolicy` with no global mutation, no DB, no
network. It is safe and cheap to call directly from a one-shot
CLI process — no gateway required.

### 1.3 The dashboard already renders an actions feed

The event sink (`web.go:1582`, `Sink` / `Event`) buffers the
last 500 actions in-memory and persists to SQLite. The
dashboard's `/api/state` and `/api/events` endpoints already
expose this stream, and `Event` carries most of what the
actions file needs: `Method`, `Path`, `ReqHeaders`, `ReqBody`,
`Host`, `Mode`, plus the produced verdict in `Action` +
`Reason`. The matched rule name is **not** currently on
`Event` — `MatchRequest` returns the `*CompiledRule` (which
has `.Name`), but the call sites at `main.go:1638` etc. drop
it before logging. A small extension of `Event` (`Rule string`)
populated at the existing dispatch sites is enough; no new
plumbing.

A "download these as an actions file" endpoint is then a
re-shape of an existing dataset, not a new pipeline.

### 1.4 Subcommand wiring

CLI subcommands live as a flat `switch os.Args[1]` in `main.go`
(around line 2000), each delegating to a `runFoo(args)` in a
sibling file (`run_linux.go`, `onboard.go`, etc.). Adding
`test` is a one-line switch case + a new `test.go`.

## 2. Proposed architecture

```
┌──────────────────────────────────┐    ┌──────────────────────────────┐
│  clawpatrol test                 │    │  gateway dashboard           │
│   --config candidate.hcl         │    │                              │
│   --actions actions.json         │    │  recent actions view         │
│                                  │    │  ┌────────────────────────┐  │
│  1. config.Load(candidate.hcl)   │    │  │ [Download actions]     │  │
│     + config.Compile()           │    │  └────────────────────────┘  │
│                                  │    │            │                 │
│  2. read actions.json            │    │            ▼                 │
│     → []Action{                  │    │  GET /api/actions/export     │
│         request: match.Request,  │    │   → ndjson over last N       │
│         verdict: Verdict,        │    │     events, each rendered    │
│       }                          │    │     as an Action             │
│                                  │    │     (request + verdict)      │
│  3. for each entry:              │◀───┤                              │
│       got := MatchRequest(...)   │    └──────────────────────────────┘
│       diff got vs verdict        │
│                                  │
│  4. print summary + exit code    │
└──────────────────────────────────┘
```

Concrete plumbing:

- **Actions format** (new): newline-delimited JSON, one entry
  per line. Same shape whether the file came from the dashboard
  exporter or was hand-written:
  ```
  {"request":{...match.Request...}, "verdict":{"action":"allow","rule":"public-readonly","reason":"..."}}
  ```
  - `verdict.action` is one of `allow`, `deny`, `approve`,
    `passthrough`. `approve` is terminal — the human approver
    chain is not invoked (§3.C).
  - `verdict.rule` is the name of the matched `CompiledRule`
    (`config/compile.go:165`), or empty when nothing matched
    and the endpoint default fired.
  - `verdict.reason` is the human-readable string the runtime
    produced.
  No `expected_*` / `assert_*` keys — the format is not
  test-specific. The CLI is the test runner; the file is
  recorded reality.
  ndjson because it streams cleanly, diffs cleanly, and the
  dashboard can emit it incrementally.
- **CLI** (`test.go`, new file): parses `--config`, `--actions`,
  optional `--endpoint` (which compiled endpoint to dispatch
  against — defaults to first matching by host), optional
  `--update` to rewrite the actions file with the new verdicts.
  No network, no auth, no gateway dependency.
- **Test runner**: a thin loop that calls `MatchRequest` per
  entry and compares the new verdict against the recorded one.
  Comparison: exact match on `verdict.action` and
  `verdict.rule`. Mismatches print a diff and bump the failure
  counter. `verdict.reason` is informational and not part of
  the comparison (it changes too freely under safe edits).
- **Dashboard endpoint**: `GET /api/actions/export` returns the
  ndjson form of the recent-events ring. The dashboard UI gets
  a "Download actions" button on the actions list that hits
  this endpoint and offers the result as a file download. Auth:
  same `dashboard_secret` as the rest of `/api/*` (§3.E).
- **Dashboard renderer**: for each `Event` in the export
  window, map fields → `request: match.Request` and
  `verdict: {action: ev.Action, rule: ev.Rule, reason:
  ev.Reason}`. This requires the small `Event.Rule` extension
  noted in §1.3. Output is "what the gateway actually
  decided" — a regression baseline.

This design removes everything that was hard about the previous
proposal: no session keying, no ephemeral peers, no response
synthesis, no whole-machine carve-out, no auth on a new gateway
endpoint, no TTL sweep, no live-traffic carve-out.

## 3. Open questions (please answer before code)

### A. Actions-file scope: per-endpoint or global?

`MatchRequest` is per-`CompiledEndpoint`. The actions file
either:

1. Pins each entry to an endpoint by name (or by host →
   endpoint resolution at run time), then dispatches into that
   endpoint's rule list. Mirrors how `MatchRequest` is actually
   called in production.
2. Walks endpoint resolution itself (host-based lookup against
   the compiled policy) before dispatching. Closer to "what
   would the gateway do end-to-end with this request?"

**Recommendation: (2)**, with each entry carrying the original
`Host` field. It matches what operators read on the dashboard
and what the export button can populate without extra metadata.
(1) is a fallback if some endpoint family doesn't fit clean
host-based lookup.

**Decision needed:** confirm (2), or do you want (1) for
explicit endpoint targeting?

### B. Which protocols / endpoint families?

HTTPS path is one `MatchRequest` call. Postgres and
clickhouse_native build their own `match.Request` from
protocol-level state before calling `MatchRequest` — same
dispatch primitive, different request synthesis.

**Recommendation:** v1 covers any endpoint family whose
`match.Request` is fully reconstructible from the data the
event sink already records. HTTPS qualifies trivially. SQL
plugins likely qualify (we already record `req_body` /
`req_sha`); confirm during implementation that the recorded
fields are sufficient for replay.

**Decision needed:** OK to ship HTTPS-first with SQL family
support landing in a follow-up bead if any field is missing?

### C. Approver-chain (HITL) verdicts in the actions file

A live `approve` verdict in production hands off to the human
approver chain, which ultimately produces an `allow` / `deny`.
Under `clawpatrol test`, invoking that chain is wrong (pages
humans, slow, non-deterministic).

**Resolved (per review):** both the recorded verdict and the
runner treat `approve` as terminal. The exporter writes
`verdict.action = "approve"` whenever the matched rule routes
to a human approver, and the runner compares that literal
string without invoking any chain. The actions file is a
*policy match* file, not an end-to-end recording — what the
human ultimately decided is out of scope.

### D. Actions-file emission: redaction

`Event.ReqBody` and `RespBody` may contain secrets the operator
doesn't want in a checked-in actions file. The export endpoint
should respect the same redaction rules the dashboard already
applies for display (`web_redaction_test.go` exists — confirm
during implementation that those rules are reusable here).

The CLI also wants a `--scrub` flag to drop bodies entirely if
the operator just wants method/path/headers coverage.

**Decision needed:** redact-by-default on export, or raw-by-
default with an explicit redact flag?

### E. Auth on the export endpoint

Reuse `dashboard_secret` (same auth as
`/api/state`, `/api/events`). The data being exported is data
the caller can already pull from `/api/events`; the export
endpoint is just a more convenient shape.

**Decision needed:** confirm `dashboard_secret`.

### F. Export window

How many recent events should the button download?

- Whole ring (last 500): matches what the dashboard already
  shows; simplest mental model.
- Time-windowed (`?since=...`): supports "actions from the last
  hour of activity"; small UI addition.
- Filter by `agent` / `mode` / `host`: lets operators export a
  per-agent or per-host actions file. Likely useful given the
  dashboard already filters this way.

**Recommendation:** start with whole ring + `?since=` query
parameter. Per-agent/per-host filtering can land as the UI
needs it.

**Decision needed:** confirm scope.

## 4. Proposed scope for the first PR

After the above questions are answered, the implementation PR should:

- Add `clawpatrol test` subcommand (`test.go`) — pure CLI,
  no gateway dependency.
- Define the ndjson actions format (`actions_file.go` or
  similar) shared between the CLI runner and the dashboard
  exporter.
- Extend `Event` with `Rule string` and populate it at the
  existing dispatch sites (`main.go:1638`, postgres,
  clickhouse_native) so the exporter can carry the matched
  rule name.
- Add `GET /api/actions/export` returning the recent-events
  ring as actions ndjson, with redaction reusing the
  dashboard's existing rules.
- Add the "Download actions" button to the dashboard's
  recent-actions view.
- HTTPS endpoint family in v1; SQL families covered if their
  recorded event fields are sufficient.
- Tests: unit tests for the runner (verdict match / mismatch
  on action and rule), a golden-file test for export ndjson
  shape, and an integration test that exports → runs → asserts
  zero diffs against the current config.

Out of scope for v1: live-session candidate dispatch (the
previous proposal — superseded), mock upstream, time-travel
replay against a historical config, file-vs-file diffing.

## 5. References

- Bead: `cl-d9d`
- Central dispatch: `config/runtime/dispatch.go:45`,
  `main.go:1638`
- Config load/compile: `main.go:92`, `config/compile.go:194`
- Event sink and recent ring: `web.go:1582`, `web.go:1620`
- Dashboard API surface: `web.go:208`+ (`/api/state`,
  `/api/events`, `/api/actions/`)
- Redaction rules: `web_redaction_test.go`
