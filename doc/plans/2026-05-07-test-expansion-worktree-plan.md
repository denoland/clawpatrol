# Clawpatrol Test Expansion Worktree Plan

**Date:** 2026-05-07

## Goal

Add focused regression/unit tests for Clawpatrol in small independent PRs, excluding the live request/dashboard `action_id` consistency work for now.

## Worktree / PR Strategy

Create each topic from `origin/main` as an independent branch/worktree. Keep PRs small and reviewable. After any PR lands, rebase remaining worktrees onto the updated `origin/main` before continuing.

Recommended worktrees and branches:

| Priority | Worktree | Branch | Scope |
| --- | --- | --- | --- |
| 1 | `clawpatrol-worktrees/test-k8s-parser` | `test/k8s-parser-edge-cases` | Kubernetes API path parser and k8s matcher edge cases. No real cluster required. |
| 2 | `clawpatrol-worktrees/test-secret-redaction` | `test/secret-redaction` | Header/event redaction tests for Authorization, Cookie, API keys, tokens, secrets. |
| 3 | `clawpatrol-worktrees/test-protocol-parsers` | `test/protocol-parser-edge-cases` | PostgreSQL and ClickHouse malformed/partial/edge parser cases. |
| 4 | `clawpatrol-worktrees/test-http-body-forwarding` | `test/http-body-forwarding` | Ensure HTTP body matching/buffering does not consume or corrupt upstream-forwarded bodies. |
| 5 | `clawpatrol-worktrees/test-approval-flow` | `test/approval-flow` | Approval-chain semantics: allow, deny, missing approver, errors, multi-stage behavior. |

## General Rules

- Use TDD for behavior changes: write failing test, confirm failure, then implement minimal fix.
- Prefer unit/small integration tests over heavy E2E tests.
- Do not require a real Kubernetes cluster for the k8s parser/matcher work.
- Run focused tests first, then broader `go test ./...` before committing.
- Avoid unrelated edits and do not stage existing unrelated/untracked files.
- If helper extraction is needed, keep it narrow and test-driven.

## Per-PR Notes

### 1. k8s parser / matcher

Primary files:

- Add: `config/runtime/k8s_parse_test.go`
- Possibly modify: `config/runtime/k8s_parse.go`
- Possibly extend: `config/match/match_test.go`

Test cases:

- core v1 namespaced resource path
- subresources: `pods/log`, `pods/exec`, `pods/portforward`
- API group path such as `/apis/apps/v1/namespaces/default/deployments/web`
- query params such as `stdin=true`, `tty=true`, `watch=true`

Open design choice:

- Decide whether `GET ...?watch=true` should produce verb `watch` instead of `list`/`get`.

Focused command:

```bash
go test ./config/runtime ./config/match
```

### 2. secret redaction

Primary files:

- Add/modify: `web_sink_test.go` or `web_test.go`
- Possibly modify: `web.go`

Start with `flatHeaders` behavior:

- `Authorization` -> `***`
- `Cookie` -> `***`
- `X-API-Key` -> `***`
- normal headers like `User-Agent` remain visible
- case-insensitive matching

Focused command:

```bash
go test .
```

### 3. protocol parser edge cases

Primary files:

- `config/plugins/endpoints/postgres_runtime_test.go`
- `config/plugins/endpoints/clickhouse_native_test.go`

Test malformed/partial inputs do not panic and known parser edge cases stay stable.

Focused command:

```bash
go test ./config/plugins/endpoints
```

### 4. HTTP body forwarding

Primary files:

- Add/modify: `main_test.go`
- Possibly modify: `main.go`

Potential helper extraction:

```go
func bufferBodyForMatch(req *http.Request, max int64) ([]byte, error)
```

Test that buffering for body match leaves `req.Body` readable for upstream forwarding and preserves content length.

Focused command:

```bash
go test .
```

### 5. approval flow

Primary files:

- Add: `approval_test.go`
- Possibly modify: `main.go`

Start with `runApproveChain`-level tests before full gateway E2E:

- all stages allow -> allow
- first deny short-circuits
- missing approver -> deny
- approver error -> deny
- multi-stage all-must-allow semantics

Focused command:

```bash
go test .
```
