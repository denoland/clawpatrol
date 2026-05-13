# Grammar inversion — migration plan

> **Status**: phase 1 (plan only). No code yet. This document covers
> the migration story so we can sign off on cutover shape before the
> implementation PR.

The design is settled in [#348](https://github.com/denoland/clawpatrol/issues/348).
This document does **not** re-derive any of those decisions; it
proposes how to get from today's tree to the inverted shape.

The inversion:

```
today:    credential → endpoint → profile     (endpoint names a credential; profile names endpoints)
proposed: endpoint → credential → profile     (endpoint names nothing; credential names an endpoint; profile names credentials)
```

---

## 1. Cutover strategy

**Recommendation: pure hard cutover (option #1 from the bead).**

The old grammar fails to load. In-tree fixtures, `gateway.example.hcl`,
and the documentation are translated as part of the implementation
PR. Operators hand-translate their own configs once, guided by a
short upgrade note and a targeted loader diagnostic when the legacy
shape is detected.

### Why not dual grammar (option #2)

The bead's framing is correct: dual grammar means permanent code-path
duplication in the plugin schemas (`credential` and `endpoint` both
optional on both block kinds, with cross-validation that only one
side is populated). The pivot in dispatch direction has knock-on
effects in `config/refs.go`, `config/compile.go`, and the runtime
resolution chain — duplicating those paths for one release of
operator mercy is more permanent code than the inversion warrants.

### Why not hard cutover + migration tool (option #3)

The gateway is pre-1.0 and the operator install base is small enough
that "every operator hand-edits once" is cheap. A migration tool
amortises a translation cost that is already small in absolute
terms, while adding its own surface area (a sibling binary, a
vendored copy of the old plugin schemas, a `testdata/legacy/`
corpus, idempotence tests) that has to be maintained until the
operator base has flipped and then deleted as dead code. Net
negative for this codebase at this point in its life.

### Loader diagnostic

When the loader sees the legacy shape — `endpoint { credential = … }`,
`endpoint { credentials = [{…}] }`, or `profile { endpoints = […] }` —
it must emit a single targeted error that names the old grammar and
points the operator at the upgrade note, instead of the wall of
unknown-field diagnostics it would otherwise produce. Concrete error
text is part of the Phase 2 PR.

---

## 2. Translation atomicity

The implementation PR will necessarily be large. The translation
must land as one atomic change because:

- Plugin schema changes (`endpoint = …` added on credentials,
  `credential` / `credentials` removed from endpoints) and the
  reference resolution flip in `config/refs.go` happen together —
  one without the other doesn't compile.
- Every in-tree HCL fixture references the schema in the old shape.
  Half-translated, every test fails.
- Documentation and `gateway.example.hcl` are referenced by tests
  (`feature_example.hcl` mirrors a slice of the example) and by the
  config-reference docgen.

Expected diff footprint (rough, not committing to numbers):

- `config/plugins/credentials/*.go` — ~20 files, each gains an
  `endpoint = …` field and a RefSpec entry.
- `config/plugins/endpoints/*.go` — ~6 files, each drops the
  `credential` / `credentials` schema and the singular RefSpec.
  Drops `emitCredentialBinding` and the dispatch-table emission
  paths.
- `config/refs.go`, `config/compile.go`, `config/config.go` (profile
  decoder) — flipped resolution direction, profile decoder rewritten
  to walk credentials, endpoint reachability computed via the new
  transitive closure.
- `config/runtime/dispatch.go` — per-request credential resolution
  now flows through the profile's credential set, filtered by which
  endpoint the request targets.
- `config/testdata/*.hcl` — every fixture translated; golden
  `*.want.json` files refreshed.
- `gateway.example.hcl` — translated.
- `config/README.md`, `site/doc/approval-rules.md`,
  `site/doc/architecture.md`, `site/doc/glossary.md`,
  `site/doc/config-reference.md` — translated and cross-references
  updated.

We will keep the PR commit-organised so reviewers can read it as a
sequence (schema → resolver → runtime → fixtures → docs), even
though all commits must land together.

---

## 3. Risks and open questions

- **`approver "llm_approver" { credential = … }` cross-reference.**
  Approvers reference a credential bare-name. Under the inversion
  this still works (RFC §3.a confirms); the symbol-table check in
  the post-inversion loader is the same shape as today.
- **`rule.credential = X` predicates.** Same. Resolution direction
  flip doesn't affect these.
- **Multi-endpoint credentials (`ch-o11y`).** RFC §3.b' option 2
  requires the `RefSpec` machinery to accept either a singleton ref
  or a list at the same path. `config/refs.go:67-136` already
  handles slice paths; we will need to allow a path to *decode*
  from either a scalar or a list value (gohcl side). This is a
  small addition to the plugin schema framework, not a rewrite.
- **No-credential endpoints (RFC §3.c, null credential).** The v14
  corpus has none today. We'll introduce a `null_credential` plugin
  so the new grammar can express "endpoint with no auth" without a
  profile reachability hole. Cost: one tiny plugin file.

---

## 4. Acceptance criteria for Phase 1 (this PR)

- Cutover shape signed off as pure hard cutover (option #1).
- Translation atomicity (§2) accepted as a constraint — i.e. nobody
  asks for a staged multi-PR rollout.
