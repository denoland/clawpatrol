# Grammar inversion — migration plan

> **Status**: phase 1 (plan only). No code yet. This document covers
> the migration story so we can sign off on cutover shape and order of
> operations before the implementation PR.

The design is settled in [#348](https://github.com/denoland/clawpatrol/issues/348).
This document does **not** re-derive any of those decisions; it
proposes how to get from today's tree to the inverted shape without
breaking in-flight work.

The inversion:

```
today:    credential → endpoint → profile     (endpoint names a credential; profile names endpoints)
proposed: endpoint → credential → profile     (endpoint names nothing; credential names an endpoint; profile names credentials)
```

---

## 1. Cutover strategy

**Recommendation: hard cutover + migration tool (option #3 from the bead).**

Old grammar fails to load. We ship
`clawpatrol config migrate <old.hcl>` to translate operator configs
deterministically. Loader emits a targeted error message pointing
operators at the tool when it sees the legacy shape.

### Why not pure hard cutover (option #1)

- `gateway.example.hcl` is the canonical onboarding artifact — every
  operator who has stood the gateway up has a copy descended from it.
  Translating in-tree fixtures is necessary but not sufficient; the
  operator's tree still has the old shape on disk.
- The translation is mechanical and deterministic per RFC #348 §3.
  The cost of writing a one-shot migration tool is bounded
  (~1 binary, ~1 day of work) and is dominated by the cost of every
  operator hand-translating their own config — which is also where
  the typo / mis-translation risk lives.
- A clear error from the loader ("run `clawpatrol config migrate`")
  is a much better operator experience than a wall of unknown-field
  diagnostics.

### Why not dual grammar (option #2)

The bead's framing is correct: dual grammar means permanent code-path
duplication in the plugin schemas (`credential` and `endpoint` both
optional on both block kinds, with cross-validation that only one
side is populated). The pivot in dispatch direction has knock-on
effects in `config/refs.go`, `config/compile.go`, and the runtime
resolution chain — duplicating those paths for one release of
operator mercy is more permanent code than the migration tool
amortises.

### Why not pure hard cutover (option #1), revisited

The honest counter-argument to choosing #3 is that the gateway is
pre-1.0 and the operator install base may be small enough that
"every operator hand-edits once" is cheap. If that turns out to be
true at review time, the migration tool can be deferred — the
schema, compile, runtime, and fixture work is identical in either
case. **The Phase 2 implementation should be structured so that the
migration tool is a strictly additive deliverable that can be
dropped without rework.**

---

## 2. In-flight PR conflict map

Surveyed `gh pr list --repo denoland/clawpatrol --state open` on
2026-05-13. PRs grouped by expected interaction with the inversion.

### Hard conflicts — must land before OR be rebased on top of inversion

| PR | Title | Conflict shape |
|---|---|---|
| **#295** (cl-6hk) | `token_pool` block | RFC §3.d. Pool block shape unchanged, but the endpoint binding moves into the member credentials. PR #295 today uses `endpoint { credential = team }`; under inversion the pool's members each carry `endpoint = …`. Endpoint plugin's `credential = X` field disappears entirely. |
| **#331** (cl-bl1) | `aws_credential` for EKS | Adds a credential plugin AND modifies `config/testdata/full.hcl` AND extends the `kubernetes` endpoint plugin with `cluster_name` / `region`. The credential currently binds via `endpoint { credential = ... }`. Must be rewritten so the credential carries `endpoint = …`. |
| **#305** (cl-1yh) | LLM facet family + anthropic/openrouter plugins | Adds two new HTTPS-family endpoint plugins (`anthropic`, `openrouter`) and extends `openai_codex_https`. New endpoint plugins drop `credential` / `credentials` fields under the inversion. |
| **#255** (ClickHouse native protocol) | New `clickhouse_native` endpoint family | Touches `clickhouse_native` plugin and fixtures. Endpoint plugin schema drops `credential` field. |

### Soft conflicts — rebase, but no schema changes

| PR | Title | Conflict shape |
|---|---|---|
| **#350** | `google_gke_credential` | New credential plugin; no HCL fixture changes today. Plugin file structure is fine, but the plugin must declare its `endpoint = …` RefSpec post-inversion (current PR has no RefSpec — it relies on `kubernetes`'s singular `credential` field). |
| **#250** (orch/issue-19) | 1Password CLI credential type | Same: new credential plugin, will declare an `endpoint = …` RefSpec post-inversion. |
| **#118** | `notion_oauth` configurable OAuth flow | Touches the existing `notion_oauth` credential plugin internals. Schema surface change is additive (`endpoint = …` field arrives). Likely clean rebase. |
| **#282** (postgres tokenizer SQL extractor) | postgres endpoint refactor | Modifies the postgres endpoint plugin but the SQL extractor is internal — the schema fields don't move. Clean rebase. |
| **#349** | Reinstate `ApproveRequest.Profile` as display-only | Reads the profile *name*, not its membership list. Approver template path is unchanged by the inversion. Clean. |

### No conflict

| PR | Why |
|---|---|
| #244, #243, #242, #241, #232 (orch issues) | Approver / rule / env pushdown / get-token / seccomp. Don't touch credential/endpoint/profile schemas. |
| #239, #267, #249, #248 (security / wg / loopback / sql audit) | Different surfaces. |
| #231, #254, #273 (dashboard, plugin diagnostic log, Tailscale docs) | Pure frontend / docs. |
| #209 (HTTP transport prune) | Internal gateway plumbing. |
| #259 / #258 / #257 / #256 / #252 (OIDC family) | OIDC enrollment is a separate grammar surface from credential/endpoint/profile; no overlap. |
| #214, #294, #204, #264, #195, #113, #112 | Various small fixes / docs / dashboard / matcher work; no schema overlap. |

### Recommended landing order

1. **Before inversion (low-coordination, value of being merged > value of being inverted-from-the-start):**
   - **#295 (token_pool)** — small schema addition; the inversion PR translates it as part of the corpus pass. Inverting `token_pool` after-the-fact requires no rework because RFC §3.d says the pool block shape is unchanged.
   - **#331 (aws_credential)** — already late-stage; let it merge in the old shape and the inversion PR translates the EKS testdata along with everything else.
   - **#349 (ApproveRequest.Profile)** — unrelated to the inversion; can land anytime.

2. **After inversion (these add new schemas; better to add in the final shape than translate twice):**
   - **#305 (LLM facet family)** — new endpoint plugins. Rebasing onto the inversion is preferable to landing the old shape and re-translating two new plugins.
   - **#350 (google_gke_credential)** — new credential plugin; one-line addition of `endpoint = …` RefSpec is easier than a translate-pass.
   - **#250 (1Password CLI credential)** — same logic.
   - **#255 (ClickHouse native protocol)** — touches both an endpoint plugin and testdata; cleaner after inversion.

3. **Parallel (no conflict):**
   - Everything else in the list above.

We will check the open-PR set again immediately before opening the
Phase 2 implementation PR and refresh this map.

---

## 3. Translation atomicity

The implementation PR will necessarily be large. The translation
must land as one atomic change because:

- Plugin schema changes (`credential` field added on credentials,
  `credential`/`credentials` removed from endpoints) and the
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
sequence (schema → resolver → runtime → fixtures → docs → migration
tool), even though all commits must land together.

---

## 4. Migration tool

If cutover #3 is approved, ship at `cmd/clawpatrol-config-migrate/`.

### Shape

```
clawpatrol config migrate <old.hcl> [> <new.hcl>]
clawpatrol config migrate --in-place <old.hcl>
```

Or, equivalently, if we'd rather not add a top-level subcommand
under the main binary, ship it as a sibling binary in
`cmd/clawpatrol-config-migrate/`. The bead suggests the latter
layout; either is fine. Recommendation: sibling binary, since the
migration is a one-shot operator concern and we don't want to grow
the `clawpatrol` CLI's stable surface area with a tool that becomes
dead code after operator base has flipped.

### Algorithm

1. Parse the old config with a **vendored copy of today's plugin
   schemas** — the migration tool has both grammars compiled in
   side-by-side, lives in its own package, never imports the main
   loader.
2. Walk the parsed model:
   - For each `endpoint`, drop `credential` / `credentials` and
     produce N new `credential` blocks (one per old `credential`
     binding), each carrying `endpoint = <old-endpoint-name>` and
     the placeholder string from the old dispatch entry (if any).
   - For each old standalone `credential` block referenced from an
     endpoint, add the same `endpoint = …` field; placeholder field
     unset (it sits with the binding entries the loader will
     synthesise).
   - For each `ch-o11y`-shape credential bound from multiple
     endpoints (§3.b'): collapse into one credential block with
     `endpoints = [...]` list form.
   - For each `profile`, rewrite `endpoints = […]` to
     `credentials = […]` by following the transitive closure:
     every credential whose endpoint was in the old endpoint list.
     Per RFC §3.f, multi-credential endpoints expand to all their
     credentials in the new profile list.
3. Emit using `hclwrite`. Preserve comments where reasonable;
   accept comment loss on the credential/endpoint/profile blocks
   (operators can re-paste). Block ordering: endpoints first,
   credentials next, profiles last (matching `gateway.example.hcl`
   conventions).
4. Idempotent: running the tool on already-translated input emits
   it back byte-equivalent (or close to it — at minimum, the loaded
   compiled output is identical).

### Test coverage

Add a `testdata/legacy/` directory containing pristine pre-inversion
copies of every fixture (currently in `config/testdata/*.hcl`). The
test:

1. For each pair `(legacy/foo.hcl, foo.hcl)`:
   - Run the migration tool on `legacy/foo.hcl`.
   - Assert the tool's output, when compiled by the post-inversion
     loader, produces a compiled `Policy` byte-identical to
     `foo.hcl` compiled by the same loader.
2. Run the tool again on its own output; assert idempotence at the
   compiled-policy level.
3. Spot-test that translating `legacy/error_unknown_endpoint.hcl`
   surfaces a clear error (the migration tool refuses to translate
   malformed input rather than producing malformed output).

### What the migration tool is not

- It is not a long-term grammar-compat shim. The loader still rejects
  the old shape with a hard error. The tool is a one-shot translator
  the operator runs once per config file. Configs translate, get
  committed, never run through the tool again.
- It is not a downgrade path. Going inverted → old is not supported.
- It does not handle secrets / dashboard state, just HCL text. The
  secret store and dashboard SQLite are unaffected.

### Cost ceiling

If the migration tool grows beyond ~600 LoC including tests, that's
a sign we're over-engineering it for the value it delivers — at
that point we should reconsider cutover #1 (pure hard cutover) and
ship a clear loader error pointing operators at a one-page upgrade
guide instead.

---

## 5. Risks and open questions

- **`approver "llm_approver" { credential = … }` cross-reference.**
  Approvers reference a credential bare-name. Under the inversion
  this still works (RFC §3.a confirms), but during translation we
  must check that the approver's referenced credential exists in
  the translated tree before the new loader sees a dangling
  reference. The migration tool's test pass catches this.
- **`rule.credential = X` predicates.** Same. Verified at the
  symbol-table level; resolution direction flip doesn't affect
  these.
- **Multi-endpoint credentials (`ch-o11y`).** RFC §3.b' option 2
  requires the `RefSpec` machinery to accept either a singleton ref
  or a list at the same path. `config/refs.go:67-136` already
  handles slice paths; we will need to allow a path to *decode*
  from either a scalar or a list value (gohcl side). This is a
  small addition to the plugin schema framework, not a rewrite.
- **No-credential endpoints (RFC §3.c, null credential).** The v14
  corpus has none today. We'll introduce a `null_credential` plugin
  so the new grammar can express "endpoint with no auth" without
  a profile reachability hole. Cost: one tiny plugin file.
- **Backward-compatible loader error.** The loader's diagnostic for
  "this looks like an old-shape config" should be specific enough
  that operators don't have to read the rendered diagnostics tree
  to figure out what changed. Concretely: if we see
  `endpoint { credential = … }` or `endpoint { credentials = [{…}] }`
  or `profile { endpoints = […] }`, emit a single targeted error
  with the migration command in the body.

---

## 6. Acceptance criteria for Phase 1 (this PR)

- Cutover shape signed off (#1 or #3).
- The PR landing order in §2 confirmed or revised.
- Translation atomicity (§3) accepted as a constraint — i.e. nobody
  asks for a staged multi-PR rollout.
- If #3 is chosen: the migration tool's location and shape (§4)
  signed off so Phase 2 can build against it from the start.
