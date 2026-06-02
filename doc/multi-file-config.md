# Multi-file HCL config (directory-mode loading)

`config.Load` accepts either a single `.hcl` file or a directory of
`.hcl` files. The directory mode mirrors Terraform's "module = a
directory whose files are joined" semantics: discover by filename,
merge, then resolve references against the merged view.

This note documents the discovery rules, the design tradeoffs vs.
Terraform's full multi-file model, and what's intentionally out of
scope for v1.

## Discovery rules

When `Load` is called with a path that is a directory:

- The loader reads **only direct children** of the directory.
  Subdirectories are silently ignored. This is deliberate — a config
  directory is flat, like a Terraform module, not a tree.
- Files included: every regular file whose name ends in `.hcl`.
- Files excluded: anything starting with `.` (editor swap files,
  hidden dotfiles), anything without the `.hcl` suffix
  (`README.md`, lockfiles, anything else operators drop in the
  directory).
- Discovered files are sorted by `filepath.Base` (lexicographic).
- Empty directory (no `.hcl` files) is a load error, not a warning —
  silently booting a gateway with no policy because someone pointed
  `-config` at the wrong directory has bitten us before.

## Merge contract

Files are merged via `hcl.MergeFiles`. The merged body is what
gohcl decodes and what pass-1 walks for symbol building.

- **Singleton blocks** (`gateway { ... }`, `defaults { ... }`)
  must appear in **exactly one** file. Duplicates surface as
  gohcl's standard `Duplicate gateway block` / `Duplicate defaults
  block` diagnostic with both source ranges.
- **`schema_version`** is a top-level singleton attribute and, like
  the singleton blocks, must appear in at most one file. It is read
  in a lenient pre-pass over the merged body before the strict
  decode, so a version newer than the binary supports fails with one
  upgrade error rather than a wall of unknown-field noise. Absent ⇒
  legacy grammar (version 0) with a warning.
- **Repeatable blocks** (`plugin "..." { ... }`, every named
  policy entity) can appear in any file. Each named entity is
  still unique within its kind across the whole module — declaring
  `endpoint "https" "github"` in two files is a load error
  (`Duplicate endpoint name "github"`), with the duplicate's
  source range as the diagnostic subject.
- **References** (`endpoint = github`, `approve = [ops]`) resolve
  against the merged symbol table. File order doesn't determine
  reachability — a rule in `00-rules.hcl` can reference an endpoint
  declared in `99-endpoints.hcl` and the loader will resolve it
  correctly.
- **Diagnostic ranges** preserve the originating filename and line
  number. When pass-2 reports an error in a block from
  `30-rules.hcl`, the diagnostic points at `30-rules.hcl:N:M`, not
  at the directory or a synthesized merged location.

## `<<file:NAME>>` markers

The file-include substitution (`<<file:NAME>>` in plugin string
fields, see `internal/config/file_include.go`) resolves paths
relative to the **directory passed to `Load`**. For directory
mode, that's the config directory itself. For single-file mode,
it's `filepath.Dir(path)`. In both cases markers and the files
they reference live alongside the `.hcl` files that wield them.

## What's intentionally out of scope (v1)

- **Override files.** Terraform has special handling for
  `*_override.tf` and `override.tf`: their top-level blocks are
  merged *into* matching blocks already defined elsewhere, rather
  than being rejected as duplicates. We do not replicate this. The
  surprise factor (a value in a "main" file silently shadowed by
  one in a sibling) outweighs the convenience for clawpatrol's
  audience, which is small enough that splitting by **disjoint
  entities** (one file per kind, or per service) is the natural
  shape. If override semantics become necessary later, the place
  to add them is in `LoadDir`'s file-name filter, before
  `hcl.MergeFiles`.
- **JSON variant.** Terraform parses `*.tf.json` alongside `*.tf`.
  We don't have a JSON variant yet; if/when we add one, this
  filter is where it goes.
- **Recursive discovery.** Subdirectories are ignored. Operators
  who want to nest configs should `include` them explicitly — and
  we don't have an `include` directive yet either. Out of scope.
- **Per-environment selection.** Terraform has `*.tfvars` and
  variable scoping per workspace; clawpatrol doesn't have
  variables at the config layer at all, so this doesn't apply.

## Why this mental model

Terraform's directory model is well-understood by the audience
clawpatrol targets (devops/platform engineers). Adopting the
familiar shape — even with a smaller feature set — means the
"how do I split a 500-line config into manageable files?"
question has a one-line answer: drop them in a directory next to
each other.

Pass-1/pass-2 already runs on a single merged block list, so
multi-file support is mostly a one-call change at the loader's
entry point (`hcl.MergeFiles`). The grammar didn't need to change
and no plugin author has to do anything different.

## Implementation pointers

- Entry point: `Load(path)` in `internal/config/config.go`.
  Stats the path; dispatches to `LoadDir` or single-file
  `LoadBytes`.
- Directory walk + merge: `LoadDir(dir)` in the same file.
- Shared decode pipeline: `loadFiles(files, configDir, diags)` —
  the post-merge work (gohcl decode, plugin spawn, pass-1, pass-2,
  file-include expansion) is identical to the single-file path.
- Tests: `internal/config/directory_test.go`.
