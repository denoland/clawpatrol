# PR #534 screenshots

Profiles page renders for the dashboard PR #534, captured against a local
gateway loaded with `internal/config/testdata/full.hcl` (3 profiles: ops,
alice, bob), with 5/3/2 seeded device rows respectively so the device
counts on the list cards are non-zero.

- `profiles-list.png` — the list view.
- `profile-ops.png` — ops (heaviest: 5 devices, 15 endpoints, 17 creds,
  55 rules; includes the multi-credential placeholder dispatch).
- `profile-alice.png` — alice (17 endpoints, 16 creds, 24 rules; per-tool
  bearer/header tokens for honeycomb, pagerduty, etc.).
- `profile-bob.png` — bob (lightest: 5 endpoints, 6 creds; only profile
  with `openai-codex` placeholder dispatch in his list).
