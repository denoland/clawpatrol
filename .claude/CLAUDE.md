# Project conventions

This file is the single source of truth for repo-level agent
instructions. `AGENTS.md` at the repo root is a symlink to this file
so Codex and Claude Code both pick it up.

## Dates and times

Render every timestamp in the UI as `yyyy-MM-dd HH:mm:ss.SSS` (24-hour,
locale-independent, millisecond precision). When only the time-of-day
is shown, use `HH:mm:ss.SSS`.

Helpers live in `www/src/lib/format.ts`:

- `fmtDateTime(t)` — full timestamp.
- `fmtTime(t)` — time-of-day only.

Do not call `toLocaleDateString`, `toLocaleTimeString`, or
`toLocaleString` for date/time rendering. They produce different
output per locale (`5/11/2026` in en-US, `11/05/2026` in en-GB,
`11.5.2026` in de-DE), which makes log entries unreadable across a
team. Number formatting (`Intl.NumberFormat`, `Number.toLocaleString`)
is fine — the rule is about dates and times.
