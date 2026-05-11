# Telemetry

Status: design — nothing is built yet. This is an internal design
doc; the user-facing pitch ("clawpatrol's update checker") lives in
the README and at [clawpatrol.dev](https://clawpatrol.dev). What
follows is the contract for the implementation: if anything ships
differently than what's described here, this document changes first.

## What this is

Two things at once:

1. **An update checker.** Your gateway asks `clawpatrol.dev` at
   startup and every six hours after that whether a newer version
   of clawpatrol exists. If yes, you see a banner in the dashboard
   and a one-line note on stderr.
2. **An anonymous usage report.** The same HTTP request carries a
   small JSON payload describing your build (version, OS, arch) and
   a few aggregate counters from your gateway (connected devices in
   the last hour, requests in the last hour, etc.).

The second part is what motivates the first part: when we know how
many people run clawpatrol and on what versions, we know which
versions to support, where to spend time, and whether the project is
worth continuing to invest in.

## What this is not

- It is not a control plane. We cannot push commands to your
  gateway, change its configuration, or disable your install.
- It is not telemetry of your traffic. No request bodies, paths,
  hostnames, headers, rule contents, or upstream service names ever
  leave your gateway. See [What never leaves the
  binary](#what-never-leaves-the-binary) for the exhaustive list.
- It is not always on. See [Opt-out](#opt-out).

## Only the gateway phones home

clawpatrol ships one binary with three relevant modes:

- `clawpatrol gateway` — long-lived central proxy. **Phones home.**
- `clawpatrol run -- <cmd>` — runs as long as the wrapped command.
  Silent.
- `clawpatrol join` — one-shot WireGuard / CA setup, then exits.
  Silent.

The gateway already counts every device that connects to it, so its
`connected_devices_1h` is enough to know how many clients exist.
Having `run` and `join` also phone home would double-count and
require a disclosure step at every CLI invocation, including the
many cases where users invoke `clawpatrol run` from scripts.

A consequence of this design: if you only ever run `clawpatrol run`
or `clawpatrol join` (i.e. you're a user of someone else's gateway,
not an operator), your installation does not contact
`clawpatrol.dev` at all. You'll learn about new versions from
GitHub or from the gateway operator.

### What's sent

```jsonc
// POST /api/telemetry/v1/check
{
  "instance_id": "01HZ…",      // random UUID, written once to
                               // <config-dir>/instance_id
  "version": "0.4.2",          // from -ldflags or "dev"
  "git_sha": "6361a3d",
  "os": "linux",               // GOOS
  "arch": "amd64",             // GOARCH
  "go_version": "go1.24.1",

  "uptime_s": 86400,
  "connected_devices_1h": 12,  // distinct agent_ip seen in last hour
  "actions_count_1h": 8420,    // SELECT COUNT(*) FROM actions
                               // WHERE ts_ns > now-1h. Windowed
                               // rather than cumulative so it's
                               // comparable across gateways with
                               // different uptimes.
  "bytes_in_1h": 18238492,
  "bytes_out_1h": 9123003,
  "transport": "tailscale" | "wireguard"
}
```

Response:

```jsonc
{
  "latest": "0.4.5",
  "your_version": "0.4.2",
  "update_available": true,
  "url": "https://github.com/denoland/clawpatrol/releases/v0.4.5",
  "advisory": null             // or { "level": "security",
                               //       "message": "..." }
}
```

When the response indicates an update is available the gateway
logs one line on stderr at startup and shows a small dismissible
banner in the dashboard header. There is no `clawpatrol update`
self-replacing subcommand; the banner links to the GitHub release
page and you upgrade through the same channel you originally
installed from (Homebrew, release binary, `go install`, etc.).

### What never leaves the binary

The exhaustive list. If anything in this list ever changes, this
document changes first.

- No hostnames of the machine running the gateway.
- No source IPs. The CDN edge sees the request's source IP
  transiently for routing; the database never receives it.
- No host names of upstream services (`api.anthropic.com`, etc.).
- No rule contents, profile names, owner emails, integration
  owners, or any HCL config.
- No request paths, bodies, or headers from traffic flowing through
  the gateway.
- No cookies, auth tokens, or anything from your dashboard session.

The request body is small (under 1 KB) and matches the schema in
[What's sent](#whats-sent) byte-for-byte. The source code lives at
[`telemetry.go`](../telemetry.go) (forthcoming) — read it to verify.

## Frequency

Every 6 hours, plus once at startup after a 30 s grace period so
quick `--help` / `--version` / config-reload runs don't ping.

If clawpatrol.dev is unreachable, fail silently. Never block the
process on telemetry — the request is dispatched on a goroutine with
a 5 s timeout.

## Storage

A Cloudflare Worker at `clawpatrol.dev` receives the POSTs and
writes them to a single Cloudflare D1 (SQLite) table:

```sql
-- One row per gateway instance. Upsert on each ping.
CREATE TABLE gateways (
  instance_id TEXT PRIMARY KEY,
  first_seen  INTEGER NOT NULL,        -- unix seconds
  last_seen   INTEGER NOT NULL,
  version     TEXT NOT NULL,
  git_sha     TEXT,
  os          TEXT,
  arch        TEXT,
  go_version  TEXT,
  transport   TEXT,
  -- last reported snapshot:
  uptime_s              INTEGER,
  connected_devices_1h  INTEGER,
  actions_count_1h      INTEGER,
  bytes_in_1h           INTEGER,
  bytes_out_1h          INTEGER,
  payload     TEXT                     -- last raw JSON, for debugging
);

CREATE INDEX gateways_last_seen ON gateways(last_seen);
```

No time-series table. If trends become useful, add a daily-rollup
table later.

## Where "latest version" comes from

The Worker fetches
`https://api.github.com/repos/denoland/clawpatrol/releases/latest`
inline when handling a check, with the response cached at the
Cloudflare edge for 30 minutes. The latest GitHub release is the
source of truth — there is no out-of-band advisory mechanism.

If a release body starts with `[security]` or `[advisory]`, the
Worker surfaces its first paragraph as the `advisory` field in the
response. Otherwise `advisory: null`.

## Who reads this data

Maintainers of clawpatrol with `wrangler` credentials for the
`clawpatrol.dev` Cloudflare account. Currently a small group at
Deno. There is no public dashboard, no per-instance lookup, no API
to read individual rows.

When we want to answer a question — "how many active installs are
on 0.4.x", "are people on macOS or Linux", "is anyone actually
using the WireGuard transport" — we run a SQL query directly. The
recurring queries are checked into `site/sql/telemetry/*.sql`, so
anyone reading the repo can see exactly which questions get asked
of the data, and `npm run telemetry` (in `site/`) executes every
file in that directory and prints the results back-to-back:

```
$ npm run telemetry

== active-7d.sql ==
count
42

== versions-7d.sql ==
version  count
0.4.5    28
0.4.4     9
0.4.2     5
...
```

Ad-hoc one-off queries skip the script and use `wrangler` directly:

```
wrangler d1 execute TELEMETRY_DB --remote \
  --command "SELECT version, COUNT(*) FROM gateways
             WHERE last_seen > unixepoch() - 7*86400
             GROUP BY version ORDER BY 2 DESC"
```

We don't run a hosted admin panel because the dataset is small and
the audience is small. If that ever changes, this document changes
first.

## Opt-out

Three independent off-switches, any of which silences the gateway:

1. `telemetry = false` in `gateway.hcl`.
2. Env var `CLAWPATROL_TELEMETRY=0`.
3. Env var `DO_NOT_TRACK=1` (the de-facto OSS standard).

Disclosure path: a small "Telemetry on — opt out" banner in the
dashboard header on first load, dismissible (sets a localStorage
key). The gateway operator lives in the dashboard; that's the right
surface, not a log line that scrolls off.

## Endpoints

`POST /api/telemetry/v1/check` — accepts JSON, returns JSON. Public.
Schema versioned in the URL so we can add fields later without
breaking older clients (they get the v1 response shape forever; v2
clients can ask for richer responses).

The Worker validates: payload ≤ 4 KB, measured in UTF-8 bytes,
required fields present. If `Content-Length` is over the limit, the
Worker rejects the request before reading the body. Oversized
payloads return 413; malformed JSON or schema errors return 400.
No other public routes; the data is read via D1 SQL.

