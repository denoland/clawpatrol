# Binary size

Clawpatrol is a single statically-linked Go binary that bundles a
gateway, a policy engine, a Tailscale node, a WireGuard server, a
userspace TCP/IP stack, a CEL evaluator, a SQLite database, and a
SPA. The build is large by design; this doc records the baseline so
future size regressions have something to diff against, and explains
which dependencies are intentional.

## Baseline (linux/amd64, Go 1.26)

Numbers below are with a stub `dashboard/dist/index.html` (i.e. the
SPA is one byte of placeholder HTML). The real release ships the
built SPA, which adds the SPA's own bundle size on top.

| Build                                              | Bytes      | MB    |
|----------------------------------------------------|-----------:|------:|
| `go build ./cmd/clawpatrol` (dev / `make build`)   | 88,088,501 | 84.0  |
| `go build -ldflags="-s -w" ./cmd/clawpatrol`       | 61,634,889 | 58.8  |
| `go build -ldflags="-s -w" -trimpath ./cmd/clawpatrol` (`make release`, release CI, `install.sh` source build) | 61,366,537 | 58.5  |

`-s -w` removes the symbol table and DWARF debug info. `-trimpath`
rewrites embedded source paths and saves a few hundred KB on top.

To reproduce:

```sh
mkdir -p dashboard/dist
printf '<!doctype html><html><body><pre>placeholder</pre></body></html>' \
  > dashboard/dist/index.html
go build -o clawpatrol-dev ./cmd/clawpatrol
go build -ldflags "-s -w" -trimpath -o clawpatrol-release ./cmd/clawpatrol
ls -la clawpatrol-dev clawpatrol-release
```

The dev binary's extra ~26 MB is debug info (`-w` removes DWARF
`.debug_*` sections) plus the symbol table (`-s` removes
`.gopclntab`'s file/line names). Both are useful at dev time for
panics and `go tool pprof`; neither is shipped to users.

## ELF section breakdown (dev build, `size -A`)

```
.text         28 MB   compiled code
.gopclntab    23 MB   PC -> file/line table (dropped by -s)
.debug_*      18 MB   DWARF (dropped by -w)
.rodata       8.7 MB  read-only data (strings, type info)
.noptrbss     33 MB   uninitialised BSS — zero on disk (FIPS DRBG reserves 32 MB)
```

The 32 MB BSS reservation under `crypto/internal/fips140/drbg.memory`
is virtual memory, not file bytes — it doesn't contribute to the
download.

## Where the .text bytes go

Top-level groups, summed over the dev binary's `T` symbols:

| Group                  | Bytes (KB) | Why it stays                                                                  |
|------------------------|-----------:|-------------------------------------------------------------------------------|
| tailscale.com          | 3,196      | tsnet embed: every gateway joins a tailnet for control-plane connectivity     |
| sqlite (modernc.org)   | 2,098      | pure-Go SQLite — state DB, no cgo                                             |
| clickhouse-go + ch-go  | 1,662      | `clickhouse_native` endpoint speaks the wire protocol; clients require both   |
| google.golang.org/{protobuf,grpc} | 1,507 | go-plugin and OTLP exporters need a real gRPC stack                          |
| github.com/google/cel-go | 1,477    | rule expressions in HCL compile to CEL programs                               |
| gvisor.dev/gvisor      | 1,321      | userspace TCP/IP stack for `clawpatrol run` (per-process WireGuard)           |
| github.com/aws/aws-sdk-go-v2 | 1,193 | SigV4 presigner for the EKS bearer-token credential                          |
| github.com/pgplex/pgparser | 916    | Postgres SQL parser for the `postgres` endpoint matcher                       |
| github.com/AfterShip/clickhouse-sql-parser | 385 | ClickHouse SQL parser for the same                                |
| go.opentelemetry.io/*  | 783        | opt-in OTLP/HTTP exporter (no-op when `OTEL_EXPORTER_OTLP_ENDPOINT` unset)    |
| github.com/hashicorp/* | 621        | `go-plugin` (out-of-process plugins) + `hcl/v2` (config DSL)                  |
| github.com/refraction-networking/utls | 517 | uTLS for ClientHello fingerprinting on the dial side                       |
| github.com/zclconf/go-cty | 464      | value model the HCL evaluator returns                                         |
| github.com/miekg/dns   | 329        | wire-format DNS for the dnsvip allocator                                      |
| golang.zx2c4.com/wireguard | 126    | userspace WireGuard (paired with gvisor netstack)                             |

Everything in that table either implements a wire protocol the
gateway intercepts (clickhouse, postgres, dns, wireguard) or a
runtime feature the policy engine exposes (cel, hcl, aws creds,
otel). Pulling any of them out drops user-facing functionality.

## Recent dependency hygiene

- The yaml v3 implementation was duplicated: `gopkg.in/yaml.v3`
  (direct import in `internal/config/plugins/tunnels/`) and
  `go.yaml.in/yaml/v3` (pulled by `clickhouse-go/v2/lib/proto`).
  Both ship the same Go code under different module paths, so the
  linker kept both copies. The direct import now uses
  `go.yaml.in/yaml/v3`, saving ~290 KB stripped.
- `github.com/mdp/qrterminal/v3` was incorrectly listed as indirect
  after the join QR feature landed in #540; `go mod tidy` promotes
  it to a direct dependency.

## Adding a new dependency

Before adding a direct dependency, check whether anything we already
pull in solves the same problem. A few common cases that have come up:

- **YAML decoding:** use `go.yaml.in/yaml/v3` (already required by
  clickhouse-go). Don't add `gopkg.in/yaml.v3` — it ships identical
  code under a different module path.
- **JSON:** use `encoding/json` from the standard library. Both
  `github.com/go-json-experiment/json` (tailscale) and the smithy /
  protobuf JSON encoders are pulled in as transitive deps, but they
  exist to serve their respective ecosystems and aren't general-purpose.
- **Compression readers:** the sampler already speaks gzip, deflate,
  zlib, brotli (`github.com/andybalholm/brotli`), and zstd
  (`github.com/klauspost/compress/zstd`) — extend `maybeDecode` in
  `cmd/clawpatrol/web.go` rather than adding a fourth decoder.

If a new direct dependency is unavoidable, mention the size impact in
the PR (`go build -ldflags '-s -w' -trimpath` before and after) so we
have a paper trail for future audits.
