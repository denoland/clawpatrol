# Contributing to Claw Patrol

Thanks for taking the time. This page says what kind of changes we
take, how to get them reviewed quickly, and what the checks expect.

## What we are focused on

Claw Patrol is a wire-level policy gateway for agents: real secrets
stay in the gateway, every credentialed request goes through it, and
rules decide what is allowed. Current priorities, in order:

1. Reliability of the three deployment shapes (`gateway`, `join`,
   `run`) on Linux and macOS, including the tunnels under them.
2. Documentation that matches the code. A documented setting must
   do what it says.
3. Security hardening of the gateway itself.
4. Features that widen what the gateway can broker for agents, such
   as workload enrollment (Kubernetes and OIDC) and remote MCP.

Things we are not taking on at the moment: Windows support and
dashboard theming. Integrations with a specific third-party service
usually belong in an external plugin rather than core; see
[Plugins](https://clawpatrol.dev/docs/plugins) and the `pluginsdk`
package.

If you are unsure whether a change fits, open an issue first and
describe the operator problem it solves. A short issue saves a long
PR.

## Bug reports

The most useful reports come with the exact command, the version
(`clawpatrol --version`), the platform, what you expected, and what
happened. For `clawpatrol run` problems on Linux, the daemon log at
`~/.local/state/clawpatrol/run/daemon.log` usually holds the real
cause. Never paste real credentials, tokens, or private hostnames;
use placeholders.

## Pull requests

- One change per PR, with a title in the form `area: what changed`
  (`run: ...`, `gateway: ...`, `docs: ...`). The body says what the
  change does and why; link the issue with `Fixes #N`.
- Add or extend tests. A fix without a regression test will usually
  get a request for one.
- Keep the config format stable. Do not rename or restructure HCL
  blocks and attributes as part of another change.
- If you touch a documented HCL field, regenerate the reference:
  `go run ./internal/tools/docgen`. CI fails when it is stale.
- If you add a rule branch to `cmd/clawpatrol/testdata/example.hcl`,
  add fixtures for both arms (see
  [clawpatrol test](https://clawpatrol.dev/docs/clawpatrol-test)).
- Small follow-up fixes to your PR may be applied by a maintainer
  before landing; the commit keeps you as author.

## Checks

Run what CI runs before you push:

```sh
gofmt -l .                       # must print nothing
cd dashboard && deno task format:check && cd ..
make lint                        # golangci-lint + dashboard lint
make test                        # go test ./...
go run ./internal/tools/docgen   # then commit any change
```

`doc/dev-setup.md` covers prerequisites, including the macOS system
extension build if you are working on `clawpatrol run` for macOS.
Linux-specific paths (`run` on Linux, the sandbox backends) need a
Linux host or VM; the CI matrix covers them, so it is fine to lean on
CI for those if you do not have one.

## Review expectations

A maintainer will respond to a new PR within a week. Reviews are
direct and specific; they are about the change, not the author. A PR
that goes quiet for a long time after a review may be closed to keep
the queue honest; it can be reopened when work resumes.

## Security issues

Do not open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md).
