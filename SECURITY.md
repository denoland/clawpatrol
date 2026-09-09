# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/denoland/clawpatrol/security/advisories/new)
for this repository. Do not open a public issue or pull request for
a security problem.

Include what you can: the version, the configuration shape that
triggers it, steps to reproduce, and what an attacker gains. Use
placeholder values for any credentials or hostnames.

You will get an acknowledgement within a few days. We will work with
you on a fix and coordinate disclosure; credit is given in the
release notes unless you prefer otherwise.

## What is in scope

The guarantee Claw Patrol makes is narrow and is described in the
[security model](https://clawpatrol.dev/docs/security-model): real
secrets live only in the gateway, and the only way to make a
credentialed request is through the gateway, where policy is
enforced. Reports that break that guarantee are in scope. Examples:

- a way to obtain a real credential from the gateway, a client, or a
  captured sample;
- a way to make a credentialed request that bypasses rule evaluation
  or approval;
- privilege escalation on the gateway host through configuration,
  plugins, or the dashboard;
- authentication or session weaknesses in the dashboard or the
  onboarding flow.

## What is out of scope

The security model lists what Claw Patrol does not defend against.
In particular, `clawpatrol run` is not a sandbox: a wrapped process
has the full local access of its OS user, and per-process traffic
interception is best-effort. Reports that a wrapped process can read
local files or the launching shell's environment, or can open
connections that bypass interception, describe the documented
boundary rather than a vulnerability.

## Supported versions

Fixes land on `main` and ship in the next release. Only the latest
release is supported; a gateway with the update checker enabled shows
a banner in the dashboard when a newer version is available.
