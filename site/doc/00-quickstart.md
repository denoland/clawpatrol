# Quickstart (Ubuntu 24.04)

End-to-end walkthrough on a freshly imaged Ubuntu 24.04 server (the
gateway) plus a desktop or laptop on the same Ubuntu release (the
device). About fifteen minutes if you already have a public IP on
the server.

If you're on macOS or another Linux distro, every step still applies
verbatim except for the Ubuntu-specific AppArmor sysctl noted under
"First run".

## What you'll have at the end

- A gateway running on `gw.example.com` (your server) with the
  dashboard on `:9080`.
- A laptop joined to the gateway. `clawpatrol run claude` routes
  Claude's HTTPS through the gateway and injects the real API key
  from gateway-side storage — your laptop never holds the credential.
- One policy rule that gates `POST` requests against
  `api.github.com` behind a human approval click on the dashboard.

You'll exercise the rule by running a wrapped `gh pr create`, see it
pause for approval, click **allow**, and watch the call complete.

## 0. Prerequisites

On the server:

- Ubuntu 24.04, root or a sudoer account, public IPv4 address.
- `udp/51820` (WireGuard) and `tcp/9080` (dashboard) reachable from
  the device. The setup wizard tries to open both via `iptables`
  but a cloud-provider firewall in front (Hetzner Cloud Firewall,
  AWS Security Group, …) needs an explicit allow rule.

On the device:

- Ubuntu 24.04, a normal user account (not root). `sudo` available
  for the one-off privileged step (installing the CA into
  `/usr/local/share/ca-certificates/`).
- Outbound `udp/51820` and `tcp/9080` to the server. Most home and
  office networks allow this by default; restrictive corporate
  networks may not.

You do **not** need Go, Docker, Node, or any other toolchain. The
installer drops a single statically linked binary at
`~/.local/bin/clawpatrol`.

## 1. Install the gateway

SSH to the server and install:

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

Now bootstrap the gateway. `gateway init` writes a starter
`gateway.hcl` (including a random `dashboard_secret`), opens the
firewall ports, and drops a systemd unit. The CA is lazy-minted into
sqlite on first boot — there's no on-disk key material to manage:

```bash
sudo clawpatrol gateway init
```

You'll see something like:

```
Detected public IP: 203.0.113.42
├ Wrote /etc/clawpatrol/gateway.hcl
├ Opened udp/51820 + tcp/9080
└ Wrote /etc/systemd/system/clawpatrol-gateway.service

Next:
  systemctl enable --now clawpatrol-gateway

Dashboard: http://203.0.113.42:9080
Join command: clawpatrol join http://203.0.113.42:9080
```

Devices that `clawpatrol join` later fetch the CA over HTTP at
`/ca.crt`.

Start it:

```bash
sudo systemctl enable --now clawpatrol-gateway
```

Sanity-check from the server itself:

```bash
curl -fsS http://203.0.113.42:9080/ca.crt | head -1
# -----BEGIN CERTIFICATE-----
```

Note: `gateway init` needs root because it writes to `/etc/clawpatrol`
and installs a systemd unit. The device-side `clawpatrol join`
**must not** be run with sudo — see step 2.

## 2. Join your device

On the laptop, install the same binary:

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

> Do **not** run the next command under `sudo`. `clawpatrol join`
> writes per-user state under `$HOME/.clawpatrol/` and
> `$HOME/.config/clawpatrol/`; under `sudo` those land in `/root`,
> and your normal shell can't read them — every subsequent
> `clawpatrol run` or `clawpatrol env` will silently fail to find
> the wg.conf. `clawpatrol join` sudo-elevates itself for the few
> steps that actually need root (CA trust install). The CLI refuses
> outright when invoked under `sudo` so the friction is loud rather
> than silent.

Run join as your normal user:

```bash
clawpatrol join http://203.0.113.42:9080
```

You'll see:

```
Verify code in browser:

    ABCD-1234

http://203.0.113.42:9080/onboard/ABCD-1234

⠧ Waiting for approval
```

Open the printed URL in a browser, confirm the code matches, and
approve. From the server side (or another machine that's already
joined) you can also approve directly from the dashboard's
**Pending devices** panel.

Back on the laptop, once approved you'll see:

```
Approved.
├ Joined as 10.55.0.7
├ CA installed in system trust
└ Shell rc: eval "$(clawpatrol env)"

Installed! Try: clawpatrol run claude

Dashboard: http://203.0.113.42:9080
           (auto-signed-in via the tunnel you just joined —
            no separate password; if the page 403s, make sure
            you're hitting it from this machine, not your laptop)
```

What that did:

- Fetched the gateway CA into `~/.clawpatrol/ca.crt` and installed
  it into `/usr/local/share/ca-certificates/` (one `sudo` prompt).
- Saved a peer wg.conf at `~/.config/clawpatrol/wg.conf`
  (mode 0600, owned by your user).
- Saved a per-peer API token at `~/.clawpatrol/api-token`
  (mode 0600, owned by your user).
- Appended an `eval "$(clawpatrol env)"` line to your shell rc so
  agent CLIs (`claude`, `gh`, `codex`) automatically inherit the
  placeholder env vars in every new shell.

Open a new shell so the rc change takes effect, then verify:

```bash
echo "$ANTHROPIC_API_KEY"
# CLAWPATROL_PLACEHOLDER_anthropic_oauth_subscription
```

That placeholder is what your agent will see. The gateway
substitutes it for the real key at the wire.

### Flags you'll occasionally want

- `--whole-machine` brings up `wg-quick` so every packet on the
  host routes through the gateway. The default per-process mode is
  almost always what you want; opt into whole-machine only if you
  need it (e.g., a workstation locked to a specific egress).
- `--no-trust` fetches the CA but skips the system trust install
  and prints the manual command instead. Use it on read-only-rootfs
  containers, distroless images, or when your security policy
  requires manual cert review. Without `--no-trust`, `clawpatrol
  join` will copy the CA to `/usr/local/share/ca-certificates/` and
  run `update-ca-certificates` (one `sudo` prompt).
- `--hostname NAME` overrides the registered device name (default:
  `os.Hostname()`).
- `--profile NAME` suggests a profile for the approver; the
  approver can still override from the dashboard.

## 3. First rule

You already have a starter `gateway.hcl` from step 1. SSH back to
the server and open `/etc/clawpatrol/gateway.hcl`:

```bash
sudo $EDITOR /etc/clawpatrol/gateway.hcl
```

The starter config sets up `anthropic`, `openai-api`, and
`github-api` endpoints. Add a rule that pulls every GitHub write
through the dashboard's pending-approvals page:

```hcl
approver "human_approver" "ops" {
  # No `credential = …` and an empty channel → dashboard-only.
  # Add `channel = "#agent-ops"` plus a `slack_tokens` credential
  # later to fan the prompt out to Slack as well.
  channel = ""
}

rule "github-writes" {
  endpoint  = github-api
  condition = "http.method in ['POST', 'PUT', 'PATCH', 'DELETE']"
  approve   = [ops]
}

rule "github-reads" {
  endpoint  = github-api
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}
```

Validate before you reload — `clawpatrol validate` runs the same
load pipeline the daemon uses, so any typo shows up here instead of
crashing the gateway on restart:

```bash
clawpatrol validate /etc/clawpatrol/gateway.hcl
# ok: /etc/clawpatrol/gateway.hcl — 4 endpoints across 1 profile(s)
```

If you see errors, they'll be one-per-line with `path:line` and a
detail string — fix them all before reloading.

Reload the gateway:

```bash
sudo systemctl reload clawpatrol-gateway
# or, if the unit doesn't define ExecReload:
sudo systemctl restart clawpatrol-gateway
```

## 4. First approval

Open two windows:

1. The dashboard at `http://203.0.113.42:9080` (from the joined
   laptop's browser — the tunnel makes the gateway reachable on its
   peer IP and the dashboard auto-signs you in via your wg peer).
2. A terminal on the laptop.

In the terminal, exercise a GitHub write through the gateway. Put
a personal access token in the gateway-side credential store first
(once, via the dashboard's **Credentials** panel) so the gateway
has a real token to substitute. Then:

```bash
clawpatrol run -- gh issue create --repo your-org/your-repo \
  --title 'hello from clawpatrol' --body 'first approval'
```

The `gh` process hangs while the request waits for approval. Flip
to the dashboard's **Pending approvals** panel — your call is
sitting there with its method, path, host, and body. Click
**allow**. The terminal unblocks and `gh` prints the issue URL as
usual.

Run the same command again — pre-approved rules don't carry over,
so it pauses again. Add a more permissive rule later (or use the
LLM approver pattern in [Approval rules](approval-rules) for
cheap, automated approvals against a written policy) once you've
verified the wire.

## What's next

- [Approval rules](approval-rules) — full rule, condition, and
  approver reference.
- [Config reference](config-reference) — `gateway.hcl` field
  reference.
- [Architecture](architecture) — how TLS interception and
  per-process tunneling work.
- [Security model](security-model) — what Claw Patrol protects
  against and what it does not.

## Friction-point notes (from the onboarding audit)

This walkthrough was rebuilt after a clean-room install on a fresh
Ubuntu 24.04 box. Seven friction points surfaced; here's how each
one is handled now:

| Friction | Status |
|---|---|
| `clawpatrol join` would silently misbehave if run under `sudo` (files landed in `/root`, normal shell couldn't see them). | **Fixed.** The CLI refuses `sudo clawpatrol join` outright and points at the right invocation. Same guard on `run` and `login`. |
| `wg.conf` and `~/.clawpatrol/*` could end up root-owned when the user ran the whole join via sudo. | **Fixed by the same guard** — the per-user files only ever get written by the non-sudo path. The privileged steps (CA trust install, optional `wg-quick`) sudo-elevate from within the CLI and write into root-owned system locations as expected. |
| `clawpatrol run` printed `kernel.unprivileged_userns_clone=1` as the fix-up when the userns clone EPERM'd, but Ubuntu 24.04 doesn't expose that sysctl — its blocker is `kernel.apparmor_restrict_unprivileged_userns`. | **Fixed.** The CLI now probes `/proc/sys/kernel/` and prints the sysctl that actually applies on the running kernel. On Ubuntu 24.04 you get `apparmor_restrict_unprivileged_userns=0`; on older Debian/Ubuntu you get `unprivileged_userns_clone=1`. |
| The dashboard URL and how to reach it weren't printed after `join`. | **Fixed.** The post-join summary now prints the dashboard URL and explains the auto-sign-in via the wg/tailnet peer. |
| `--no-trust` was an undocumented flag, even though it's the only practical option on read-only-rootfs or distroless containers. | **Fixed.** Listed in `clawpatrol --help`, in [CLI reference](cli), and called out in step 2 above. |
| `clawpatrol gateway init` emitted an HCL that failed `clawpatrol validate` on the first run — no `dashboard_secret`, plus the `profile "default"` block referenced a `openai` endpoint that doesn't exist (the real names are `openai-api` / `openai-chatgpt`). The user had to read a wall of HCL diagnostics before the gateway would boot. | **Fixed.** `gateway init` now generates a per-host random `dashboard_secret` (hex, written 0o600), and the `profile "default"` endpoints list matches the endpoint names declared above it. |
| `clawpatrol validate` truncated its output to "first-error, and N other diagnostic(s)" — to see the rest you had to fix the first error and re-run, doing one round-trip per problem. | **Fixed.** All diagnostics now print on their own line, with `path:line` and detail, so a single editor session can clean up the whole file. |

If you hit a friction point we haven't addressed, file an issue
against `denoland/clawpatrol`.
