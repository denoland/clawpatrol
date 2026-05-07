# Getting Started

## Install

```bash
npm install -g clawpatrol
```

Requires Node.js 22+.

## Onboard

Run the interactive setup:

```bash
clawpatrol onboard
```

This will:

1. Start a local proxy on your machine
2. Scan for API keys (environment variables, config files)
3. Import selected keys into the proxy
4. Configure your system to route agent traffic through it

On macOS, you'll be prompted to approve a Network Extension
and proxy configuration. On Linux, you can choose between a
systemd service or an ephemeral process.

See [Onboarding](/docs/03-onboarding/) for all the details about the
onboarding process.

## Run an Agent

Once onboarded, run any command through the proxy:

```bash
clawpatrol run claude
clawpatrol run python agent.py
clawpatrol run node my-agent.js
```

The proxy intercepts the agent's traffic, injects your API
keys, and logs every request. Open `http://localhost:8080` to
see the dashboard.

## What Just Happened

After onboarding, Claw Patrol is running as a background service.
Your API keys are stored in the local proxy (at `~/.clawpatrol/`),
not in plaintext environment variables. When you run an agent
through `clawpatrol run`, the proxy:

1. Intercepts HTTPS requests from the agent
2. Matches requests to configured integrations (by hostname)
3. Injects the real API key into the request headers
4. Forwards the request to the upstream service
5. Logs the request and response for the dashboard

The agent never sees your actual credentials.

## Dashboard

Open `http://localhost:8080` in your browser. The dashboard
shows:

- **Devices** — registered machines
- **Integrations** — configured API keys and plugins
- **Profiles** — groups of integrations assigned to agents
- **Requests** — live request log with full details
- **Analytics** — latency, status codes, LLM token costs

## Uninstall

```bash
clawpatrol offboard
```

This stops the proxy, removes the Network Extension (macOS)
or systemd service (Linux), and optionally deletes all data.

## Connecting to a remote gateway

Instead of running a local proxy, you can connect to any
self-hosted Claw Patrol gateway:

```bash
clawpatrol onboard --server https://gateway.example.com
```

This skips local proxy setup and authenticates with the remote
gateway via an OAuth device-code flow.
