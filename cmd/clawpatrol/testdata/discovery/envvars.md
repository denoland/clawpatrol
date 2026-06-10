# Claw Patrol access manifest — profile: ai

You are connected through the Claw Patrol gateway. It intercepts your
connections transparently: dial the hosts below as you normally would and
the gateway injects credentials and enforces policy. A credential
`placeholder` is a literal string you send where the secret would go — the
gateway swaps it for the real secret. This manifest is scoped to YOUR
device profile; it lists only what this profile grants.

TLS is intercepted only for the hosts this profile grants — the
endpoints listed below. For those, the gateway terminates TLS and acts
as a transparent man-in-the-middle: the certificate you see is minted on
the fly by Claw Patrol's own certificate authority, not the host's real
public certificate. The hostname matches but the issuer is the gateway
CA. You normally don't have to do anything to trust it: Claw Patrol
already installed its CA on this device when you joined — both in the
system trust store and via environment-variable pushdown
(SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE,
and similar) that `clawpatrol run` sets for the processes it wraps. So
most clients validate these connections out of the box, and a
certificate-authority mismatch against the public web PKI is expected
for these hosts, not an attack. If a client ignores both the system
store and those env vars, fetch the CA from
https://clawpatrol.internal/ca.crt, verify its fingerprint against
https://clawpatrol.internal/info, and point that
client at it explicitly.

Every other host is passed through untouched: the gateway does not
intercept it, you get the upstream's real certificate, and you must
still verify it against the public web PKI as usual.

## Endpoints (2)

### gemini  (https)

- Host(s): generativelanguage.googleapis.com
- Credential: gemini_api_key `gem`
- Example: `curl https://generativelanguage.googleapis.com/`

### github  (https)

- Host(s): api.github.com
- Credential: bearer_token `gh` — send placeholder `PH_GH`
- Example: `curl https://api.github.com/ -H "Authorization: Bearer PH_GH"`

## Environment variables (2)

`clawpatrol run` sets these in your process environment so your CLI/SDK
finds its credential automatically. The value shown is what the gateway
exports — a placeholder that looks like a real token (swapped for the
real secret at request time) or a synthetic token, never the secret
itself. You don't need to set these yourself; this is what is already
in your environment.

- `GOOGLE_API_KEY` = `AIzaClawpatrolPlaceholderDoNotUse00000000` — Gemini SDKs
- `GEMINI_API_KEY` = `AIzaClawpatrolPlaceholderDoNotUse00000000` — Gemini CLI

