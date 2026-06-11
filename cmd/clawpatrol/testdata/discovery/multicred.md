# Claw Patrol access manifest — profile: dba

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

## Human-in-the-loop approval

Some endpoints have rules that gate a matching request behind human approval (human-in-the-loop). When such a rule matches, the gateway PARKS the request pending a human decision instead of forwarding it upstream — and it may stay parked indefinitely while it waits for a person to approve or deny it. The gateway does NOT call upstream while a request is parked, so no side effect has happened yet. Do NOT treat a slow or hanging request to a gated endpoint as a failure or retry it blindly; the gateway is holding it on purpose.

By default the gateway parks the request synchronously: it holds your connection open until a human decides and then answers on that same connection — the real upstream response once the request is approved, or a denial if it is rejected. You do not have to do anything special; just let the request run instead of aborting it.

Either way the parked request has an approval status you can poll — you do not need to wait on a held connection to see where it stands. The gateway identifies a parked request by an `operation_id`. When it cannot hold the connection open long enough to answer inline it hands the request back with that `operation_id` (carried in a `status_url` field and the Location header) so you can follow it without re-sending. Poll the returned `status_url`, or GET https://clawpatrol.internal/api/hitl/operations/{operation_id}/status with that id, until the state is terminal: pending (still awaiting a human), approved, or denied (plus expired if the approval window lapses). On approval, replay the original request with the Clawpatrol-HITL-Operation header set to the operation_id to execute it — the gateway recognizes it as the same approved request and forwards it upstream.

None of this profile's endpoints currently gate requests behind human approval.

## Endpoints (1)

### pg  (postgres)

- Host(s): pg.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `pg-ro` — read-only: reporting and ad-hoc queries — connect with database=app user=reader
- Credential: postgres_credential `pg-rw` — read-write: schema migrations and data fixes — connect with database=app user=writer
- Example: `psql "host=pg.example port=5432 user=reader dbname=app sslmode=require"`

## Environment variables (0)

_None pushed for this profile._

