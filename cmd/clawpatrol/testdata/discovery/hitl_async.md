# Claw Patrol access manifest — profile: ops

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

The gateway parks the request synchronously: it holds your connection open until a human decides and then answers on that same connection — the real upstream response once the request is approved, or a denial if it is rejected. You do not have to do anything special or re-send anything; just let the request run instead of aborting it.

To see everything currently waiting on a human for your device, GET https://clawpatrol.internal/pending. It lists each parked action — its method, endpoint, and redacted target — so you can tell what is held without keeping the original connection in view.

Endpoints below that may park a request for human approval: admin, deploy, release.

### Asynchronous approval (202 + polling)

Some gated endpoints do not hold your connection forever. Each such endpoint has a synchronous wait window (its sync_wait_timeout, listed per endpoint below): if a human has not decided within that window, the gateway stops holding the connection and answers with HTTP 202 Accepted. A 202 is NOT success and NOT failure — it means "parked for human approval, continuing asynchronously." Do not treat it as either; switch to polling.

The 202 body is JSON describing the parked operation. The fields you act on:
- operation_id: the parked operation's id.
- status_url: the absolute URL to poll for this operation's status (also returned in the Location header). Poll THIS url; do not build your own — the template is /api/hitl/operations/{operation_id}/status.
- state: the current state (see below).
- terminal: true once the operation has reached a final state and will not change.
- poll_operation_status: true while you should keep polling status_url (the operation is parked waiting on a human). Mutually exclusive with retry_original_request.
- retry_original_request: true once a human has approved and you should RE-SEND the original request to execute it (see approved_waiting_for_retry below). Mutually exclusive with poll_operation_status.
The 202 also carries a Retry-After header (suggested 5 seconds) — wait that long between polls.

Poll status_url with GET until the state resolves. The states:
- sync_waiting / pending_approval: still waiting on a human; keep polling (honoring Retry-After). No upstream call has happened. pending_approval includes an approval_expires_at — the operation stays pollable until then; only after that does it become expired, so keep polling a pending operation rather than giving up early.
- approved_waiting_for_retry: a human approved it, but the gateway has NOT called upstream yet. To execute it, RE-SEND the exact same original request with the header Clawpatrol-HITL-Operation set to the operation_id, before retry_expires_at. The retry is what performs the upstream call.
- denied: a human rejected it; do not retry. Stop.
- expired: the approval window or the post-approval retry window elapsed with no (or no acted-on) decision; do not retry. Stop. expired is distinct from pending_approval — pending means keep polling, expired means it is over.

You can also GET status_url at any time without a prior 202 to re-check an operation you already know the id of.

Endpoints that fall back to asynchronous approval, and the synchronous wait window before each returns a 202:

- deploy: returns 202 after 1m30s of waiting; the parked operation then stays pollable for 8m30s.

## Endpoints (4)

### admin  (https)

- Host(s): admin.example
- Credential: bearer_token `admin` — send placeholder `PH_ADMIN`
- Example: `curl https://admin.example/ -H "Authorization: Bearer PH_ADMIN"`
- Human-in-the-loop: a matching request may be PARKED pending human approval and held until a person decides. Let it run instead of treating a slow request as a failure; see the human-in-the-loop section above.

### deploy  (https)

- Host(s): deploy.example
- Credential: bearer_token `deploy` — send placeholder `PH_DEPLOY`
- Example: `curl https://deploy.example/ -H "Authorization: Bearer PH_DEPLOY"`
- Human-in-the-loop: a matching request may be PARKED pending human approval and held until a person decides. Let it run instead of treating a slow request as a failure; see the human-in-the-loop section above.

### release  (https)

- Host(s): release.example
- Credential: bearer_token `release` — send placeholder `PH_RELEASE`
- Example: `curl https://release.example/ -H "Authorization: Bearer PH_RELEASE"`
- Human-in-the-loop: a matching request may be PARKED pending human approval and held until a person decides. Let it run instead of treating a slow request as a failure; see the human-in-the-loop section above.

### status  (https)

- Host(s): status.example
- Credential: bearer_token `status` — send placeholder `PH_STATUS`
- Example: `curl https://status.example/ -H "Authorization: Bearer PH_STATUS"`

## Environment variables (0)

_None pushed for this profile._

