# Claw Patrol access manifest — profile: tunneled

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

## Endpoints (5)

### github  (https)

- Host(s): api.github.com
- Credential: bearer_token `gh` — send placeholder `PH_GH`
- Example: `curl https://api.github.com/ -H "Authorization: Bearer PH_GH"`

### k8s-pg  (postgres)

- Host(s): k8s-pg.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `k8s-rw` — connect with database=prod user=app
- Example: `psql "host=k8s-pg.example port=5432 user=app dbname=prod sslmode=require"`

### metrics  (clickhouse_native)

- Host(s): ch.example
- Port: 9440
- Credential: clickhouse_credential `ch-ro` — connect with user=ro
- Example: `clickhouse-client --host ch.example --port 9440 --user ro`

### prod-pg  (postgres)

- Host(s): main-pg.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `pg-rw` — connect with database=prod user=app
- Example: `psql "host=main-pg.example port=5432 user=app dbname=prod sslmode=require"`

### rds-pg  (postgres)

- Host(s): rds.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `rds-rw` — connect with database=prod user=app
- Example: `psql "host=rds.example port=5432 user=app dbname=prod sslmode=require"`

## Environment variables (0)

_None pushed for this profile._

