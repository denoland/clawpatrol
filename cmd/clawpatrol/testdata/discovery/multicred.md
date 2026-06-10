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
CA. Trust that CA to verify these connections — fetch it from
https://clawpatrol/ca.crt and check its fingerprint against
https://clawpatrol/info. A certificate-authority mismatch against the
public web PKI is expected for these hosts, not an attack.

Every other host is passed through untouched: the gateway does not
intercept it, you get the upstream's real certificate, and you must
still verify it against the public web PKI as usual.

## Endpoints (1)

### pg  (postgres)

- Host(s): pg.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `pg-ro` — connect with database=app user=reader
- Credential: postgres_credential `pg-rw` — connect with database=app user=writer
- Example: `psql "host=pg.example port=5432 user=reader dbname=app sslmode=require"`

