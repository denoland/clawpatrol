# Claw Patrol access manifest — profile: dba

You are connected through the Claw Patrol gateway. It intercepts your
connections transparently: dial the hosts below as you normally would and
the gateway injects credentials and enforces policy. A credential
`placeholder` is a literal string you send where the secret would go — the
gateway swaps it for the real secret. This manifest is scoped to YOUR
device profile; it lists only what this profile grants.

## Endpoints (1)

### pg  (postgres)

- Host(s): pg.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `pg-ro` — connect with database=app user=reader
- Credential: postgres_credential `pg-rw` — connect with database=app user=writer
- Example: `psql "host=pg.example port=5432 user=reader dbname=app sslmode=require"`

## Credentials (2)

- postgres_credential `pg-ro` → endpoints: pg
- postgres_credential `pg-rw` → endpoints: pg
