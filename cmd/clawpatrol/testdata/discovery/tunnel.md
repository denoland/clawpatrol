# Claw Patrol access manifest — profile: tunneled

You are connected through the Claw Patrol gateway. It intercepts your
connections transparently: dial the hosts below as you normally would and
the gateway injects credentials and enforces policy. A credential
`placeholder` is a literal string you send where the secret would go — the
gateway swaps it for the real secret. This manifest is scoped to YOUR
device profile; it lists only what this profile grants.

## Endpoints (2)

### github  (https)

- Host(s): api.github.com
- Tunnel: none (reachable directly through the gateway)
- Credential: bearer_token `gh` — send placeholder `PH_GH`
- Example: `curl https://api.github.com/ -H "Authorization: Bearer PH_GH"`

### prod-pg  (postgres)

- Host(s): main-pg.example
- Port: 5432
- SSL mode: require
- Tunnel: REQUIRED — `csql` (local_command) must be active to reach this endpoint
- Credential: postgres_credential `pg-rw` — connect with database=prod user=app
- Example: `psql "host=main-pg.example port=5432 user=app dbname=prod sslmode=require"`

## Credentials (2)

- bearer_token `gh` → placeholder `PH_GH` → endpoints: github
- postgres_credential `pg-rw` → endpoints: prod-pg
