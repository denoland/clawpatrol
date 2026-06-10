# Claw Patrol access manifest — profile: tunneled

You are connected through the Claw Patrol gateway. It intercepts your
connections transparently: dial the hosts below as you normally would and
the gateway injects credentials and enforces policy. A credential
`placeholder` is a literal string you send where the secret would go — the
gateway swaps it for the real secret. This manifest is scoped to YOUR
device profile; it lists only what this profile grants.

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

