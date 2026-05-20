listen        = "0.0.0.0:8443"
unknown_host  = "passthrough"
llm_fail_mode = "closed"

# Regression for the "silent dead-end" footgun: profile lists a
# postgres_environment whose `credential = pg-rw` ref points at a
# credential the profile does NOT include in `credentials = [...]`.
# Without the validation, the env-pushdown would emit a PGPASSWORD
# placeholder that the MITM path could never replace, and the agent
# would receive a placeholder forever with no runtime error.
endpoint "postgres" "pg" {
  host = "pg.internal.example.com:5432"
}

credential "postgres_credential" "pg-ro" {
  endpoint = postgres.pg
  user     = "agent_ro"
  database = "appdb"
}

credential "postgres_credential" "pg-rw" {
  endpoint = postgres.pg
  user     = "agent_rw"
  database = "appdb"
}

environment "postgres_environment" "pg-rw-env" {
  endpoint   = postgres.pg
  credential = postgres_credential.pg-rw
}

profile "default" {
  credentials  = [postgres_credential.pg-ro]
  environments = [postgres_environment.pg-rw-env]
}
