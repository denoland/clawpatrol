listen     = "0.0.0.0:8443"

unknown_host  = "passthrough"
llm_fail_mode = "closed"

# Two postgres credentials over the same endpoint: readonly + writer.
# The profile picks ONE of them (pg-rw) to source env vars via a
# postgres_environment block; the other (pg-ro) is still reachable
# but its PG* vars aren't pushed.
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

environment "custom_environment" "aws-region" {
  key   = "AWS_REGION"
  value = "us-east-1"
}

profile "default" {
  credentials  = [postgres_credential.pg-ro, postgres_credential.pg-rw]
  environments = [postgres_environment.pg-rw-env, custom_environment.aws-region]
}
