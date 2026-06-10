# Render profile: dba
#
# Two postgres credentials bound to the SAME endpoint, disambiguated by
# user/database. The endpoint must list both credentials (sorted by
# name), the Credentials section must list both pointing back at the one
# endpoint, and the psql hint must pin to the first credential by sort
# order (pg-ro). Locks down the multiple-creds-per-endpoint shape.
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "postgres" "pg" {
  host    = "pg.example:5432"
  sslmode = "require"
}

credential "postgres_credential" "pg-rw" {
  endpoint    = postgres.pg
  user        = "writer"
  database    = "app"
  description = "read-write: schema migrations and data fixes"
}
credential "postgres_credential" "pg-ro" {
  endpoint    = postgres.pg
  user        = "reader"
  database    = "app"
  description = "read-only: reporting and ad-hoc queries"
}

profile "dba" { credentials = [postgres_credential.pg-rw, postgres_credential.pg-ro] }
