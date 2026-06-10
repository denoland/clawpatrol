# Render profile: tunneled
#
# A profile whose reachable endpoint sits behind a tunnel. Exercises the
# tunnel-reporting path end-to-end: the endpoint must carry the tunnel's
# name/type, the markdown must spell out "Tunnel: REQUIRED", and a
# second, directly-reachable endpoint in the same profile must render
# "Tunnel: none" so the contrast is locked down. Pairs the local_command
# tunnel (the one the unit tests use) with a tunneled postgres endpoint.
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

tunnel "local_command" "csql" {
  command     = ["cloud_sql_proxy", "--instances", "p:r:db=tcp:5432"]
  listen      = "127.0.0.1:5432"
  ready_probe = "tcp"
  share       = "singleton"
  keepalive   = "5m"
}

endpoint "https" "github" { hosts = ["api.github.com"] }

endpoint "postgres" "prod-pg" {
  host    = "main-pg.example:5432"
  sslmode = "require"
  tunnel  = local_command.csql
}

credential "bearer_token" "gh" {
  endpoint    = https.github
  placeholder = "PH_GH"
}
credential "postgres_credential" "pg-rw" {
  endpoint = postgres.prod-pg
  user     = "app"
  database = "prod"
}

profile "tunneled" { credentials = [bearer_token.gh, postgres_credential.pg-rw] }
