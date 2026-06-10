# Render profile: tunneled
#
# A profile whose endpoints sit behind tunnels — one per tunnel plugin
# type (local_command, tailscale, ssh_port_forward,
# kubernetes_port_forward). The point of covering every type is to lock
# down that NONE of them leak into the agent-facing manifest: the gateway
# brings the tunnel up transparently, so each endpoint must render
# identically to a directly-reachable one (host/port/credential only, no
# tunnel line). A direct `github` endpoint is kept alongside as the
# contrast — the tunneled endpoints must read no differently from it.
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

tunnel "tailscale" "ts" {
  hostname = "clawpatrol-tunnel-o11y"
}

credential "ssh_key" "bastion" {}

tunnel "ssh_port_forward" "bastion-pg" {
  bastion    = "bastion.example:22"
  user       = "deploy"
  credential = ssh_key.bastion
}

tunnel "kubernetes_port_forward" "kpf" {
  context = "prod-eks"
  service = "postgres"
  port    = 5432
}

endpoint "https" "github" { hosts = ["api.github.com"] }

endpoint "postgres" "prod-pg" {
  host    = "main-pg.example:5432"
  sslmode = "require"
  tunnel  = local_command.csql
}

endpoint "clickhouse_native" "metrics" {
  hosts  = ["ch.example"]
  port   = 9440
  tls    = true
  tunnel = tailscale.ts
}

endpoint "postgres" "rds-pg" {
  host    = "rds.example:5432"
  sslmode = "require"
  tunnel  = ssh_port_forward.bastion-pg
}

endpoint "postgres" "k8s-pg" {
  host    = "k8s-pg.example:5432"
  sslmode = "require"
  tunnel  = kubernetes_port_forward.kpf
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
credential "clickhouse_credential" "ch-ro" {
  endpoint = clickhouse_native.metrics
  user     = "ro"
}
credential "postgres_credential" "rds-rw" {
  endpoint = postgres.rds-pg
  user     = "app"
  database = "prod"
}
credential "postgres_credential" "k8s-rw" {
  endpoint = postgres.k8s-pg
  user     = "app"
  database = "prod"
}

profile "tunneled" {
  credentials = [
    bearer_token.gh,
    postgres_credential.pg-rw,
    clickhouse_credential.ch-ro,
    postgres_credential.rds-rw,
    postgres_credential.k8s-rw,
  ]
}
