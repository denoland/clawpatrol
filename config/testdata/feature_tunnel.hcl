listen = "0.0.0.0:8443"
ca_dir = "/opt/clawpatrol/ca"

credential "bearer_token" "github-pat" {}

# Singleton local_command tunnel — one process serves every endpoint
# that references it.
tunnel "local_command" "csql-prod" {
  command       = ["cloud_sql_proxy", "--enable_iam_login",
                   "--instances", "example-project:us-central1:main-pg14=tcp:5432"]
  listen        = "127.0.0.1:5432"
  ready_probe   = "tcp"
  ready_timeout = "30s"
  share         = "singleton"
  keepalive     = "5m"
}

endpoint "https" "github" {
  hosts      = ["api.github.com", "github.com"]
  credential = github-pat
}

# Tunneled endpoint: dispatcher dials through csql-prod. RequiresVIP
# is forced on at compile time because the upstream isn't reachable
# from the agent's namespace.
endpoint "postgres" "deploy-classic" {
  host       = "main-pg14.classic.example:5432"
  database   = "deployng"
  tunnel     = csql-prod
  credential = github-pat
}

profile "default" {
  endpoints = [github, deploy-classic]
}
