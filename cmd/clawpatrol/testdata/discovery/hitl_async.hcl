gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

# deploy: async-capable human approver (sync_wait_timeout + async_grant) -> async HITL
# release: human approver, async_grant enabled but NO sync_wait_timeout -> sync HITL only
# admin:   built-in dashboard approver -> sync HITL only (dashboard never goes async)
# status:  no approve rule -> NOT HITL
endpoint "https" "deploy" { hosts = ["deploy.example"] }
endpoint "https" "release" { hosts = ["release.example"] }
endpoint "https" "admin" { hosts = ["admin.example"] }
endpoint "https" "status" { hosts = ["status.example"] }

credential "bearer_token" "deploy" {
  endpoint    = https.deploy
  placeholder = "PH_DEPLOY"
}
credential "bearer_token" "release" {
  endpoint    = https.release
  placeholder = "PH_RELEASE"
}
credential "bearer_token" "admin" {
  endpoint    = https.admin
  placeholder = "PH_ADMIN"
}
credential "bearer_token" "status" {
  endpoint    = https.status
  placeholder = "PH_STATUS"
}

# Async-capable: 90s sync window, 10m overall timeout -> async poll TTL of 8m30s.
approver "human_approver" "deployer" {
  channel           = "#deploy"
  timeout           = 600
  sync_wait_timeout = "90s"
  async_grant {
    enabled            = true
    approved_retry_ttl = "5m"
    fingerprint_body   = "raw"
  }
}

# async_grant enabled but no sync_wait_timeout -> never hands back a 202.
approver "human_approver" "releaser" {
  channel = "#release"
  async_grant {
    enabled = true
  }
}

rule "gated-deploy" {
  endpoint  = https.deploy
  condition = "http.method == 'POST'"
  approve   = [human_approver.deployer]
}
rule "gated-release" {
  endpoint  = https.release
  condition = "http.method == 'POST'"
  approve   = [human_approver.releaser]
}
rule "gated-admin" {
  endpoint  = https.admin
  condition = "http.method == 'DELETE'"
  approve   = [builtin.dashboard]
}

profile "ops" {
  credentials       = [bearer_token.deploy, bearer_token.release, bearer_token.admin, bearer_token.status]
  hitl_async_grants = true
}
