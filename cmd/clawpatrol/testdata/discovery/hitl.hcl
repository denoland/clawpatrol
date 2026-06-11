gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

# deploy: gated by a human approver  -> HITL
# admin:  gated by the built-in dashboard approver -> HITL
# search: gated by an llm approver (automated) -> NOT HITL
# status: no approve rule -> NOT HITL
endpoint "https" "deploy" { hosts = ["deploy.example"] }
endpoint "https" "admin" { hosts = ["admin.example"] }
endpoint "https" "search" { hosts = ["search.example"] }
endpoint "https" "status" { hosts = ["status.example"] }

credential "bearer_token" "deploy" {
  endpoint    = https.deploy
  placeholder = "PH_DEPLOY"
}
credential "bearer_token" "admin" {
  endpoint    = https.admin
  placeholder = "PH_ADMIN"
}
credential "bearer_token" "search" {
  endpoint    = https.search
  placeholder = "PH_SEARCH"
}
credential "bearer_token" "status" {
  endpoint    = https.status
  placeholder = "PH_STATUS"
}

# Auth for the llm approver's own API call — never granted to the agent
# (kept out of the profile), so it must not surface in the manifest.
credential "bearer_token" "judge" {
  endpoint    = https.search
  placeholder = "PH_JUDGE"
}

approver "human_approver" "release" { channel = "#release" }
approver "llm_approver" "auto" {
  model      = "claude-haiku-4-5"
  credential = bearer_token.judge
  policy     = "Allow read-only queries."
}

rule "gated-deploy" {
  endpoint  = https.deploy
  condition = "http.method == 'POST'"
  approve   = [human_approver.release]
}
rule "gated-admin" {
  endpoint  = https.admin
  condition = "http.method == 'DELETE'"
  approve   = [builtin.dashboard]
}
rule "auto-search" {
  endpoint  = https.search
  condition = "http.method == 'POST'"
  approve   = [llm_approver.auto]
}

profile "ops" {
  credentials = [bearer_token.deploy, bearer_token.admin, bearer_token.search, bearer_token.status]
}
