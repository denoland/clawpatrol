gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

defaults {
  unknown_host  = "passthrough"
  llm_fail_mode = "closed"
}

endpoint "http" "github" {
  hosts = ["api.github.com", "github.com"]
}

credential "bearer_token" "github" {
  endpoint = http.github
}

approver "human_approver" "ops" {
  channel = "#agent-ops"
  timeout = 600
}

rule "github-reads" {
  endpoint  = http.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = http.github
  condition = "http.method in ['POST', 'PATCH', 'DELETE']"
  approve   = [human_approver.ops]
}

profile "default" {
  credentials = [bearer_token.github]
}
