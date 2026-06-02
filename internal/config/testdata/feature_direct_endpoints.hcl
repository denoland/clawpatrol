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

# Credential-bound endpoint (transitive claim via the credential).
endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "github" {
  endpoint = https.github
}

# Credential-less endpoints claimed directly by the profile. No
# credential binds them; the profile's rules still apply.
endpoint "https" "public_status" {
  hosts = ["status.example.com"]
}

endpoint "https" "internal_metrics" {
  hosts = ["metrics.internal"]
}

rule "status-reads" {
  endpoint  = https.public_status
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "metrics-default-deny" {
  endpoint = https.internal_metrics
  priority = -100
  verdict  = "deny"
  reason   = "metrics endpoint is read-path only"
}

profile "data" {
  credentials = [bearer_token.github]
  endpoints   = [https.public_status, https.internal_metrics]
}
