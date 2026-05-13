listen     = "0.0.0.0:8443"
ca_dir     = "/opt/clawpatrol/ca"

unknown_host  = "passthrough"
llm_fail_mode = "closed"

credential "anthropic_oauth_subscription" "alice" {}
credential "anthropic_oauth_subscription" "bob"   {}
credential "anthropic_oauth_subscription" "carol" {}

credential "pool" "team" {
  credentials = [alice, bob, carol]
  strategy    = "round_robin"
}

endpoint "https" "anthropic" {
  hosts      = ["api.anthropic.com"]
  credential = team
}

profile "default" {
  endpoints = [anthropic]
}
