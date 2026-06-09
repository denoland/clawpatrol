# Render profile: empty
#
# A declared profile that grants no credentials. Other endpoints and
# credentials exist in the config, so a non-empty manifest here would
# mean the per-profile scoping leaked. The manifest must come back with
# zero endpoints and zero credentials (not an error, not a config dump).
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "github" { hosts = ["api.github.com"] }

credential "bearer_token" "gh" {
  endpoint    = https.github
  placeholder = "PH_GH"
}

profile "haz-access" { credentials = [bearer_token.gh] }
profile "empty"      { credentials = [] }
