# Render profile: simple
#
# The minimal real profile: one HTTPS endpoint reachable with one bearer
# credential. Exercises host rendering, the placeholder, the curl hint,
# and the per-credential Credentials section in both formats.
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

profile "simple" { credentials = [bearer_token.gh] }
