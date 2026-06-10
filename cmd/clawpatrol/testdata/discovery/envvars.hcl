# Render profile: ai
#
# A profile whose credential pushes environment variables into the
# agent's process. gemini_api_key implements EnvPushdownProvider, so its
# GOOGLE_API_KEY / GEMINI_API_KEY exports must surface in the manifest's
# Environment variables section (the bearer endpoint above it pushes
# none, proving only env-pushdown plugins appear).
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "github" { hosts = ["api.github.com"] }
endpoint "https" "gemini" { hosts = ["generativelanguage.googleapis.com"] }

credential "bearer_token" "gh" {
  endpoint    = https.github
  placeholder = "PH_GH"
}
credential "gemini_api_key" "gem" {
  endpoint = https.gemini
}

profile "ai" { credentials = [bearer_token.gh, gemini_api_key.gem] }
