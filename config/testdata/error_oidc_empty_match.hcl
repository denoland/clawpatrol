public_url = "https://clawpatrol.example.com"

profile "ci" {
  endpoints = []
  allow_ephemeral_oidc = true
}

enrollment "oidc" "gha" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "ci"
  ttl     = "1h"
  max_ttl = "2h"
  match   = {}
}
