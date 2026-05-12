public_url = "https://clawpatrol.example.com"

profile "ci" {
  endpoints = []
}

enrollment "oidc" "gha" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "ci"
  ttl     = "1h"
  max_ttl = "2h"
  match   = { repository_id = "123" }
}
