public_url = "https://clawpatrol.example.com"

enrollment "oidc" "ci" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "missing"
  ttl     = "1h"
  max_ttl = "2h"
  match   = { repository_id = "123" }
}
