gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.com"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

enrollment "oidc" "ci" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "missing"
  ttl     = "1h"
  max_ttl = "2h"
  match   = { repository_id = "123" }
}
