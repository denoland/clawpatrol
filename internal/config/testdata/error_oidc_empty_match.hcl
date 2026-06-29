gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.com"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

profile "ci" {
  credentials = []
  allow_ephemeral_oidc = true
}

enrollment "oidc" "gha" {
  issuer  = "https://token.actions.githubusercontent.com"
  profile = "ci"
  ttl     = "1h"
  max_ttl = "2h"
  match   = {}
}
