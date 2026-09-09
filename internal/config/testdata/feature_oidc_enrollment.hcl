gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://clawpatrol.example.com/"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "github-pat" {
  endpoint = https.github
}

profile "ci-readonly" {
  credentials          = [bearer_token.github-pat]
  allow_ephemeral_oidc = true
}

enrollment "oidc" "github-main-ci" {
  issuer = "https://token.actions.githubusercontent.com"

  profile = "ci-readonly"
  ttl     = "1h"
  max_ttl = "2h"

  match = {
    repository_owner_id = "12345678"
    repository_id       = "987654321"
    workflow_ref        = "example-org/example-repo/.github/workflows/ci.yml@refs/heads/main"
    ref                 = "refs/heads/main"
    ref_type            = "branch"
    event_name          = ["push", "workflow_dispatch"]
  }

  metadata = {
    provider = "github_actions"
    label    = "github-main-ci"
  }
}
