gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

# A profile lists two credentials that both bind the same endpoint
# without any placeholder dispatch entries. The compiler must reject
# this — at most one no-placeholder (fallback) credential is allowed
# per (profile, endpoint), and ambiguous bindings must disambiguate
# with `{ placeholder = "PH_...", credential = name }` entries.

endpoint "http" "anthropic" {
  hosts = ["api.anthropic.com"]
}

credential "bearer_token" "anthropic-prod" {
  endpoint = http.anthropic
}

credential "bearer_token" "anthropic-test" {
  endpoint = http.anthropic
}

profile "ops" {
  credentials = [bearer_token.anthropic-prod, bearer_token.anthropic-test]
}
