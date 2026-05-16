rule "k8s-no-secrets" {
  endpoints = [k8s-dev, k8s-prod]
  priority  = 1000
  condition = "k8s.resource == 'secrets'"
  verdict   = "deny"
  reason    = "secrets stay in the cluster"
}

# ===== harness =====
# Everything below is config scaffolding so `clawpatrol validate`
# accepts this file. The landing page renders only the snippet above.

admin_email = "ops@example.com"

credential "mtls_credential" "k8s-dev-cred"  {}
credential "mtls_credential" "k8s-prod-cred" {}

endpoint "kubernetes" "k8s-dev" {
  server     = "k8s-dev.example"
  credential = k8s-dev-cred
}

endpoint "kubernetes" "k8s-prod" {
  server     = "k8s-prod.example"
  credential = k8s-prod-cred
}

profile "default" { endpoints = [k8s-dev, k8s-prod] }
