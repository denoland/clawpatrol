# kubectl exec is gated by an LLM judge that reads the command argv:
# allows ls / ps / df, denies env dumps, sensitive file reads, and
# anything touching pod tokens or container sockets.

rule "k8s-exec-content-check" {
  endpoints = [kubernetes.k8s-dev, kubernetes.k8s-prod]
  priority  = 500
  condition = "k8s.resource == 'pods/exec'"
  approve   = [llm_approver.k8s-exec-content-judge]
}

# ===== harness =====

admin_email = "ops@example.com"

endpoint "kubernetes" "k8s-dev" {
  server = "k8s-dev.example"
}

endpoint "kubernetes" "k8s-prod" {
  server = "k8s-prod.example"
}

credential "mtls_credential" "k8s" {
  endpoints = [kubernetes.k8s-dev, kubernetes.k8s-prod]
}
credential "anthropic_manual_key" "anthropic-key" {}

approver "llm_approver" "k8s-exec-content-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic_manual_key.anthropic-key
  policy     = <<-EOT
    Inspect the kubectl exec command (each ?command= argv element).
    Deny if it dumps env vars (env, printenv, set, export, cat
    /proc/*/environ). Deny if it reads sensitive host-mount files.
    Allow ls, ps, df, ip, ss, mount, dmesg, top.
  EOT
}

profile "default" { credentials = [mtls_credential.k8s] }
