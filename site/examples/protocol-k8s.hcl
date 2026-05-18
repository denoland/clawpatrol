# kubectl exec is gated by an LLM judge that reads the command argv:
# allows ls / ps / df, denies env dumps, sensitive file reads, and
# anything touching pod tokens or container sockets.
rule "k8s-exec-content-check" {
  endpoints = [k8s-dev, k8s-prod]
  priority  = 500
  condition = "k8s.resource == 'pods/exec'"
  approve   = [k8s-exec-content-judge]
}

# ===== harness =====

admin_email = "ops@example.com"

policy "k8s-exec-content" {
  text = <<-EOT
    Inspect the kubectl exec command (each ?command= argv element).
    Deny if it dumps env vars (env, printenv, set, export, cat
    /proc/*/environ). Deny if it reads sensitive host-mount files.
    Allow ls, ps, df, ip, ss, mount, dmesg, top.
  EOT
}

credential "mtls_credential" "k8s-cred" {}
credential "anthropic_manual_key" "anthropic-key" {}

approver "llm_approver" "k8s-exec-content-judge" {
  model      = "claude-haiku-4-5-20251001"
  credential = anthropic-key
  policy     = k8s-exec-content
}

endpoint "kubernetes" "k8s-dev" {
  server     = "k8s-dev.example"
  credential = k8s-cred
}

endpoint "kubernetes" "k8s-prod" {
  server     = "k8s-prod.example"
  credential = k8s-cred
}

profile "default" { endpoints = [k8s-dev, k8s-prod] }
