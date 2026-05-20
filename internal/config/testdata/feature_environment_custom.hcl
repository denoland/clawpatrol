listen     = "0.0.0.0:8443"

unknown_host  = "passthrough"
llm_fail_mode = "closed"

endpoint "https" "github" {
  hosts = ["api.github.com", "github.com"]
}

credential "bearer_token" "github-pat" {
  endpoint = https.github
}

rule "github-reads" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

environment "custom_environment" "aws-region" {
  key   = "AWS_REGION"
  value = "us-east-1"
}

environment "custom_environment" "openai-base-url" {
  key         = "OPENAI_BASE_URL"
  value       = "https://gateway.example.test/openai/v1"
  description = "route the OpenAI SDK through the gateway"
}

profile "default" {
  credentials  = [bearer_token.github-pat]
  environments = [custom_environment.aws-region, custom_environment.openai-base-url]
}
