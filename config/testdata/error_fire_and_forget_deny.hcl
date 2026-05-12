credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

# fire_and_forget on a deny rule makes no semantic sense — there's
# nothing to auto-allow when the outcome is to block.
rule "github-blocked-deletes" {
  endpoint        = github
  condition       = "http.method == 'DELETE'"
  verdict         = "deny"
  fire_and_forget = true
}

profile "default" {
  endpoints = [github]
}
