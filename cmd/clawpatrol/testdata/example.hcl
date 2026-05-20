// Sample config for `clawpatrol test` (see site/doc/clawpatrol-test.md). Pair
// with the *.json fixtures alongside it to verify the runner
// end-to-end:
//
//   ./clawpatrol test testdata/example.hcl testdata/
//
// Edit any rule below and re-run to see a mismatch.

// admin_email is required by config.Compile; the runner doesn't
// consult it.
admin_email = "you@example.com"

endpoint "https" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "github" {
  endpoint = https.github
}

rule "github-reads" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "github-writes" {
  endpoint  = https.github
  condition = "http.method in ['POST', 'PATCH', 'PUT', 'DELETE']"
  verdict   = "deny"
  reason    = "writes go through PR review"
}

profile "default" { credentials = [bearer_token.github] }
