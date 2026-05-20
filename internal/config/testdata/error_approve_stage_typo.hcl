credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = bearer_token.pat
}

approver "human_approver" "ops" {
  channel = "#ops"
}

policy "draft-review" { text = "Approve only safe edits." }

# Object-form approve stages are no longer accepted — every stage must
# be a bare-name reference. The previous closed-set check on stage
# attributes is now subsumed by the shape check.
rule "broken-approve" {
  endpoint  = https.github
  condition = "http.method == 'POST'"
  approve   = [{ naem = human_approver.ops, policy = policy.draft-review }]
}

profile "default" {
  endpoints = [https.github]
}
