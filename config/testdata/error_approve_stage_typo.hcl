credential "bearer_token" "pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}

approver "human_approver" "ops" {
  channel = "#ops"
}

policy "draft-review" { text = "Approve only safe edits." }

# Object-form stage with a typo'd attribute (`naem` instead of
# `name`). Without the closed-set check, this stage would carry an
# empty Name and silently no-op at request time.
rule "http_rule" "broken-approve" {
  endpoint = github
  match    = { method = "POST" }
  approve  = [{ naem = ops, policy = draft-review }]
}

profile "default" {
  endpoints = [github]
}
