gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "http" "github" {
  hosts = ["api.github.com"]
}

credential "bearer_token" "pat" {
  endpoint = http.github
}

approver "human_approver" "ops" {
  channel = "#ops"
}

# Object-form approve stages are no longer accepted — every stage must
# be a bare-name reference. The previous closed-set check on stage
# attributes is now subsumed by the shape check.
rule "broken-approve" {
  endpoint  = http.github
  condition = "http.method == 'POST'"
  approve   = [{ naem = human_approver.ops }]
}

profile "default" {
  credentials = [bearer_token.pat]
}
