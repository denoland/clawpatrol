credential "bearer_token" "pat" {}
credential "postgres_credential" "pg" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = pat
}
endpoint "postgres" "db" {
  host       = "db.example.com:5432"
  credential = pg
}

# A rule's endpoint list must be from a single protocol family —
# family inference can only pick one CEL env for the condition.
rule "mixed-family" {
  endpoints = [github, db]
  condition = "http.method == 'GET'"
  verdict   = "allow"
}

profile "default" {
  endpoints = [github, db]
}
