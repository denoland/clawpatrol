endpoint "https" "github" {
  hosts = ["api.github.com"]
}
endpoint "postgres" "db" {
  host = "db.example.com:5432"
}

credential "bearer_token" "pat" {
  endpoint = https.github
}
credential "postgres_credential" "pg" {
  endpoint = postgres.db
}

# A rule's endpoint list must be from a single protocol family —
# family inference can only pick one CEL env for the condition.
rule "mixed-family" {
  endpoints = [https.github, postgres.db]
  condition = "http.method == 'GET'"
  verdict   = "allow"
}

profile "default" {
  credentials = [bearer_token.pat, postgres_credential.pg]
}
