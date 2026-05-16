rule "clickhouse-allow-read" {
  endpoints = [clickhouse-o11y]
  condition = "sql.verb in ['select', 'show', 'describe', 'explain', 'use', 'exists']"
  verdict   = "allow"
}

# ===== harness =====

admin_email = "ops@example.com"

credential "clickhouse_credential" "ch-cred" { user = "agent" }

endpoint "clickhouse_native" "clickhouse-o11y" {
  hosts      = ["clickhouse.example"]
  credential = ch-cred
}

profile "default" { endpoints = [clickhouse-o11y] }
