# Block Postgres functions that could read the filesystem or open
# outbound connections from inside the database — pg_read_file,
# lo_get, and the whole dblink family.
rule "pg-banned-functions" {
  endpoint = pg-staging
  priority = 100
  condition = <<-CEL
    sets.intersects(sql.functions, [
      'pg_read_file', 'pg_read_binary_file', 'lo_get',
    ])
    || sql.functions.exists(f, f.startsWith('dblink_'))
  CEL
  verdict = "deny"
  reason  = "filesystem-reaching function"
}

# ===== harness =====

admin_email = "ops@example.com"

credential "postgres_credential" "pg-cred" { user = "agent" }

endpoint "postgres" "pg-staging" {
  host       = "pg-staging.example:5432"
  credential = pg-cred
}

profile "default" { endpoints = [pg-staging] }
