# Block Postgres functions that could read the filesystem or open
# outbound connections from inside the database — pg_read_file,
# lo_get, and the whole dblink family.

rule "pg-banned-functions" {
  endpoint = postgres.pg-staging
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

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "postgres" "pg-staging" {
  host = "pg-staging.example:5432"
}

credential "postgres_credential" "pg" {
  endpoint = postgres.pg-staging
  user     = "agent"
}

profile "default" { credentials = [postgres_credential.pg] }
