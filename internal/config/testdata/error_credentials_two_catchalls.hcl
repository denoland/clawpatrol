credential "clickhouse_credential" "a" {}
credential "clickhouse_credential" "b" {}

endpoint "clickhouse_native" "ep" {
  hosts = ["ch.example.com"]
  credentials = [
    { credential = a },
    { credential = b },
  ]
}
