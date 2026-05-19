credential "clickhouse_credential" "a" {}

endpoint "clickhouse_native" "ep" {
  hosts = ["ch.example.com"]
  credentials = [
    { database = "prod", databases = ["dev"], credential = a },
  ]
}
