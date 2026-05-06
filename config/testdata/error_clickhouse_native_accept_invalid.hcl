credential "clickhouse_credential" "ch" {}

endpoint "clickhouse_native" "bad-accept-invalid" {
  hosts                      = ["ch.example.com"]
  accept_invalid_certificate = true
  credential                 = ch
}
