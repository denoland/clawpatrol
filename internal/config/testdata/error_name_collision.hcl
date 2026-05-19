credential "bearer_token" "shared" {}

# Same name, different kind — flat namespace forbids this.
endpoint "https" "shared" {
  hosts      = ["api.example.com"]
  credential = shared
}
