credential "bearer_token" "a" {}
credential "bearer_token" "b" {}

endpoint "https" "ep" {
  hosts = ["x.example.com"]
  credentials = [
    { placeholder = "PH_x", database = "prod", credential = a },
    { placeholder = "PH_x", database = "prod", credential = b },
  ]
}
