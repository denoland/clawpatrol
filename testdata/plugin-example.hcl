// Sample gateway config that loads the example external plugin.
//
// Build the plugin first:
//
//   go build -o ./plugin-example/plugin-example ./plugin-example
//
// Then run the gateway against this file. The plugin declares one
// credential type (magic_token), one tunnel type (passthrough), and
// three endpoint types (demo_https, demo_smtp, demo_echo). Type
// names are namespaced under the plugin's manifest name "example".

admin_email = "you@example.com"

plugin "example" {
  source = "./plugin-example/plugin-example"
}

credential "example.magic_token" "demo_token" {
  // header_name is the HTTP header the demo_https endpoint adds to
  // upstream requests. Defaults to "X-Magic" when omitted.
  header_name = "X-Magic"
}

tunnel "example.passthrough" "passthru" {}

// HTTPS endpoint: gateway terminates TLS, plugin parses HTTP, adds
// the credential's secret bytes as <header_name>: <token> to the
// upstream request, then appends "\nbye!\n" to the response body
// before sending it back to the agent.
//
// Set CLAWPATROL_SECRET_DEMO_TOKEN=hello in the environment, then
// `curl -k https://demo.invalid/` against a local HTTP upstream
// (e.g. `python3 -m http.server 8000`) — the upstream sees the
// X-Magic header and curl prints the body with "bye!" appended.
endpoint "example.demo_https" "demo-site" {
  hosts      = ["demo.invalid"]
  credential = demo_token
  tunnel     = passthru
  upstream   = "http://127.0.0.1:8000"
}

// TLS-but-not-HTTPS endpoint: synthetic ESMTP-ish handshake.
// Gateway terminates TLS, plugin reads lines and runs a tiny
// AUTH PLAIN gate against the credential secret. No upstream.
endpoint "example.demo_smtp" "demo-mail" {
  hosts      = ["mail.invalid:25"]
  credential = demo_token
}

// Plain-TCP endpoint: no TLS at all. Plugin reads lines and echoes
// them back prefixed with the credential secret.
endpoint "example.demo_echo" "demo-echo" {
  hosts      = ["echo.invalid:7"]
  credential = demo_token
}

profile "default" {
  endpoints = [demo-site, demo-mail, demo-echo]
}
