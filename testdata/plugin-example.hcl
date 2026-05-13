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
// Gateway terminates TLS; the plugin runs the protocol but asks
// the gateway for an allow/deny on every command via Conn.Evaluate.
// The plugin declares an `smtp` facet — the rules below target it
// by writing CEL conditions against `smtp.verb`, `smtp.mail_from`,
// `smtp.rcpt_to`, etc. The action map for each command also lands
// on the dashboard event stream as the request's facet payload, so
// the request log shows Verb / From / Rcpt / User columns.
endpoint "example.demo_smtp" "demo-mail" {
  hosts      = ["mail.invalid:25"]
  credential = demo_token
}

rule "smtp-handshake" {
  endpoint  = demo-mail
  condition = "smtp.verb in ['EHLO', 'HELO', 'AUTH', 'QUIT']"
  verdict   = "allow"
}

rule "smtp-internal-only" {
  endpoint  = demo-mail
  condition = "smtp.verb in ['MAIL', 'RCPT', 'DATA'] && smtp.mail_from.endsWith('@internal')"
  verdict   = "allow"
}

rule "smtp-deny-external" {
  endpoint  = demo-mail
  condition = "smtp.verb in ['MAIL', 'RCPT', 'DATA']"
  verdict   = "deny"
  reason    = "external sender"
}

// Body-content rule. References smtp.body, so the gateway pulls the
// full message body (up to its 1 MiB cap) for BODY evaluations on
// this endpoint. The handshake / MAIL / RCPT rules above don't
// touch smtp.body, so the gateway only pulls a log-prefix when those
// fire on a non-DATA verb — bodies on internal-allowed messages are
// pulled in full only because of this rule.
rule "smtp-body-no-secrets" {
  endpoint  = demo-mail
  condition = "smtp.verb == 'BODY' && !smtp.body.contains('SECRET')"
  verdict   = "allow"
}

rule "smtp-body-deny" {
  endpoint  = demo-mail
  condition = "smtp.verb == 'BODY'"
  verdict   = "deny"
  reason    = "body contains restricted token"
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
