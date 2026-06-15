// Sample gateway config that loads the example external plugin.
//
// Build the plugin first:
//
//   go build -o ./pluginsdk/example/example ./pluginsdk/example
//
// Then run the gateway against this file. The plugin declares one
// credential type (example_magic_token), one tunnel type
// (example_passthrough), and three endpoint types
// (example_https, example_smtp, example_echo). Type
// and facet names are flat — Claw Patrol doesn't auto-prefix
// anything. Plugin authors prefix their own names by convention,
// the way Terraform providers do (`aws_iam_role`,
// `kubernetes_deployment`).

gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

plugin "example" {
  source = "./pluginsdk/example/example"
  // No network grant here: the example plugin declares its own
  // network need (NetworkOutbound, for the passthrough tunnel) in its
  // manifest. The gateway records the approval in clawpatrol.lock.hcl
  // on first load. The endpoints don't need it — their upstream
  // connections go through the gateway's brokered dial.
}

tunnel "example_passthrough" "passthru" {}

// HTTPS endpoint: gateway terminates TLS, plugin parses HTTP and
// asks the gateway for a verdict on every request via the built-in
// `http` facet. The plugin reuses the gateway's stock HTTPS
// matcher, so the rules below are written exactly the same way
// they would be against any in-process HTTPS endpoint
// (`http.method`, `http.path`, `http.body`, `http.body_json`).
// On allow the plugin forwards upstream, injects the magic header,
// and rewrites the response body by appending "\nbye!\n". On deny
// it replies 403 with the rule's reason.
//
// Set CLAWPATROL_SECRET_DEMO_TOKEN=hello in the environment, then
// `curl -k https://demo.invalid/` against a local HTTP upstream
// (e.g. `python3 -m http.server 8000`) — the upstream sees the
// X-Magic header and curl prints the body with "bye!" appended.
endpoint "example_https" "demo-site" {
  hosts    = ["demo.invalid"]
  tunnel   = example_passthrough.passthru
  upstream = "http://127.0.0.1:8000"
  // The plugin reaches the upstream through the gateway's brokered
  // dial (it has no network access of its own); `dial` is the
  // operator-sanctioned allow-list of targets the gateway will open
  // for it beyond the agent's own destination.
  dial = ["127.0.0.1:8000"]
}

rule "https-reads" {
  endpoint  = example_https.demo-site
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
}

rule "https-writes-deny" {
  endpoint  = example_https.demo-site
  condition = "http.method in ['POST', 'PUT', 'PATCH', 'DELETE']"
  verdict   = "deny"
  reason    = "writes to demo upstream are not allowed"
}

// TLS-but-not-HTTPS endpoint: synthetic ESMTP-ish handshake.
// Gateway terminates TLS; the plugin runs the protocol but asks
// the gateway for an allow/deny on every command via Conn.Evaluate.
// The plugin declares an `example_smtp` facet — the rules below
// target it by writing CEL conditions against `example_smtp.verb`,
// `example_smtp.mail_from`, `example_smtp.rcpt_to`, etc. The action
// map for each command also lands on the dashboard event stream as
// the request's facet payload, so the request log shows
// Verb / From / Rcpt / User columns.
endpoint "example_smtp" "demo-mail" {
  hosts = ["mail.invalid:25"]
}

rule "smtp-handshake" {
  endpoint  = example_smtp.demo-mail
  condition = "example_smtp.verb in ['EHLO', 'HELO', 'AUTH', 'QUIT']"
  verdict   = "allow"
}

rule "smtp-internal-only" {
  endpoint  = example_smtp.demo-mail
  condition = "example_smtp.verb in ['MAIL', 'RCPT', 'DATA'] && example_smtp.mail_from.endsWith('@internal')"
  verdict   = "allow"
}

rule "smtp-deny-external" {
  endpoint  = example_smtp.demo-mail
  condition = "example_smtp.verb in ['MAIL', 'RCPT', 'DATA']"
  verdict   = "deny"
  reason    = "external sender"
}

// Body-content rule. References example_smtp.body, so the gateway
// pulls the full message body (up to its 1 MiB cap) for BODY
// evaluations on this endpoint. The handshake / MAIL / RCPT rules
// above don't touch example_smtp.body, so the gateway only pulls a
// log-prefix when those fire on a non-DATA verb — bodies on
// internal-allowed messages are pulled in full only because of this
// rule.
rule "smtp-body-no-secrets" {
  endpoint  = example_smtp.demo-mail
  condition = "example_smtp.verb == 'BODY' && !example_smtp.body.contains('SECRET')"
  verdict   = "allow"
}

rule "smtp-body-deny" {
  endpoint  = example_smtp.demo-mail
  condition = "example_smtp.verb == 'BODY'"
  verdict   = "deny"
  reason    = "body contains restricted token"
}

// Plain-TCP endpoint: no TLS at all. Plugin reads lines and asks
// the gateway whether to echo each one (allow) or reject it (deny).
// On allow the plugin echoes prefixed with the credential secret;
// on deny it replies "DENY: <reason>".
endpoint "example_echo" "demo-echo" {
  hosts = ["echo.invalid:7"]
}

rule "echo-no-bad-words" {
  endpoint  = example_echo.demo-echo
  condition = "!example_echo.line.contains('forbidden')"
  verdict   = "allow"
}

rule "echo-deny-fallback" {
  endpoint  = example_echo.demo-echo
  condition = "true"
  verdict   = "deny"
  reason    = "line contains a forbidden token"
}

// The shared example_magic_token credential auths against all three
// demo endpoints (HTTPS, SMTP, and echo).
//
// header_name is the HTTP header the example_https endpoint adds to
// upstream requests. Defaults to "X-Magic" when omitted; the SMTP
// and echo endpoints ignore it.
credential "example_magic_token" "demo" {
  endpoints   = [example_https.demo-site, example_smtp.demo-mail, example_echo.demo-echo]
  header_name = "X-Magic"
}

profile "default" {
  credentials = [example_magic_token.demo]
}
