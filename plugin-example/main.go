// Standalone clawpatrol plugin demonstrating the v1 plugin protocol.
//
// Build:   go build -o plugin-example ./plugin-example
// Run:     the gateway spawns the binary; not invoked directly.
//
// Provides one credential (magic_token), one tunnel (passthrough),
// and three endpoints (demo_https, demo_smtp, demo_echo) covering
// HTTPS, TLS-but-not-HTTPS, and plain TCP respectively.
package main

import "github.com/denoland/clawpatrol/pluginsdk"

func main() {
	pluginsdk.Run(&pluginsdk.Plugin{
		Name:    "example",
		Version: "0.1",
		Credentials: []pluginsdk.CredentialDef{
			magicTokenDef(),
		},
		Tunnels: []pluginsdk.TunnelDef{
			passthroughDef(),
		},
		Endpoints: []pluginsdk.EndpointDef{
			demoHTTPSDef(),
			demoSMTPDef(),
			demoEchoDef(),
		},
		Facets: []pluginsdk.FacetDef{
			// SMTP isn't covered by any built-in facet, so the
			// plugin defines its own. Built-in facets (http, sql,
			// k8s) are reused as-is by setting the endpoint's
			// Family to the facet's name — see demo_https.
			{
				Name: "smtp",
				Fields: []pluginsdk.FacetField{
					{Name: "verb", Kind: pluginsdk.FacetString, Label: "Verb"},
					// Optional fields are zero-filled by the gateway
					// before CEL evaluation, so rules can reference
					// them on every command without `has()` guards.
					{Name: "auth_user", Kind: pluginsdk.FacetString, Label: "User", Optional: true},
					{Name: "mail_from", Kind: pluginsdk.FacetString, Label: "From", Optional: true},
					{Name: "rcpt_to", Kind: pluginsdk.FacetStringList, Label: "Rcpt", Optional: true},
					// Stream field. The plugin offers the message
					// body as a pluginsdk.Stream(io.Reader) on the
					// EvaluateAction for the DATA command; the
					// gateway pulls the full body when a rule reads
					// it, otherwise just a log-prefix.
					{Name: "body", Kind: pluginsdk.FacetStream, Label: "Body", Optional: true},
				},
			},
			// Echo is a synthetic toy protocol with no built-in
			// equivalent.
			{
				Name: "echo",
				Fields: []pluginsdk.FacetField{
					{Name: "line", Kind: pluginsdk.FacetString, Label: "Line"},
				},
			},
		},
	})
}
