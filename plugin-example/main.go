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
	})
}
