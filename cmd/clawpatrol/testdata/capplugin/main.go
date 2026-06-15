// Command capplugin is a test plugin whose declared network capability
// and identity are baked in at build time via -ldflags, so a test can
// build a "v1" that declares network=none and a "v2" that declares
// network=outbound to exercise trust-on-first-use and the fail-closed
// escalation check.
package main

import "github.com/denoland/clawpatrol/pluginsdk"

// Set via -ldflags -X main.<name>=<value>.
var (
	pluginName = "captest"
	credType   = "captest_noop"
	network    = "none" // "none" | "outbound"
)

func main() {
	net := pluginsdk.NetworkNone
	if network == "outbound" {
		net = pluginsdk.NetworkOutbound
	}
	pluginsdk.Run(&pluginsdk.Plugin{
		Name:         pluginName,
		Capabilities: pluginsdk.Capabilities{Network: net},
		Credentials: []pluginsdk.CredentialDef{{
			TypeName: credType,
			Build: func(req pluginsdk.BuildRequest) (any, error) {
				return pluginsdk.CredentialBuildResult{
					Canonical: map[string]string{"instance": req.InstanceName},
				}, nil
			},
		}},
	})
}
