// Command nosyplugin is a negative-test plugin: at startup it probes
// the sandbox boundary (reading a secret-marker file, reading the
// host home directory, dialing outbound and loopback, reading
// /proc/1/cmdline) and reports the outcomes back to the gateway in
// the manifest's Version field as a JSON object. The sandbox tests
// assert every probe was blocked under each backend, and that the
// same probes succeed with sandbox = "off".
//
// Probe targets are baked in at build time with -ldflags -X so they
// survive the environment scrub the sandbox always applies.
package main

import (
	"encoding/json"
	"net"
	"os"
	"time"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// Set via -ldflags -X main.<name>=<value>.
var (
	secretPath   string // a file the gateway can read but the plugin must not
	hostHomeFile string // a marker under the real $HOME
	loopbackAddr string // a gateway-side TCP listener (host netns)
	// pluginName / credType are unique per test run so repeated
	// loads in one test binary don't collide in the global plugin
	// registry (which has no deregistration).
	pluginName = "nosyplugin"
	credType   = "nosy_noop"
)

type probeResult struct {
	SecretRead  bool   `json:"secret_read"`
	HostHome    bool   `json:"host_home_read"`
	OutboundOK  bool   `json:"outbound_ok"`
	LoopbackOK  bool   `json:"loopback_ok"`
	ProcInitOK  bool   `json:"proc_init_read"`
	SecretError string `json:"secret_error,omitempty"`
}

func canRead(path string) (bool, string) {
	if path == "" {
		return false, "no path"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err.Error()
	}
	return len(b) >= 0, ""
}

func canDial(addr string) bool {
	if addr == "" {
		return false
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func main() {
	var r probeResult
	r.SecretRead, r.SecretError = canRead(secretPath)
	r.HostHome, _ = canRead(hostHomeFile)
	r.OutboundOK = canDial("1.1.1.1:443")
	r.LoopbackOK = canDial(loopbackAddr)
	if _, err := os.ReadFile("/proc/1/cmdline"); err == nil {
		r.ProcInitOK = true
	}
	report, _ := json.Marshal(r)

	pluginsdk.Run(&pluginsdk.Plugin{
		Name:    pluginName,
		Version: string(report),
		// One trivial credential type so the manifest is well-formed.
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
