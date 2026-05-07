package all

// Walks every endpoint plugin's ExampleHCL and asserts the snippet
// parses cleanly through config.LoadBytes. Catches drift between an
// example block and the plugin's actual schema (referenced credential
// type missing required slots, attribute renamed, ref name typo).

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

const exampleOperationalPrefix = `
listen      = "0.0.0.0:0"
info_listen = "0.0.0.0:0"
public_url  = ""
admin_email = "test@example.com"
ca_dir      = "/tmp/clawpatrol-ca"
oauth_dir   = "/tmp/clawpatrol-oauth"
insecure_no_dashboard_secret = true

`

func TestEndpointPluginExampleHCLParses(t *testing.T) {
	for _, p := range config.AllPlugins(config.KindEndpoint) {
		if p.ExampleHCL == "" {
			t.Errorf("endpoint plugin %q: ExampleHCL is empty", p.Type)
			continue
		}
		src := exampleOperationalPrefix + p.ExampleHCL
		_, diags := config.LoadBytes([]byte(src), p.Type+".example.hcl")
		if diags.HasErrors() {
			t.Errorf("endpoint plugin %q: ExampleHCL fails to parse:\n%s",
				p.Type, strings.TrimSpace(diags.Error()))
		}
	}
}
