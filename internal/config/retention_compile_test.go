package config_test

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

// Per-endpoint `retention` must be validated at compile — a typo has to
// fail config load like a bad gateway actions_keep does, instead of
// surfacing only as an hourly sweeper log line at runtime.
func TestCompileValidatesEndpointRetention(t *testing.T) {
	load := func(t *testing.T, retention string) (*config.CompiledPolicy, error) {
		t.Helper()
		src := `
endpoint "https" "x" {
  hosts     = ["example.com"]
  retention = "` + retention + `"
}
credential "bearer_token" "tok" {
  endpoint = https.x
}
profile "p" { credentials = [bearer_token.tok] }
`
		gw, diags := config.LoadBytes([]byte(testGatewayPrefix+src), "in.hcl")
		if diags.HasErrors() {
			t.Fatalf("load with retention %q: %v", retention, diags)
		}
		return config.Compile(gw)
	}

	// "0s" is keep-forever (same as "0"), not an error.
	for _, ok := range []string{"168h", "0", "0s", "off"} {
		if _, err := load(t, ok); err != nil {
			t.Errorf("Compile with retention %q: unexpected error: %v", ok, err)
		}
	}
	// A bare number, garbage, or a negative duration must fail compile.
	for _, bad := range []string{"30", "1 week", "-24h"} {
		if _, err := load(t, bad); err == nil {
			t.Errorf("Compile with retention %q: want error, got nil", bad)
		}
	}
}
