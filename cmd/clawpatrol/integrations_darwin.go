//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// applyEnvPushdown sets every pushdown var on the current process
// environment. Called by `clawpatrol run` before exec'ing the child
// command, so the wrapped agent CLI inherits the placeholders + CA
// paths without the operator having to source `clawpatrol env`
// separately.
//
// Opt-out: setting CLAWPATROL_NO_ENV=1 disables the entire pushdown.
// Use when an agent CLI is incompatible with one of the pushed vars
// (e.g. an OPENAI_API_KEY placeholder that forces a CLI into API
// mode when its native auth would have worked through the tunnel).
//
// Linux callers fetch vars from the daemon over the control socket
// and call applyEnvPushdownVars directly; this helper only exists for
// the darwin path that talks to the gateway in-process.
func applyEnvPushdown(caDir string) {
	if os.Getenv("CLAWPATROL_NO_ENV") == "1" {
		return
	}
	caPath := filepath.Join(caDir, "ca.crt")
	if _, err := os.Stat(caPath); err != nil {
		// CA not set up yet — `clawpatrol join` hasn't run. Don't
		// silently skip; the agent CLI will fail TLS verification
		// and the operator will be confused. Log and continue.
		fmt.Fprintf(os.Stderr, "clawpatrol: ca not found at %s — env pushdown skipped (run `clawpatrol join` first)\n", caPath)
		return
	}
	vars, err := envPushdownVars(caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol: %v — agent will run without placeholder push-down\n", err)
	}
	applyEnvPushdownVars(vars)
}
