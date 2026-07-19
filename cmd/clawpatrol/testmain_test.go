package main

import (
	"os"
	"testing"

	"github.com/denoland/clawpatrol/internal/sandbox"
)

// TestMain wires the sandbox stage-1 hook: tests in this package
// spawn external plugin subprocesses by re-exec'ing the test binary,
// so the test binary needs the same early hook a real host binary
// has at the top of main().
func TestMain(m *testing.M) {
	sandbox.Stage1()
	startWireGuardCAStageServer()
	code := m.Run()
	if sharedWireGuardCAStageServer != nil {
		sharedWireGuardCAStageServer.server.Close()
	}
	os.Exit(code)
}
