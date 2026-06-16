// Package sandboxtest holds test helpers for code that spawns
// sandboxed plugin subprocesses.
package sandboxtest

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/sandbox"
)

// RequireBackend skips the test when no sandbox backend works on
// this host (e.g. a container with user namespaces and Landlock both
// unavailable). CI hosts are configured so the skip never fires
// there; the helper keeps `go test` green on restricted dev
// machines. The calling package must wire sandbox.Stage1 in its
// TestMain.
func RequireBackend(t *testing.T) sandbox.Availability {
	t.Helper()
	av, err := sandbox.Probe()
	if err != nil {
		t.Skipf("no sandbox backend available on this host: %v", err)
	}
	return av
}
