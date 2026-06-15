//go:build !linux && !darwin

package sandbox

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Stage1 records that the host binary wired the hook; there is no
// sandbox child role on this platform.
func Stage1() {
	stage1Wired = true
}

func commandPlatform(_ Spec, mode Mode) (*exec.Cmd, error) {
	return nil, fmt.Errorf("sandbox: backend %q is not supported on %s", mode, runtime.GOOS)
}

func probePlatform(_ Mode) (Availability, error) {
	return Availability{}, fmt.Errorf("plugin sandboxing is not implemented on %s; set sandbox = \"off\" on the plugin block to run the plugin unsandboxed", runtime.GOOS)
}
