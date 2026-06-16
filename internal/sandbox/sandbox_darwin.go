package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const sandboxExecPath = "/usr/bin/sandbox-exec"

// Stage1 has no child role on darwin (sandbox-exec wraps the plugin
// directly, no re-exec); it only records that the host binary wired
// the hook, keeping the fail-fast check uniform across platforms.
func Stage1() {
	stage1Wired = true
}

func commandPlatform(spec Spec, mode Mode) (*exec.Cmd, error) {
	if mode != ModeSeatbelt {
		return nil, fmt.Errorf("sandbox: backend %q is not supported on darwin (have: seatbelt)", mode)
	}
	profile, err := seatbeltProfile(spec)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(sandboxExecPath, "-p", profile, spec.BinaryPath)
	cmd.Env = BaseEnv(spec)
	return cmd, nil
}

var seatbeltProbe = sync.OnceValue(func() error {
	if _, err := os.Stat(sandboxExecPath); err != nil {
		return fmt.Errorf("%s: %w", sandboxExecPath, err)
	}
	// A permissive no-op profile: proves sandbox_init works here.
	// It fails when the gateway itself already runs sandboxed
	// (seatbelt does not nest).
	cmd := exec.Command(sandboxExecPath, "-p", "(version 1)(allow default)", "/usr/bin/true")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(out.String())
		if detail == "" {
			detail = err.Error()
		}
		return fmt.Errorf("sandbox-exec probe failed (gateway already sandboxed?): %s", detail)
	}
	return nil
})

func probePlatform(force Mode) (Availability, error) {
	switch force {
	case "", ModeSeatbelt:
	default:
		return Availability{}, fmt.Errorf("backend %q is not supported on darwin (have: seatbelt)", force)
	}
	if err := seatbeltProbe(); err != nil {
		return Availability{}, err
	}
	return Availability{Mode: ModeSeatbelt}, nil
}
