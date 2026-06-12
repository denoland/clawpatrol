// Package sandbox confines external plugin subprocesses. The gateway
// treats plugins as untrusted (they will eventually be fetched from a
// registry), so every plugin runs inside an OS sandbox that hides the
// gateway's secrets (state DB, WireGuard/Tailscale keys, the user's
// home directory) and, unless granted, the network.
//
// Backends:
//   - linux: user+mount+pid(+net) namespaces with a deny-by-default
//     mount tree (ModeNamespaces); Landlock when user namespaces are
//     unavailable (ModeLandlock, degraded).
//   - darwin: seatbelt via sandbox-exec (ModeSeatbelt).
//   - other: none; plugins require an explicit sandbox = "off".
//
// The linux backends re-exec /proc/self/exe to set the sandbox up in
// the child before exec'ing the plugin binary. Host binaries that
// spawn plugins MUST call Stage1 as the first statement of main()
// (test packages: from TestMain) — Command and Probe fail fast if the
// hook was never wired, instead of hanging the go-plugin handshake.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
)

// Network is the network capability granted to a plugin.
type Network string

const (
	// NetworkNone confines the plugin to its socket dir: the only
	// channel is the gRPC unix socket shared with the gateway.
	NetworkNone Network = "none"
	// NetworkOutbound leaves the plugin in the host network (tunnel
	// plugins are the upstream transport and need to dial out).
	NetworkOutbound Network = "outbound"
)

// Mode identifies a sandbox backend.
type Mode string

const (
	// ModeOff runs the plugin unsandboxed (explicit operator opt-out).
	// Environment scrubbing still applies.
	ModeOff Mode = "off"
	// ModeNamespaces is the linux namespace backend.
	ModeNamespaces Mode = "namespaces"
	// ModeLandlock is the degraded linux fallback for hosts where
	// unprivileged user namespaces are blocked.
	ModeLandlock Mode = "landlock"
	// ModeSeatbelt is the macOS sandbox-exec backend.
	ModeSeatbelt Mode = "seatbelt"
)

// Spec describes one plugin launch. All paths must be absolute and
// symlink-resolved by the caller.
type Spec struct {
	// PluginName is the HCL block label, used in error text only.
	PluginName string
	// BinaryPath is the resolved plugin executable.
	BinaryPath string
	// SocketDir is the short-pathed directory holding the go-plugin
	// unix socket. It is read-write inside the sandbox at the SAME
	// absolute path, so the socket address the plugin prints on
	// stdout resolves identically for the gateway.
	SocketDir string
	// TmpDir is the plugin's private writable scratch space (HOME and
	// TMPDIR point here). Conventionally SocketDir/tmp.
	TmpDir string
	// Network is the granted network capability.
	Network Network
	// ReadPaths are extra recursive read-only grants.
	ReadPaths []string
	// WritePaths are extra recursive read-write grants.
	WritePaths []string
}

// Availability is the result of probing this host for a backend.
type Availability struct {
	// Mode is the best working backend. Never ModeOff: when nothing
	// works Probe returns an error instead.
	Mode Mode
	// Warning is non-empty when Mode is a degraded fallback; it
	// spells out exactly what the fallback does not cover.
	Warning string
	// LandlockABI is the kernel's Landlock ABI version on linux
	// (0 when unsupported). ABI >= 4 adds TCP bind/connect rules.
	LandlockABI int
}

// Env var names. EnvBackend forces a specific backend (tests, CI).
// EnvStage1 and EnvSpec drive the linux re-exec child and must never
// leak into the plugin's environment (stage-1 strips them).
const (
	EnvBackend = "CLAWPATROL_SANDBOX_BACKEND"
	EnvStage1  = "CLAWPATROL_SANDBOX_STAGE1"
	EnvSpec    = "CLAWPATROL_SANDBOX_SPEC"

	// stage1Exec runs the full sandbox setup and execs the plugin;
	// stage1Probe runs the setup and exits 0 instead of exec'ing.
	stage1Exec  = "exec"
	stage1Probe = "probe"

	// stage1ExitCode is the child's exit code when sandbox setup
	// fails (accompanied by a "clawpatrol-sandbox:" line on stderr).
	stage1ExitCode = 87
)

// envUnixSocketDir is go-plugin's documented contract: the plugin
// server creates its listen socket inside this directory.
const envUnixSocketDir = "PLUGIN_UNIX_SOCKET_DIR"

var (
	stage1Wired bool

	probeMu    sync.Mutex
	probeCache = map[string]probeOutcome{} // keyed by forced-backend env value
)

type probeOutcome struct {
	av  Availability
	err error
}

// errNotWired is returned by Probe/Command when the host binary never
// called Stage1.
func errNotWired() error {
	return fmt.Errorf("sandbox: host binary never called sandbox.Stage1(); add sandbox.Stage1() as the first statement of main() (or TestMain)")
}

// Probe detects the best available sandbox backend on this host. The
// result is cached per CLAWPATROL_SANDBOX_BACKEND value. A forced
// backend that fails its own probe is an error (it does not fall
// through to another backend).
func Probe() (Availability, error) {
	if !stage1Wired {
		return Availability{}, errNotWired()
	}
	force := os.Getenv(EnvBackend)
	probeMu.Lock()
	defer probeMu.Unlock()
	if out, ok := probeCache[force]; ok {
		return out.av, out.err
	}
	av, err := probePlatform(Mode(force))
	probeCache[force] = probeOutcome{av, err}
	return av, err
}

// Command builds the wrapper *exec.Cmd that launches spec's plugin
// under mode. It sets cmd.Env (BaseEnv plus any backend control
// vars); go-plugin appends its handshake vars to it. It never touches
// Stdin/Stdout/Stderr — go-plugin owns those pipes.
func Command(spec Spec, mode Mode) (*exec.Cmd, error) {
	if !stage1Wired {
		return nil, errNotWired()
	}
	if mode == ModeOff {
		cmd := exec.Command(spec.BinaryPath)
		cmd.Env = BaseEnv(spec)
		return cmd, nil
	}
	return commandPlatform(spec, mode)
}

// BaseEnv is the minimal environment every plugin gets, sandboxed or
// not. Nothing from the gateway's own environment (secrets,
// CLAWPATROL_*, cloud credentials) is inherited; go-plugin's
// ClientConfig.SkipHostEnv must be set by the spawner.
func BaseEnv(spec Spec) []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + spec.TmpDir,
		"TMPDIR=" + spec.TmpDir,
		envUnixSocketDir + "=" + spec.SocketDir,
	}
}
