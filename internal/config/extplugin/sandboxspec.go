package extplugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/sandbox"
)

// buildSandboxSpec validates the plugin block's grant attributes and
// materializes the launch spec: resolved binary, a fresh short-pathed
// socket dir (the only writable surface a network="none" plugin
// has), and the sandbox mode. Fail-closed: when no backend works and
// the operator didn't opt out, the returned error tells them both
// the cause and the cost of sandbox = "off".
//
// The caller owns spec.SocketDir and must remove it when the plugin
// dies.
func buildSandboxSpec(sp config.PluginSource) (sandbox.Spec, sandbox.Mode, string, error) {
	var zero sandbox.Spec

	switch sp.Sandbox {
	case "", "enforce", "off":
	default:
		return zero, "", "", fmt.Errorf("invalid sandbox %q: expected \"enforce\" or \"off\"", sp.Sandbox)
	}
	var network sandbox.Network
	switch sp.Network {
	case "", string(sandbox.NetworkNone):
		network = sandbox.NetworkNone
	case string(sandbox.NetworkOutbound):
		network = sandbox.NetworkOutbound
	default:
		return zero, "", "", fmt.Errorf("invalid network %q: expected \"none\" or \"outbound\"", sp.Network)
	}

	bin, err := resolveSandboxPath(sp.Source)
	if err != nil {
		return zero, "", "", fmt.Errorf("plugin source %q: %w", sp.Source, err)
	}
	if fi, err := os.Stat(bin); err != nil {
		return zero, "", "", fmt.Errorf("plugin source %q: %w", sp.Source, err)
	} else if fi.IsDir() {
		return zero, "", "", fmt.Errorf("plugin source %q is a directory", sp.Source)
	} else if fi.Mode()&0o111 == 0 {
		return zero, "", "", fmt.Errorf("plugin source %q is not executable", sp.Source)
	}

	readPaths, err := resolveGrantPaths(sp.ReadPaths)
	if err != nil {
		return zero, "", "", fmt.Errorf("read_paths: %w", err)
	}
	writePaths, err := resolveGrantPaths(sp.WritePaths)
	if err != nil {
		return zero, "", "", fmt.Errorf("write_paths: %w", err)
	}

	mode := sandbox.Mode("")
	warning := ""
	if sp.Sandbox == "off" {
		mode = sandbox.ModeOff
	} else {
		av, err := sandbox.Probe()
		if err != nil {
			return zero, "", "", fmt.Errorf(
				"cannot establish a sandbox on this system: %v. "+
					"clawpatrol treats plugins as untrusted and refuses to run them unsandboxed by default. "+
					"Fix the cause above, or accept the risk explicitly by adding sandbox = \"off\" to the plugin %q block "+
					"(the plugin then runs with this user's full file-system and network access, including clawpatrol's secrets)",
				err, sp.Name)
		}
		mode = av.Mode
		warning = av.Warning
	}

	sockDir, tmpDir, err := makePluginDirs()
	if err != nil {
		return zero, "", "", err
	}
	return sandbox.Spec{
		PluginName: sp.Name,
		BinaryPath: bin,
		SocketDir:  sockDir,
		TmpDir:     tmpDir,
		Network:    network,
		ReadPaths:  readPaths,
		WritePaths: writePaths,
	}, mode, warning, nil
}

// makePluginDirs creates the per-plugin socket dir (short path: the
// go-plugin unix socket address must fit sun_path, 104 bytes on
// darwin) and its tmp subdir, both 0700.
func makePluginDirs() (string, string, error) {
	base := os.TempDir()
	// dir + "/plugin" + up to ~14 random digits from os.CreateTemp,
	// plus our own "cp-<random>" segment. Stay well clear of 104.
	if len(base) > 60 {
		base = "/tmp"
	}
	sockDir, err := os.MkdirTemp(base, "cp-")
	if err != nil {
		return "", "", err
	}
	// Seatbelt and the mount plan want symlink-canonical paths
	// (/tmp -> /private/tmp on darwin), and the path the plugin
	// prints must equal the path the gateway dials.
	if resolved, err := filepath.EvalSymlinks(sockDir); err == nil {
		sockDir = resolved
	}
	tmpDir := filepath.Join(sockDir, "tmp")
	if err := os.Mkdir(tmpDir, 0o700); err != nil {
		_ = os.RemoveAll(sockDir)
		return "", "", err
	}
	return sockDir, tmpDir, nil
}

// resolveSandboxPath canonicalizes one operator-supplied path:
// "~/" expansion, absolutization, symlink resolution, and rejection
// of characters a seatbelt profile cannot carry.
func resolveSandboxPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(resolved, "\"\n\\") {
		return "", fmt.Errorf("path %q contains characters not representable in a sandbox profile", resolved)
	}
	return resolved, nil
}

func resolveGrantPaths(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		r, err := resolveSandboxPath(p)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
