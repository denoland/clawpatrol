package extplugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
// network is the already-resolved network grant (from the manifest +
// lockfile, or an operator override); see resolveNetwork. privileged is
// the already-resolved privileged grant (the operator-approved answer to
// the plugin's declared privileged capability); see resolvePrivileged.
// Either it or the operator's `sandbox = "off"` HCL attribute turns the
// sandbox off.
//
// The caller owns spec.SocketDir and must remove it when the plugin
// dies.
func buildSandboxSpec(sp config.PluginSource, binSource string, network sandbox.Network, privileged bool, stateDir string) (sandbox.Spec, sandbox.Mode, string, error) {
	var zero sandbox.Spec

	switch sp.Sandbox {
	case "", "enforce", "off":
	default:
		return zero, "", "", fmt.Errorf("invalid sandbox %q: expected \"enforce\" or \"off\"", sp.Sandbox)
	}

	bin, err := resolveSandboxPath(binSource)
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
	// A read_paths grant overlapping the state dir would expose the
	// secret store (clawpatrol.db — the CA key and every credential).
	// That is the all-credentials tier; refuse it outright.
	if err := checkReadPathsAgainstStateDir(readPaths, stateDir); err != nil {
		return zero, "", "", err
	}

	mode := sandbox.Mode("")
	warning := ""
	if sp.Sandbox == "off" || privileged {
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
	}, mode, warning, nil
}

// checkReadPathsAgainstStateDir refuses a read grant that would let
// the plugin read the gateway's secret store. A grant is rejected when
// it is at, under, or a parent of the resolved state dir.
func checkReadPathsAgainstStateDir(readPaths []string, stateDir string) error {
	if stateDir == "" || len(readPaths) == 0 {
		return nil
	}
	sd := stateDir
	if abs, err := filepath.Abs(sd); err == nil {
		sd = abs
	}
	if resolved, err := filepath.EvalSymlinks(sd); err == nil {
		sd = resolved
	}
	for _, p := range readPaths {
		if p == sd || pathContains(p, sd) || pathContains(sd, p) {
			return fmt.Errorf(
				"read_paths grant %q overlaps the state dir %q, which holds the credential store. "+
					"A plugin must not be granted read access to clawpatrol's secrets; remove the grant",
				p, sd)
		}
	}
	return nil
}

// pathContains reports whether parent is an ancestor of (or equal to)
// child, comparing cleaned absolute paths by path segment.
func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// parseNetwork validates an operator-supplied HCL `network` override.
func parseNetwork(s string) (sandbox.Network, error) {
	switch s {
	case "", string(sandbox.NetworkNone):
		return sandbox.NetworkNone, nil
	case string(sandbox.NetworkOutbound):
		return sandbox.NetworkOutbound, nil
	default:
		return "", fmt.Errorf("invalid network %q: expected \"none\" or \"outbound\"", s)
	}
}

// hashFile returns "sha256:<hex>" of the file at path — the binary
// identity the lockfile records so an upgrade is detectable.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
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
