package main

import (
	"os"
	"path/filepath"
)

// systemRootsReader is the seam tests swap to inject fake system roots.
// It defaults to the platform reader defined in
// system_roots_{linux,darwin,other}.go.
var systemRootsReader = defaultSystemRootsReader

// readSystemRootsPEM returns the platform's trusted root certificates as
// PEM bytes, and whether any were found.
func readSystemRootsPEM() ([]byte, bool) { return systemRootsReader() }

// buildBundlePEM concatenates the system roots and the clawpatrol MITM CA
// into one PEM bundle, guaranteeing a newline between the two blocks so
// they never abut (a missing separator would corrupt the first cert after
// the join).
func buildBundlePEM(systemPEM, caPEM []byte) []byte {
	out := make([]byte, 0, len(systemPEM)+len(caPEM)+1)
	out = append(out, systemPEM...)
	if len(systemPEM) > 0 && systemPEM[len(systemPEM)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, caPEM...)
	return out
}

// ensureCABundle writes <dir>/ca-bundle.crt = system roots + the MITM CA
// found at caPath, and returns that bundle's path. The replace-style CA
// env vars point at it so a wrapped agent trusts BOTH the gateway's MITM
// certs (defined endpoints) and real public certs (passthrough hosts) —
// the fix for issue #764.
//
// Fail-safe: returns caPath unchanged when the CA file is missing or no
// system roots can be read (e.g. an unsupported platform, or `security`
// unavailable on macOS). Behavior is then no worse than today's
// MITM-CA-only pushdown.
func ensureCABundle(caPath string) string {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return caPath
	}
	sysPEM, ok := readSystemRootsPEM()
	if !ok || len(sysPEM) == 0 {
		return caPath
	}
	bundlePath := filepath.Join(filepath.Dir(caPath), "ca-bundle.crt")
	if bundleFresh(bundlePath, caPath) {
		return bundlePath
	}
	if err := atomicWriteFile(bundlePath, buildBundlePEM(sysPEM, caPEM), 0o644); err != nil {
		return caPath
	}
	return bundlePath
}

// bundleFresh reports whether the bundle already exists and is at least as
// new as caPath. It is a cheap staleness gate: `clawpatrol env` re-runs the
// pushdown on every new shell, and without this each terminal would rewrite
// the bundle. It deliberately does not track system-root updates — a
// `clawpatrol join` (which rewrites ca.crt) or deleting ca-bundle.crt forces
// a refresh.
func bundleFresh(bundlePath, caPath string) bool {
	bi, err := os.Stat(bundlePath)
	if err != nil {
		return false
	}
	ci, err := os.Stat(caPath)
	if err != nil {
		return false
	}
	return !bi.ModTime().Before(ci.ModTime())
}

// atomicWriteFile writes data to path via a temp file + rename so a
// concurrent reader (or a second `clawpatrol run`) never observes a
// half-written bundle.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ca-bundle-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
