package main

import (
	"bytes"
	"os"
	"path/filepath"
)

// caBundleMaxAttempts bounds the ca.crt-rotation retry loop in
// ensureCABundle. A join rewriting ca.crt while we build the bundle is a
// one-shot race, so a couple of attempts converge; the cap only guards a
// pathological writer that never settles.
const caBundleMaxAttempts = 4

// systemRootsReader is the seam tests swap to inject fake system roots. It
// receives the path of the bundle we are about to (re)generate so a reader
// that honors SSL_CERT_FILE can skip it — otherwise, once `clawpatrol env`
// persists SSL_CERT_FILE=…/ca-bundle.crt into the shell rc, the reader would
// fold the bundle back into itself on every shell. It defaults to the
// platform reader in system_roots_{linux,darwin,other}.go.
var systemRootsReader = defaultSystemRootsReader

// readSystemRootsPEM returns the platform's trusted root certificates as
// PEM bytes, and whether any were found. selfBundle is the path of the
// combined bundle, excluded from any file-based source to avoid a feedback
// loop.
func readSystemRootsPEM(selfBundle string) ([]byte, bool) { return systemRootsReader(selfBundle) }

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
// Freshness is content-based: the desired bundle is rebuilt from the
// current system roots + ca.crt every call and written only when it
// differs from what's on disk. Unlike an mtime check this tracks system-
// root additions/removals (e.g. an emergency distrust) and CA rotation,
// and has no equal-mtime boundary. The cost is reading the roots each call;
// `clawpatrol env` runs per shell, but the platform readers are cheap
// (a file read on Linux, a ~40ms `security` dump on macOS) and no write
// happens when nothing changed.
//
// A join can rewrite ca.crt concurrently. Because ca.crt is read before the
// bundle is written, a naive single pass could persist a bundle embedding
// the *old* CA after the new ca.crt landed. We defend by re-reading ca.crt
// after the write and rebuilding if it changed; content-based freshness also
// means a later call self-heals rather than pinning the stale CA forever.
//
// Fail-safe: returns caPath unchanged when the CA file is missing or no
// system roots can be read (e.g. an unsupported platform, or `security`
// unavailable on macOS). Behavior is then no worse than today's
// MITM-CA-only pushdown.
func ensureCABundle(caPath string) string {
	bundlePath := filepath.Join(filepath.Dir(caPath), "ca-bundle.crt")
	for attempt := 0; attempt < caBundleMaxAttempts; attempt++ {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return caPath
		}
		sysPEM, ok := readSystemRootsPEM(bundlePath)
		if !ok || len(sysPEM) == 0 {
			return caPath
		}
		want := buildBundlePEM(sysPEM, caPEM)
		if existing, err := os.ReadFile(bundlePath); err != nil || !bytes.Equal(existing, want) {
			if err := atomicWriteFile(bundlePath, want, 0o644); err != nil {
				return caPath
			}
		}
		// If ca.crt changed while we built the bundle, our snapshot may embed
		// the old CA — loop and rebuild from the new one. Converges as soon
		// as ca.crt is stable across a read/verify pair.
		after, err := os.ReadFile(caPath)
		if err != nil {
			return caPath
		}
		if bytes.Equal(after, caPEM) {
			return bundlePath
		}
	}
	return bundlePath
}

// atomicWriteFile writes data to path via a temp file + rename so a
// concurrent reader (or a second `clawpatrol run`) never observes a
// half-written file. The temp lives in the destination directory so the
// rename stays on one filesystem.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
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
