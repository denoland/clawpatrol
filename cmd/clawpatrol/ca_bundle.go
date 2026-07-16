package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
)

// caBundleMaxAttempts bounds the ca.crt-rotation retry loop in
// ensureCABundle. A join rewriting ca.crt while we build the bundle is a
// one-shot race, so a couple of attempts converge; the cap only guards a
// pathological writer that never settles.
const caBundleMaxAttempts = 4

// systemRootsReader is the seam tests swap to inject fake system roots. It
// defaults to the platform reader in system_roots_{linux,darwin,other}.go.
//
// The source is the MACHINE's trust store (the distro root bundle on Linux,
// Apple's curated roots on macOS) — deliberately NOT the invoking process's
// SSL_CERT_FILE/SSL_CERT_DIR. Deriving the bundle from per-process env would
// make a single shared pathname (ca-bundle.crt) mean different things in
// different shells/cron/sudo contexts and let one context atomically replace
// another's trust set. A machine-wide source keeps the bundle content a
// deterministic function of machine state, so every writer produces identical
// bytes.
var systemRootsReader = defaultSystemRootsReader

// readSystemRootsPEM returns the machine's trusted root certificates as PEM
// bytes, and whether any were found.
func readSystemRootsPEM() ([]byte, bool) { return systemRootsReader() }

// buildBundlePEM concatenates the system roots and the clawpatrol MITM CA
// with a guaranteed newline between them, then hands the result to
// normalizeCertsPEM so the seam and every source file are re-encoded cleanly.
func buildBundlePEM(systemPEM, caPEM []byte) []byte {
	joined := make([]byte, 0, len(systemPEM)+len(caPEM)+1)
	joined = append(joined, systemPEM...)
	if len(systemPEM) > 0 && systemPEM[len(systemPEM)-1] != '\n' {
		joined = append(joined, '\n')
	}
	joined = append(joined, caPEM...)
	return normalizeCertsPEM(joined)
}

// normalizeCertsPEM parses every PEM block, keeps only well-formed
// CERTIFICATE blocks (no PEM headers, DER that x509.ParseCertificate
// accepts), dedups by DER, and re-encodes each from cert.Raw. This mirrors
// what CertPool.AppendCertsFromPEM / OpenSSL accept: a single malformed or
// header-bearing block can otherwise make an OpenSSL-family consumer reject
// the entire CA file with ASN.1 errors, so we must drop it rather than
// pass it through. Re-encoding also guarantees clean separators, so a source
// file lacking a trailing newline can't abut the next block.
func normalizeCertsPEM(pemBytes []byte) []byte {
	seen := map[[32]byte]bool{}
	var out []byte
	rest := pemBytes
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		rest = r
		if blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		h := sha256.Sum256(cert.Raw)
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

// ensureCABundle writes <dir>/ca-bundle.crt = machine system roots + the MITM
// CA found at caPath, and returns that bundle's path. The replace-style CA env
// vars point at it so a wrapped agent trusts BOTH the gateway's MITM certs
// (defined endpoints) and real public certs (passthrough hosts) — the fix for
// issue #764.
//
// Freshness is content-based: the desired bundle is rebuilt from the current
// system roots + ca.crt every call and written only when it differs from
// what's on disk. Unlike an mtime check this tracks system-root
// additions/removals (e.g. an emergency distrust) and CA rotation, and has no
// equal-mtime boundary. Because the roots come from the machine store rather
// than per-process env, every caller (shell, cron, sudo helper) computes the
// same bytes, so no context can silently replace another's trust set.
//
// A join can rewrite ca.crt concurrently. Because ca.crt is read before the
// bundle is written, a naive single pass could persist a bundle embedding the
// *old* CA after the new ca.crt landed. We defend by re-reading ca.crt after
// the write and rebuilding if it changed.
//
// Fail-safe: returns caPath unchanged when the CA file is missing, no system
// roots can be read (e.g. an unsupported platform, or `security` unavailable
// on macOS), or ca.crt never settles across the retry budget. Behavior is then
// no worse than today's MITM-CA-only pushdown.
func ensureCABundle(caPath string) string {
	bundlePath := filepath.Join(filepath.Dir(caPath), "ca-bundle.crt")
	for attempt := 0; attempt < caBundleMaxAttempts; attempt++ {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return caPath
		}
		sysPEM, ok := readSystemRootsPEM()
		if !ok || len(sysPEM) == 0 {
			return caPath
		}
		want := buildBundlePEM(sysPEM, caPEM)
		if len(want) == 0 {
			return caPath
		}
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
	// ca.crt never settled across the retry budget (a pathological writer):
	// the bundle on disk may embed a stale CA, so fall back to caPath rather
	// than hand out a bundle we couldn't prove current. Fail-safe: the wrapped
	// agent still trusts the current MITM CA, only losing passthrough roots.
	return caPath
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
