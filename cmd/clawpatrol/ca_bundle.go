package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

// isMITMCACertBlock reports whether blk is a usable MITM CA certificate: a
// header-free CERTIFICATE whose DER parses and which is an actual CA able to
// sign the gateway's minted endpoint certs (IsCA + valid basic constraints +
// certSign key usage). A leaf (IsCA=false) can't sign endpoint certs, so it
// must never be accepted as the mandatory MITM CA — the earlier
// caFingerprintFromPEM check accepted one.
func isMITMCACertBlock(blk *pem.Block) (*x509.Certificate, bool) {
	if blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
		return nil, false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, false
	}
	if !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, false
	}
	return c, true
}

// mitmCACertsPEM returns the subset of pemBytes that are usable MITM CA certs,
// deduped and re-encoded (empty if none). This is the single strict acceptance
// rule for the mandatory CA, shared by ensureCABundle and every CA write path.
func mitmCACertsPEM(pemBytes []byte) []byte {
	seen := map[[32]byte]bool{}
	var out []byte
	rest := pemBytes
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		rest = r
		c, ok := isMITMCACertBlock(blk)
		if !ok {
			continue
		}
		h := sha256.Sum256(c.Raw)
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// validateMITMCAPEM errors unless pemBytes holds at least one usable MITM CA
// certificate. Called before persisting a fetched/pushed ca.crt so a leaf,
// header-bearing, or malformed cert never lands on disk and later breaks TLS to
// every defined endpoint.
func validateMITMCAPEM(pemBytes []byte) error {
	if len(mitmCACertsPEM(pemBytes)) == 0 {
		return errors.New("no usable MITM CA certificate (need a header-free CA cert with certSign key usage)")
	}
	return nil
}

// certFingerprints returns the DER SHA-256 fingerprints of every CERTIFICATE
// block in pemBytes (expects normalized input).
func certFingerprints(pemBytes []byte) map[[32]byte]bool {
	set := map[[32]byte]bool{}
	rest := pemBytes
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		rest = r
		if blk.Type == "CERTIFICATE" {
			set[sha256.Sum256(blk.Bytes)] = true
		}
	}
	return set
}

// containsAllCerts reports whether every certificate in certs (which must be
// non-empty) appears in bundle. Used to prove the mandatory MITM CA survived
// into the final bundle rather than being silently dropped as malformed.
func containsAllCerts(bundle, certs []byte) bool {
	have := certFingerprints(bundle)
	want := certFingerprints(certs)
	if len(want) == 0 {
		return false
	}
	for fp := range want {
		if !have[fp] {
			return false
		}
	}
	return true
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
// A join can rewrite ca.crt, and the machine trust store can change, while we
// build. After publishing we re-sample BOTH inputs and rebuild if either
// drifted from the snapshot we used — otherwise a slow reader holding an old
// snapshot could rename its stale bundle last and resurrect a just-removed
// root.
//
// The MITM CA is mandatory. We validate ca.crt on its own and require at least
// one acceptable certificate that survives into the final bundle: a malformed
// ca.crt (empty, garbage, invalid DER, header-bearing — reachable via the
// tsnet fetchCA path) must not yield a system-roots-only bundle that passes
// passthrough TLS while every defined endpoint fails.
//
// Fail-safe: returns caPath unchanged when the CA file is missing/malformed, no
// system roots can be read, or the inputs never settle across the retry budget.
func ensureCABundle(caPath string) string {
	bundlePath := filepath.Join(filepath.Dir(caPath), "ca-bundle.crt")
	for attempt := 0; attempt < caBundleMaxAttempts; attempt++ {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return caPath
		}
		caCerts := mitmCACertsPEM(caPEM)
		if len(caCerts) == 0 {
			// The mandatory MITM CA holds no usable CA certificate (empty,
			// garbage, header-bearing, or a non-CA leaf) — fail safe rather than
			// publish a bundle that can't validate gateway-minted endpoint certs.
			return caPath
		}
		sysPEM, ok := readSystemRootsPEM()
		if !ok || len(sysPEM) == 0 {
			return caPath
		}
		want := buildBundlePEM(sysPEM, caPEM)
		if !containsAllCerts(want, caCerts) {
			return caPath
		}
		if existing, rerr := os.ReadFile(bundlePath); rerr == nil && bytes.Equal(existing, want) {
			return bundlePath // already current; nothing published, no race
		}
		if err := atomicWriteFile(bundlePath, want, 0o644); err != nil {
			return caPath
		}
		// Re-sample both inputs. If neither drifted, our published bundle is
		// consistent with current machine state; otherwise loop and rebuild so
		// a concurrent writer's newer content isn't clobbered by our stale one.
		afterCA, errCA := os.ReadFile(caPath)
		afterSys, okSys := readSystemRootsPEM()
		if errCA == nil && okSys && bytes.Equal(afterCA, caPEM) && bytes.Equal(afterSys, sysPEM) {
			return bundlePath
		}
	}
	// Inputs never settled across the retry budget (a pathological writer): the
	// bundle on disk may be stale, so fall back to caPath rather than hand out a
	// bundle we couldn't prove current. Fail-safe: the wrapped agent still
	// trusts the current MITM CA, only losing passthrough roots.
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
