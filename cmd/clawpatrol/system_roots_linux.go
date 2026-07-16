//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/pem"
	"os"
	"path/filepath"
)

// systemRootCertFiles mirrors crypto/x509's root_linux.go candidate list —
// the distro-specific locations of the aggregate trusted-root PEM bundle. We
// read the file directly (rather than x509.SystemCertPool, which returns a
// *CertPool that can't be re-serialized to PEM) because the wrapped agents
// need a file path. Package var so tests can point it at a fixture.
var systemRootCertFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine
}

// systemRootCertDirs mirrors root_unix.go's certDirectories — the hashed
// per-certificate directories always scanned after the aggregate file.
var systemRootCertDirs = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/system/etc/security/cacerts",
}

// defaultSystemRootsReader reproduces crypto/x509 root_unix.go discovery so the
// generated bundle matches the trust set Go (and thus the system default) would
// assemble:
//
//   - SSL_CERT_FILE, when set, REPLACES the aggregate file list — Go never
//     falls back to the distro aggregate once the override is set, so neither
//     do we (tracking "override configured" separately from "bytes loaded"
//     avoids a fail-open widening to the default roots). Our own generated
//     bundle is resolved back to the operator's original source via
//     sslCertFileOrig so a corporate CA survives repeated `clawpatrol env`.
//   - the certificate directories (SSL_CERT_DIR, else the defaults) are ALWAYS
//     scanned after the file loop, exactly as root_unix.go does — roots
//     installed only under /etc/ssl/certs must not be dropped.
//
// Every source is parsed into CERTIFICATE blocks and re-encoded (deduped by
// DER) before concatenation, so a source file missing a trailing newline can't
// abut the next block and silently corrupt the bundle.
//
// selfBundle is the ca-bundle.crt path, excluded from every file source to
// avoid folding the bundle back into itself.
func defaultSystemRootsReader(selfBundle string) ([]byte, bool) {
	seen := map[[32]byte]bool{}
	var ders [][]byte
	add := func(data []byte) {
		rest := data
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			h := sha256.Sum256(blk.Bytes)
			if seen[h] {
				continue
			}
			seen[h] = true
			ders = append(ders, blk.Bytes)
		}
	}

	// Aggregate file: SSL_CERT_FILE override replaces the candidate list.
	files := systemRootCertFiles
	if override := sslCertFileOrig(selfBundle); override != "" {
		files = []string{override}
	}
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			add(b)
			break
		}
	}

	// Certificate directories: always scanned, SSL_CERT_DIR overrides defaults.
	dirs := systemRootCertDirs
	if d := os.Getenv("SSL_CERT_DIR"); d != "" {
		dirs = filepath.SplitList(d)
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if samePath(p, selfBundle) {
				continue
			}
			if b, err := os.ReadFile(p); err == nil {
				add(b)
			}
		}
	}

	if len(ders) == 0 {
		return nil, false
	}
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out, true
}
