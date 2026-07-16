//go:build linux

package main

import (
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

// defaultSystemRootsReader returns the machine distro trust store as PEM: the
// first existing aggregate file plus every certificate under the standard
// certificate directories. This is the MACHINE's trust set — it deliberately
// ignores the invoking process's SSL_CERT_FILE/SSL_CERT_DIR so the generated
// bundle is a deterministic function of machine state (see systemRootsReader).
//
// Sources are concatenated raw (newline-separated per file); ensureCABundle's
// normalizeCertsPEM does the parsing, validation, and dedup, so this reader
// stays a thin file gatherer.
func defaultSystemRootsReader() ([]byte, bool) {
	var buf []byte
	appendPEM := func(b []byte) {
		if len(b) == 0 {
			return
		}
		buf = append(buf, b...)
		if b[len(b)-1] != '\n' {
			buf = append(buf, '\n')
		}
	}

	// Aggregate file: first candidate that exists.
	for _, f := range systemRootCertFiles {
		if b, err := os.ReadFile(f); err == nil && len(b) > 0 {
			appendPEM(b)
			break
		}
	}

	// Certificate directories: always scanned (matches root_unix.go), so roots
	// installed only under /etc/ssl/certs are not dropped.
	for _, dir := range systemRootCertDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
				appendPEM(b)
			}
		}
	}

	if len(buf) == 0 {
		return nil, false
	}
	return buf, true
}
