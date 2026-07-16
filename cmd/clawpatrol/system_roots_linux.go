//go:build linux

package main

import (
	"bytes"
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
// per-certificate directories used by distros that ship no aggregate file.
var systemRootCertDirs = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/system/etc/security/cacerts",
}

var pemCertMarker = []byte("-----BEGIN CERTIFICATE-----")

// defaultSystemRootsReader reproduces crypto/x509 root_unix.go's discovery so
// the bundle matches what Go (and thus the system's default trust) would use,
// closing the enterprise/custom-CA gap in the earlier file-only version:
//
//   - SSL_CERT_FILE overrides everything (Go honors it first) — but never our
//     own generated bundle, which SSL_CERT_FILE is set to after `clawpatrol
//     env`; folding it back in would grow the bundle on every shell.
//   - Otherwise the first existing aggregate file (systemRootCertFiles).
//   - SSL_CERT_DIR (or, when neither an aggregate file nor SSL_CERT_DIR is
//     present, the default cert directories) supplies directory-only distros
//     and enterprise roots dropped into /etc/ssl/certs.
//
// selfBundle is the ca-bundle.crt path to exclude from any file source.
func defaultSystemRootsReader(selfBundle string) ([]byte, bool) {
	var buf []byte

	if f := os.Getenv("SSL_CERT_FILE"); f != "" && !samePath(f, selfBundle) {
		if b, err := os.ReadFile(f); err == nil {
			buf = append(buf, b...)
		}
	}
	if len(buf) == 0 {
		for _, f := range systemRootCertFiles {
			if b, err := os.ReadFile(f); err == nil && len(b) > 0 {
				buf = append(buf, b...)
				break
			}
		}
	}

	// Read the cert directories when the admin points us at one explicitly,
	// or when no aggregate file was found (directory-only distros).
	if dir := os.Getenv("SSL_CERT_DIR"); dir != "" {
		for _, d := range filepath.SplitList(dir) {
			buf = appendDirCerts(buf, d, selfBundle)
		}
	} else if len(buf) == 0 {
		for _, d := range systemRootCertDirs {
			buf = appendDirCerts(buf, d, selfBundle)
		}
	}

	if len(buf) == 0 {
		return nil, false
	}
	return buf, true
}

// appendDirCerts appends every PEM certificate file found directly in dir.
func appendDirCerts(buf []byte, dir, selfBundle string) []byte {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return buf
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if samePath(p, selfBundle) {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil || !bytes.Contains(b, pemCertMarker) {
			continue
		}
		buf = append(buf, b...)
	}
	return buf
}

// samePath compares two paths by their absolute form so SSL_CERT_FILE=./x
// and the absolute selfBundle still match.
func samePath(a, b string) bool {
	if b == "" {
		return false
	}
	aa, err := filepath.Abs(a)
	if err != nil {
		aa = a
	}
	ba, err := filepath.Abs(b)
	if err != nil {
		ba = b
	}
	return aa == ba
}
