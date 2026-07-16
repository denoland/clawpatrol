//go:build linux

package main

import "os"

// systemRootCertFiles mirrors crypto/x509's root_linux.go candidate list —
// the distro-specific locations of the trusted-root PEM bundle. We read the
// file directly (rather than x509.SystemCertPool, which returns a *CertPool
// that can't be re-serialized to PEM) because the wrapped agents need a file
// path. Package var so tests can point it at a fixture.
var systemRootCertFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine
}

func defaultSystemRootsReader() ([]byte, bool) {
	for _, f := range systemRootCertFiles {
		if b, err := os.ReadFile(f); err == nil && len(b) > 0 {
			return b, true
		}
	}
	return nil, false
}
