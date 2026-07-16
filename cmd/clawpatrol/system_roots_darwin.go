//go:build darwin

package main

import "os/exec"

// securityKeychains are the macOS trust stores dumped to build the combined
// bundle: Apple's public roots, plus any admin-installed roots in the System
// keychain. macOS has no system-roots PEM file (root_darwin.go reaches the
// keychain via the Security framework), so we shell out.
var securityKeychains = []string{
	"/System/Library/Keychains/SystemRootCertificates.keychain",
	"/Library/Keychains/System.keychain",
}

// runSecurityFindCerts dumps every certificate in keychain as PEM. Injectable
// so tests don't depend on the host's keychains.
var runSecurityFindCerts = func(keychain string) ([]byte, error) {
	return exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", keychain).Output()
}

func defaultSystemRootsReader() ([]byte, bool) {
	var buf []byte
	for _, kc := range securityKeychains {
		b, err := runSecurityFindCerts(kc)
		if err != nil || len(b) == 0 {
			continue
		}
		buf = append(buf, b...)
	}
	if len(buf) == 0 {
		return nil, false
	}
	return buf, true
}
