//go:build darwin

package main

import "os/exec"

// systemRootKeychain is Apple's curated public-root store. Every certificate
// in it is a trusted TLS anchor by default, so dumping it wholesale yields a
// faithful public-root bundle — the same anchors curl-with-openssl or certifi
// would trust.
//
// We deliberately do NOT fold in /Library/Keychains/System.keychain or the
// user login keychain: `security find-certificate -a -p` exports certificate
// *objects* without evaluating trust settings ("Never Trust", trust domains,
// SSL-purpose constraints), so concatenating those keychains could promote a
// certificate macOS actually rejects into a trust anchor. Honoring admin/user
// trust settings requires Security.framework trust evaluation
// (SecTrustSettingsCopyTrustSettings), which is out of scope here.
//
// Consequence: enterprise/private roots added to the System or login keychain
// are not in the bundle, so passthrough TLS to hosts chaining to them still
// fails — but it fails closed (a visible TLS error), never a silent MITM.
var systemRootKeychain = "/System/Library/Keychains/SystemRootCertificates.keychain"

// runSecurityFindCerts dumps every certificate in keychain as PEM. Injectable
// so tests don't depend on the host's keychains.
var runSecurityFindCerts = func(keychain string) ([]byte, error) {
	return exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", keychain).Output()
}

// defaultSystemRootsReader returns Apple's curated root store as PEM. selfBundle
// is unused on darwin (the source is a keychain, never our generated file).
func defaultSystemRootsReader(selfBundle string) ([]byte, bool) {
	_ = selfBundle
	b, err := runSecurityFindCerts(systemRootKeychain)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}
