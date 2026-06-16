package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
)

// seatbeltProfile renders the sandbox-exec profile for spec. Deny by
// default; everything a self-contained plugin binary needs is allowed
// explicitly. The shape follows Bazel's darwin sandbox and Chromium's
// common.sb: dyld + libSystem read access (every darwin binary links
// libSystem), full access to the plugin's private socket/tmp dir, and
// network only when granted.
//
// All paths must be symlink-canonical before they get here (seatbelt
// matches canonical paths: /tmp is really /private/tmp).
func seatbeltProfile(spec Spec) (string, error) {
	bin, err := sbLiteral(spec.BinaryPath)
	if err != nil {
		return "", err
	}
	sockDir, err := sbLiteral(spec.SocketDir)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n\n")

	b.WriteString("; process lifecycle\n")
	fmt.Fprintf(&b, "(allow process-exec (literal %s))\n", bin)
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow signal (target self))\n\n")

	b.WriteString("; dyld, libSystem, shared cache\n")
	b.WriteString(`(allow file-read*
  (literal "/")
  (subpath "/usr/lib")
  (subpath "/usr/share/locale")
  (subpath "/System")
  (subpath "/Library/Frameworks")
  (subpath "/private/var/db/dyld")
  (subpath "/System/Volumes/Preboot/Cryptexes"))
(allow file-read-metadata
  (literal "/") (literal "/usr") (literal "/var") (literal "/tmp")
  (literal "/private") (literal "/private/tmp") (literal "/private/var")
  (literal "/etc") (literal "/dev"))
`)
	b.WriteString("(allow sysctl-read)\n\n")

	b.WriteString("; the plugin binary and its private dir (rw + unix sockets)\n")
	fmt.Fprintf(&b, "(allow file-read* (literal %s))\n", bin)
	fmt.Fprintf(&b, "(allow file* (subpath %s))\n", sockDir)
	fmt.Fprintf(&b, "(allow network* (subpath %s))\n", sockDir)
	b.WriteString(`(allow file-read* (literal "/dev/null") (literal "/dev/zero")
  (literal "/dev/random") (literal "/dev/urandom"))
(allow file-write-data (literal "/dev/null") (literal "/dev/zero"))
(allow file-ioctl (literal "/dev/null"))
`)

	if len(spec.ReadPaths) > 0 {
		b.WriteString("\n; operator-granted extra read paths\n")
		for _, p := range spec.ReadPaths {
			lit, err := sbLiteral(p)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "(allow file-read* (subpath %s))\n", lit)
		}
	}

	if spec.Network == NetworkOutbound {
		b.WriteString(`
; network grant: outbound dials, DNS, system trust store
(allow network-outbound)
(allow system-socket)
(allow mach-lookup
  (global-name "com.apple.dnssd.service")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.trustd")
  (global-name "com.apple.networkd"))
(allow file-read*
  (literal "/private/etc/hosts")
  (literal "/private/etc/resolv.conf")
  (literal "/private/etc/services")
  (subpath "/private/etc/ssl")
  (subpath "/private/var/db/mds")
  (subpath "/System/Library/Keychains")
  (subpath "/Library/Keychains"))
(allow ipc-posix-shm-read* (ipc-posix-name "com.apple.AppleDatabaseChanged"))
`)
	}

	return b.String(), nil
}

// sbLiteral renders p as a Scheme string literal. Paths that need
// escaping beyond what seatbelt's reader handles predictably are
// rejected up front (config validation rejects them too).
func sbLiteral(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("sandbox: path %q must be absolute", p)
	}
	if strings.ContainsAny(p, "\"\\\n") {
		return "", fmt.Errorf("sandbox: path %q contains characters not representable in a sandbox profile", p)
	}
	return `"` + p + `"`, nil
}
