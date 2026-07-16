//go:build !linux && !darwin

package main

// defaultSystemRootsReader has no portable way to enumerate the system trust
// store on unsupported platforms, so it reports "none found" and ensureCABundle
// falls back to the MITM-CA-only path. selfBundle is unused.
func defaultSystemRootsReader(selfBundle string) ([]byte, bool) {
	_ = selfBundle
	return nil, false
}
