//go:build !darwin

package main

// Stubs for darwin-only symbols. Callers gate with runtime.GOOS, but
// Go still needs each symbol resolvable at compile time. On non-darwin
// the install is a no-op and the path never exists (status / uninstall
// branches guard with os.Stat).
func macHelperInstall(_ bool) error { return nil }

const macHelperPath = "/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol"
