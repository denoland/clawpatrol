//go:build !darwin

package main

// macHelperInstall is darwin-only — no-op on every other platform.
// login.go's runJoin guards the call with `runtime.GOOS == "darwin"`
// already, but Go still needs the symbol resolvable at compile time
// on every build.
func macHelperInstall(wholeMachine bool) error { return nil }

// macHelperPath alias for cross-platform builds. On non-darwin, the
// path doesn't exist (uninstall + status guard with os.Stat); the
// const just lets the symbol resolve on linux compiles.
const macHelperPath = "/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol"
