//go:build !linux && !darwin

package main

func runRun(args []string) {
	fail("clawpatrol run is not supported on this platform — linux + macOS only.")
}

// macHelperInstall is a no-op everywhere except darwin. login.go's
// runJoin guards the call with `runtime.GOOS == "darwin"` already,
// but Go still needs the symbol resolvable at compile time on every
// build.
func macHelperInstall(wholeMachine bool) error { return nil }
