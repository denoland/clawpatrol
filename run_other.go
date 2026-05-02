//go:build !linux && !darwin

package main

func runRun(args []string) {
	fail("clawpatrol run is not supported on this platform — linux + macOS only.")
}

func macHelperInstall(wholeMachine bool) error { return nil }
