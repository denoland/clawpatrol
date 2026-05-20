//go:build !linux

package main

// The self-forking daemon is Linux-only. macOS has the NE provider
// (which already serves the equivalent role); other platforms aren't
// supported for `clawpatrol run`. Stubs let the `daemon` subcommand
// compile cross-platform — it just refuses to run.

func runDaemon(_ []string) {
	fail("clawpatrol daemon-internal: linux only")
}
