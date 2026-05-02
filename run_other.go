//go:build !linux

package main

// `clawpatrol run` is Linux-only for now. macOS lands in a follow-up
// PR via the NetworkExtension path described in RUN.md (lifted from
// ../unclaw/macos/UnclawExtension/).

func runRun(args []string) {
	fail("clawpatrol run is not yet supported on this platform — Linux only.\n  see RUN.md for the macOS NE roadmap.")
}
