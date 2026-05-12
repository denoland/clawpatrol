//go:build !linux

package main

// The auto-expose relay is linux-only — it relies on seccomp user_notify
// and pidfd_getfd to peek into another netns. On non-linux platforms the
// subcommands are never invoked from runRun, but main.go's switch
// references them unconditionally, so we provide stubs.

func runRelaySupervisor(_ []string) {
	fail("relay-supervisor is linux-only")
}

func runRelayWorker(_ []string) {
	fail("relay-worker is linux-only")
}
