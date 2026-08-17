//go:build linux

package main

import "testing"

// The gateway-restart DNS black-hole (cl-pmcy) was caused by the
// handshake-recovery watchdog being implemented but never wired into
// the WG transport's lifecycle. Guard that Close still tears the
// watchdog down so a started watchdog can't outlive its transport.
func TestWGTransportCloseStopsWatchdog(t *testing.T) {
	stopped := false
	tr := &wgTransport{
		stopWatchdog: func() { stopped = true },
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !stopped {
		t.Fatal("Close did not stop the watchdog")
	}
}

// A transport with no watchdog (e.g. a future code path that skips it)
// must not panic on Close.
func TestWGTransportCloseNilWatchdog(t *testing.T) {
	tr := &wgTransport{}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close with nil watchdog: %v", err)
	}
}
