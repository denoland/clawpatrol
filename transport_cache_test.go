package main

import (
	"net"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestPruneTransportsRemovesEndpointsMissingAfterReload(t *testing.T) {
	oldEndpoint := &config.CompiledEndpoint{Name: "api", Family: "https"}
	reloadedEndpoint := &config.CompiledEndpoint{Name: "api", Family: "https"}
	removedEndpoint := &config.CompiledEndpoint{Name: "old", Family: "https"}

	g := &Gateway{dialer: &net.Dialer{}}
	g.policy.Store(&config.CompiledPolicy{Endpoints: map[string]*config.CompiledEndpoint{
		"api": oldEndpoint,
		"old": removedEndpoint,
	}})
	oldTransport, releaseOld := g.transportFor(oldEndpoint)
	defer releaseOld()
	removedTransport, releaseRemoved := g.transportFor(removedEndpoint)
	defer releaseRemoved()

	reloadedPolicy := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{
			"api": reloadedEndpoint,
		},
	}
	g.policy.Store(reloadedPolicy)
	g.pruneTransports(reloadedPolicy)

	if _, ok := g.transports.Load(oldEndpoint); ok {
		t.Fatalf("transport for stale pointer to still-present endpoint remained cached")
	}
	if _, ok := g.transports.Load(removedEndpoint); ok {
		t.Fatalf("transport for removed endpoint remained cached")
	}
	if _, ok := g.transports.Load(reloadedEndpoint); ok {
		t.Fatalf("reload pruning should not eagerly create transports for new endpoints")
	}
	got, releaseReloaded := g.transportFor(reloadedEndpoint)
	defer releaseReloaded()
	if got == oldTransport || got == removedTransport {
		t.Fatalf("transportFor reused a stale transport after reload prune")
	}
}

func TestTransportForStaleEndpointAfterReloadDoesNotRecache(t *testing.T) {
	oldEndpoint := &config.CompiledEndpoint{Name: "api", Family: "https"}
	reloadedEndpoint := &config.CompiledEndpoint{Name: "api", Family: "https"}

	g := &Gateway{dialer: &net.Dialer{}}
	g.policy.Store(&config.CompiledPolicy{Endpoints: map[string]*config.CompiledEndpoint{
		"api": oldEndpoint,
	}})
	oldTransport, releaseOld := g.transportFor(oldEndpoint)
	defer releaseOld()

	reloadedPolicy := &config.CompiledPolicy{
		Endpoints: map[string]*config.CompiledEndpoint{
			"api": reloadedEndpoint,
		},
	}
	g.policy.Store(reloadedPolicy)
	g.pruneTransports(reloadedPolicy)

	staleTransport, releaseStale := g.transportFor(oldEndpoint)
	defer releaseStale()
	if staleTransport == nil {
		t.Fatalf("transportFor returned nil transport for stale endpoint")
	}
	if staleTransport == oldTransport {
		t.Fatalf("transportFor reused pruned cached transport for stale endpoint")
	}
	if _, ok := g.transports.Load(oldEndpoint); ok {
		t.Fatalf("transportFor re-cached stale endpoint after reload prune")
	}

	currentTransport, releaseCurrent := g.transportFor(reloadedEndpoint)
	defer releaseCurrent()
	if currentTransport == nil {
		t.Fatalf("transportFor returned nil transport for current endpoint")
	}
	if _, ok := g.transports.Load(reloadedEndpoint); !ok {
		t.Fatalf("transportFor did not cache current reloaded endpoint")
	}
}
