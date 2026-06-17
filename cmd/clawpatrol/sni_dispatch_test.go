package main

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestSNIDispatchMarkerExcludesBuiltinConnEndpoints guards the :443 SNI
// dispatch branch in g.handle. That branch hands a connection to an
// endpoint plugin that terminates TLS itself. Built-in wire-protocol conn
// endpoints (postgres / clickhouse_native / ssh) also satisfy
// runtime.ConnEndpointRuntime, but they can't read a raw TLS ClientHello —
// they route via VIP / direct-IP, not SNI-on-443. So their compiled body
// must NOT satisfy the TLSTerminates() marker the branch gates on;
// otherwise a postgres endpoint declared with a bare/wildcard host and hit
// on :443 would be misrouted to the plugin path and break.
func TestSNIDispatchMarkerExcludesBuiltinConnEndpoints(t *testing.T) {
	g := gatewayWithPolicy(t, `
endpoint "postgres" "pg" { host = "pg.example.com:5432" }
credential "postgres_credential" "pg-user" { endpoint = postgres.pg }
profile "default" { credentials = [postgres_credential.pg-user] }
`)
	ep := g.Policy().Endpoints["pg"]
	if ep == nil {
		t.Fatal("missing pg endpoint")
	}
	// Premise: postgres is a conn runtime, so the broader
	// ConnEndpointRuntime check alone would have misrouted it.
	if _, ok := ep.Plugin.Runtime.(runtime.ConnEndpointRuntime); !ok {
		t.Fatal("expected built-in postgres to be a ConnEndpointRuntime")
	}
	if tt, ok := ep.Body.(interface{ TLSTerminates() bool }); ok && tt.TLSTerminates() {
		t.Fatal("built-in postgres endpoint satisfies TLSTerminates(); it would be misrouted to the plugin SNI dispatch path on :443")
	}
}
