package main

// Tests for the ClickHouse-native dispatch helpers wired into
// tcpDispatch. The wire-protocol pump is exhaustively tested in
// config/plugins/endpoints/clickhouse_native_test.go; this file only
// pins the policy-walk side of dispatch — pick the right endpoint
// out of a CompiledPolicy given a device profile.

import (
	"testing"

	"github.com/denoland/clawpatrol/config"
)

// TestFirstClickhouseNativeEndpoint covers the lowest-priority
// dispatch path in handleClickhouseNativeConn: pick the first
// clickhouse_native endpoint in the device's profile. Mirrors the
// shape firstPostgresEndpoint depends on but exercises the type
// filter explicitly.
func TestFirstClickhouseNativeEndpoint(t *testing.T) {
	chPlugin := &config.Plugin{Type: "clickhouse_native", Family: "sql"}
	pgPlugin := &config.Plugin{Type: "postgres", Family: "sql"}

	chA := &config.CompiledEndpoint{Name: "ch-a", Family: "sql", Plugin: chPlugin}
	chB := &config.CompiledEndpoint{Name: "ch-b", Family: "sql", Plugin: chPlugin}
	pg := &config.CompiledEndpoint{Name: "pg", Family: "sql", Plugin: pgPlugin}

	t.Run("nil policy returns nil", func(t *testing.T) {
		if got := firstClickhouseNativeEndpoint(nil, "any"); got != nil {
			t.Errorf("nil policy → endpoint %q, want nil", got.Name)
		}
	})

	t.Run("profile with ch endpoint wins", func(t *testing.T) {
		policy := &config.CompiledPolicy{
			Profiles: map[string]*config.CompiledProfile{
				"dev": {Name: "dev", Endpoints: map[string]*config.CompiledEndpoint{
					"ch-a": chA,
					"pg":   pg,
				}},
			},
		}
		got := firstClickhouseNativeEndpoint(policy, "dev")
		if got != chA {
			t.Errorf("got %v, want ch-a", got)
		}
	})

	t.Run("profile without ch endpoint returns nil", func(t *testing.T) {
		policy := &config.CompiledPolicy{
			Profiles: map[string]*config.CompiledProfile{
				"dev": {Name: "dev", Endpoints: map[string]*config.CompiledEndpoint{
					"pg": pg,
				}},
			},
		}
		got := firstClickhouseNativeEndpoint(policy, "dev")
		if got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("unknown profile falls back to any profile's ch endpoint", func(t *testing.T) {
		// Mirrors firstPostgresEndpoint's single-tenant fallback:
		// when the device has no profile binding, scan every
		// profile so a single-tenant deployment without an
		// explicit profile keeps working.
		policy := &config.CompiledPolicy{
			Profiles: map[string]*config.CompiledProfile{
				"prod": {Name: "prod", Endpoints: map[string]*config.CompiledEndpoint{
					"ch-b": chB,
				}},
			},
		}
		got := firstClickhouseNativeEndpoint(policy, "missing")
		if got != chB {
			t.Errorf("got %v, want ch-b (single-tenant fallback)", got)
		}
	})

	t.Run("type filter excludes postgres", func(t *testing.T) {
		// Important: firstClickhouseNativeEndpoint must NOT return
		// a postgres endpoint even if it's the only SQL-family
		// endpoint in scope. The port-based dispatch on :9000 /
		// :9440 routes only ClickHouse traffic; mis-dispatching
		// to a postgres runtime would break the agent.
		policy := &config.CompiledPolicy{
			Profiles: map[string]*config.CompiledProfile{
				"dev": {Name: "dev", Endpoints: map[string]*config.CompiledEndpoint{
					"pg": pg,
				}},
			},
		}
		got := firstClickhouseNativeEndpoint(policy, "dev")
		if got != nil {
			t.Errorf("got %v, want nil — postgres must not satisfy a ch-native query", got)
		}
	})
}

// TestFirstEndpointOfTypeMissingProfileSingleTenant pins the
// single-tenant fallback shared by firstPostgresEndpoint and
// firstClickhouseNativeEndpoint: when the device has no profile
// binding, scan every profile so single-profile deployments
// without explicit binding still dispatch. Asserts the order is
// stable enough to be useful — the first profile iteration is
// nondeterministic so we only check the type filter applies.
func TestFirstEndpointOfTypeMissingProfileSingleTenant(t *testing.T) {
	chPlugin := &config.Plugin{Type: "clickhouse_native", Family: "sql"}
	chA := &config.CompiledEndpoint{Name: "ch-a", Family: "sql", Plugin: chPlugin}
	policy := &config.CompiledPolicy{
		Profiles: map[string]*config.CompiledProfile{
			"only": {Name: "only", Endpoints: map[string]*config.CompiledEndpoint{
				"ch-a": chA,
			}},
		},
	}
	if got := firstEndpointOfType(policy, "", "clickhouse_native"); got != chA {
		t.Errorf("empty profile → %v, want ch-a", got)
	}
	if got := firstEndpointOfType(policy, "anything", "clickhouse_native"); got != chA {
		t.Errorf("unknown profile → %v, want ch-a", got)
	}
}
