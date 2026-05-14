package config_test

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

// TestCompileClickhouseNativeDatabaseRoutingSpecific+CatchAllOK covers
// the valid shape: one specific endpoint and one catch-all on the
// same host. The dispatcher resolves a connection to the specific
// when Hello.Database matches and to the catch-all otherwise.
func TestCompileClickhouseNativeSpecificPlusCatchAllOK(t *testing.T) {
	src := []byte(`
credential "clickhouse_credential" "ch-prod" {}
credential "clickhouse_credential" "ch-default" {}

endpoint "clickhouse_native" "prod" {
  hosts      = ["clickhouse.example.com"]
  database   = "analytics_prod"
  credential = ch-prod
}
endpoint "clickhouse_native" "any" {
  hosts      = ["clickhouse.example.com"]
  credential = ch-default
}
`)
	gw, diags := config.LoadBytes(src, "specific_plus_catchall.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if _, err := config.Compile(gw); err != nil {
		t.Fatalf("specific + catch-all on same host should compile, got: %v", err)
	}
}

// TestCompileClickhouseNativeTwoSpecificsDifferentDBsOK exercises the
// dual-database shape from the bead: two endpoints, same host, two
// different specific databases. Both compile and the dispatcher can
// route a connection to whichever one Hello.Database picks.
func TestCompileClickhouseNativeTwoSpecificsDifferentDBsOK(t *testing.T) {
	src := []byte(`
credential "clickhouse_credential" "ch-prod" {}
credential "clickhouse_credential" "ch-dev" {}

endpoint "clickhouse_native" "prod" {
  hosts      = ["clickhouse.example.com"]
  database   = "analytics_prod"
  credential = ch-prod
}
endpoint "clickhouse_native" "dev" {
  hosts      = ["clickhouse.example.com"]
  database   = "analytics_dev"
  credential = ch-dev
}
`)
	gw, diags := config.LoadBytes(src, "two_specifics.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if _, err := config.Compile(gw); err != nil {
		t.Fatalf("two different specifics on same host should compile, got: %v", err)
	}
}

func TestCompileClickhouseNativeDuplicateSpecificFails(t *testing.T) {
	src := []byte(`
credential "clickhouse_credential" "a" {}
credential "clickhouse_credential" "b" {}

endpoint "clickhouse_native" "alpha" {
  hosts      = ["clickhouse.example.com"]
  database   = "analytics_prod"
  credential = a
}
endpoint "clickhouse_native" "beta" {
  hosts      = ["clickhouse.example.com"]
  database   = "analytics_prod"
  credential = b
}
`)
	gw, diags := config.LoadBytes(src, "dup_specific.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	_, err := config.Compile(gw)
	if err == nil {
		t.Fatal("two endpoints on same (host, database) should fail compile")
	}
	if !strings.Contains(err.Error(), "analytics_prod") {
		t.Errorf("error %q does not mention the offending database", err)
	}
	if !strings.Contains(err.Error(), "clickhouse.example.com") {
		t.Errorf("error %q does not mention the offending host", err)
	}
}

func TestCompileClickhouseNativeDuplicateCatchAllFails(t *testing.T) {
	src := []byte(`
credential "clickhouse_credential" "a" {}
credential "clickhouse_credential" "b" {}

endpoint "clickhouse_native" "alpha" {
  hosts      = ["clickhouse.example.com"]
  credential = a
}
endpoint "clickhouse_native" "beta" {
  hosts      = ["clickhouse.example.com"]
  credential = b
}
`)
	gw, diags := config.LoadBytes(src, "dup_catchall.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	_, err := config.Compile(gw)
	if err == nil {
		t.Fatal("two catch-all endpoints on same host should fail compile")
	}
	if !strings.Contains(err.Error(), "catch-all") {
		t.Errorf("error %q does not mention catch-all", err)
	}
}

func TestCompileClickhouseHTTPSDuplicateSpecificFails(t *testing.T) {
	src := []byte(`
credential "clickhouse_credential" "a" {}
credential "clickhouse_credential" "b" {}

endpoint "clickhouse_https" "alpha" {
  hosts      = ["clickhouse.example.com"]
  database   = "prod"
  credential = a
}
endpoint "clickhouse_https" "beta" {
  hosts      = ["clickhouse.example.com"]
  database   = "prod"
  credential = b
}
`)
	gw, diags := config.LoadBytes(src, "https_dup.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if _, err := config.Compile(gw); err == nil {
		t.Fatal("two clickhouse_https endpoints on same (host, database) should fail compile")
	}
}

// TestCompileClickhouseDifferentPluginsDontConflict ensures the
// (plugin, host, database) key keeps native and https from colliding
// on shared infra — a clickhouse cluster typically exposes both
// protocols on the same hostname.
func TestCompileClickhouseDifferentPluginsDontConflict(t *testing.T) {
	src := []byte(`
credential "clickhouse_credential" "a" {}

endpoint "clickhouse_native" "native-prod" {
  hosts      = ["clickhouse.example.com"]
  database   = "analytics_prod"
  credential = a
}
endpoint "clickhouse_https" "https-prod" {
  hosts      = ["clickhouse.example.com"]
  database   = "analytics_prod"
  credential = a
}
`)
	gw, diags := config.LoadBytes(src, "different_plugins.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if _, err := config.Compile(gw); err != nil {
		t.Fatalf("native + https on same (host, database) should compile, got: %v", err)
	}
}

// TestCompileClickhouseHostPortNormalization makes the routing check
// host-only — `clickhouse.example.com:9000` and
// `clickhouse.example.com` are the same host. Two specifics with the
// same database on these two host strings must still fail compile.
func TestCompileClickhouseHostPortNormalization(t *testing.T) {
	src := []byte(`
credential "clickhouse_credential" "a" {}
credential "clickhouse_credential" "b" {}

endpoint "clickhouse_native" "alpha" {
  hosts      = ["clickhouse.example.com"]
  database   = "prod"
  credential = a
}
endpoint "clickhouse_native" "beta" {
  hosts      = ["clickhouse.example.com:9000"]
  database   = "prod"
  credential = b
}
`)
	gw, diags := config.LoadBytes(src, "port_normalization.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if _, err := config.Compile(gw); err == nil {
		t.Fatal("host:port and bare host should normalize to the same routing key")
	}
}
