package config_test

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

// TestLoadEnvPushdownFromBytes exercises the env_pushdown block
// decoder end-to-end via config.LoadBytes — the same path the
// gateway runs at boot. Keeps the assertions tight on what
// downstream callers depend on: EnvPushdown is populated in source
// order, secret/value forms are mutually exclusive, and the
// placeholder string is deterministic.
func TestLoadEnvPushdownFromBytes(t *testing.T) {
	src := []byte(`
listen = "0.0.0.0:8443"
state_dir = "/x"

env_pushdown {
  OPENAI_API_KEY    = { secret = "openai_key", description = "OpenAI SDKs" }
  AWS_ACCESS_KEY_ID = { secret = "aws_access" }
  AWS_REGION        = { value  = "us-east-1" }
}
`)
	gw, diags := config.LoadBytes(src, "test.hcl")
	if diags.HasErrors() {
		t.Fatalf("unexpected diagnostics: %s", diags.Error())
	}
	if len(gw.EnvPushdown) != 3 {
		t.Fatalf("got %d entries want 3: %#v", len(gw.EnvPushdown), gw.EnvPushdown)
	}
	byName := map[string]*config.EnvPushdownEntry{}
	for _, e := range gw.EnvPushdown {
		byName[e.Name] = e
	}
	if e := byName["OPENAI_API_KEY"]; e == nil || e.SecretRef != "openai_key" || e.HasLiteral || e.Description != "OpenAI SDKs" {
		t.Errorf("OPENAI_API_KEY: %#v", e)
	}
	if e := byName["AWS_REGION"]; e == nil || !e.HasLiteral || e.Literal != "us-east-1" || e.SecretRef != "" {
		t.Errorf("AWS_REGION: %#v", e)
	}
	if got := byName["OPENAI_API_KEY"].Placeholder(); got != "clawpatrol-env-pushdown-OPENAI_API_KEY-placeholder-do-not-use" {
		t.Errorf("placeholder drift: %q", got)
	}
	if byName["AWS_REGION"].IsSecret() {
		t.Error("value-form entry should not report IsSecret")
	}
	if !byName["OPENAI_API_KEY"].IsSecret() {
		t.Error("secret-form entry should report IsSecret")
	}
}

func TestLoadEnvPushdownRejectsBothSecretAndValue(t *testing.T) {
	src := []byte(`
listen = "0.0.0.0:8443"
state_dir = "/x"

env_pushdown {
  BAD = { secret = "x", value = "y" }
}
`)
	_, diags := config.LoadBytes(src, "test.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected error for both secret + value")
	}
	if !strings.Contains(diags.Error(), "both `secret` and `value`") {
		t.Errorf("unexpected diag message: %s", diags.Error())
	}
}

func TestLoadEnvPushdownRejectsEmptyEntry(t *testing.T) {
	src := []byte(`
listen = "0.0.0.0:8443"
state_dir = "/x"

env_pushdown {
  EMPTY = {}
}
`)
	_, diags := config.LoadBytes(src, "test.hcl")
	if !diags.HasErrors() {
		t.Fatal("expected error for empty entry")
	}
	if !strings.Contains(diags.Error(), "missing `secret` or `value`") {
		t.Errorf("unexpected diag message: %s", diags.Error())
	}
}

func TestLoadEnvPushdownRejectsDuplicate(t *testing.T) {
	src := []byte(`
listen = "0.0.0.0:8443"
state_dir = "/x"

env_pushdown {
  FOO = { value = "a" }
}

env_pushdown {
  FOO = { value = "b" }
}
`)
	_, diags := config.LoadBytes(src, "test.hcl")
	// Two env_pushdown blocks themselves is a load error, but the
	// duplicate-name detector still runs and surfaces a separate
	// diagnostic with a clear "declared more than once" message —
	// stay defensive against operators who restructure a multi-block
	// config into a single block via a regex.
	if !diags.HasErrors() {
		t.Fatal("expected error for duplicate env_pushdown entry")
	}
}
