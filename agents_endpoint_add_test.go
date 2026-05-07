package main

// Tests for the apiEndpointAdd splice path: append a snippet to
// gateway.hcl, optionally amend a profile's endpoints list, leave
// the file in a state that re-parses.

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/config"
	_ "github.com/denoland/clawpatrol/config/plugins/all"
)

// applyAddEndpoint mirrors the persist branch of apiEndpointAdd
// without the HTTP plumbing — exercises hclwrite splice + final
// validation. Returns the merged bytes and whether the splice fired.
func applyAddEndpoint(t *testing.T, current, snippet, profile string) (string, bool) {
	t.Helper()
	startPos := hcl.Pos{Line: 1, Column: 1}
	snipFile, diags := hclwrite.ParseConfig([]byte(snippet), "snippet.hcl", startPos)
	if diags.HasErrors() {
		t.Fatalf("snippet parse: %s", diags.Error())
	}
	var newEndpoints []string
	for _, b := range snipFile.Body().Blocks() {
		if b.Type() == "endpoint" && len(b.Labels()) == 2 {
			newEndpoints = append(newEndpoints, b.Labels()[1])
		}
	}

	merged := []byte(current)
	if !strings.HasSuffix(string(merged), "\n") {
		merged = append(merged, '\n')
	}
	merged = append(merged, '\n')
	merged = append(merged, snippet...)
	if !strings.HasSuffix(string(merged), "\n") {
		merged = append(merged, '\n')
	}

	attached := false
	if profile != "" && len(newEndpoints) > 0 {
		gw, ldiags := config.LoadBytes(merged, "gateway.hcl")
		if ldiags.HasErrors() {
			t.Fatalf("merged parse: %s", ldiags.Error())
		}
		if prof, ok := gw.Policy.Profiles[profile]; ok {
			hf, hdiags := hclwrite.ParseConfig(merged, "gateway.hcl", startPos)
			if hdiags.HasErrors() {
				t.Fatalf("merged hclwrite: %s", hdiags.Error())
			}
			combined := append([]string{}, prof.Endpoints...)
			for _, n := range newEndpoints {
				if !contains(combined, n) {
					combined = append(combined, n)
				}
			}
			for _, blk := range hf.Body().Blocks() {
				if blk.Type() != "profile" {
					continue
				}
				if labels := blk.Labels(); len(labels) == 1 && labels[0] == profile {
					config.SetIdentList(blk.Body(), "endpoints", combined)
					attached = true
					break
				}
			}
			if attached {
				merged = hf.Bytes()
			}
		}
	}
	if _, diags := config.LoadBytes(merged, "gateway.hcl"); diags.HasErrors() {
		t.Fatalf("validate: %s", diags.Error())
	}
	return string(merged), attached
}

const baseHCL = `listen      = "0.0.0.0:0"
info_listen = "0.0.0.0:0"
public_url  = ""
admin_email = "test@example.com"
ca_dir      = "/tmp/clawpatrol-ca"
oauth_dir   = "/tmp/clawpatrol-oauth"
insecure_no_dashboard_secret = true

credential "bearer_token" "github-pat" {}

endpoint "https" "github" {
  hosts      = ["api.github.com"]
  credential = github-pat
}

profile "default" {
  endpoints = [github]
}
`

func TestAddEndpointAttachesToProfile(t *testing.T) {
	snippet := `credential "postgres_credential" "pg-cred" {}

endpoint "postgres" "pg" {
  host       = "db.example.com:5432"
  database   = "postgres"
  credential = pg-cred
}
`
	merged, attached := applyAddEndpoint(t, baseHCL, snippet, "default")
	if !attached {
		t.Fatal("expected attached=true; got false")
	}
	gw, diags := config.LoadBytes([]byte(merged), "merged.hcl")
	if diags.HasErrors() {
		t.Fatalf("re-parse: %s", diags.Error())
	}
	prof := gw.Policy.Profiles["default"]
	if prof == nil {
		t.Fatal("default profile missing after splice")
	}
	if len(prof.Endpoints) != 2 || prof.Endpoints[1] != "pg" {
		t.Fatalf("profile endpoints wrong: %v", prof.Endpoints)
	}
}

func TestAddEndpointWithoutProfileLeavesProfileIntact(t *testing.T) {
	snippet := `credential "postgres_credential" "pg-cred2" {}

endpoint "postgres" "pg2" {
  host       = "db.example.com:5432"
  database   = "postgres"
  credential = pg-cred2
}
`
	merged, attached := applyAddEndpoint(t, baseHCL, snippet, "")
	if attached {
		t.Fatal("expected attached=false when profile is empty")
	}
	gw, diags := config.LoadBytes([]byte(merged), "merged.hcl")
	if diags.HasErrors() {
		t.Fatalf("re-parse: %s", diags.Error())
	}
	prof := gw.Policy.Profiles["default"]
	if prof == nil {
		t.Fatal("default profile missing")
	}
	if len(prof.Endpoints) != 1 || prof.Endpoints[0] != "github" {
		t.Fatalf("profile endpoints changed: %v", prof.Endpoints)
	}
}

func TestAddEndpointDuplicateNameRejected(t *testing.T) {
	snippet := `endpoint "https" "github" {
  hosts      = ["other.example.com"]
  credential = github-pat
}
`
	startPos := hcl.Pos{Line: 1, Column: 1}
	if _, diags := hclwrite.ParseConfig([]byte(snippet), "s.hcl", startPos); diags.HasErrors() {
		t.Fatalf("parse: %s", diags.Error())
	}
	merged := append([]byte(baseHCL), '\n', '\n')
	merged = append(merged, snippet...)
	if _, diags := config.LoadBytes(merged, "merged.hcl"); !diags.HasErrors() {
		t.Fatal("expected duplicate-name diagnostic, got none")
	}
}
