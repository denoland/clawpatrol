package main

// Smoke test for the operator-facing reference HCL. The file is a
// living example users copy-paste from; if a refactor breaks it
// silently CI catches the breakage here.

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

func TestGatewayExampleHCLLoadsAndCompiles(t *testing.T) {
	gw, diags := config.Load("gateway.example.hcl")
	if diags.HasErrors() {
		t.Fatalf("load gateway.example.hcl: %v", diags.Error())
	}
	if _, err := config.Compile(gw); err != nil {
		t.Fatalf("compile gateway.example.hcl: %v", err)
	}
}
