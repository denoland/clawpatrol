package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFlagSetUsageUsesDoubleDash(t *testing.T) {
	fs := newFlagSet("gateway", "clawpatrol gateway [--config FILE] [--read-only-config]")
	fs.String("config", "config.yaml", "config file")
	fs.Bool("read-only-config", false, "reject dashboard writes to the HCL config file")

	var out bytes.Buffer
	fs.SetOutput(&out)
	fs.Usage()
	help := out.String()
	for _, want := range []string{"--config VALUE", "--read-only-config"} {
		if !strings.Contains(help, want) {
			t.Fatalf("help output missing %q:\n%s", want, help)
		}
	}
	if strings.Contains(help, "\n  -config") || strings.Contains(help, "\n  -read-only-config") {
		t.Fatalf("help output used single-dash long flags:\n%s", help)
	}
}
