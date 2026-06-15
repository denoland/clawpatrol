package extplugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/sandbox"
)

func testPluginBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "plug")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestBuildSandboxSpecValidation(t *testing.T) {
	bin := testPluginBinary(t)

	cases := []struct {
		name    string
		sp      config.PluginSource
		wantErr string
	}{
		{
			name:    "bad sandbox enum",
			sp:      config.PluginSource{Name: "x", Source: bin, Sandbox: "auto"},
			wantErr: `invalid sandbox "auto"`,
		},
		{
			name:    "missing binary",
			sp:      config.PluginSource{Name: "x", Source: filepath.Join(t.TempDir(), "nope")},
			wantErr: "no such file",
		},
		{
			name:    "non-executable binary",
			sp:      config.PluginSource{Name: "x", Source: writeFileMode(t, 0o644)},
			wantErr: "not executable",
		},
		{
			name:    "hostile read path",
			sp:      config.PluginSource{Name: "x", Source: bin, Sandbox: "off", ReadPaths: []string{"/tmp/a\"b"}},
			wantErr: "read_paths",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := buildSandboxSpec(tc.sp, sandbox.NetworkNone)
			if err == nil {
				t.Fatalf("buildSandboxSpec accepted %+v", tc.sp)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func writeFileMode(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plug")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildSandboxSpecOff(t *testing.T) {
	bin := testPluginBinary(t)
	spec, mode, warning, err := buildSandboxSpec(config.PluginSource{
		Name: "x", Source: bin, Sandbox: "off",
	}, sandbox.NetworkNone)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(spec.SocketDir) }()
	if mode != sandbox.ModeOff {
		t.Errorf("mode = %q, want off", mode)
	}
	if warning != "" {
		t.Errorf("warning = %q, want empty", warning)
	}
	if spec.BinaryPath != bin {
		t.Errorf("BinaryPath = %q, want %q", spec.BinaryPath, bin)
	}
	if spec.Network != sandbox.NetworkNone {
		t.Errorf("Network = %q, want none default", spec.Network)
	}
	if fi, err := os.Stat(spec.TmpDir); err != nil || !fi.IsDir() {
		t.Errorf("TmpDir %q not created: %v", spec.TmpDir, err)
	}
	if !strings.HasPrefix(spec.TmpDir, spec.SocketDir) {
		t.Errorf("TmpDir %q not under SocketDir %q", spec.TmpDir, spec.SocketDir)
	}
}
