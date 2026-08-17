package main

import (
	"slices"
	"testing"
)

func TestSanitizedChildEnv(t *testing.T) {
	pushedRunEnv.Lock()
	old := pushedRunEnv.values
	pushedRunEnv.values = map[string]string{}
	pushedRunEnv.Unlock()
	t.Cleanup(func() {
		pushedRunEnv.Lock()
		pushedRunEnv.values = old
		pushedRunEnv.Unlock()
	})

	in := []string{
		"PATH=/usr/bin",
		"HOME=/home/agent",
		"LANG=C.UTF-8",
		"TERM=xterm-256color",
		"AWS_SECRET_ACCESS_KEY=[REDACTED]",
		"GITHUB_TOKEN=[REDACTED]",
		"OPENAI_API_KEY=[REDACTED]",
		"CLAWPATROL_PLACEHOLDER_TOKEN=placeholder",
		"SSL_CERT_FILE=/clawpatrol/ca-bundle.crt",
	}
	want := []string{
		"PATH=/usr/bin",
		"HOME=/home/agent",
		"LANG=C.UTF-8",
		"TERM=xterm-256color",
		"CLAWPATROL_PLACEHOLDER_TOKEN=placeholder",
		"SSL_CERT_FILE=/clawpatrol/ca-bundle.crt",
	}
	if got := sanitizedChildEnv(in, runEnvFlags{}); !slices.Equal(got, want) {
		t.Fatalf("sanitized env = %q, want %q", got, want)
	}
}

func TestSanitizedChildEnvUsesPushedPlaceholder(t *testing.T) {
	pushedRunEnv.Lock()
	old := pushedRunEnv.values
	pushedRunEnv.values = map[string]string{"OPENAI_API_KEY": "clawpatrol-placeholder"}
	pushedRunEnv.Unlock()
	t.Cleanup(func() {
		pushedRunEnv.Lock()
		pushedRunEnv.values = old
		pushedRunEnv.Unlock()
	})

	in := []string{"PATH=/usr/bin", "OPENAI_API_KEY=[REDACTED]", "SSL_CERT_FILE=/clawpatrol/ca-bundle.crt"}
	want := []string{"PATH=/usr/bin", "OPENAI_API_KEY=clawpatrol-placeholder", "SSL_CERT_FILE=/clawpatrol/ca-bundle.crt"}
	if got := sanitizedChildEnv(in, runEnvFlags{}); !slices.Equal(got, want) {
		t.Fatalf("sanitized env = %q, want %q", got, want)
	}
}

func TestSanitizedChildEnvExplicitAllow(t *testing.T) {
	in := []string{"PATH=/usr/bin", "GITHUB_TOKEN=[REDACTED]", "OPENAI_API_KEY=[REDACTED]"}
	got := sanitizedChildEnv(in, runEnvFlags{allow: stringListFlag{"GITHUB_TOKEN"}})
	want := []string{"PATH=/usr/bin", "GITHUB_TOKEN=[REDACTED]"}
	if !slices.Equal(got, want) {
		t.Fatalf("sanitized env = %q, want %q", got, want)
	}
}

func TestSanitizedChildEnvInherit(t *testing.T) {
	in := []string{"PATH=/usr/bin", "OPENAI_API_KEY=[REDACTED]"}
	if got := sanitizedChildEnv(in, runEnvFlags{inherit: true}); !slices.Equal(got, in) {
		t.Fatalf("inherited env = %q, want %q", got, in)
	}
}
