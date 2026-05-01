package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// Placeholder tokens. Agent CLIs (claude, gh, codex) refuse to start
// without these env vars set, even though our gateway swaps in the real
// OAuth-issued token server-side. The placeholder must match the
// provider's expected format closely enough to pass client-side
// validation — but the bytes never reach the API.
const (
	envClaudePlaceholder = "sk-ant-oat01-clawpatrol-placeholder-token-do-not-use-as-real-key"
	envGitHubPlaceholder = "ghp_clawpatrol_placeholder_token_do_not_use_as_real_key"
)

func runEnv(args []string) {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	caDir := fs.String("ca-dir", defaultClawpatrolDir(), "directory containing ca.crt")
	_ = fs.Parse(args)

	caPath := filepath.Join(*caDir, "ca.crt")
	if _, err := os.Stat(caPath); err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol: ca not found at %s — run `clawpatrol login` first\n", caPath)
		os.Exit(2)
	}
	for _, k := range []string{
		"SSL_CERT_FILE",
		"NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
		"GIT_SSL_CAINFO",
	} {
		fmt.Printf("export %s=%q\n", k, caPath)
	}
	// Agent-specific placeholders. Real tokens are injected by the
	// gateway via OAuth based on the tailnet user identity.
	fmt.Printf("export ANTHROPIC_AUTH_TOKEN=%q\n", envClaudePlaceholder)
	fmt.Printf("export GH_TOKEN=%q\n", envGitHubPlaceholder)
	fmt.Printf("export GITHUB_TOKEN=%q\n", envGitHubPlaceholder)
}
