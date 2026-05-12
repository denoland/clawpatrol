package main

// Persisted dashboard admin token. The HCL `dashboard_secret` lives
// in gateway.hcl, which `clawpatrol gateway init` writes 0o644 so the
// agent user can still read other config values — meaning the agent
// user can also read the dashboard secret. The admin token closes
// that gap: a 0o600 file in the state directory, readable only by
// the clawpatrol service user (or root). The gateway loads it at
// startup and accepts it as a second valid credential alongside
// dashboard_secret. Operators recover a lost token with
// `sudo clawpatrol get-token` (denoland/clawpatrol#193 finding 5;
// security-model.md "UNIX user separation").

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/denoland/clawpatrol/config"
)

// adminTokenFilename is the basename of the persisted admin token
// inside the gateway's state directory.
const adminTokenFilename = "admin_token"

// adminTokenPath returns the on-disk location for the persisted
// admin token. stateDir is the resolved state directory the gateway
// is using (cfg.OAuthDir or the ca_dir-relative fallback).
func adminTokenPath(stateDir string) string {
	return filepath.Join(stateDir, adminTokenFilename)
}

// generateAdminToken returns a fresh, URL-safe random token. 32
// bytes of crypto/rand entropy — same width as peer API tokens.
func generateAdminToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// loadAdminToken reads the persisted admin token. Returns ("", nil)
// when the file is absent so callers can decide whether to generate
// one. Permission errors come through unwrapped so the CLI can tell
// the operator to re-run with sudo.
func loadAdminToken(stateDir string) (string, error) {
	b, err := os.ReadFile(adminTokenPath(stateDir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// loadOrCreateAdminToken returns the persisted token, generating
// and writing one when the file is absent. The bool return is true
// when a new token was minted on this call (so CLI callers can note
// the recovery).
//
// The file is written 0o600 inside stateDir (the gateway creates
// stateDir 0o700). When the caller is root we chown the new file
// to match the state dir's owner so the service user retains
// read access; otherwise the caller's own uid/gid is used.
func loadOrCreateAdminToken(stateDir string) (string, bool, error) {
	if tok, err := loadAdminToken(stateDir); err != nil {
		return "", false, err
	} else if tok != "" {
		return tok, false, nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", false, fmt.Errorf("state dir %q: %w", stateDir, err)
	}
	tok, err := generateAdminToken()
	if err != nil {
		return "", false, err
	}
	path := adminTokenPath(stateDir)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", false, fmt.Errorf("write %s: %w", path, err)
	}
	if os.Geteuid() == 0 {
		// Best-effort: hand the new file to the state dir's owner so
		// the gateway daemon can still read it after root mints the
		// token via `sudo clawpatrol get-token`. Silent failure is
		// fine — root will always retain access.
		_ = chownToStateDirOwner(path, stateDir)
	}
	return tok, true, nil
}

// resolveStateDir applies the same state-directory fallback the
// gateway daemon uses: cfg.OAuthDir if set, otherwise <ca_dir>/../oauth.
// Keeps `get-token` aligned with whatever the running gateway reads.
func resolveStateDir(cfg *config.Gateway) string {
	if cfg.OAuthDir != "" {
		return cfg.OAuthDir
	}
	return filepath.Join(cfg.CADir, "..", "oauth")
}

// runGetToken implements `clawpatrol get-token`. Reads the persisted
// dashboard admin token from the state directory and prints it on
// stdout. Generates one on first use. Backstops the recovery path
// documented in security-model.md.
func runGetToken(args []string) {
	fset := flag.NewFlagSet("get-token", flag.ExitOnError)
	cfgPath := fset.String("config", "config.yaml", "gateway config file")
	_ = fset.Parse(args)

	cfg, _, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol get-token: %v\n", err)
		os.Exit(1)
	}
	stateDir := resolveStateDir(cfg)
	tok, _, err := loadOrCreateAdminToken(stateDir)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			fmt.Fprintf(os.Stderr,
				"clawpatrol get-token: permission denied reading %s. "+
					"Re-run as root or as the clawpatrol service user "+
					"(e.g. `sudo clawpatrol get-token`).\n",
				adminTokenPath(stateDir))
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "clawpatrol get-token: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(tok)
}
