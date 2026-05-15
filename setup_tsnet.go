package main

// tsnet onboarding for `clawpatrol join`. Walks an authkey-supplied
// embedded tsnet bring-up, validates the operator's named gateway is
// visible as a peer (so a typo isn't deferred to the next
// `clawpatrol run`), then tears the node down — the persistent
// node-state lives in `<dir>/tsnet-client/` so subsequent
// `clawpatrol run` invocations resume the identity without ever
// touching the (one-shot) authkey again.
//
// Joining this way is mutually exclusive with the WG / host-tailscale
// paths: tsnet-mode clients reach the gateway via tailnet IP and
// don't need a gateway-side WG peer registration, so the device-flow
// onboard is skipped entirely. The CA fetch is shared.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

const (
	tsnetClientDir      = "tsnet-client"    // tsnet state dir under defaultClawpatrolDir
	tsnetExitNodeFile   = "tsnet-exit-node" // hostname or IP of the gateway exit node
	tsnetControlURLFile = "tsnet-control-url"
	tsnetHostnameFile   = "tsnet-hostname"
)

type tsnetJoinOpts struct {
	authKey    string
	exitNode   string
	controlURL string
	hostname   string
	clientDir  string // <ca-dir>/tsnet-client; tsnet.Server.Dir
}

// runTsnetJoin executes the tsnet branch of `clawpatrol join`. The
// caller has already fetched the CA and is responsible for printing
// the success banner.
func runTsnetJoin(opts tsnetJoinOpts) error {
	if opts.authKey == "" {
		return errors.New("--tsnet-authkey is required")
	}
	if opts.exitNode == "" {
		return errors.New("--tsnet-exit-node is required (gateway tailnet hostname or IP)")
	}
	if opts.clientDir == "" {
		return errors.New("client state dir is required")
	}
	if err := os.MkdirAll(opts.clientDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", opts.clientDir, err)
	}

	hn := opts.hostname
	if hn == "" {
		if h, err := os.Hostname(); err == nil {
			hn = "clawpatrol-" + h
		} else {
			hn = "clawpatrol-client"
		}
	}

	logger := log.New(os.Stderr, "[clawpatrol join tsnet] ", log.LstdFlags)
	srv := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    opts.authKey,
		ControlURL: opts.controlURL,
		Dir:        opts.clientDir,
		Logf:       func(f string, args ...any) { logger.Printf(f, args...) },
	}
	defer func() { _ = srv.Close() }()

	stop := startSpinner("Joining tailnet")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	status, err := srv.Up(ctx)
	stop()
	if err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}
	if len(status.TailscaleIPs) == 0 {
		return errors.New("tsnet: joined but no tailnet IP")
	}

	if _, err := exitNodePrefs(status, opts.exitNode); err != nil {
		return fmt.Errorf("validate exit-node: %w", err)
	}

	return nil
}

// persistTsnetJoinConfig writes the operator-supplied tsnet config
// alongside ca.crt so `clawpatrol run` can find it without flags. The
// authkey is intentionally not persisted — node identity lives in
// the tsnet state dir, the authkey is one-shot.
func persistTsnetJoinConfig(caDir string, opts tsnetJoinOpts) error {
	type entry struct {
		name string
		val  string
	}
	files := []entry{
		{tsnetExitNodeFile, opts.exitNode},
		{tsnetControlURLFile, opts.controlURL},
		{tsnetHostnameFile, opts.hostname},
	}
	for _, e := range files {
		path := filepath.Join(caDir, e.name)
		if e.val == "" {
			_ = os.Remove(path)
			continue
		}
		if err := os.WriteFile(path, []byte(strings.TrimSpace(e.val)+"\n"), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", e.name, err)
		}
	}
	return nil
}

// loadTsnetJoinConfig reads what persistTsnetJoinConfig wrote.
// Returns ok=false when the join wasn't done in tsnet mode (no exit
// node persisted) so callers can fall back to the WG path.
func loadTsnetJoinConfig(caDir string) (opts tsnetJoinOpts, ok bool) {
	opts.clientDir = filepath.Join(caDir, tsnetClientDir)
	opts.exitNode = strings.TrimSpace(readFileSilentDir(caDir, tsnetExitNodeFile))
	opts.controlURL = strings.TrimSpace(readFileSilentDir(caDir, tsnetControlURLFile))
	opts.hostname = strings.TrimSpace(readFileSilentDir(caDir, tsnetHostnameFile))
	if opts.exitNode == "" {
		return opts, false
	}
	if _, err := os.Stat(opts.clientDir); err != nil {
		return opts, false
	}
	return opts, true
}

func readFileSilentDir(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(b)
}
