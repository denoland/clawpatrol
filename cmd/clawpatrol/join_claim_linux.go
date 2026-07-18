//go:build linux

package main

// Peer api-token acquisition for the per-process Linux join path.
//
// In Tailscale mode the gateway mints the per-peer bearer inside
// /api/onboard/claim, not at approve time, because the peer's tailnet
// IP isn't known until the device actually joins the tailnet (see
// onboard.go → "Mint the per-peer bearer ... we mint it here instead").
// The whole-machine path claims after `tailscale up`, using the system
// tailnet IP. The per-process path has no system tailscale, so it used
// to skip the claim entirely and never persisted an api-token — leaving
// the daemon unable to authenticate /api/env-pushdown, so wrapped agents
// booted with an empty credential set.
//
// Bring the daemon's *persistent* tsnet identity up here, one time, to
// learn the IP it will own, claim against that IP, and persist the
// token next to ca.crt. The daemon reuses the same state dir (and so
// the same node identity and IP), which is what makes the gateway's
// ip→profile mapping from the claim line up with the daemon's later
// registerTsnetPeer call.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/tsnet"
)

// claimPeerAPIToken stands up the daemon's tsnet node, claims the
// device against its tailnet IP, and writes <caDir>/api-token.
//
// When onboarding used a tailnet bootstrap, the claim POST reuses its
// client so tailnet-only gateway URLs remain reachable. Otherwise it uses
// the default secure HTTP transport for a public gateway URL.
func claimPeerAPIToken(gateway, deviceCode, hostname, authKey, controlURL, stateDir, caDir string, cli *http.Client) error {
	tsnetDir := filepath.Join(stateDir, "tsnet")
	if err := os.MkdirAll(tsnetDir, 0o700); err != nil {
		return fmt.Errorf("tsnet state dir: %w", err)
	}

	hn := hostname
	if hn == "" {
		hn, _ = os.Hostname()
	}

	// Ephemeral:false and the shared Dir are load-bearing: the daemon
	// re-opens this exact state and must come up as the same node.
	s := &tsnet.Server{
		Hostname:   hn,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Dir:        tsnetDir,
		Ephemeral:  false,
		Logf:       func(string, ...any) {},
	}
	defer func() { _ = s.Close() }()

	tsIP, err := waitTsnetUp(s)
	if err != nil {
		return fmt.Errorf("bring up tsnet node: %w", err)
	}

	claimURL := fmt.Sprintf("%s/api/onboard/claim?device_code=%s&ip=%s",
		gateway, neturl.QueryEscape(deviceCode), neturl.QueryEscape(tsIP.String()))
	if hn != "" {
		claimURL += "&hostname=" + neturl.QueryEscape(hn)
	}
	return claimPeerAPITokenAtURL(claimURL, tsIP.String(), caDir, cli)
}

func claimPeerAPITokenAtURL(claimURL, tsIP, caDir string, cli *http.Client) error {
	if cli == nil {
		cli = &http.Client{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, claimURL, nil)
	if err != nil {
		return fmt.Errorf("build claim request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("claim %s: %w", tsIP, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return fmt.Errorf("claim %s: status %d: %s", tsIP, resp.StatusCode, string(body))
	}

	var claimResp map[string]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&claimResp); err != nil {
		return fmt.Errorf("decode claim response: %w", err)
	}
	tok := claimResp["api_token"]
	if tok == "" {
		if why := claimResp["api_token_error"]; why != "" {
			return fmt.Errorf("gateway could not mint an api_token for %s: %s", tsIP, why)
		}
		return fmt.Errorf("gateway returned no api_token for %s (peer token minting failed server-side)", tsIP)
	}
	if err := os.WriteFile(filepath.Join(caDir, "api-token"), []byte(tok+"\n"), 0o600); err != nil {
		return fmt.Errorf("write api-token: %w", err)
	}
	return nil
}
