//go:build !linux

package main

import "net/http"

// On macOS the per-process join hands authKey/apiToken to the network
// extension via macHelper start-tsnet, so there's no CLI-side tsnet node
// to claim against. See join_claim_linux.go for the Linux path.
func claimPeerAPIToken(gateway, deviceCode, hostname, authKey, controlURL, stateDir, caDir string, cli *http.Client) error {
	return nil
}
