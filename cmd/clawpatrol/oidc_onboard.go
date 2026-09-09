package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	configruntime "github.com/denoland/clawpatrol/internal/config/runtime"
)

const maxOIDCOnboardBodyBytes = 1 << 20

type oidcOnboardRequest struct {
	IDToken    string `json:"id_token"`
	PubKey     string `json:"pubkey"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

type oidcOnboardResponse struct {
	IP          string `json:"ip"`
	IP6         string `json:"ip6"`
	Profile     string `json:"profile"`
	Enrollment  string `json:"enrollment"`
	APIEndpoint string `json:"api_endpoint"`
	APIToken    string `json:"api_token"`
	WGEndpoint  string `json:"wg_endpoint"`
	WGInterface string `json:"wg_interface"`
	ServerPub   string `json:"server_pub"`
	ExpiresAt   int64  `json:"expires_at"`
}

func (w *webMux) apiOnboardOIDC(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	if r.Body == nil {
		http.Error(rw, "missing body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()
	var req oidcOnboardRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxOIDCOnboardBodyBytes))
	if err := dec.Decode(&req); err != nil {
		http.Error(rw, "invalid json", http.StatusBadRequest)
		return
	}
	resp, err := w.provisionOIDCOnboard(r.Context(), req)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, errOIDCReplayAlreadyUsed):
			status = http.StatusConflict
		case errors.Is(err, errOIDCOnboardUnavailable):
			status = http.StatusServiceUnavailable
		case errors.Is(err, errOIDCOnboardUnauthorized):
			status = http.StatusUnauthorized
		}
		http.Error(rw, err.Error(), status)
		return
	}
	writeJSON(rw, resp)
}

var (
	errOIDCOnboardUnavailable  = errors.New("oidc onboarding unavailable")
	errOIDCOnboardUnauthorized = errors.New("oidc onboarding unauthorized")
)

func (w *webMux) provisionOIDCOnboard(ctx context.Context, req oidcOnboardRequest) (*oidcOnboardResponse, error) {
	if w == nil || w.g == nil || w.g.db == nil || w.g.onboard == nil {
		return nil, errOIDCOnboardUnavailable
	}
	if globalWG == nil || w.ts.WGSubnetCIDR == "" || w.ts.WGEndpoint == "" {
		return nil, fmt.Errorf("%w: wireguard not active", errOIDCOnboardUnavailable)
	}
	if req.IDToken == "" || req.PubKey == "" {
		return nil, errors.New("id_token and pubkey are required")
	}
	policy := w.g.Policy()
	if policy == nil {
		return nil, fmt.Errorf("%w: policy not loaded", errOIDCOnboardUnavailable)
	}
	verifier := w.oidcVerifier
	if verifier == nil {
		return nil, errOIDCOnboardUnavailable
	}
	verified, err := verifier.Verify(ctx, policy, req.IDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid oidc token", errOIDCOnboardUnauthorized)
	}
	enrollment, profile, err := configruntime.MatchOIDCEnrollment(policy, &verified.Claims)
	if err != nil {
		return nil, fmt.Errorf("%w: oidc enrollment rejected", errOIDCOnboardUnauthorized)
	}
	if profile == nil || !profile.AllowEphemeralOIDC {
		return nil, fmt.Errorf("%w: profile does not allow oidc enrollment", errOIDCOnboardUnauthorized)
	}
	now := time.Now().UTC()
	reservation, err := reserveOIDCReplay(w.g.db, verified, enrollment.Name, profile.Name, now)
	if err != nil {
		return nil, err
	}
	wgOnboarder := &wireguardOnboarder{ts: w.ts}
	ip, err := wgOnboarder.allocateIP()
	if err != nil {
		return nil, err
	}
	if err := globalWG.AddPeer(req.PubKey, ip); err != nil {
		return nil, fmt.Errorf("add wireguard peer: %w", err)
	}
	leaseExpires := reservation.ExpiresAt
	if req.TTLSeconds > 0 {
		requested := now.Add(time.Duration(req.TTLSeconds) * time.Second)
		if requested.Before(leaseExpires) {
			leaseExpires = requested
		}
	}
	lease, err := createOIDCEphemeralLease(w.g.db, reservation, oidcLeasePeer{IP: ip, PubKey: req.PubKey}, enrollment.Metadata, now, leaseExpires)
	if err != nil {
		globalWG.RevokePeerByIP(ip)
		return nil, err
	}
	w.g.onboard.AssignProfile(ip, profile.Name)
	if w.g.agents != nil {
		w.g.agents.Seed(ip)
	}
	apiToken, err := mintAndPersistPeerAPIToken(w.g.db, ip)
	if err != nil {
		globalWG.RevokePeerByIP(ip)
		_ = revokeOIDCEphemeralLease(w.g.db, ip, now)
		return nil, fmt.Errorf("mint api token: %w", err)
	}
	serverPub, err := globalWG.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("wireguard server pub: %w", err)
	}
	serverPubB64, err := hexToB64(serverPub)
	if err != nil {
		return nil, err
	}
	ip6 := wg6FromV4(netip.MustParseAddr(ip)).String()
	return &oidcOnboardResponse{
		IP:          lease.PeerIP,
		IP6:         ip6,
		Profile:     profile.Name,
		Enrollment:  enrollment.Name,
		APIEndpoint: strings.TrimRight(w.publicURL, "/"),
		APIToken:    apiToken,
		WGEndpoint:  w.ts.WGEndpoint,
		WGInterface: oidcWGInterface(w.ts),
		ServerPub:   serverPubB64,
		ExpiresAt:   lease.ExpiresAt.Unix(),
	}, nil
}

func oidcWGInterface(ts JoinConfig) string {
	if ts.WGInterface != "" {
		return ts.WGInterface
	}
	return "clawpatrol"
}
