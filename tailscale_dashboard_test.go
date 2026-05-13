package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

func TestCredentialsInProfileWalksTunnelCredential(t *testing.T) {
	credEntity := &config.Entity{Symbol: &config.Symbol{Name: "corp-tailnet"}}
	tun := &config.CompiledTunnel{Name: "corp", Credential: credEntity}
	ep := &config.CompiledEndpoint{Name: "grafana", Tunnel: tun}
	policy := &config.CompiledPolicy{
		Profiles: map[string]*config.CompiledProfile{
			"default": {
				Endpoints: map[string]*config.CompiledEndpoint{"grafana": ep},
			},
		},
	}
	got := credentialsInProfile(policy, "default")
	if !got["corp-tailnet"] {
		t.Fatalf("credentialsInProfile = %v, expected tunnel credential surfaced", got)
	}
}

func TestCredentialsInProfileWalksTransitivelyViaTunnelChain(t *testing.T) {
	tailnetCred := &config.Entity{Symbol: &config.Symbol{Name: "corp-tailnet"}}
	endpointCred := &config.Entity{Symbol: &config.Symbol{Name: "grafana-bearer"}}
	innerTun := &config.CompiledTunnel{Name: "corp-inner", Credential: tailnetCred}
	outerTun := &config.CompiledTunnel{Name: "corp", Via: innerTun}
	ep := &config.CompiledEndpoint{
		Name:        "grafana",
		Tunnel:      outerTun,
		Credentials: []*config.CompiledCredential{{Credential: endpointCred}},
	}
	policy := &config.CompiledPolicy{
		Profiles: map[string]*config.CompiledProfile{
			"default": {
				Endpoints: map[string]*config.CompiledEndpoint{"grafana": ep},
			},
		},
	}
	got := credentialsInProfile(policy, "default")
	if !got["corp-tailnet"] {
		t.Errorf("expected tailnet credential via tunnel.Via chain in %v", got)
	}
	if !got["grafana-bearer"] {
		t.Errorf("expected endpoint credential in %v", got)
	}
}

func TestApiTailscaleConnectUnknownCredential(t *testing.T) {
	g := &Gateway{}
	g.policy.Store(&config.CompiledPolicy{Credentials: map[string]*config.Entity{}})
	w := &webMux{g: g}
	r := httptest.NewRequest(http.MethodPost, "/api/tailscale/connect?id=nope", nil)
	rw := httptest.NewRecorder()
	w.apiTailscaleConnect(rw, r)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown credential", rw.Code)
	}
}

func TestApiTailscaleConnectMissingID(t *testing.T) {
	g := &Gateway{}
	g.policy.Store(&config.CompiledPolicy{Credentials: map[string]*config.Entity{}})
	w := &webMux{g: g}
	r := httptest.NewRequest(http.MethodPost, "/api/tailscale/connect", nil)
	rw := httptest.NewRecorder()
	w.apiTailscaleConnect(rw, r)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when id is missing", rw.Code)
	}
}
