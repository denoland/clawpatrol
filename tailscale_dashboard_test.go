package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/ipn"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/plugins/tailscaleproto"
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

func TestFirstTunnelByCredentialPicksMatchingTunnel(t *testing.T) {
	credA := &config.Entity{Symbol: &config.Symbol{Name: "tailnet-a"}}
	credB := &config.Entity{Symbol: &config.Symbol{Name: "tailnet-b"}}
	policy := &config.CompiledPolicy{
		Tunnels: map[string]*config.CompiledTunnel{
			"alpha": {Name: "alpha", Credential: credA},
			"bravo": {Name: "bravo", Credential: credB},
			"plain": {Name: "plain"},
		},
	}
	got := firstTunnelByCredential(policy, "tailnet-b")
	if got == nil || got.Name != "bravo" {
		t.Fatalf("firstTunnelByCredential(tailnet-b) = %v, want tunnel bravo", got)
	}
	if firstTunnelByCredential(policy, "missing") != nil {
		t.Fatalf("expected nil for credential with no bound tunnel")
	}
	if firstTunnelByCredential(nil, "tailnet-a") != nil {
		t.Fatalf("expected nil for nil policy")
	}
}

func TestFirstTunnelByCredentialIsDeterministic(t *testing.T) {
	cred := &config.Entity{Symbol: &config.Symbol{Name: "tailnet"}}
	policy := &config.CompiledPolicy{
		Tunnels: map[string]*config.CompiledTunnel{
			"zeta":  {Name: "zeta", Credential: cred},
			"alpha": {Name: "alpha", Credential: cred},
			"mike":  {Name: "mike", Credential: cred},
		},
	}
	for range 16 {
		got := firstTunnelByCredential(policy, "tailnet")
		if got == nil || got.Name != "alpha" {
			t.Fatalf("firstTunnelByCredential = %v, want lexicographically-first 'alpha'", got)
		}
	}
}

func TestPendingNodeAuthWaitReturnsExistingURL(t *testing.T) {
	p := &tailscaleproto.PendingNodeAuth{}
	p.Set("c", "https://login.example/x")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got := p.Wait(ctx, "c"); got != "https://login.example/x" {
		t.Fatalf("Wait returned %q, want already-parked URL", got)
	}
}

func TestPendingNodeAuthWaitWakesOnSet(t *testing.T) {
	p := &tailscaleproto.PendingNodeAuth{}
	got := make(chan string, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		got <- p.Wait(ctx, "c")
	}()
	// Give the waiter a moment to register before parking.
	time.Sleep(20 * time.Millisecond)
	p.Set("c", "https://login.example/y")
	select {
	case u := <-got:
		if u != "https://login.example/y" {
			t.Fatalf("Wait returned %q, want URL parked after subscribe", u)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not wake after Set parked the URL")
	}
}

func TestPendingNodeAuthWaitCtxDone(t *testing.T) {
	p := &tailscaleproto.PendingNodeAuth{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if got := p.Wait(ctx, "c"); got != "" {
		t.Fatalf("Wait returned %q, want empty string when ctx expires before Set", got)
	}
}

func TestDashboardTailscaleStateRespectsLive(t *testing.T) {
	cases := []struct {
		name      string
		label     tailscaleproto.NodeStateLabel
		slots     bool
		want      tailscaleproto.NodeStateLabel
		connected bool
	}{
		{"running with slots", tailscaleproto.NodeStateRunning, true, tailscaleproto.NodeStateRunning, true},
		{"running no slots", tailscaleproto.NodeStateRunning, false, tailscaleproto.NodeStateRunning, true},
		{"starting overrides slots", tailscaleproto.NodeStateStarting, true, tailscaleproto.NodeStateStarting, false},
		{"needs login with slots", tailscaleproto.NodeStateNeedsLogin, true, tailscaleproto.NodeStateNeedsLogin, false},
		{"unknown with slots maps to stopped", tailscaleproto.NodeStateUnknown, true, tailscaleproto.NodeStateStopped, false},
		{"unknown no slots stays unknown", tailscaleproto.NodeStateUnknown, false, tailscaleproto.NodeStateUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dashboardTailscaleState(tc.label, tc.slots)
			if got != tc.want {
				t.Fatalf("dashboardTailscaleState(%q, slots=%v) = %q, want %q", tc.label, tc.slots, got, tc.want)
			}
			if connected := tc.label == tailscaleproto.NodeStateRunning; connected != tc.connected {
				t.Fatalf("connected = %v, want %v", connected, tc.connected)
			}
		})
	}
}

func TestLabelFromIPNStateMapping(t *testing.T) {
	cases := []struct {
		in   ipn.State
		want tailscaleproto.NodeStateLabel
	}{
		{ipn.NoState, tailscaleproto.NodeStateUnknown},
		{ipn.InUseOtherUser, tailscaleproto.NodeStateInUseOtherUser},
		{ipn.NeedsLogin, tailscaleproto.NodeStateNeedsLogin},
		{ipn.NeedsMachineAuth, tailscaleproto.NodeStateNeedsMachAuth},
		{ipn.Stopped, tailscaleproto.NodeStateStopped},
		{ipn.Starting, tailscaleproto.NodeStateStarting},
		{ipn.Running, tailscaleproto.NodeStateRunning},
	}
	for _, tc := range cases {
		if got := tailscaleproto.LabelFromIPNState(tc.in); got != tc.want {
			t.Fatalf("LabelFromIPNState(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNodeStatesSetGet(t *testing.T) {
	r := &tailscaleproto.NodeStates{}
	if got := r.Get("c"); got != tailscaleproto.NodeStateUnknown {
		t.Fatalf("Get before Set = %q, want unknown", got)
	}
	r.Set("c", tailscaleproto.NodeStateStarting)
	if got := r.Get("c"); got != tailscaleproto.NodeStateStarting {
		t.Fatalf("Get after Set = %q, want starting", got)
	}
	r.Set("c", tailscaleproto.NodeStateRunning)
	if got := r.Get("c"); got != tailscaleproto.NodeStateRunning {
		t.Fatalf("Get after second Set = %q, want running", got)
	}
	r.Set("c", tailscaleproto.NodeStateUnknown)
	if got := r.Get("c"); got != tailscaleproto.NodeStateUnknown {
		t.Fatalf("Get after clearing = %q, want unknown", got)
	}
}

func TestApiTailscaleConnectRunningStateMarksConnected(t *testing.T) {
	// A credential whose live tsnet state is Running should drive the
	// connect endpoint into the "connected" branch — no auth URL fetch
	// is attempted, the operator doesn't have anything to click.
	defer tailscaleproto.DefaultStates.Set("live-cred", tailscaleproto.NodeStateUnknown)
	tailscaleproto.DefaultStates.Set("live-cred", tailscaleproto.NodeStateRunning)

	g := &Gateway{}
	credEnt := &config.Entity{
		Plugin: &config.Plugin{Type: "tailscale_credential"},
		Body:   stubTailscaleCred{},
	}
	g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{"live-cred": credEnt},
	})
	w := &webMux{g: g}
	r := httptest.NewRequest(http.MethodPost, "/api/tailscale/connect?id=live-cred", nil)
	rw := httptest.NewRecorder()
	w.apiTailscaleConnect(rw, r)
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q, want 200", rw.Code, rw.Body.String())
	}
	var resp tailscaleAuthResponse
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Connected || resp.Status != "connected" {
		t.Fatalf("response = %+v, want Connected=true Status=connected", resp)
	}
	if resp.State != tailscaleproto.NodeStateRunning {
		t.Fatalf("response.State = %q, want running", resp.State)
	}
}

// stubTailscaleCred satisfies tailscaleproto.TailscaleAuthProvider so
// lookupTailscaleAuth's type assertion succeeds without dragging in the
// real credential plugin (which would pull the gateway's full secret-
// store wiring).
type stubTailscaleCred struct{}

func (stubTailscaleCred) TailscaleAuth() *tailscaleproto.TailscaleAuthIntegration {
	return &tailscaleproto.TailscaleAuthIntegration{}
}
