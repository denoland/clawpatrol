package credentials

// google_gke_credential: stamps a short-lived Google OAuth2 access
// token onto the upstream Authorization header so the kubernetes
// endpoint plugin can talk to a GKE cluster's API server without
// shelling out to gcloud / gke-gcloud-auth-plugin. The token is
// minted from a service-account JSON key paste held in the
// credential's secret store; we cache the oauth2.TokenSource keyed
// by SHA-256(sa_key) so a key rotation (different JSON) busts the
// cache automatically while same-key requests reuse a single source
// (the source itself caches the token until ~5min before expiry).
//
// Schema is intentionally empty: the SA JSON carries everything
// (client_email, project_id, private_key) needed to mint a token,
// and the upstream cluster identity lives on the kubernetes endpoint
// (server + ca_cert). Two endpoints pointing at the same project
// can share one credential.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// gkeOAuthScope is what GKE's control plane (and every other Google
// Cloud API) accepts. Narrower scopes like `…/auth/userinfo.email`
// don't grant container.* permissions — the project's IAM policy
// is the actual access gate, the scope just has to be broad enough
// for it to be evaluated.
const gkeOAuthScope = "https://www.googleapis.com/auth/cloud-platform"

// GoogleGKECredential is part of the clawpatrol plugin API.
type GoogleGKECredential struct{}

// gkeTokenSources caches an oauth2.TokenSource by SHA-256(sa_key).
// oauth2.TokenSource is itself safe for concurrent use and the
// jwt.Config-derived source already wraps the live token in
// oauth2.ReuseTokenSource — we just need to avoid re-parsing the
// JSON + RSA private key on every signed request.
var gkeTokenSources sync.Map

// SignHTTPRequest is part of the clawpatrol plugin API.
func (*GoogleGKECredential) SignHTTPRequest(_ context.Context, req *http.Request, sec runtime.Secret, _ any) error {
	saKey := []byte(sec.Extras["sa_key"])
	if len(saKey) == 0 {
		return errors.New("google_gke_credential: missing sa_key (paste the SA JSON into the dashboard or set CLAWPATROL_SECRET_<NAME>_SA_KEY)")
	}
	ts, err := tokenSourceForSAKey(saKey)
	if err != nil {
		return err
	}
	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("google_gke_credential: mint access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	return nil
}

// tokenSourceForSAKey returns the per-SA-key cached
// oauth2.TokenSource. The first caller for a given key parses the
// JSON and builds the source; subsequent callers — within or across
// requests — hit the map. We pin the source's refresh context to
// context.Background() so a single dispatcher request's cancellation
// doesn't poison the cached source for everyone else.
func tokenSourceForSAKey(saKey []byte) (oauth2.TokenSource, error) {
	sum := sha256.Sum256(saKey)
	key := hex.EncodeToString(sum[:])
	if v, ok := gkeTokenSources.Load(key); ok {
		return v.(oauth2.TokenSource), nil
	}
	cfg, err := google.JWTConfigFromJSON(saKey, gkeOAuthScope)
	if err != nil {
		return nil, fmt.Errorf("google_gke_credential: parse sa_key: %w", err)
	}
	ts := cfg.TokenSource(context.Background())
	// LoadOrStore handles the (rare) concurrent-first-call race —
	// we keep whichever source landed first and discard ours.
	actual, _ := gkeTokenSources.LoadOrStore(key, ts)
	return actual.(oauth2.TokenSource), nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*GoogleGKECredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{
		Name:        "sa_key",
		Label:       "Service account JSON key",
		Description: "Full contents of the GCP service-account JSON key file, braces included. The plugin parses client_email + private_key and mints a short-lived OAuth2 access token at request time.",
	}}
}

func init() {
	var _ runtime.HTTPRequestSigner = (*GoogleGKECredential)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "google_gke_credential",
		New:     newer[GoogleGKECredential](),
		Runtime: (*GoogleGKECredential)(nil),
		Build:   passthrough,
		Emit: func(_ any, _ string, _ *hclwrite.Body) {
			// GoogleGKECredential has no HCL attributes — the SA
			// JSON in the secret store carries every parameter the
			// token exchange needs.
		},
	})
}
