// Package oidcverify verifies OIDC ID tokens for ephemeral enrollment.
package oidcverify

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/denoland/clawpatrol/config"
	configruntime "github.com/denoland/clawpatrol/config/runtime"
)

const defaultMaxTokenBytes = 64 * 1024

// Options configures a Verifier.
type Options struct {
	HTTPClient    *http.Client
	Now           func() time.Time
	MaxTokenBytes int
}

// VerifiedToken is the sanitized output of ID token verification. It contains
// only claims and derived identifiers needed by later enrollment layers; it does
// not retain the raw JWT.
type VerifiedToken struct {
	Issuer    string
	Subject   string
	Audience  []string
	Expiry    time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	JWTID     string
	TokenHash string
	ReplayKey string
	Claims    config.OIDCClaimRequest
}

// Verifier verifies ID tokens against the issuers and audience present in a
// compiled policy. Providers and their JWKS-backed verifiers are cached per
// issuer for reuse across join requests.
type Verifier struct {
	httpClient    *http.Client
	now           func() time.Time
	maxTokenBytes int

	mu        sync.Mutex
	providers map[string]*coreosoidc.Provider
}

// New constructs a Verifier.
func New(opts Options) *Verifier {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	maxTokenBytes := opts.MaxTokenBytes
	if maxTokenBytes <= 0 {
		maxTokenBytes = defaultMaxTokenBytes
	}
	return &Verifier{
		httpClient:    opts.HTTPClient,
		now:           now,
		maxTokenBytes: maxTokenBytes,
		providers:     map[string]*coreosoidc.Provider{},
	}
}

// Verify verifies rawIDToken against policy, returning sanitized claims suitable
// for runtime enrollment matching. Errors are intentionally generic and must not
// include the raw token.
func (v *Verifier) Verify(ctx context.Context, policy *config.CompiledPolicy, rawIDToken string) (*VerifiedToken, error) {
	if policy == nil || len(policy.OIDCEnrollmentsByIssuer) == 0 || policy.OIDCAudience == "" {
		return nil, errors.New("oidc enrollment is not configured")
	}
	if rawIDToken == "" {
		return nil, errors.New("oidc token is required")
	}
	if len(rawIDToken) > v.maxTokenBytes {
		return nil, errors.New("oidc token exceeds maximum size")
	}
	issuer, err := unsafePeekIssuer(rawIDToken)
	if err != nil {
		return nil, errors.New("invalid oidc token")
	}
	if _, ok := policy.OIDCEnrollmentsByIssuer[issuer]; !ok {
		return nil, errors.New("untrusted oidc issuer")
	}

	provider, err := v.provider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc provider discovery failed: %w", err)
	}
	tok, err := provider.Verifier(&coreosoidc.Config{
		ClientID: policy.OIDCAudience,
		Now:      v.now,
	}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, errors.New("oidc token verification failed")
	}

	claims := map[string]any{}
	if err := tok.Claims(&claims); err != nil {
		return nil, errors.New("oidc token claims are invalid")
	}
	azp, _ := claims["azp"].(string)
	if len(tok.Audience) > 1 && azp != policy.OIDCAudience {
		return nil, errors.New("oidc authorized party mismatch")
	}

	req := config.OIDCClaimRequest{
		Issuer:          tok.Issuer,
		Audience:        append([]string(nil), tok.Audience...),
		AuthorizedParty: azp,
		Claims:          claims,
	}
	if _, _, err := configruntime.MatchOIDCEnrollment(policy, &req); err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(rawIDToken))
	tokenHash := base64.RawURLEncoding.EncodeToString(hash[:])
	jwtID, _ := claims["jti"].(string)
	nbf := unixClaimTime(claims["nbf"])
	return &VerifiedToken{
		Issuer:    tok.Issuer,
		Subject:   tok.Subject,
		Audience:  append([]string(nil), tok.Audience...),
		Expiry:    tok.Expiry,
		IssuedAt:  tok.IssuedAt,
		NotBefore: nbf,
		JWTID:     jwtID,
		TokenHash: tokenHash,
		ReplayKey: replayKey(tok.Issuer, tok.Subject, jwtID, tokenHash),
		Claims:    req,
	}, nil
}

func (v *Verifier) provider(ctx context.Context, issuer string) (*coreosoidc.Provider, error) {
	v.mu.Lock()
	provider := v.providers[issuer]
	v.mu.Unlock()
	if provider != nil {
		return provider, nil
	}
	if v.httpClient != nil {
		ctx = coreosoidc.ClientContext(ctx, v.httpClient)
	}
	provider, err := coreosoidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if existing := v.providers[issuer]; existing != nil {
		return existing, nil
	}
	v.providers[issuer] = provider
	return provider, nil
}

func unsafePeekIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	if claims.Issuer == "" {
		return "", errors.New("missing issuer")
	}
	return claims.Issuer, nil
}

func unixClaimTime(v any) time.Time {
	switch vv := v.(type) {
	case float64:
		return time.Unix(int64(vv), 0).UTC()
	case json.Number:
		i, err := vv.Int64()
		if err == nil {
			return time.Unix(i, 0).UTC()
		}
	}
	return time.Time{}
}

func replayKey(issuer, subject, jwtID, tokenHash string) string {
	if jwtID != "" {
		return issuer + "\x00" + subject + "\x00" + jwtID
	}
	return issuer + "\x00" + subject + "\x00sha256:" + tokenHash
}
