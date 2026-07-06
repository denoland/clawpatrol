package endpoints

// openai_codex_https endpoint: the chatgpt.com + auth.openai.com path
// for codex-cli's subscription auth flow. Pushes a synthesized Agent
// Identity JWT down via env (CODEX_ACCESS_TOKEN / CODEX_AGENT_IDENTITY)
// so codex enters AgentIdentity mode on its own. At MITM time we serve
// the matching JWKS at `/backend-api/wham/agent-identities/jwks`
// (chatgpt.com) and stub the agent-task registration POST. The
// registration host depends on codex version: <= 0.141 sent it to
// chatgpt.com/backend-api/wham (redirected via env), while 0.142+
// hardcodes auth.openai.com/api/accounts — so this endpoint claims
// auth.openai.com too (see codexAuthAPIHost) and stubs the
// task-register path on either host. Codex's Authorization gets
// overwritten by the bound credential plugin (openai_codex_oauth)
// before forwarding upstream — except on auth.openai.com, where the
// credential skips injection so codex login / token refresh keep
// their native auth.
//
// Sample HCL:
//
//	credential "openai_codex_oauth" "codex" {}
//
//	endpoint "openai_codex_https" "codex" {
//	  hosts      = ["chatgpt.com"]
//	  credential = codex
//	}

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// OpenAICodexHTTPSEndpoint is part of the clawpatrol plugin API.
type OpenAICodexHTTPSEndpoint struct {
	// Hosts is the chatgpt.com host list intercepted for Codex
	// subscription-auth traffic.
	Hosts []string `hcl:"hosts"`
}

// codexAuthAPIHost is OpenAI's accounts/auth host. codex >= 0.142
// hardcodes agent task-registration to https://auth.openai.com/api/accounts
// (the env override clawpatrol used on <= 0.141 was removed upstream), so
// the gateway must MITM this host to keep stubbing task-register. We claim
// it unconditionally (see EndpointHosts) and stub only the task-register
// path (see RespondHTTP); every other auth.openai.com path — codex login,
// token refresh — is forwarded untouched, and the bound credential's
// InjectHTTP skips this host so it never clobbers their native auth.
const codexAuthAPIHost = "auth.openai.com"

// codexSyntheticRuntimeID is the agent_runtime_id baked into the JWT we
// mint (mintCodexAccessToken). The task-register stub keys on it so we
// only forge a task_id for OUR synthetic identity — a real OpenAI Agent
// Identity (e.g. the JWT-mint-failure fallback to ~/.codex/auth.json)
// registers a different runtime id and is forwarded upstream untouched.
const codexSyntheticRuntimeID = "clawpatrol-codex"

// EndpointHosts is part of the clawpatrol plugin API. It always includes
// codexAuthAPIHost so the codex >= 0.142 registration host is MITM'd
// without an HCL edit on upgrade.
func (e *OpenAICodexHTTPSEndpoint) EndpointHosts() []string {
	if slices.Contains(e.Hosts, codexAuthAPIHost) {
		return e.Hosts
	}
	return append(slices.Clone(e.Hosts), codexAuthAPIHost)
}

// EnvVars pushes down a synthetic CODEX_ACCESS_TOKEN so codex enters
// AgentIdentity mode (which routes it to chatgpt.com). Also pushes
// CODEX_AGENT_IDENTITY for codex <= 0.128, which read the same JWT
// from the older env-var name.
//
// CODEX_AGENT_IDENTITY_AUTHAPI_BASE_URL is load-bearing only for codex
// <= 0.141: it redirected per-task registration onto a host clawpatrol
// MITMs (chatgpt.com/backend-api/wham). codex 0.142 REMOVED this
// override and hardcoded registration to auth.openai.com, so for 0.142+
// the gateway instead MITMs auth.openai.com directly (see
// codexAuthAPIHost / RespondHTTP). The var is kept here because it's
// harmless on 0.142 (ignored) and still required on <= 0.141. We do NOT
// push the 0.142 replacement CODEX_AUTHAPI_BASE_URL: codex host-restricts
// it to OpenAI hosts, so it can't be pointed at a clawpatrol host anyway.
func (e *OpenAICodexHTTPSEndpoint) EnvVars() []config.EnvVar {
	jwt, err := mintCodexAccessToken()
	if err != nil {
		// Fall back silently — without the JWT codex falls back to its
		// real ~/.codex/auth.json and clawpatrol's MITM still works
		// for users who already ran `codex login`.
		return nil
	}
	return []config.EnvVar{
		{
			Name:        "CODEX_ACCESS_TOKEN",
			Value:       jwt,
			Description: "synthetic Agent Identity JWT — routes codex >= 0.129 to chatgpt.com",
		},
		{
			Name:        "CODEX_AGENT_IDENTITY",
			Value:       jwt,
			Description: "synthetic Agent Identity JWT — routes codex <= 0.128 to chatgpt.com",
		},
		{
			Name:        "CODEX_AGENT_IDENTITY_AUTHAPI_BASE_URL",
			Value:       "https://chatgpt.com/backend-api/wham",
			Description: "keeps agent-task registration on a host clawpatrol MITMs",
		},
	}
}

// OpenAICodexHTTPSEndpointRuntime is part of the clawpatrol plugin API.
type OpenAICodexHTTPSEndpointRuntime struct{}

// DetectPlaceholder mirrors the default https endpoint — agent
// placeholders show up in the Authorization header, possibly wrapped
// as `Bearer <PH>` or `AgentAssertion <PH>`.
func (OpenAICodexHTTPSEndpointRuntime) DetectPlaceholder(req *runtime.Request, candidates []string) string {
	if req == nil || req.Headers == nil {
		return ""
	}
	hay := req.Headers.Get("Authorization")
	for _, c := range candidates {
		if c != "" && strings.Contains(hay, c) {
			return c
		}
	}
	return ""
}

// RespondHTTP intercepts the two paths codex hits during Agent
// Identity load: the JWKS that validates the JWT we minted, and the
// agent-task registration POST that returns a task_id. Both are
// served from clawpatrol-controlled state — neither reaches real
// OpenAI. The JWKS is on chatgpt.com; the registration host moved to
// auth.openai.com in codex 0.142 (was chatgpt.com/backend-api/wham on
// <= 0.141), so the register matcher is deliberately host-agnostic and
// keys on the stable path shape. This is safe because this endpoint
// only owns chatgpt.com + auth.openai.com (see EndpointHosts); every
// other auth.openai.com path (codex login, token refresh) falls
// through to be forwarded untouched.
func (OpenAICodexHTTPSEndpointRuntime) RespondHTTP(_ context.Context, req *http.Request) (*http.Response, bool, error) {
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/backend-api/wham/agent-identities/jwks":
		body, err := codexJWKSResponse()
		if err != nil {
			return nil, false, err
		}
		return jsonResp(req, http.StatusOK, body), true, nil
	// Agent task-register for OUR synthetic identity only. The suffix
	// match covers both the <= 0.141 path
	// (/backend-api/wham/v1/agent/clawpatrol-codex/task/register) and the
	// 0.142+ path (/api/accounts/v1/agent/clawpatrol-codex/task/register)
	// while scoping to codexSyntheticRuntimeID — a real Agent Identity
	// (different runtime id) is forwarded upstream untouched, and
	// /v1/agent/register (agent bootstrap) never matches.
	case req.Method == http.MethodPost &&
		strings.HasSuffix(req.URL.Path, "/v1/agent/"+codexSyntheticRuntimeID+"/task/register"):
		return jsonResp(req, http.StatusOK, []byte(`{"task_id":"clawpatrol-task"}`)), true, nil
	}
	return nil, false, nil
}

func jsonResp(req *http.Request, status int, body []byte) *http.Response {
	resp := &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Cache-Control", "no-store")
	return resp
}

func init() {
	var _ runtime.PlaceholderDetector = OpenAICodexHTTPSEndpointRuntime{}
	var _ runtime.HTTPSyntheticResponder = OpenAICodexHTTPSEndpointRuntime{}
	config.Register(&config.Plugin{
		Kind:     config.KindEndpoint,
		Type:     "openai_codex_https",
		Family:   "http",
		New:      func() any { return &OpenAICodexHTTPSEndpoint{} },
		Runtime:  OpenAICodexHTTPSEndpointRuntime{},
		Validate: hostsValidate,
		Build:    passthroughBuild,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*OpenAICodexHTTPSEndpoint)
			b.SetAttributeValue("hosts", config.StringListVal(e.Hosts))
		},
	})
}

// ── Synthetic Agent Identity JWT + JWKS ──────────────────────────────
//
// Keys live in the host's BlobStore under
// (kind=CodexJWTKeysKind, name=""). The gateway process serves both
// the JWKS and the JWT mint path (clients fetch the minted JWT over
// /api/env-pushdown), so the keypair is gateway-internal.
//
// SetBlobStore plumbs the host's BlobStore into this package. The
// gateway wires it up once after OpenDB; tests substitute an
// in-memory fake. Mirrors the wireguard.go setDB/globalDB precedent
// for plugin code that needs gateway-side persistence without a
// circular import.

// CodexJWTKeysKind is the BlobStore namespace for the gateway's
// minted RSA + ed25519 Agent Identity JWT signing material.
// Exported so the gateway's legacy-state importer can address the
// row when migrating on-disk codex_jwt_keys.json into sqlite.
const CodexJWTKeysKind = "codex_jwt_keys"

var blobs runtime.BlobStore

// SetBlobStore is part of the clawpatrol plugin API.
func SetBlobStore(b runtime.BlobStore) { blobs = b }

// codexJWTKeys is the persisted keypair set. RSA signs the JWT
// envelope (codex enforces RS256). Ed25519 lives inside the JWT as
// `agent_private_key` — codex uses it to sign per-task AgentAssertion
// headers, but those headers get overwritten by the bound credential's
// InjectHTTP before they leave clawpatrol, so the key is effectively
// decorative. Persisted so the same JWT validates across CLI
// invocations.
type codexJWTKeys struct {
	KID                string `json:"kid"`
	RSAPrivatePKCS8B64 string `json:"rsa_private_pkcs8_b64"`
	Ed25519PKCS8B64    string `json:"ed25519_private_pkcs8_b64"`
}

var (
	codexKeysOnce sync.Once
	codexKeys     *codexJWTKeys
	codexKeysErr  error
)

func loadCodexJWTKeys() (*codexJWTKeys, error) {
	codexKeysOnce.Do(func() {
		codexKeys, codexKeysErr = loadOrGenerateCodexJWTKeys(blobs)
	})
	return codexKeys, codexKeysErr
}

func loadOrGenerateCodexJWTKeys(b runtime.BlobStore) (*codexJWTKeys, error) {
	if b == nil {
		return nil, fmt.Errorf("codex jwt keys: no blob store")
	}
	if data, found, err := b.Get(CodexJWTKeysKind, ""); err != nil {
		return nil, fmt.Errorf("codex jwt keys read: %w", err)
	} else if found {
		var k codexJWTKeys
		if err := json.Unmarshal(data, &k); err != nil {
			return nil, fmt.Errorf("parse codex jwt keys: %w", err)
		}
		if k.KID != "" && k.RSAPrivatePKCS8B64 != "" && k.Ed25519PKCS8B64 != "" {
			return &k, nil
		}
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, fmt.Errorf("marshal rsa pkcs8: %w", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		return nil, fmt.Errorf("marshal ed25519 pkcs8: %w", err)
	}

	// kid mirrors the production shape (sha256-- prefix + base64url of
	// the SPKI hash) so anything that greps for it sees a familiar
	// pattern in logs.
	spki, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal rsa spki: %w", err)
	}
	sum := sha256.Sum256(spki)

	k := &codexJWTKeys{
		KID:                "sha256--" + base64.RawURLEncoding.EncodeToString(sum[:]),
		RSAPrivatePKCS8B64: base64.StdEncoding.EncodeToString(rsaDER),
		Ed25519PKCS8B64:    base64.StdEncoding.EncodeToString(edDER),
	}
	out, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal keys: %w", err)
	}
	if err := b.Put(CodexJWTKeysKind, "", out); err != nil {
		return nil, fmt.Errorf("write codex jwt keys: %w", err)
	}
	return k, nil
}

func (k *codexJWTKeys) rsaPrivate() (*rsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(k.RSAPrivatePKCS8B64)
	if err != nil {
		return nil, fmt.Errorf("decode rsa b64: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse rsa pkcs8: %w", err)
	}
	rk, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("rsa key is %T not *rsa.PrivateKey", parsed)
	}
	return rk, nil
}

// mintCodexAccessToken returns a fresh RS256-signed Agent Identity JWT
// suitable for CODEX_ACCESS_TOKEN. The exp claim is set ten years out
// — codex only checks `exp > now` and we never use refresh.
func mintCodexAccessToken() (string, error) {
	k, err := loadCodexJWTKeys()
	if err != nil {
		return "", err
	}
	rsaKey, err := k.rsaPrivate()
	if err != nil {
		return "", err
	}

	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": k.KID}
	now := time.Now().Unix()
	// Issuer / audience are enforced by codex's
	// decode_agent_identity_jwt — see codex-rs/agent-identity/src/lib.rs.
	claims := map[string]any{
		"iss":                        "https://chatgpt.com/codex-backend/agent-identity",
		"aud":                        "codex-app-server",
		"iat":                        now,
		"exp":                        now + int64(10*365*24*60*60),
		"agent_runtime_id":           codexSyntheticRuntimeID,
		"agent_private_key":          k.Ed25519PKCS8B64,
		"account_id":                 "clawpatrol",
		"chatgpt_user_id":            "clawpatrol",
		"email":                      "clawpatrol@local",
		"plan_type":                  "pro",
		"chatgpt_account_is_fedramp": false,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// codexJWKSResponse returns the JSON bytes of a single-key JWKS that
// matches the kid in the JWT mintCodexAccessToken returns.
func codexJWKSResponse() ([]byte, error) {
	k, err := loadCodexJWTKeys()
	if err != nil {
		return nil, err
	}
	rsaKey, err := k.rsaPrivate()
	if err != nil {
		return nil, err
	}
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	type jwks struct {
		Keys []jwk `json:"keys"`
	}
	pub := rsaKey.PublicKey
	return json.MarshalIndent(jwks{Keys: []jwk{{
		Kty: "RSA", Kid: k.KID, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}, "", "  ")
}
