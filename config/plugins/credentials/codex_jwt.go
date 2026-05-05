package credentials

// Synthetic Agent Identity for codex subscription users. We mint a JWT
// that codex's CODEX_ACCESS_TOKEN env path validates against a JWKS we
// serve via MITM at chatgpt.com/backend-api/wham/agent-identities/jwks.
// That swaps codex into AgentIdentity auth mode, which routes requests
// to chatgpt.com/backend-api/codex/responses where the existing
// openai_codex_oauth credential plugin overwrites Authorization +
// chatgpt-account-id with the real subscription bearer.
//
// Keys live as a JSON file in the user's clawpatrol dir (same dir
// `clawpatrol login` writes ca.crt to). Both the gateway process
// (which serves the JWKS) and the `clawpatrol env` CLI (which mints
// the JWT) read from the same path so the JWT's kid resolves against
// what the gateway exposes.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// codexJWTKeysFile is the on-disk file holding the RSA + ed25519 keys
// used to mint and verify the synthetic Agent Identity JWT.
const codexJWTKeysFile = "codex_jwt_keys.json"

// codexJWTKeys is the persisted keypair set. RSA signs the JWT
// envelope (codex enforces RS256). Ed25519 lives inside the JWT as
// `agent_private_key` — codex would use it to sign per-task
// AgentAssertion headers, but those headers get overwritten by the
// credential injector before they leave clawpatrol, so the key is
// effectively decorative. We persist it so the same JWT validates
// across CLI invocations.
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

// CodexJWTKeys returns the persisted keypair set, generating it on
// first call if the keys file doesn't exist. Result is cached for the
// process lifetime.
func CodexJWTKeys() (*codexJWTKeys, error) {
	codexKeysOnce.Do(func() {
		codexKeys, codexKeysErr = loadOrGenerateCodexJWTKeys(codexJWTKeysPath())
	})
	return codexKeys, codexKeysErr
}

// codexJWTKeysPath mirrors the main package's defaultClawpatrolDir
// (see login.go). Replicating the logic here avoids a dependency
// inversion — credential plugins live below the main package.
func codexJWTKeysPath() string {
	if d := os.Getenv("CLAWPATROL_DIR"); d != "" {
		return filepath.Join(d, codexJWTKeysFile)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".clawpatrol", codexJWTKeysFile)
}

func loadOrGenerateCodexJWTKeys(path string) (*codexJWTKeys, error) {
	if b, err := os.ReadFile(path); err == nil {
		var k codexJWTKeys
		if err := json.Unmarshal(b, &k); err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
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
	// the SPKI hash) so anything that grepss for it sees a familiar
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	out, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal keys: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
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

// MintCodexAccessToken returns a fresh RS256-signed Agent Identity JWT
// suitable for CODEX_ACCESS_TOKEN. The exp claim is set ten years out
// — codex only checks `exp > now` and we never use refresh.
func MintCodexAccessToken() (string, error) {
	k, err := CodexJWTKeys()
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
		"agent_runtime_id":           "clawpatrol-codex",
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

// CodexJWKSResponse returns the JSON bytes of a single-key JWKS that
// matches the kid in the JWT MintCodexAccessToken returns.
func CodexJWKSResponse() ([]byte, error) {
	k, err := CodexJWTKeys()
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
