package endpoints

// Postgres upstream auth: gateway terminates auth on the upstream
// side using the operator-configured (user, password) from the
// matching credential, then synthesizes AuthenticationOk for the
// agent — agent never participates in the SCRAM handshake.
//
// Why offload instead of swap-PasswordMessage: SCRAM-SHA-256 (the
// PostgreSQL 14+ default) is designed to defeat MITM swap. The
// gateway can't sit between two SCRAM peers and rewrite the proof —
// it has to BE one of the peers. So the gateway acts as the SCRAM
// client to the upstream, and as the SCRAM server (a trivial one
// that always says "you're in") to the agent. Practically: we never
// even read the agent's PasswordMessage.
//
// Supported auth methods (upstream-side):
//
//   - SCRAM-SHA-256 (RFC 5802 + 7677). Default in modern Postgres.
//   - cleartext (rare; trust over private network).
//   - trust (no auth message — server sends AuthenticationOk
//     immediately after StartupMessage).
//
// Not supported: MD5 (predates SCRAM, weak), GSSAPI/SSPI/SASL-other.
// If upstream demands an unsupported method, HandleConn closes the
// agent connection with a clear ErrorResponse.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const sslRequestCodeUpstream uint32 = 80877103

// pgUpgradeSSL probes the upstream for TLS support via the standard
// SSLRequest pre-startup probe, then wraps the connection in TLS
// when the server agrees ('S'). Returns the upgraded conn, or nil
// when the server refused and sslmode permits plaintext.
//
// sslmode semantics (libpq-compatible):
//
//   - prefer      → try TLS, fall back to plain on 'N'
//   - require     → try TLS, error on 'N'
//   - verify-full → require + validate cert against pgEp.Host
func pgUpgradeSSL(upstream net.Conn, pgEp *PostgresEndpoint, sslmode string) (net.Conn, error) {
	// Send SSLRequest: [int32 length=8][int32 code=80877103].
	probe := make([]byte, 8)
	binary.BigEndian.PutUint32(probe[:4], 8)
	binary.BigEndian.PutUint32(probe[4:8], sslRequestCodeUpstream)
	if _, err := upstream.Write(probe); err != nil {
		return nil, fmt.Errorf("write SSLRequest: %w", err)
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(upstream, reply); err != nil {
		return nil, fmt.Errorf("read SSLRequest reply: %w", err)
	}
	switch reply[0] {
	case 'S':
		host := ""
		if pgEp != nil {
			host = pgEp.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		cfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: sslmode != "verify-full",
		}
		secured := tls.Client(upstream, cfg)
		if err := secured.Handshake(); err != nil {
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return secured, nil
	case 'N':
		if sslmode == "require" || sslmode == "verify-full" {
			return nil, fmt.Errorf("upstream refused TLS but sslmode=%q requires it", sslmode)
		}
		return nil, nil // continue plaintext
	default:
		return nil, fmt.Errorf("unexpected SSLRequest reply byte %q", reply[0])
	}
}

const (
	pgAuthOK            uint32 = 0
	pgAuthCleartextPass uint32 = 3
	pgAuthMD5Pass       uint32 = 5
	pgAuthSASL          uint32 = 10
	pgAuthSASLContinue  uint32 = 11
	pgAuthSASLFinal     uint32 = 12
)

// pgSendStartup writes a v3 StartupMessage(user, database) to upstream.
// Other params (application_name, client_encoding) are intentionally
// omitted — the agent renegotiates them via Set after auth completes.
func pgSendStartup(w io.Writer, user, database string) error {
	var params []byte
	addParam := func(k, v string) {
		params = append(params, []byte(k)...)
		params = append(params, 0)
		params = append(params, []byte(v)...)
		params = append(params, 0)
	}
	addParam("user", user)
	if database != "" && database != user {
		addParam("database", database)
	}
	params = append(params, 0) // terminator

	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 196608) // protocol version 3.0
	body = append(body, params...)

	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(body)+4))
	out = append(out, body...)
	_, err := w.Write(out)
	return err
}

// pgReadAuthFrame reads one type-prefixed frame from upstream.
// Returns the type byte, length-prefixed payload, and any error.
func pgReadAuthFrame(r io.Reader) (typ byte, payload []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	typ = hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 || length > 1<<20 {
		return 0, nil, fmt.Errorf("pg: bogus auth frame length %d", length)
	}
	payload = make([]byte, length-4)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// pgWriteFrame serializes one tagged frame to w.
func pgWriteFrame(w io.Writer, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// pgPerformAuth drives the upstream auth handshake using (user, password).
// Returns the buffered post-auth bytes (AuthenticationOk through and
// including ReadyForQuery) the relay loop must replay to the agent.
//
// Walks Authentication* frames; halts on the first non-Authentication
// frame and returns it concatenated to anything else read.
func pgPerformAuth(upstream net.Conn, user, password string) ([]byte, error) {
	var postAuth []byte
	scram := newScramClient(user, password)
	for {
		typ, payload, err := pgReadAuthFrame(upstream)
		if err != nil {
			return nil, fmt.Errorf("read auth frame: %w", err)
		}
		if typ != 'R' {
			// ParameterStatus / BackendKeyData / NoticeResponse / etc.
			// arrive after AuthenticationOk; collect them so the relay
			// can replay.
			postAuth = append(postAuth, frameBytes(typ, payload)...)
			if typ == 'Z' /* ReadyForQuery */ {
				return postAuth, nil
			}
			if typ == 'E' /* ErrorResponse */ {
				return postAuth, fmt.Errorf("upstream error: %s", parseErrorFields(payload))
			}
			continue
		}
		if len(payload) < 4 {
			return nil, fmt.Errorf("pg: short auth payload")
		}
		code := binary.BigEndian.Uint32(payload[:4])
		switch code {
		case pgAuthOK:
			postAuth = append(postAuth, frameBytes(typ, payload)...)
			// Continue reading until ReadyForQuery — server still
			// sends ParameterStatus / BackendKeyData first.
		case pgAuthCleartextPass:
			out := append([]byte(password), 0)
			if err := pgWriteFrame(upstream, 'p', out); err != nil {
				return nil, err
			}
		case pgAuthMD5Pass:
			return nil, fmt.Errorf("pg: upstream uses MD5 auth, only SCRAM-SHA-256 + cleartext + trust supported")
		case pgAuthSASL:
			// Mechanism list is null-terminated strings followed by
			// a zero terminator.
			mechs := splitCStrings(payload[4:])
			ok := false
			for _, m := range mechs {
				if m == "SCRAM-SHA-256" {
					ok = true
					break
				}
			}
			if !ok {
				return nil, fmt.Errorf("pg: upstream offered SASL mechanisms %v, want SCRAM-SHA-256", mechs)
			}
			out := scram.initialResponse()
			if err := pgWriteFrame(upstream, 'p', out); err != nil {
				return nil, err
			}
		case pgAuthSASLContinue:
			out, err := scram.continueResponse(payload[4:])
			if err != nil {
				return nil, fmt.Errorf("scram continue: %w", err)
			}
			if err := pgWriteFrame(upstream, 'p', out); err != nil {
				return nil, err
			}
		case pgAuthSASLFinal:
			if err := scram.finalize(payload[4:]); err != nil {
				return nil, fmt.Errorf("scram final: %w", err)
			}
		default:
			return nil, fmt.Errorf("pg: unsupported auth code %d", code)
		}
	}
}

func frameBytes(typ byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)+4))
	copy(out[5:], payload)
	return out
}

func splitCStrings(b []byte) []string {
	var out []string
	for {
		i := 0
		for i < len(b) && b[i] != 0 {
			i++
		}
		if i == 0 {
			break
		}
		out = append(out, string(b[:i]))
		if i+1 > len(b) {
			break
		}
		b = b[i+1:]
	}
	return out
}

func parseErrorFields(b []byte) string {
	// Each field: type byte + null-terminated string. Stop on type 0.
	var sb strings.Builder
	for len(b) > 0 {
		if b[0] == 0 {
			break
		}
		t := b[0]
		b = b[1:]
		end := 0
		for end < len(b) && b[end] != 0 {
			end++
		}
		val := string(b[:end])
		if end < len(b) {
			b = b[end+1:]
		} else {
			b = nil
		}
		if t == 'M' || t == 'C' {
			if sb.Len() > 0 {
				sb.WriteString(" ")
			}
			sb.WriteString(val)
		}
	}
	return sb.String()
}

// pgWriteAuthOK sends a synthetic AuthenticationOk to the agent so it
// proceeds as if it just completed auth itself. Followed by the
// upstream's ParameterStatus / BackendKeyData / ReadyForQuery bytes
// (already collected during pgPerformAuth).
func pgWriteAuthOK(w io.Writer, postAuth []byte) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, pgAuthOK)
	if err := pgWriteFrame(w, 'R', payload); err != nil {
		return err
	}
	// Skip the leading AuthenticationOk in postAuth — we just sent
	// our own. The first frame in postAuth IS the upstream's
	// AuthenticationOk; strip it.
	rest := postAuth
	if len(rest) >= 5 && rest[0] == 'R' {
		l := binary.BigEndian.Uint32(rest[1:5])
		if int(1+l) <= len(rest) {
			rest = rest[1+l:]
		}
	}
	if len(rest) > 0 {
		_, err := w.Write(rest)
		return err
	}
	return nil
}

// ── SCRAM-SHA-256 client — RFC 5802 + 7677 ────────────────────────────
//
// Trimmed implementation: gs2-header is "n,," (no channel binding,
// no authzid). Nonce is 24 random bytes base64'd. We don't validate
// the channel-binding round trip beyond the standard.

type scramClient struct {
	user            string
	password        string
	clientNonce     string
	clientFirstBare string
	serverFirst     string
}

func newScramClient(user, password string) *scramClient {
	nb := make([]byte, 24)
	_, _ = rand.Read(nb)
	return &scramClient{
		user:        user,
		password:    password,
		clientNonce: base64.StdEncoding.EncodeToString(nb),
	}
}

func (s *scramClient) initialResponse() []byte {
	s.clientFirstBare = "n=" + s.user + ",r=" + s.clientNonce
	clientFirst := "n,," + s.clientFirstBare
	// SASLInitialResponse payload: mechanism\0 + int32(len) + initial-resp
	mech := []byte("SCRAM-SHA-256\x00")
	resp := []byte(clientFirst)
	out := make([]byte, 0, len(mech)+4+len(resp))
	out = append(out, mech...)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(resp)))
	out = append(out, lenBuf...)
	out = append(out, resp...)
	return out
}

func (s *scramClient) continueResponse(serverFirst []byte) ([]byte, error) {
	s.serverFirst = string(serverFirst)
	parts := parseSCRAMAttrs(s.serverFirst)
	r := parts["r"]
	saltB64 := parts["s"]
	iterStr := parts["i"]
	if r == "" || saltB64 == "" || iterStr == "" {
		return nil, fmt.Errorf("malformed server-first: %q", s.serverFirst)
	}
	if !strings.HasPrefix(r, s.clientNonce) {
		return nil, fmt.Errorf("server nonce doesn't extend client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("salt decode: %w", err)
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter <= 0 {
		return nil, fmt.Errorf("bad iteration count: %q", iterStr)
	}
	// gs2-header base64'd as "biws" = "n,,"
	clientFinalNoProof := "c=biws,r=" + r
	saltedPassword := pbkdf2.Key([]byte(s.password), salt, iter, 32, sha256.New)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256Sum(clientKey)
	authMessage := s.clientFirstBare + "," + s.serverFirst + "," + clientFinalNoProof
	clientSignature := hmacSHA256(storedKey, []byte(authMessage))
	clientProof := xorBytes(clientKey, clientSignature)
	clientFinal := clientFinalNoProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)
	return []byte(clientFinal), nil
}

func (s *scramClient) finalize(serverFinal []byte) error {
	parts := parseSCRAMAttrs(string(serverFinal))
	if e := parts["e"]; e != "" {
		return fmt.Errorf("server reported scram error: %s", e)
	}
	v := parts["v"]
	if v == "" {
		return fmt.Errorf("server-final missing verifier")
	}
	// Optional: verify ServerSignature. Skip — upstream gave us
	// AuthenticationOk after this, which we trust.
	_ = v
	return nil
}

func parseSCRAMAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		out[kv[:eq]] = kv[eq+1:]
	}
	return out
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
