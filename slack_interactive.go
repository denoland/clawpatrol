package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol-go/config/runtime"
)

// apiSlackInteractive handles Slack's interactive payload POSTs —
// the approve/deny button clicks coming from the chat.postMessage
// Block Kit messages the slack approver runtime sent earlier.
//
// Slack signs every interactive callback with the app's Signing
// Secret; we verify before honoring the action. Walks every loaded
// slack_tokens credential and tries each one's signing_secret slot —
// the first that verifies wins. Operators with one Slack app have
// one credential; multi-app deployments work without per-credential
// URLs.
//
// Public path (no dashboard secret gate) — Slack POSTs from its own
// IPs and we don't get to authenticate the channel any other way.
func (w *webMux) apiSlackInteractive(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", 405)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	ts := r.Header.Get("X-Slack-Request-Timestamp")
	sig := r.Header.Get("X-Slack-Signature")
	if ts == "" || sig == "" {
		http.Error(rw, "missing slack signature headers", 401)
		return
	}
	// Replay protection: timestamp within 5 minutes.
	if tsi, _ := strconv.ParseInt(ts, 10, 64); tsi == 0 || time.Since(time.Unix(tsi, 0)) > 5*time.Minute {
		http.Error(rw, "stale slack signature", 401)
		return
	}

	policy := w.g.Policy()
	if policy == nil {
		http.Error(rw, "no policy loaded", 500)
		return
	}
	verified := false
	for name, ent := range policy.Credentials {
		if ent.Plugin.Type != "slack_tokens" {
			continue
		}
		sec, err := w.g.secrets.Get(name, "")
		if err != nil {
			continue
		}
		signingSecret := sec.Extras["signing_secret"]
		if signingSecret == "" {
			continue
		}
		if verifySlackSig(signingSecret, ts, body, sig) {
			verified = true
			break
		}
	}
	if !verified {
		http.Error(rw, "slack signature verification failed", 401)
		return
	}

	// Slack posts payload= as a form-encoded field. The value is JSON.
	form, err := parseSlackForm(body)
	if err != nil {
		http.Error(rw, "parse: "+err.Error(), 400)
		return
	}
	payload := form["payload"]
	if payload == "" {
		http.Error(rw, "no payload", 400)
		return
	}
	var p struct {
		Type string `json:"type"`
		User struct {
			Name string `json:"name"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	}
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		http.Error(rw, "json: "+err.Error(), 400)
		return
	}
	if len(p.Actions) == 0 {
		http.Error(rw, "no actions", 400)
		return
	}
	act := p.Actions[0]
	if act.Value == "" {
		http.Error(rw, "missing pending id", 400)
		return
	}
	allow := act.ActionID == "approve"
	by := "slack:" + p.User.Name
	ok := w.g.hitl.Decide(act.Value, runtime.HITLDecision{Allow: allow, By: by})
	if !ok {
		// Already decided / expired.
		writeJSON(rw, map[string]string{"text": "Already resolved or expired."})
		return
	}
	verb := "approved"
	if !allow {
		verb = "denied"
	}
	writeJSON(rw, map[string]string{"text": fmt.Sprintf("Request %s by %s.", verb, p.User.Name)})
	log.Printf("slack-interactive: %s %s by %s", act.Value, verb, p.User.Name)
}

// verifySlackSig checks Slack's v0 HMAC-SHA256 signature.
//
//	basestring := "v0:" + ts + ":" + body
//	expected   := "v0=" + hex(HMAC-SHA256(signing_secret, basestring))
func verifySlackSig(signingSecret, ts string, body []byte, got string) bool {
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte("v0:"))
	mac.Write([]byte(ts))
	mac.Write([]byte(":"))
	mac.Write(body)
	want := "v0=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(got))
}

// parseSlackForm parses Slack's `payload=<json>` form body without
// pulling net/url's full form decoder (avoids surprises with body
// re-reads). Single key with URL-encoded value.
func parseSlackForm(body []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range strings.Split(string(body), "&") {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		k := kv[:eq]
		v := kv[eq+1:]
		dec, err := slackFormDecode(v)
		if err != nil {
			return nil, err
		}
		out[k] = dec
	}
	return out, nil
}

// slackFormDecode is x-www-form-urlencoded decode for one value:
// '+' → space, %xx → byte.
func slackFormDecode(s string) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '+':
			sb.WriteByte(' ')
		case '%':
			if i+2 >= len(s) {
				return "", fmt.Errorf("truncated %% escape")
			}
			b, err := hex.DecodeString(s[i+1 : i+3])
			if err != nil {
				return "", err
			}
			sb.WriteByte(b[0])
			i += 2
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String(), nil
}
