package main

import (
	"bytes"
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

	"github.com/denoland/clawpatrol/config/runtime"
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
	// Try every (slack_tokens credential, profile) signing_secret —
	// secrets are per-profile in the dashboard, but Slack doesn't
	// know which profile a click came from. First match wins.
	verified := false
	profiles := []string{""}
	for name := range policy.Profiles {
		profiles = append(profiles, name)
	}
outer:
	for name, ent := range policy.Credentials {
		if ent.Plugin.Type != "slack_tokens" {
			continue
		}
		for _, prof := range profiles {
			sec, err := w.g.secrets.Get(name, prof)
			if err != nil {
				continue
			}
			signingSecret := sec.Extras["signing_secret"]
			if signingSecret == "" {
				continue
			}
			if verifySlackSig(signingSecret, ts, body, sig) {
				verified = true
				break outer
			}
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
	resp := applySlackInteractivePayload(w.g, []byte(payload))
	writeJSON(rw, resp)
}

// applySlackInteractivePayload parses one Slack block_actions payload,
// resolves the matching pending HITL entry, and POSTs an updated
// message back to Slack's response_url so the buttons disappear and
// a verdict line appears — instant in-place update.
//
// Returns an empty ack map; Slack requires HTTP 200 within 3s and the
// real message swap happens via response_url (not the immediate body —
// that path doesn't work for block_actions per Slack docs).
func applySlackInteractivePayload(g *Gateway, payload []byte) map[string]any {
	var p struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
		ResponseURL string `json:"response_url"`
		Actions     []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
		Message struct {
			Blocks []map[string]any `json:"blocks"`
		} `json:"message"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return map[string]any{"text": "couldn't parse payload: " + err.Error()}
	}
	if len(p.Actions) == 0 {
		return map[string]any{"text": "no actions"}
	}
	act := p.Actions[0]
	if act.Value == "" {
		return map[string]any{"text": "missing pending id"}
	}
	allow := act.ActionID == "approve"
	ok := g.hitl.Decide(act.Value, runtime.HITLDecision{Allow: allow, By: "slack:" + p.User.Name})

	var status string
	if !ok {
		status = "Already resolved or expired."
	} else {
		verb := "approved"
		emoji := ":white_check_mark:"
		if !allow {
			verb = "denied"
			emoji = ":no_entry:"
		}
		log.Printf("slack-interactive: %s %s by %s", act.Value, verb, p.User.Name)
		status = fmt.Sprintf("%s %s by <@%s>", emoji, verb, p.User.Name)
	}

	if p.ResponseURL != "" {
		go postSlackResponseURL(p.ResponseURL, status, withStatusBlock(p.Message.Blocks, status))
	}
	return map[string]any{} // empty ack — real update flows via response_url
}

// postSlackResponseURL fires the message-replace POST. Slack accepts
// JSON with {replace_original: true, text, blocks} on the response_url
// for up to 30 minutes / 5 calls per interactive event.
func postSlackResponseURL(url, text string, blocks []map[string]any) {
	body := map[string]any{
		"replace_original": true,
		"text":             text,
		"blocks":           blocks,
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(buf))
	if err != nil {
		log.Printf("slack response_url: build: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("slack response_url: post: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("slack response_url: status=%d", resp.StatusCode)
	}
}

// withStatusBlock returns the original message blocks minus any
// `actions` block, plus a context block carrying the verdict.
// Slack `replace_original` swaps the message in place — operator
// sees the buttons disappear and the verdict line appear instantly.
func withStatusBlock(blocks []map[string]any, status string) []map[string]any {
	out := make([]map[string]any, 0, len(blocks)+1)
	for _, b := range blocks {
		if b["type"] == "actions" {
			continue
		}
		out = append(out, b)
	}
	out = append(out, map[string]any{
		"type":     "context",
		"elements": []map[string]any{{"type": "mrkdwn", "text": status}},
	})
	return out
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
