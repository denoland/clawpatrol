package credentials

// slack_tokens: bot + app token pair plus the optional signing
// secret. Implements:
//
//   - HTTPCredentialRuntime — pick the right token per Slack endpoint
//     and stamp Authorization: Bearer.
//   - HITLNotifier          — post Block Kit approval prompts to a
//     channel; powers the human_approver plugin without approvers
//     having to know anything Slack-specific.
//   - WebhookProvider       — handle Slack's interactive (button-click)
//     callback. Mounted by main at /api/cred/<credName>/interactive.
//
// Adding another notification channel (Discord, Telegram, SMTP) is a
// new credential plugin with its own NotifyHITL — no human_approver /
// runtime.go changes.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// SlackTokens is part of the clawpatrol plugin API.
type SlackTokens struct{}

// InjectHTTP defaults to the bot token (xoxb-…) for chat.postMessage
// etc. Slack admin endpoints (auth.test, admin.*, apps.*) prefer the
// app token; if the operator declared one, use it for those paths.
// Falls back to bot when only one slot is filled.
func (s *SlackTokens) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	bot := sec.Extras["bot"]
	app := sec.Extras["app"]
	pick := bot
	if app != "" && slackPathPrefersApp(req.URL.Path) {
		pick = app
	}
	if pick == "" && len(sec.Bytes) > 0 {
		pick = string(sec.Bytes)
	}
	if pick == "" {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+pick)
	// Slack's legacy SDKs send `token=<value>` in the form body alongside
	// the Authorization header. If the body token is a placeholder it
	// reaches Slack unsubstituted and causes invalid_auth. Strip it so
	// Slack uses only the Authorization header we just set.
	if strings.Contains(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") && req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err == nil {
			vals, err := url.ParseQuery(string(raw))
			if err == nil && vals.Get("token") != "" {
				vals.Del("token")
				encoded := vals.Encode()
				req.Body = io.NopCloser(strings.NewReader(encoded))
				req.ContentLength = int64(len(encoded))
			} else {
				req.Body = io.NopCloser(bytes.NewReader(raw))
			}
		}
	}
	return nil
}

func slackPathPrefersApp(path string) bool {
	for _, p := range []string{"/api/admin.", "/api/apps.", "/api/auth.test"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// SecretSlots is part of the clawpatrol plugin API.
func (*SlackTokens) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "bot", Label: "Bot token", Description: "xoxb-…"},
		{Name: "app", Label: "App-level token (optional)", Description: "xapp-…"},
		{Name: "signing_secret", Label: "Signing secret", Description: "Slack app's signing secret — required for interactive approve/deny buttons"},
	}
}

// NotifyHITL posts a Block Kit approval prompt to the operator's
// Slack channel. Bot token comes from the credential's `bot` slot
// (or Bytes for single-slot setups), fetched via the request's
// SecretStore so dashboard rotations apply per-call.
//
// When target.Interactive is true, the message includes Approve /
// Deny buttons resolved by the gateway's /api/slack/interactive
// HTTP handler. Otherwise, only an "Open dashboard" link.
func (s *SlackTokens) NotifyHITL(_ context.Context, req runtime.ApproveRequest, target runtime.HITLTarget) error {
	if req.Secrets == nil {
		return fmt.Errorf("no secret store on request")
	}
	sec, err := req.Secrets.Get(target.CredentialName)
	if err != nil {
		return fmt.Errorf("fetch credential %s: %w", target.CredentialName, err)
	}
	bot := sec.Extras["bot"]
	if bot == "" && len(sec.Bytes) > 0 {
		bot = string(sec.Bytes)
	}
	if bot == "" {
		return fmt.Errorf("credential %s has no bot token (paste via dashboard)", target.CredentialName)
	}
	link := strings.TrimRight(target.DashboardURL, "/") + "/#hitl/" + target.PendingID

	endpoint := runtime.HITLEndpointLabel(req)
	queryLabel := runtime.HITLQueryLabel(req.Endpoint)

	title := slackTrunc(runtime.HITLTitle(req.Method, endpoint), 140)
	var blocks []map[string]any
	if s := target.Summary; s != nil {
		headerText := s.TicketID
		if headerText == "" {
			headerText = title
		}
		emoji := hitlClassificationEmoji(s.Classification)
		classLine := emoji + " " + s.Classification
		if s.Confidence > 0 {
			classLine += fmt.Sprintf(" (%d%%)", s.Confidence)
		}
		sectionText := "*Classification:* " + classLine + "\n*Summary:* " + slackTrunc(s.Text, 500)
		blocks = []map[string]any{
			{"type": "header", "text": map[string]any{"type": "plain_text", "text": slackTrunc(headerText, 140)}},
			{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": sectionText}},
		}
	} else {
		blocks = []map[string]any{
			{"type": "header", "text": map[string]any{"type": "plain_text", "text": title}},
			{"type": "section", "text": map[string]any{
				"type": "mrkdwn",
				"text": "*" + queryLabel + "*\n```" + slackTrunc(req.Path, 800) + "```",
			}},
		}
	}
	ctx := []map[string]any{}
	if req.AgentIP != "" {
		ctx = append(ctx, map[string]any{
			"type": "mrkdwn",
			"text": "agent `" + req.AgentIP + "`",
		})
	}
	if r := strings.TrimSpace(req.Reason); r != "" {
		ctx = append(ctx, map[string]any{
			"type": "mrkdwn",
			"text": "reason: " + slackTrunc(r, 200),
		})
	}
	if len(ctx) > 0 {
		blocks = append(blocks, map[string]any{
			"type":     "context",
			"elements": ctx,
		})
	}
	if bs := strings.TrimSpace(req.BodySample); bs != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": "*Body*\n```" + slackTrunc(bs, 1000) + "```"},
		})
	}
	if target.Interactive {
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []map[string]any{
				{
					"type":      "button",
					"text":      map[string]any{"type": "plain_text", "text": "Approve"},
					"action_id": "approve",
					"value":     target.PendingID,
					"style":     "primary",
				},
				{
					"type":      "button",
					"text":      map[string]any{"type": "plain_text", "text": "Deny"},
					"action_id": "deny",
					"value":     target.PendingID,
					"style":     "danger",
				},
			},
		})
	} else {
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []map[string]any{
				{
					"type":  "button",
					"text":  map[string]any{"type": "plain_text", "text": "Open dashboard"},
					"url":   link,
					"style": "primary",
				},
			},
		})
	}

	body := map[string]any{
		"channel": target.Channel,
		"text":    "clawpatrol: " + title,
		"blocks":  blocks,
	}
	if target.ThreadTS != "" {
		body["thread_ts"] = target.ThreadTS
	}
	buf, _ := json.Marshal(body)
	hreq, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	hreq.Header.Set("Authorization", "Bearer "+bot)
	hreq.Header.Set("Content-Type", "application/json; charset=utf-8")

	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(hreq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(respBody, &result)
	if resp.StatusCode >= 400 || !result.OK {
		log.Printf("slack notify %s: chat.postMessage failed: status=%d ok=%v error=%q",
			req.ApproverName, resp.StatusCode, result.OK, result.Error)
		return fmt.Errorf("slack chat.postMessage error: %s", result.Error)
	}
	return nil
}

func hitlClassificationEmoji(c string) string {
	switch strings.ToLower(c) {
	case "spam":
		return ":no_entry_sign:"
	case "legit", "legitimate":
		return ":white_check_mark:"
	default:
		return ":question:"
	}
}

func slackTrunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// WebhookRoutes returns Slack's interactive callback handler. main
// mounts it at /api/cred/<credName>/interactive — operator pastes
// that URL into the Slack app's "Interactivity & Shortcuts" config.
// Public path (no dashboard secret gate); Slack auths via signature
// header verified per-request.
func (*SlackTokens) WebhookRoutes() []runtime.WebhookRoute {
	return []runtime.WebhookRoute{
		{Path: "/interactive", Handler: slackInteractive},
	}
}

// slackInteractive handles Slack's interactive payload POSTs — the
// approve/deny button clicks coming from the chat.postMessage Block
// Kit messages NotifyHITL sent earlier. Verifies the v0 HMAC-SHA256
// signature against the credential's signing_secret slot, parses the
// payload, and decides the matching pending HITL entry.
func slackInteractive(ctx runtime.WebhookCtx, rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
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
		http.Error(rw, "missing slack signature headers", http.StatusUnauthorized)
		return
	}
	// Replay protection: timestamp within 5 minutes.
	if tsi, _ := strconv.ParseInt(ts, 10, 64); tsi == 0 || time.Since(time.Unix(tsi, 0)) > 5*time.Minute {
		http.Error(rw, "stale slack signature", http.StatusUnauthorized)
		return
	}

	verified := false
	sec, secErr := ctx.Secrets.Get(ctx.CredentialName)
	if secErr == nil {
		signingSecret := sec.Extras["signing_secret"]
		if signingSecret != "" && verifySlackSig(signingSecret, ts, body, sig) {
			verified = true
		}
	}
	if !verified {
		http.Error(rw, "slack signature verification failed", http.StatusUnauthorized)
		return
	}

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
	resp := applySlackInteractivePayload(ctx, []byte(payload))
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(resp)
}

// applySlackInteractivePayload parses one Slack block_actions payload,
// resolves the matching pending HITL entry, and POSTs an updated
// message back to Slack's response_url so the buttons disappear and
// a verdict line appears — instant in-place update.
//
// Returns an empty ack map; Slack requires HTTP 200 within 3s and the
// real message swap happens via response_url (not the immediate body —
// that path doesn't work for block_actions per Slack docs).
func applySlackInteractivePayload(ctx runtime.WebhookCtx, payload []byte) map[string]any {
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
	ok := ctx.HITL.Decide(act.Value, runtime.HITLDecision{Allow: allow, By: "slack:" + p.User.Name})

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
	defer func() { _ = resp.Body.Close() }()
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

// parseSlackForm parses Slack's `payload=<json>` form body. Single
// key with URL-encoded value.
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

func init() {
	var (
		_ runtime.HTTPCredentialRuntime = (*SlackTokens)(nil)
		_ runtime.HITLNotifier          = (*SlackTokens)(nil)
		_ runtime.WebhookProvider       = (*SlackTokens)(nil)
	)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "slack_tokens",
		New:     newer[SlackTokens](),
		Runtime: (*SlackTokens)(nil),
		Build:   passthrough,
		Emit:    emptyEmit,
	})
}
