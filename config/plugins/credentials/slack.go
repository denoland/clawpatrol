package credentials

// slack_tokens: bot + app token pair plus the optional signing
// secret. Implements:
//
//   - HTTPCredentialRuntime — pick the right token per Slack endpoint
//     and stamp Authorization: Bearer.
//   - HITLNotifier          — post Block Kit approval prompts to a
//     channel; powers the human_approver plugin without approvers
//     having to know anything Slack-specific.
//
// Adding another notification channel (Discord, Telegram, SMTP) is a
// new credential plugin with its own NotifyHITL — no human_approver /
// runtime.go changes.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

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
	sec, err := req.Secrets.Get(target.CredentialName, req.Profile)
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

	title := fmt.Sprintf("Approve: %s %s%s", req.Method, req.Host, slackTrunc(req.Path, 60))
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": title}},
		{"type": "section", "fields": []map[string]any{
			{"type": "mrkdwn", "text": "*Method*\n`" + req.Method + "`"},
			{"type": "mrkdwn", "text": "*Host*\n`" + req.Host + "`"},
			{"type": "mrkdwn", "text": "*Path*\n`" + slackTrunc(req.Path, 80) + "`"},
			{"type": "mrkdwn", "text": "*Agent*\n`" + req.Profile + "`"},
		}},
	}
	if r := strings.TrimSpace(req.Reason); r != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": "*Reason*\n" + r},
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
		"text":    fmt.Sprintf("clawpatrol HITL: %s %s%s", req.Method, req.Host, req.Path),
		"blocks":  blocks,
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
	defer resp.Body.Close()
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

func slackTrunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func init() {
	var (
		_ runtime.HTTPCredentialRuntime = (*SlackTokens)(nil)
		_ runtime.HITLNotifier          = (*SlackTokens)(nil)
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
