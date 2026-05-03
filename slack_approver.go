package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/denoland/clawpatrol-go/config"
	"github.com/denoland/clawpatrol-go/config/runtime"
)

// slackHITLNotifier posts pending HITL requests to a Slack channel
// via chat.postMessage. One notifier per `human_approver` block in
// gateway.hcl that names a slack_tokens credential. The bot token
// is fetched from the credential's `bot` slot (or Bytes for single-
// slot bot-only credentials) at notify time, so dashboard rotations
// pick up immediately.
//
// v1 has no interactive buttons. The Block Kit message links to the
// dashboard's HITL panel where the operator approves/denies.
type slackHITLNotifier struct {
	approverName string
	channel      string
	credName     string // bare-name ref to a slack_tokens credential
	secrets      runtime.SecretStore
	dashboardURL string
}

func (s *slackHITLNotifier) Notify(p *HITLPending) {
	if !approverNamed(p.Approvers, s.approverName) {
		return
	}
	if s.secrets == nil {
		return
	}
	sec, err := s.secrets.Get(s.credName, "")
	if err != nil {
		log.Printf("slack approver %s: fetch credential %s: %v", s.approverName, s.credName, err)
		return
	}
	bot := sec.Extras["bot"]
	if bot == "" && len(sec.Bytes) > 0 {
		bot = string(sec.Bytes)
	}
	if bot == "" {
		log.Printf("slack approver %s: credential %s has no bot token (paste via dashboard)", s.approverName, s.credName)
		return
	}
	link := strings.TrimRight(s.dashboardURL, "/") + "/#hitl/" + p.ID

	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": "clawpatrol HITL request"},
		},
		{
			"type": "section",
			"fields": []map[string]any{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Method*\n`%s`", p.Method)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Host*\n`%s`", p.Host)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Path*\n`%s`", truncate(p.Path, 80))},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Agent*\n`%s`", p.AgentIP)},
			},
		},
	}
	if r := strings.TrimSpace(p.Reason); r != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": "*Reason*\n" + r},
		})
	}
	if bs := strings.TrimSpace(p.BodySample); bs != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": "*Body*\n```" + truncate(bs, 1000) + "```"},
		})
	}
	blocks = append(blocks, map[string]any{
		"type": "actions",
		"elements": []map[string]any{
			{
				"type":  "button",
				"text":  map[string]any{"type": "plain_text", "text": "Approve / deny on dashboard"},
				"url":   link,
				"style": "primary",
			},
		},
	})

	body := map[string]any{
		"channel": s.channel,
		"text":    fmt.Sprintf("clawpatrol HITL: %s %s%s (%s)", p.Method, p.Host, p.Path, p.AgentIP),
		"blocks":  blocks,
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", bytes.NewReader(buf))
	if err != nil {
		log.Printf("slack approver %s: build request: %v", s.approverName, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+bot)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("slack approver %s: post: %v", s.approverName, err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(respBody, &result)
	if resp.StatusCode >= 400 || !result.OK {
		log.Printf("slack approver %s: chat.postMessage failed: status=%d ok=%v error=%q",
			s.approverName, resp.StatusCode, result.OK, result.Error)
	}
}

func approverNamed(list []string, name string) bool {
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}

// registerSlackHITLNotifiers walks the loaded policy's human_approver
// blocks and registers one slackHITLNotifier per approver that names
// a slack_tokens credential. Idempotent across reloads — currently
// the registry doesn't support deregistration, so reloads accumulate;
// notify-time bot-token lookup means stale registrations using a
// removed credential just log "no token" rather than crashing.
func registerSlackHITLNotifiers(g *Gateway, policy *config.CompiledPolicy, dashboardURL string) {
	if g == nil || policy == nil {
		return
	}
	type humanCfg interface {
		HumanApproverChannel() string
		HumanApproverCredential() string
	}
	for name, ent := range policy.Approvers {
		if ent.Plugin.Type != "human_approver" {
			continue
		}
		h, ok := ent.Body.(humanCfg)
		if !ok {
			continue
		}
		credName := h.HumanApproverCredential()
		channel := h.HumanApproverChannel()
		if credName == "" || channel == "" {
			continue
		}
		g.hitl.Register(&slackHITLNotifier{
			approverName: name,
			channel:      channel,
			credName:     credName,
			secrets:      g.secrets,
			dashboardURL: dashboardURL,
		})
	}
}
