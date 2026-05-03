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
)

// SlackNotifier posts pending HITL requests to a Slack channel via
// chat.postMessage. One workspace-scoped bot token (Config.SlackBotToken)
// is shared across every slack approver; each approver picks its
// channel by name.
//
// Filters by approver name: only fires when its own name appears in
// HITLPending.Approvers, so a rule that says
//
//   approve = ["console-dba", "billing"]
//
// notifies #agent-db and #billing-approvals — not every slack
// approver the operator declared.
//
// v1 has no interactive buttons. The Block Kit message links back
// to the dashboard's HITL panel where the operator approves/denies.
type SlackNotifier struct {
	Name      string
	Channel   string
	BotToken  string
	Dashboard string
}

const slackPostMessageURL = "https://slack.com/api/chat.postMessage"

func (s *SlackNotifier) Notify(p *HITLPending) {
	if s.BotToken == "" || s.Channel == "" {
		return
	}
	if !approverNamed(p.Approvers, s.Name) {
		return
	}
	link := strings.TrimRight(s.Dashboard, "/") + "/#hitl/" + p.ID

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
		"channel": s.Channel,
		// fallback text for notifications and clients that don't render blocks.
		"text":   fmt.Sprintf("clawpatrol HITL: %s %s%s (%s)", p.Method, p.Host, p.Path, p.AgentIP),
		"blocks": blocks,
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", slackPostMessageURL, bytes.NewReader(buf))
	if err != nil {
		log.Printf("slack approver %s: build request: %v", s.Name, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.BotToken)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("slack approver %s: post: %v", s.Name, err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// chat.postMessage returns 200 even on logical failures; the JSON
	// has {ok: false, error: "..."} when something went wrong.
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(respBody, &result)
	if resp.StatusCode >= 400 || !result.OK {
		log.Printf("slack approver %s: chat.postMessage failed: status=%d ok=%v error=%q",
			s.Name, resp.StatusCode, result.OK, result.Error)
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
