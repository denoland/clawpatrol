package approvers

// Approver runtimes — every approver plugin's body satisfies
// runtime.ApproverRuntime so the gateway dispatcher can call
// .Approve(ctx, req) without knowing the plugin's specific shape.
//
// Built-in DashboardApprover is registered programmatically (not from
// HCL) so `approve = [dashboard]` works without an explicit block.
// HumanApprover speaks Slack via chat.postMessage when a credential
// is bound; falls through to dashboard-only behaviour otherwise.
// LLMApprover lives separately — it doesn't share the pool wait
// pattern.

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

	"github.com/denoland/clawpatrol-go/config/runtime"
)

// DashboardApprover: pool.Add → wait for the dashboard's PUT
// /api/hitl/decide. No external notification — operator sees the
// pending entry on the dashboard's HITL panel directly.
type DashboardApprover struct{}

func (DashboardApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if req.Pool == nil {
		return runtime.ApproveVerdict{}, fmt.Errorf("dashboard approver: no pool")
	}
	pending := buildPending(req)
	id, ch := req.Pool.Add(pending)
	defer req.Pool.Discard(id)
	select {
	case d := <-ch:
		return runtime.ApproveVerdict{
			Decision: decision(d.Allow),
			Reason:   d.Reason,
			By:       d.By,
		}, nil
	case <-ctx.Done():
		return runtime.ApproveVerdict{}, ctx.Err()
	}
}

// Approve on HumanApprover: post a Block Kit message to the
// configured Slack channel (when a credential is bound) AND publish
// to the dashboard pool. First operator to act — Slack-deep-link
// click on the dashboard or direct dashboard click — wins.
//
// HumanApprover with Channel="" or Credential="" falls through to
// pool-only dashboard behaviour, same as DashboardApprover.
func (h *HumanApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if req.Pool == nil {
		return runtime.ApproveVerdict{}, fmt.Errorf("human approver %q: no pool", req.ApproverName)
	}
	pending := buildPending(req)
	id, ch := req.Pool.Add(pending)
	defer req.Pool.Discard(id)

	if h.Channel != "" && h.Credential != "" && req.Secrets != nil {
		go postSlackHITL(req, h.Channel, h.Credential, id, h.Interactive)
	}

	timeout := time.Duration(h.Timeout) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(req.Defaults.HumanTimeout) * time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case d := <-ch:
		return runtime.ApproveVerdict{
			Decision: decision(d.Allow),
			Reason:   d.Reason,
			By:       d.By,
		}, nil
	case <-timer.C:
		// Defaults.HumanOnTimeout selects allow vs deny — caller
		// applies. We surface "" so the dispatcher uses its
		// configured fail mode.
		return runtime.ApproveVerdict{
			Reason: fmt.Sprintf("approver %q timed out after %s", req.ApproverName, timeout),
		}, nil
	case <-ctx.Done():
		return runtime.ApproveVerdict{}, ctx.Err()
	}
}

// postSlackHITL sends the chat.postMessage notification. Best-effort
// — failures log but don't surface as a verdict; the pool wait is
// the source of truth for the actual decision.
func postSlackHITL(req runtime.ApproveRequest, channel, credName, id string, interactive bool) {
	sec, err := req.Secrets.Get(credName, req.Profile)
	if err != nil {
		log.Printf("slack approver %s: fetch credential %s: %v", req.ApproverName, credName, err)
		return
	}
	bot := sec.Extras["bot"]
	if bot == "" && len(sec.Bytes) > 0 {
		bot = string(sec.Bytes)
	}
	if bot == "" {
		log.Printf("slack approver %s: credential %s has no bot token (paste via dashboard)", req.ApproverName, credName)
		return
	}
	link := strings.TrimRight(req.DashboardURL, "/") + "/#hitl/" + id

	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": "clawpatrol HITL request"}},
		{"type": "section", "fields": []map[string]any{
			{"type": "mrkdwn", "text": "*Method*\n`" + req.Method + "`"},
			{"type": "mrkdwn", "text": "*Host*\n`" + req.Host + "`"},
			{"type": "mrkdwn", "text": "*Path*\n`" + truncate(req.Path, 80) + "`"},
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
			"text": map[string]any{"type": "mrkdwn", "text": "*Body*\n```" + truncate(bs, 1000) + "```"},
		})
	}
	// Action buttons depend on the approver's `interactive` setting.
	// Interactive: approve + deny buttons that the gateway resolves
	// via /api/slack/interactive (requires Slack app's Interactivity
	// URL pointed at the gateway + signing_secret pasted via the
	// dashboard). Non-interactive: only an "Open dashboard" link —
	// operator decides on the dashboard.
	var elements []map[string]any
	if interactive {
		elements = append(elements,
			map[string]any{
				"type":      "button",
				"text":      map[string]any{"type": "plain_text", "text": "Approve"},
				"action_id": "approve",
				"value":     id,
				"style":     "primary",
			},
			map[string]any{
				"type":      "button",
				"text":      map[string]any{"type": "plain_text", "text": "Deny"},
				"action_id": "deny",
				"value":     id,
				"style":     "danger",
			},
		)
	}
	elements = append(elements, map[string]any{
		"type": "button",
		"text": map[string]any{"type": "plain_text", "text": "Open dashboard"},
		"url":  link,
	})
	blocks = append(blocks, map[string]any{
		"type":     "actions",
		"elements": elements,
	})

	body := map[string]any{
		"channel": channel,
		"text":    fmt.Sprintf("clawpatrol HITL: %s %s%s", req.Method, req.Host, req.Path),
		"blocks":  blocks,
	}
	buf, _ := json.Marshal(body)
	hreq, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", bytes.NewReader(buf))
	if err != nil {
		log.Printf("slack approver %s: build request: %v", req.ApproverName, err)
		return
	}
	hreq.Header.Set("Authorization", "Bearer "+bot)
	hreq.Header.Set("Content-Type", "application/json; charset=utf-8")

	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(hreq)
	if err != nil {
		log.Printf("slack approver %s: post: %v", req.ApproverName, err)
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
			req.ApproverName, resp.StatusCode, result.OK, result.Error)
	}
}

func buildPending(req runtime.ApproveRequest) runtime.HITLPending {
	now := time.Now()
	return runtime.HITLPending{
		AgentIP:    req.Profile,
		Host:       req.Host,
		Method:     req.Method,
		Path:       req.Path,
		UA:         req.UA,
		BodySample: req.BodySample,
		Reason:     req.Reason,
		Approvers:  []string{req.ApproverName},
		CreatedAt:  now,
	}
}

func decision(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
