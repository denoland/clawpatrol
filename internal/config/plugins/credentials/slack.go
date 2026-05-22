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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// SlackTokens is part of the clawpatrol plugin API.
type SlackTokens struct{}

var (
	slackPostMessageURL     = "https://slack.com/api/chat.postMessage"
	slackUpdateMessageURL   = "https://slack.com/api/chat.update"
	slackHTTPClient         = &http.Client{Timeout: 5 * time.Second}
	slackNotifyRetryBackoff = 500 * time.Millisecond
)

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
func (s *SlackTokens) NotifyHITL(ctx context.Context, req runtime.ApproveRequest, target runtime.HITLTarget) error {
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
	blocks := slackHITLContentBlocks(title, queryLabel, req.Path, target.Message, target.Summary)
	contextBlocks := []map[string]any{}
	if req.Profile != "" {
		contextBlocks = append(contextBlocks, map[string]any{
			"type": "mrkdwn",
			"text": "agent `" + req.Profile + "`",
		})
	}
	if r := strings.TrimSpace(req.Reason); r != "" {
		contextBlocks = append(contextBlocks, map[string]any{
			"type": "mrkdwn",
			"text": "reason: " + slackTrunc(r, 200),
		})
	}
	if len(contextBlocks) > 0 {
		blocks = append(blocks, map[string]any{
			"type":     "context",
			"elements": contextBlocks,
		})
	}
	if bs := strings.TrimSpace(req.BodySample); bs != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": "*Body*\n```" + slackTrunc(bs, 1000) + "```"},
		})
	}
	if guidance := slackHITLApprovalGuidance(target); guidance != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": slackTrunc(guidance, 1000)},
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
	posted, err := slackPostHITLMessage(ctx, bot, buf)
	if err != nil {
		return err
	}
	if posted.Channel != "" && posted.TS != "" {
		ref := encodeSlackMessageRef(slackMessageRef{Credential: target.CredentialName, Channel: posted.Channel, TS: posted.TS, PendingID: target.PendingID, Interactive: target.Interactive, Message: target.Message, Summary: target.Summary})
		if target.MessageUpdateSink != nil && req.AsyncOperationID != "" {
			if err := target.MessageUpdateSink(ctx, req.AsyncOperationID, ref); err != nil {
				log.Printf("slack notify: record HITL message ref for %s: %v", req.AsyncOperationID, err)
			}
		}
		if target.PendingMessageUpdateSink != nil && target.PendingID != "" {
			if err := target.PendingMessageUpdateSink(ctx, target.PendingID, ref); err != nil {
				log.Printf("slack notify: record pending HITL message ref for %s: %v", target.PendingID, err)
			}
		}
	}
	return nil
}

func slackHITLApprovalGuidance(target runtime.HITLTarget) string {
	message := strings.TrimSpace(target.ApprovalMessage)
	if message != "" {
		return message
	}
	if target.OperationState == "" && target.ApprovalEffect == "" && !target.UpstreamCalled {
		return ""
	}
	state := target.OperationState
	if state == "" {
		state = runtime.HITLOperationStateSyncWaiting
	}
	effect := target.ApprovalEffect
	if effect == "" {
		effect = runtime.HITLApprovalEffectForOperationState(state)
	}
	return runtime.HITLApprovalMessage(state, effect, target.UpstreamCalled)
}

func slackHITLContentBlocks(title, queryLabel, path, message string, summary *runtime.HITLSummary) []map[string]any {
	switch {
	case message != "":
		return []map[string]any{
			{"type": "header", "text": map[string]any{"type": "plain_text", "text": title}},
			{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": slackTrunc(message, 3000)}},
		}
	case summary != nil:
		s := summary
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
		return []map[string]any{
			{"type": "header", "text": map[string]any{"type": "plain_text", "text": slackTrunc(headerText, 140)}},
			{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": sectionText}},
		}
	default:
		return []map[string]any{
			{"type": "header", "text": map[string]any{"type": "plain_text", "text": title}},
			{"type": "section", "text": map[string]any{
				"type": "mrkdwn",
				"text": "*" + queryLabel + "*\n```" + slackTrunc(path, 800) + "```",
			}},
		}
	}
}

type slackPostedMessage struct {
	Channel string
	TS      string
}

func slackPostHITLMessage(ctx context.Context, bot string, buf []byte) (slackPostedMessage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		hreq, err := http.NewRequestWithContext(ctx, "POST", slackPostMessageURL, bytes.NewReader(buf))
		if err != nil {
			return slackPostedMessage{}, err
		}
		hreq.Header.Set("Authorization", "Bearer "+bot)
		hreq.Header.Set("Content-Type", "application/json; charset=utf-8")

		var posted slackPostedMessage
		resp, err := slackHTTPClient.Do(hreq)
		if err == nil {
			posted, lastErr = slackDecodePostMessageResponse(resp)
			if closeErr := resp.Body.Close(); lastErr == nil && closeErr != nil {
				lastErr = closeErr
			}
		} else {
			lastErr = err
		}
		if lastErr == nil {
			return posted, nil
		}
		if attempt == 2 || !slackShouldRetryPostMessage(resp, err) {
			return slackPostedMessage{}, lastErr
		}
		log.Printf("slack notify: chat.postMessage failed on attempt %d, retrying once: %v", attempt, lastErr)
		if err := slackWaitBeforeRetry(ctx, resp); err != nil {
			return slackPostedMessage{}, err
		}
	}
	return slackPostedMessage{}, lastErr
}

func slackDecodePostMessageResponse(resp *http.Response) (slackPostedMessage, error) {
	if resp == nil {
		return slackPostedMessage{}, fmt.Errorf("slack chat.postMessage error: missing response")
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Channel string `json:"channel"`
		TS      string `json:"ts"`
	}
	_ = json.Unmarshal(respBody, &result)
	if resp.StatusCode >= 400 || !result.OK {
		log.Printf("slack notify: chat.postMessage failed: status=%d ok=%v error=%q", resp.StatusCode, result.OK, result.Error)
		if result.Error != "" {
			return slackPostedMessage{}, fmt.Errorf("slack chat.postMessage error: %s", result.Error)
		}
		return slackPostedMessage{}, fmt.Errorf("slack chat.postMessage error: HTTP %d", resp.StatusCode)
	}
	return slackPostedMessage{Channel: result.Channel, TS: result.TS}, nil
}

func slackShouldRetryPostMessage(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return false
	}
	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
}

func slackWaitBeforeRetry(ctx context.Context, resp *http.Response) error {
	backoff := slackNotifyRetryBackoff
	if resp != nil {
		if retryAfter := strings.TrimSpace(resp.Header.Get("Retry-After")); retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
				backoff = time.Duration(seconds) * time.Second
			}
		}
	}
	if backoff <= 0 {
		return nil
	}
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type slackMessageRef struct {
	Type        string               `json:"type"`
	Credential  string               `json:"credential"`
	Channel     string               `json:"channel"`
	TS          string               `json:"ts"`
	PendingID   string               `json:"pending_id,omitempty"`
	Interactive bool                 `json:"interactive,omitempty"`
	Message     string               `json:"message,omitempty"`
	Summary     *runtime.HITLSummary `json:"summary,omitempty"`
}

func encodeSlackMessageRef(ref slackMessageRef) string {
	ref.Type = "slack"
	b, _ := json.Marshal(ref)
	return string(b)
}

func decodeSlackMessageRef(raw string) (slackMessageRef, bool) {
	var ref slackMessageRef
	if err := json.Unmarshal([]byte(raw), &ref); err != nil || ref.Type != "slack" || ref.Credential == "" || ref.Channel == "" || ref.TS == "" {
		return slackMessageRef{}, false
	}
	return ref, true
}

// UpdateHITLMessage edits the originating Slack interactive message
// after a HITL decision lands. update.MessageRef is the JSON-encoded
// slackMessageRef the credential plugin emitted when posting; this
// call resolves the credential, then issues chat.update with the
// rendered decision text.
func (s *SlackTokens) UpdateHITLMessage(ctx context.Context, secrets runtime.SecretStore, update runtime.HITLMessageUpdate) error {
	ref, ok := decodeSlackMessageRef(update.MessageRef)
	if !ok {
		return nil
	}
	if secrets == nil {
		return fmt.Errorf("no secret store on request")
	}
	sec, err := secrets.Get(ref.Credential)
	if err != nil {
		return fmt.Errorf("fetch credential %s: %w", ref.Credential, err)
	}
	bot := sec.Extras["bot"]
	if bot == "" && len(sec.Bytes) > 0 {
		bot = string(sec.Bytes)
	}
	if bot == "" {
		return fmt.Errorf("credential %s has no bot token", ref.Credential)
	}
	blocks := slackHITLUpdateBlocks(update, ref)
	body := map[string]any{
		"channel": ref.Channel,
		"ts":      ref.TS,
		"text":    "clawpatrol: HITL " + string(update.State),
		"blocks":  blocks,
	}
	buf, _ := json.Marshal(body)
	return slackPostJSON(ctx, slackUpdateMessageURL, bot, buf, "chat.update")
}

func slackHITLUpdateBlocks(update runtime.HITLMessageUpdate, ref slackMessageRef) []map[string]any {
	path := update.Path
	if path == "" {
		path = "/"
	}
	title := slackTrunc(runtime.HITLTitle(update.Method, update.Host), 140)
	blocks := slackHITLContentBlocks(title, "Path", path, ref.Message, ref.Summary)
	guidance := runtime.HITLApprovalMessage(update.State, runtime.HITLApprovalEffectForOperationState(update.State), update.UpstreamCalled)
	if strings.TrimSpace(guidance) != "" {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": slackTrunc(guidance, 1000)}})
	}
	if update.State == runtime.HITLOperationStatePendingApproval && ref.Interactive && ref.PendingID != "" {
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []map[string]any{
				{"type": "button", "text": map[string]any{"type": "plain_text", "text": "Approve"}, "action_id": "approve", "value": ref.PendingID, "style": "primary"},
				{"type": "button", "text": map[string]any{"type": "plain_text", "text": "Deny"}, "action_id": "deny", "value": ref.PendingID, "style": "danger"},
			},
		})
	}
	status := slackOperationStatus(update)
	blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{{"type": "mrkdwn", "text": status}}})
	return blocks
}

func slackOperationStatus(update runtime.HITLMessageUpdate) string {
	switch update.State {
	case runtime.HITLOperationStatePendingApproval:
		return ":hourglass_flowing_sand: HITL approval is pending"
	case runtime.HITLOperationStateApprovedWaitingForRetry:
		return ":white_check_mark: Approved — waiting for matching client retry"
	case runtime.HITLOperationStateExecutingUpstream:
		return ":arrow_forward: Matching retry received — executing upstream"
	case runtime.HITLOperationStateUpstreamSucceeded:
		return ":white_check_mark: Upstream request succeeded"
	case runtime.HITLOperationStateUpstreamFailed:
		if update.LastError != "" {
			return ":x: Upstream request failed: " + slackTrunc(slackRedactStatusText(update.LastError), 300)
		}
		return ":x: Upstream request failed"
	case runtime.HITLOperationStateDenied:
		return ":no_entry: Denied"
	case runtime.HITLOperationStateExpired:
		return ":alarm_clock: HITL approval expired"
	case runtime.HITLOperationStateClientDisconnected:
		return ":warning: Original client disconnected before approval. The upstream request was not sent."
	default:
		return "HITL state: `" + string(update.State) + "`"
	}
}

func slackPostJSON(ctx context.Context, endpoint, bot string, buf []byte, method string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		hreq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(buf))
		if err != nil {
			return err
		}
		hreq.Header.Set("Authorization", "Bearer "+bot)
		hreq.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp, err := slackHTTPClient.Do(hreq)
		if err == nil {
			lastErr = slackDecodeJSONResponse(resp, method)
			if closeErr := resp.Body.Close(); lastErr == nil && closeErr != nil {
				lastErr = closeErr
			}
		} else {
			lastErr = err
		}
		if lastErr == nil {
			return nil
		}
		if attempt == 2 || !slackShouldRetryPostMessage(resp, err) {
			return lastErr
		}
		log.Printf("slack notify: %s failed on attempt %d, retrying once: %v", method, attempt, lastErr)
		if err := slackWaitBeforeRetry(ctx, resp); err != nil {
			return err
		}
	}
	return lastErr
}

func slackDecodeJSONResponse(resp *http.Response, method string) error {
	if resp == nil {
		return fmt.Errorf("slack %s error: missing response", method)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(respBody, &result)
	if resp.StatusCode >= 400 || !result.OK {
		log.Printf("slack notify: %s failed: status=%d ok=%v error=%q", method, resp.StatusCode, result.OK, result.Error)
		if result.Error != "" {
			return fmt.Errorf("slack %s error: %s", method, result.Error)
		}
		return fmt.Errorf("slack %s error: HTTP %d", method, resp.StatusCode)
	}
	return nil
}

var (
	slackSensitiveQueryValue  = regexp.MustCompile(`(?i)([?&][^=]*(?:auth|token|secret|key|password|cookie)[^=]*=)[^&\s]+`)
	slackSensitiveURLPath     = regexp.MustCompile(`(?i)(https?://hooks\.slack\.com/services/)[^\s,;]+`)
	slackSensitivePathSegment = regexp.MustCompile(`(?i)(/(?:auth|token|secret|key|password|cookie)(?:/|=))[^/\s,;]+`)
	slackAuthorizationValue   = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*)(?:bearer|bot|basic)\s+[^\s,;]+`)
	slackSensitiveHeaderValue = regexp.MustCompile(`(?i)\b([A-Za-z0-9-]*(?:auth|token|secret|key|password|cookie)[A-Za-z0-9-]*\s*[:=]\s*)([^\s,;]+)`)
)

func slackRedactStatusText(s string) string {
	s = slackSensitiveQueryValue.ReplaceAllString(s, `${1}[redacted]`)
	s = slackSensitiveURLPath.ReplaceAllString(s, `${1}[redacted]`)
	s = slackSensitivePathSegment.ReplaceAllString(s, `${1}[redacted]`)
	s = slackAuthorizationValue.ReplaceAllString(s, `${1}[redacted]`)
	s = slackSensitiveHeaderValue.ReplaceAllString(s, `${1}[redacted]`)
	return s
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
	decision := runtime.HITLDecision{Allow: allow, By: "slack:" + p.User.Name}
	result := runtime.HITLResolveResult{State: runtime.HITLStateUnknown, Reason: "unknown or expired HITL request"}
	if decider, ok := ctx.HITL.(runtime.HITLPoolDecider); ok {
		result = decider.DecideWithResult(act.Value, decision)
	} else if ctx.HITL != nil {
		result.OK = ctx.HITL.Decide(act.Value, decision)
		if result.OK {
			if allow {
				result.State = runtime.HITLStateApproved
			} else {
				result.State = runtime.HITLStateDenied
			}
		}
	}

	status := slackHITLStatus(result, allow, p.User.Name)
	if result.OK {
		verb := "approved"
		if !allow {
			verb = "denied"
		}
		log.Printf("slack-interactive: %s %s by %s", act.Value, verb, p.User.Name)
	}

	if p.ResponseURL != "" {
		guidance := slackResolvedApprovalGuidance(result, allow)
		go postSlackResponseURL(p.ResponseURL, status, withStatusBlock(p.Message.Blocks, status, guidance))
	}
	return map[string]any{} // empty ack — real update flows via response_url
}

func slackHITLStatus(result runtime.HITLResolveResult, allow bool, user string) string {
	if result.OK {
		verb := "approved"
		emoji := ":white_check_mark:"
		if !allow {
			verb = "denied"
			emoji = ":no_entry:"
		}
		return fmt.Sprintf("%s %s by <@%s>", emoji, verb, user)
	}

	switch result.State {
	case runtime.HITLStateClientDisconnected:
		return ":warning: Request is no longer active. The original client connection closed before approval, so the upstream request was not sent."
	case runtime.HITLStateTimedOut:
		return ":hourglass_flowing_sand: Approval expired. The upstream request was not sent."
	case runtime.HITLStateApproved:
		return ":white_check_mark: This request was already approved."
	case runtime.HITLStateDenied:
		return ":no_entry: This request was already denied."
	case runtime.HITLStateCanceled:
		if result.Reason != "" {
			return ":warning: Approval canceled. " + result.Reason
		}
		return ":warning: Approval canceled. The upstream request was not sent."
	default:
		return "Already resolved or expired."
	}
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
// approval guidance and `actions` block, plus optional replacement
// guidance and a context block carrying the verdict.
// Slack `replace_original` swaps the message in place — operator
// sees the buttons disappear and the verdict line appear instantly.
func withStatusBlock(blocks []map[string]any, status, guidance string) []map[string]any {
	out := make([]map[string]any, 0, len(blocks)+2)
	for _, b := range blocks {
		if b["type"] == "actions" || slackIsApprovalGuidanceBlock(b) {
			continue
		}
		out = append(out, b)
	}
	if strings.TrimSpace(guidance) != "" {
		out = append(out, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": slackTrunc(guidance, 1000)},
		})
	}
	out = append(out, map[string]any{
		"type":     "context",
		"elements": []map[string]any{{"type": "mrkdwn", "text": status}},
	})
	return out
}

func slackResolvedApprovalGuidance(result runtime.HITLResolveResult, allow bool) string {
	if !result.OK {
		return ""
	}
	if allow && strings.Contains(result.Reason, "waiting for matching client retry") {
		return runtime.HITLApprovalMessage(runtime.HITLOperationStateApprovedWaitingForRetry, runtime.HITLApprovalEffectCreateRetryGrant, false)
	}
	if !allow {
		return runtime.HITLApprovalMessage(runtime.HITLOperationStateDenied, runtime.HITLApprovalEffectCreateRetryGrant, false)
	}
	return ""
}

func slackIsApprovalGuidanceBlock(block map[string]any) bool {
	text := strings.TrimSpace(slackBlockText(block))
	if text == "" {
		return false
	}
	for _, guidance := range slackKnownApprovalGuidanceMessages() {
		if text == guidance {
			return true
		}
	}
	return false
}

func slackKnownApprovalGuidanceMessages() []string {
	messages := []string{
		runtime.HITLApprovalMessage(runtime.HITLOperationStateSyncWaiting, runtime.HITLApprovalEffectExecuteUpstream, false),
		runtime.HITLApprovalMessage(runtime.HITLOperationStatePendingApproval, runtime.HITLApprovalEffectCreateRetryGrant, false),
		runtime.HITLApprovalMessage(runtime.HITLOperationStateApprovedWaitingForRetry, runtime.HITLApprovalEffectCreateRetryGrant, false),
		runtime.HITLApprovalMessage(runtime.HITLOperationStateDenied, runtime.HITLApprovalEffectCreateRetryGrant, false),
		runtime.HITLApprovalMessage(runtime.HITLOperationStateExpired, runtime.HITLApprovalEffectCreateRetryGrant, false),
		runtime.HITLApprovalMessage(runtime.HITLOperationStateClientDisconnected, runtime.HITLApprovalEffectCreateRetryGrant, false),
		runtime.HITLApprovalMessage("", runtime.HITLApprovalEffectCreateRetryGrant, false),
	}
	for i := range messages {
		messages[i] = strings.TrimSpace(slackTrunc(messages[i], 1000))
	}
	return messages
}

func slackBlockText(block map[string]any) string {
	var parts []string
	if text, ok := block["text"].(map[string]any); ok {
		if value, ok := text["text"].(string); ok {
			parts = append(parts, value)
		}
	}
	if elements, ok := block["elements"].([]map[string]any); ok {
		for _, element := range elements {
			if value, ok := element["text"].(string); ok {
				parts = append(parts, value)
			}
		}
	}
	return strings.Join(parts, "\n")
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
		Kind:           config.KindCredential,
		Type:           "slack_tokens",
		Disambiguators: []string{"placeholder"},
		New:            newer[SlackTokens](),
		Runtime:        (*SlackTokens)(nil),
		Build:          passthrough,
		Emit:           emptyEmit,
	})
}
