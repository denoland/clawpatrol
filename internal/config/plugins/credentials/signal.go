package credentials

// signal_cli: deliver HITL approval prompts to Signal via a
// signal-cli-rest-api instance (https://github.com/bbernhard/signal-cli-rest-api).
//
// Signal has no bot/HTTP API of its own and no interactive button UI,
// so this is a notification-only notifier: it POSTs a plain-text prompt
// ending with an "Open dashboard" link, and the human approves/denies
// there. It implements HITLNotifier and HITLMessageUpdater — there is
// no HTTP injection runtime and no WebhookProvider callback (contrast
// slack.go).
//
// Config is pasted via the dashboard secret slots:
//
//   - api_url: base URL of the signal-cli-rest-api (e.g. http://localhost:8080)
//   - number:  the registered Signal sender number, E.164 (+15551234567)
//   - auth:    optional "user:pass" if the REST API is behind HTTP basic auth
//
// The recipient is the human_approver block's `channel` — a recipient
// number (E.164) or a "group.<base64-id>" group identifier.
//
// Adding another notification channel is a new credential plugin with
// its own NotifyHITL — no human_approver / runtime.go changes.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// SignalCLI is a notification-only HITL notifier that delivers approval
// prompts to Signal via a signal-cli-rest-api instance
// (https://github.com/bbernhard/signal-cli-rest-api). Signal has no
// interactive buttons, so the prompt is plain text ending in an
// "Open dashboard" link where the operator approves or denies.
//
// Connection details live in the secret store as named slots, filled via the
// dashboard: api_url (base URL of the signal-cli-rest-api), number (the
// registered E.164 sender), and auth (optional "user:pass" for HTTP basic
// auth). The recipient is the human_approver's channel - an E.164 number or a
// "group.<base64-id>".
//
// DeleteOnDecision remote-deletes the prompt once the operation is decided,
// so a conversation does not fill up with dead approve/deny links. It runs
// off the runtime's HITLMessageUpdater hook - the same one the Slack notifier
// uses to edit its message - so a prompt is only ever removed after the
// decision lands, never on a timer while the operator is still expected to
// act.
//
// Remote-delete needs a real peer: a group with another member, or a
// different number. It does NOT work for Note-to-Self (channel = the
// account's own number): signal-cli returns the sync-envelope timestamp for
// self-sends, not the message timestamp remote-delete needs, so the delete is
// a no-op on the linked phone.
type SignalCLI struct {
	// DeleteOnDecision remote-deletes the sent prompt once the HITL
	// operation is decided. Off by default, which leaves the prompts in the
	// conversation as a record of what was asked.
	DeleteOnDecision bool `hcl:"delete_on_decision,optional" json:"delete_on_decision,omitempty"`
}

var (
	signalHTTPClient   = &http.Client{Timeout: 10 * time.Second}
	signalRetryBackoff = 500 * time.Millisecond
)

// signalDo sends req without following redirects: api_url is
// operator-supplied, so basic auth must not be replayed to another
// host, and a bodyless GET after a 302 must not count as a send.
func signalDo(req *http.Request) (*http.Response, error) {
	c := *signalHTTPClient
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c.Do(req)
}

// signalSetBasicAuth applies the optional auth slot. The slot is
// "user:password"; anything else is a configuration error rather
// than a silent unauthenticated request.
func signalSetBasicAuth(req *http.Request, auth string) error {
	if auth == "" {
		return nil
	}
	user, pass, ok := strings.Cut(auth, ":")
	if !ok || user == "" {
		return fmt.Errorf("signal_cli auth slot must be \"user:password\"")
	}
	req.SetBasicAuth(user, pass)
	return nil
}

// signalSendPath is the signal-cli-rest-api v2 send endpoint.
const signalSendPath = "/v2/send"

// signalRemoteDeletePath is the signal-cli-rest-api remote-delete endpoint
// (the registered number is appended, URL-escaped, per call).
const signalRemoteDeletePath = "/v1/remote-delete"

// signalMessageMax bounds the prompt text. Signal messages can be long,
// but we keep individual sections trimmed so a giant body/path can't
// blow up the message; this is a soft overall guard.
const signalMessageMax = 4000

// signalMessageRef locates an already-sent prompt so a later
// UpdateHITLMessage can act on it. It is handed to the runtime's message-ref
// sinks and stored there, so it carries no secrets: the credential name is
// enough to re-read api_url / number / auth from the secret store at delete
// time, which also means a dashboard rotation applies to queued updates.
type signalMessageRef struct {
	Type        string `json:"type"`
	Credential  string `json:"credential"`
	Recipient   string `json:"recipient"`
	TimestampMs int64  `json:"timestamp_ms"`
}

func encodeSignalMessageRef(ref signalMessageRef) string {
	ref.Type = "signal_cli"
	b, _ := json.Marshal(ref)
	return string(b)
}

func decodeSignalMessageRef(raw string) (signalMessageRef, bool) {
	var ref signalMessageRef
	if err := json.Unmarshal([]byte(raw), &ref); err != nil ||
		ref.Type != "signal_cli" || ref.Credential == "" ||
		ref.Recipient == "" || ref.TimestampMs <= 0 {
		return signalMessageRef{}, false
	}
	return ref, true
}

// SecretSlots is part of the clawpatrol plugin API.
func (*SignalCLI) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "api_url", Label: "signal-cli-rest-api URL", Description: "Base URL of the signal-cli-rest-api, e.g. http://localhost:8080"},
		{Name: "number", Label: "Sender number", Description: "Registered Signal number in E.164 form, e.g. +15551234567"},
		{Name: "auth", Label: "Basic auth (optional)", Description: "user:pass if the REST API is behind HTTP basic auth"},
	}
}

// NotifyHITL posts an approval prompt to the operator's Signal recipient
// via signal-cli-rest-api's POST /v2/send. api_url + number come from the
// credential's secret slots (fetched per-call via the request's
// SecretStore so dashboard rotations apply); the recipient is the
// approver block's channel.
func (s *SignalCLI) NotifyHITL(ctx context.Context, req runtime.ApproveRequest, target runtime.HITLTarget) error {
	if req.Secrets == nil {
		return fmt.Errorf("no secret store on request")
	}
	sec, err := req.Secrets.Get(target.CredentialName)
	if err != nil {
		return fmt.Errorf("fetch credential %s: %w", target.CredentialName, err)
	}
	apiURL := strings.TrimRight(sec.Extras["api_url"], "/")
	number := strings.TrimSpace(sec.Extras["number"])
	if apiURL == "" || number == "" {
		return fmt.Errorf("credential %s missing api_url or number (paste them via the dashboard)", target.CredentialName)
	}
	if strings.TrimSpace(target.Channel) == "" {
		return fmt.Errorf("human approver %s has no channel (set it to a Signal recipient number or group.<id>)", target.CredentialName)
	}

	body := map[string]any{
		"number":     number,
		"recipients": []string{target.Channel},
		"message":    signalHITLMessage(req, target),
	}
	buf, _ := json.Marshal(body)
	sentTS, err := signalPostSend(ctx, apiURL+signalSendPath, sec.Extras["auth"], buf)
	if err != nil {
		return err
	}
	if sentTS > 0 {
		ref := encodeSignalMessageRef(signalMessageRef{Credential: target.CredentialName, Recipient: target.Channel, TimestampMs: sentTS})
		if target.MessageUpdateSink != nil && req.AsyncOperationID != "" {
			if err := target.MessageUpdateSink(ctx, req.AsyncOperationID, ref); err != nil {
				log.Printf("signal notify: record HITL message ref for %s: %v", req.AsyncOperationID, err)
			}
		}
		if target.PendingMessageUpdateSink != nil && target.PendingID != "" {
			if err := target.PendingMessageUpdateSink(ctx, target.PendingID, ref); err != nil {
				log.Printf("signal notify: record pending HITL message ref for %s: %v", target.PendingID, err)
			}
		}
	}
	return nil
}

// signalHITLMessage renders the plain-text prompt. Signal has no rich
// blocks or buttons, so it is a compact text card ending with the
// dashboard link where the operator approves or denies.
func signalHITLMessage(req runtime.ApproveRequest, target runtime.HITLTarget) string {
	endpoint := runtime.HITLEndpointLabel(req)
	title := runtime.HITLTitle(req.Method, endpoint)

	var b strings.Builder
	b.WriteString("clawpatrol: " + slackTrunc(title, 200) + "\n")

	switch {
	case strings.TrimSpace(target.Message) != "":
		b.WriteString("\n" + slackTrunc(target.Message, 1500) + "\n")
	case target.Summary != nil:
		sm := target.Summary
		if sm.Subject != "" {
			b.WriteString("\n" + slackTrunc(sm.Subject, 200) + "\n")
		}
		label := sm.Label
		if sm.Confidence > 0 {
			if label == "" {
				label = fmt.Sprintf("%d%% confidence", sm.Confidence)
			} else {
				label += fmt.Sprintf(" (%d%%)", sm.Confidence)
			}
		}
		if label != "" {
			b.WriteString("Label: " + label + "\n")
		}
		if sm.Summary != "" {
			b.WriteString("Summary: " + slackTrunc(sm.Summary, 500) + "\n")
		}
	default:
		if req.Path != "" {
			b.WriteString("\n" + runtime.HITLQueryLabel(req.Endpoint) + ": " + slackTrunc(req.Path, 800) + "\n")
		}
	}

	if req.Profile != "" {
		b.WriteString("agent: " + slackTrunc(req.Profile, 80) + "\n")
	}
	if r := strings.TrimSpace(req.Reason); r != "" {
		b.WriteString("reason: " + slackTrunc(r, 200) + "\n")
	}
	if bs := strings.TrimSpace(req.BodySample); bs != "" {
		b.WriteString("\nBody:\n" + slackTrunc(bs, 800) + "\n")
	}
	if g := slackHITLApprovalGuidance(target); g != "" {
		b.WriteString("\n" + slackTrunc(g, 1000) + "\n")
	}

	// Bound the variable content, then append the dashboard link last and
	// unconditionally — so an overflowing body/summary can never truncate
	// away the approve/deny link, the actionable part of the prompt.
	content := strings.TrimRight(slackTrunc(b.String(), signalMessageMax), "\n")
	link := strings.TrimRight(target.DashboardURL, "/") + "/#hitl/" + target.PendingID
	return content + "\n\nApprove or deny: " + link
}

// signalPostSend POSTs the send request with one retry on transient
// failure, mirroring the Slack notifier's backoff behavior. On success it
// returns the sent message's timestamp (ms since epoch) parsed from the
// response; 0 means the API did not report one.
func signalPostSend(ctx context.Context, endpoint, auth string, buf []byte) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	var sent int64
	for attempt := 1; attempt <= 2; attempt++ {
		hreq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(buf))
		if err != nil {
			return 0, err
		}
		hreq.Header.Set("Content-Type", "application/json")
		if err := signalSetBasicAuth(hreq, auth); err != nil {
			return 0, err
		}

		resp, err := signalDo(hreq)
		if err == nil {
			sent, lastErr = signalDecodeResponse(resp)
			if closeErr := resp.Body.Close(); lastErr == nil && closeErr != nil {
				lastErr = closeErr
			}
		} else {
			lastErr = err
		}
		if lastErr == nil {
			return sent, nil
		}
		if attempt == 2 || !signalShouldRetry(resp, err) {
			return 0, lastErr
		}
		log.Printf("signal notify: %s failed on attempt %d, retrying once: %v", signalSendPath, attempt, lastErr)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(signalRetryBackoff):
		}
	}
	return 0, lastErr
}

func signalDecodeResponse(resp *http.Response) (int64, error) {
	if resp == nil {
		return 0, fmt.Errorf("signal %s: missing response", signalSendPath)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(respBody))
		// signal-cli-rest-api returns {"error":"..."} on failure.
		var parsed struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &parsed) == nil && parsed.Error != "" {
			msg = parsed.Error
		}
		log.Printf("signal notify: %s failed: status=%d error=%q", signalSendPath, resp.StatusCode, slackTrunc(msg, 300))
		return 0, fmt.Errorf("signal %s error: HTTP %d: %s", signalSendPath, resp.StatusCode, slackTrunc(msg, 300))
	}
	var parsed struct {
		Timestamp string `json:"timestamp"`
	}
	if json.Unmarshal(respBody, &parsed) == nil && parsed.Timestamp != "" {
		if ts, err := strconv.ParseInt(parsed.Timestamp, 10, 64); err == nil {
			return ts, nil
		}
	}
	return 0, nil
}

func signalShouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return false
	}
	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
}

// UpdateHITLMessage removes the prompt from the Signal conversation once the
// HITL operation is decided. Signal has no message-edit API, so where the
// Slack notifier rewrites its message with the outcome, this deletes the now
// dead approve/deny link. update.MessageRef is the signalMessageRef emitted
// when the prompt was posted; the connection details are re-read from the
// secret store here, so a rotation between posting and deciding applies.
func (s *SignalCLI) UpdateHITLMessage(ctx context.Context, secrets runtime.SecretStore, update runtime.HITLMessageUpdate) error {
	if !s.DeleteOnDecision || !signalDecided(update.State) {
		return nil
	}
	ref, ok := decodeSignalMessageRef(update.MessageRef)
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
	apiURL := strings.TrimRight(sec.Extras["api_url"], "/")
	number := strings.TrimSpace(sec.Extras["number"])
	if apiURL == "" || number == "" {
		return fmt.Errorf("credential %s missing api_url or number (paste them via the dashboard)", ref.Credential)
	}
	return signalRemoteDelete(ctx, apiURL, number, sec.Extras["auth"], ref)
}

// signalDecided reports whether an update means the prompt has stopped being
// actionable — the human answered, the request lapsed, or the upstream call
// is already under way. The states before that leave the prompt alone, which
// is the part the old age-based sweep got wrong.
//
// A single operation reaches several of these in turn (approved, then
// executing, then succeeded), so the delete has to be safe to repeat:
// remote-deleting an already-deleted timestamp is a no-op.
func signalDecided(state runtime.HITLOperationState) bool {
	switch state {
	case runtime.HITLOperationStateApproved,
		runtime.HITLOperationStateApprovedWaitingForRetry,
		runtime.HITLOperationStateDenied,
		runtime.HITLOperationStateExpired,
		runtime.HITLOperationStateClientDisconnected,
		runtime.HITLOperationStateExecutingUpstream,
		runtime.HITLOperationStateUpstreamSucceeded,
		runtime.HITLOperationStateUpstreamFailed:
		return true
	default:
		return false
	}
}

// signalRemoteDelete calls signal-cli-rest-api's
// DELETE /v1/remote-delete/{number}.
func signalRemoteDelete(ctx context.Context, apiURL, number, auth string, ref signalMessageRef) error {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint := apiURL + signalRemoteDeletePath + "/" + url.PathEscape(number)
	body, err := json.Marshal(map[string]any{"recipient": ref.Recipient, "timestamp": ref.TimestampMs})
	if err != nil {
		return err
	}
	// One retry on transient failure, like the send path: the decided
	// states that trigger a delete are reached once, so there is no
	// later chance to clean the prompt up.
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if err := signalSetBasicAuth(req, auth); err != nil {
			return err
		}
		resp, err := signalDo(req)
		if err == nil {
			if resp.StatusCode < 300 {
				_ = resp.Body.Close()
				return nil
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("signal %s error: HTTP %d: %s", signalRemoteDeletePath, resp.StatusCode, slackTrunc(string(b), 300))
		} else {
			lastErr = err
		}
		if attempt == 2 || !signalShouldRetry(resp, err) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(signalRetryBackoff):
		}
	}
	return lastErr
}

func init() {
	var _ runtime.HITLNotifier = (*SignalCLI)(nil)
	var _ runtime.HITLMessageUpdater = (*SignalCLI)(nil)
	config.Register(&config.Plugin{
		Kind: config.KindCredential,
		Type: "signal_cli",
		// Notifier-only: no HTTP/SQL/TLS injection runtime, so Runtime is
		// nil (schema-only). The approver and dashboard read NotifyHITL /
		// SecretSlots off the built body (ent.Body), not off Runtime.
		New:   newer[SignalCLI](),
		Build: passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			if v := body.(*SignalCLI); v.DeleteOnDecision {
				b.SetAttributeValue("delete_on_decision", cty.BoolVal(true))
			}
		},
	})
}
