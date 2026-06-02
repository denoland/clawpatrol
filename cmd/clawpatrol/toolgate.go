package main

// Tool-call gating glue between the HTTPS MITM hook in main.go and
// the standalone internal/toolgate package. The gating logic itself
// (parsing tool_use, picking a verdict, rewriting the response body)
// lives in internal/toolgate; this file is the integration layer:
//
//   - reads + (optionally) gunzips the upstream response body before
//     handing it to GateAnthropicResponse,
//   - swaps the response shape if the gate rewrote anything (body,
//     Content-Length, Content-Encoding),
//   - attaches the rewrite note to the request log so the dashboard's
//     event row carries a "gated" marker.
//
// Streaming SSE responses (text/event-stream) take a separate path —
// gateAnthropicSSEStream below wraps the body in an incremental,
// per-block-buffering transform (internal/toolgate.GateAnthropicSSE).
// gateAnthropicResponse here assumes a buffered JSON body.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/denoland/clawpatrol/internal/toolgate"
)

// maxToolgateReqBody caps how much of the agent's original /v1/messages
// request the gateway buffers to rebuild the conversation for a
// gateway-initiated HITL follow-up (and how much follow-up response it
// reads back). Larger than the 1MB match cap (maxHTTPMatchBody) because
// the full message history must be valid JSON to re-serialise; 8MB
// mirrors the response-body cap. A request larger than this disables the
// follow-up for that turn — the HITL path then degrades to a text block.
const maxToolgateReqBody = 8 << 20

// loadToolgateRulesFromEnv pulls a JSON-encoded rule list out of
// CLAWPATROL_TOOLGATE_RULES, an opt-in knob for prototyping the
// draft. Shape: an array of {name, tool_name, args_contains, verdict,
// reason}. Verdicts are "allow", "deny", "hitl". Bad JSON is logged
// and ignored — gating then defaults to off, which is the safe path.
//
// Example:
//
//	CLAWPATROL_TOOLGATE_RULES='[
//	  {"name":"no-bash","tool_name":"bash","verdict":"deny",
//	   "reason":"no shell execution"},
//	  {"name":"approve-fs-writes","tool_name":"write_file",
//	   "verdict":"hitl","reason":"writes need operator approval"}
//	]'
//
// The production design intent is for these to ride in the gateway's
// HCL config under cl-1yh's llm_rule plugin. The env var is the
// minimum viable thing for a draft PR; it is not load-bearing for
// the architecture.
func loadToolgateRulesFromEnv() toolgate.RuleSet {
	raw := os.Getenv("CLAWPATROL_TOOLGATE_RULES")
	if raw == "" {
		return nil
	}
	var entries []struct {
		Name         string `json:"name"`
		ToolName     string `json:"tool_name"`
		ArgsContains string `json:"args_contains"`
		Verdict      string `json:"verdict"`
		Reason       string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		log.Printf("toolgate rules env: parse: %v (gating disabled)", err)
		return nil
	}
	out := make(toolgate.RuleSet, 0, len(entries))
	for _, e := range entries {
		var v toolgate.Verdict
		switch strings.ToLower(e.Verdict) {
		case "allow":
			v = toolgate.VerdictAllow
		case "deny":
			v = toolgate.VerdictDeny
		case "hitl", "approve":
			v = toolgate.VerdictHITL
		default:
			log.Printf("toolgate rule %q: unknown verdict %q (skipped)", e.Name, e.Verdict)
			continue
		}
		out = append(out, toolgate.Rule{
			Name:         e.Name,
			ToolName:     e.ToolName,
			ArgsContains: e.ArgsContains,
			Verdict:      v,
			Reason:       e.Reason,
		})
	}
	if len(out) > 0 {
		log.Printf("toolgate: %d rule(s) loaded from CLAWPATROL_TOOLGATE_RULES", len(out))
	}
	return out
}

// gateAnthropicResponse buffers the response body, runs the toolgate
// rule set, and returns a swapped response if the gate rewrote
// anything. The returned bool is whether a swap happened — false
// means the caller should keep the original resp. Errors are logged
// and swallowed (fail-open) so a gating bug never bricks the agent;
// the matched-deny path remains intact via the rule set's deny verdict.
func (g *Gateway) gateAnthropicResponse(ctx context.Context, resp *http.Response, ev *Event, fc *toolgate.FollowupConfig) (*http.Response, bool) {
	if resp == nil || resp.Body == nil {
		return resp, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, 8<<20))
	if err != nil {
		log.Printf("toolgate read upstream: %v", err)
		return resp, false
	}
	_ = resp.Body.Close()

	// gzip-aware: the gate operates on the decoded JSON; we re-encode
	// without compression on the way out (cheap, small bodies) so the
	// agent's decoder doesn't have to swallow a mis-framed gzip stream.
	decoded := body
	wasGzip := strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip")
	if wasGzip {
		zr, zerr := gzip.NewReader(bytes.NewReader(body))
		if zerr != nil {
			log.Printf("toolgate gunzip: %v", zerr)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return resp, false
		}
		decoded, err = io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			log.Printf("toolgate gunzip read: %v", err)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return resp, false
		}
	}

	outcome, err := toolgate.GateAnthropicResponse(ctx, g.toolgateRules, g.toolgate, decoded, fc)
	if err != nil {
		log.Printf("toolgate evaluate: %v", err)
		// Put the original body back so the caller's resp.Write
		// streams the upstream bytes verbatim.
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, false
	}
	if !outcome.Rewrote {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, false
	}

	// Attach a short marker to the dashboard event so operators can
	// see at a glance that this turn was gated. The notes carry rule
	// names + tokens; ev.Reason is the single-line summary slot.
	if ev != nil {
		if ev.Reason == "" {
			ev.Reason = fmt.Sprintf("toolgate: %d rewrite", len(outcome.Notes))
		} else {
			ev.Reason = ev.Reason + " | toolgate: " + strings.Join(outcome.Notes, "; ")
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(outcome.Body))
	resp.ContentLength = int64(len(outcome.Body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(outcome.Body)))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Transfer-Encoding")
	resp.TransferEncoding = nil
	return resp, true
}

// gateAnthropicSSEStream wires the streaming (text/event-stream) gate
// into the response. Unlike the JSON path it cannot buffer the whole
// body — it wraps resp.Body in a transforming pipe so frames are gated
// and forwarded incrementally, preserving the agent's time-to-first-
// token for non-tool_use content. The returned *SSEOutcome is filled in
// by the streaming goroutine and is safe to read once resp.Write has
// drained the body (the pipe close establishes the happens-before).
//
// FAIL CLOSED. The transform never forwards a tool_use it could not
// evaluate: an undecodable body or a stream error terminates the
// response rather than leaking the raw tool call. This is the explicit
// contract for the streaming path (the JSON path above still fails open
// on parse errors — see GateAnthropicResponse).
func (g *Gateway) gateAnthropicSSEStream(ctx context.Context, resp *http.Response, fc *toolgate.FollowupConfig) *toolgate.SSEOutcome {
	if resp == nil || resp.Body == nil {
		return nil
	}
	src := resp.Body
	var rdr io.Reader = src
	// Anthropic does not gzip SSE in practice, but a gzipped body we
	// can't decode might carry an ungated tool_use — so on a gunzip
	// failure we fail closed (terminate) rather than forward it raw.
	// Note: stripping Content-Encoding here means the usage tracker's
	// trackBuf (captured upstream, still gzipped) won't be re-inflated
	// for this rare case; non-gzip SSE — the norm — is unaffected.
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(src)
		if err != nil {
			log.Printf("toolgate sse gunzip: %v (failing closed)", err)
			_ = src.Close()
			resp.Body = io.NopCloser(bytes.NewReader(nil))
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = 0
			return nil
		}
		rdr = zr
	}

	out := &toolgate.SSEOutcome{}
	pr, pw := io.Pipe()
	go func() {
		err := toolgate.GateAnthropicSSE(ctx, g.toolgateRules, g.toolgate, rdr, pw, out, fc)
		_ = src.Close()
		if err != nil {
			log.Printf("toolgate sse: %v", err)
		}
		// CloseWithError(nil) is a clean EOF; a non-nil err surfaces to
		// resp.Write so the client connection breaks (fail closed).
		_ = pw.CloseWithError(err)
	}()

	resp.Body = pr
	// We emit decoded, chunked SSE; drop framing headers that no longer
	// describe the body.
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	if len(resp.TransferEncoding) == 0 {
		resp.TransferEncoding = []string{"chunked"}
	}
	return out
}

// loadToolgateApprovalURL reads the base URL the agent's polling tool
// should target, from CLAWPATROL_TOOLGATE_APPROVAL_URL. The follow-up
// model is told to POST to <base>/api/approval/poll. Empty falls back to
// toolgate.DefaultApprovalBaseURL — a placeholder that must be overridden
// for the polling call to actually connect to clawpatrol from the agent's
// network.
func loadToolgateApprovalURL() string {
	return strings.TrimRight(os.Getenv("CLAWPATROL_TOOLGATE_APPROVAL_URL"), "/")
}

// newToolgateFollowup builds the per-request FollowupConfig for the
// gateway-initiated HITL "LLM picks the polling tool" dance. reqBody is
// the agent's full original /v1/messages body (nil when it couldn't be
// buffered — the follow-up then no-ops and HITL degrades to a text
// block). The caller reuses req's already-injected credentials and the
// same upstream transport to round-trip clawpatrol's own LLM call.
func (g *Gateway) newToolgateFollowup(req *http.Request, transport *http.Transport, profile string, reqBody []byte) *toolgate.FollowupConfig {
	return &toolgate.FollowupConfig{
		ReqBody:     reqBody,
		ApprovalURL: g.toolgateApprovalURL,
		Caller:      g.newToolgateLLMCaller(req, transport, profile),
	}
}

// newToolgateLLMCaller returns a toolgate.LLMCaller bound to this
// request's credential-injected template and the upstream transport. The
// follow-up clones req (which already carries the injected Anthropic auth
// header — header injection, not body signing, so swapping the body is
// safe), replaces the body with the rebuilt conversation, forces a
// non-streaming JSON response, and round-trips it upstream. The follow-up
// never re-enters the MITM handler, so it is not itself re-gated.
func (g *Gateway) newToolgateLLMCaller(req *http.Request, transport *http.Transport, profile string) toolgate.LLMCaller {
	return func(ctx context.Context, body []byte) ([]byte, error) {
		fr := req.Clone(context.WithValue(ctx, profileCtxKey{}, profile))
		fr.Body = io.NopCloser(bytes.NewReader(body))
		fr.ContentLength = int64(len(body))
		fr.Header.Set("Content-Type", "application/json")
		fr.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		// Ask for identity encoding so the JSON is readable without a
		// gunzip step; we still handle gzip below in case upstream ignores
		// it.
		fr.Header.Set("Accept-Encoding", "identity")
		fr.Header.Del("Content-Encoding")

		resp, err := transport.RoundTrip(fr)
		if err != nil {
			return nil, fmt.Errorf("toolgate follow-up roundtrip: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		rb, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, maxToolgateReqBody))
		if err != nil {
			return nil, fmt.Errorf("toolgate follow-up read: %w", err)
		}
		if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			if zr, zerr := gzip.NewReader(bytes.NewReader(rb)); zerr == nil {
				if d, derr := io.ReadAll(zr); derr == nil {
					rb = d
				}
				_ = zr.Close()
			}
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("toolgate follow-up upstream status %d", resp.StatusCode)
		}
		return rb, nil
	}
}

// bufferFullHTTPBody reads up to cap bytes of req.Body, re-attaches what
// it read in front of the remaining stream so the upstream forward stays
// byte-exact, and returns the buffered bytes. It returns nil when the
// body is absent, unreadable, or larger than cap (a too-large body
// disables the toolgate follow-up for that turn rather than feeding it a
// truncated, unparseable JSON request).
func bufferFullHTTPBody(req *http.Request, limit int64) []byte {
	if req.Body == nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	if err != nil {
		return nil
	}
	req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), req.Body))
	if int64(len(b)) > limit {
		return nil
	}
	return b
}
