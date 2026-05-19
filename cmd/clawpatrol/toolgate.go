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
// Streaming SSE responses (text/event-stream) are filtered out by the
// caller's Content-Type check; this function assumes a buffered JSON
// body.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/denoland/clawpatrol/internal/toolgate"
)

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
func (g *Gateway) gateAnthropicResponse(resp *http.Response, ev *Event) (*http.Response, bool) {
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

	outcome, err := toolgate.GateAnthropicResponse(g.toolgateRules, g.toolgate, decoded)
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
