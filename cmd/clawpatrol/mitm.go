package main

// HTTPS MITM handler + the byte-pipe / request-body helpers it depends
// on. mitmHTTPS is the single workhorse for every https-mitm endpoint
// (today: https, k8s; tomorrow: any facet whose Transport() returns
// "https-mitm"). The connection-dispatch entry points in dispatch.go
// land flows here once they've decided the destination wants a CA-
// signed leaf cert and a full HTTP request loop.
//
// pipeProgress + countWriter sit here because the splice / wgRelay
// paths and any future raw-byte forwarders share the same fan-out
// shape: copy each direction in its own goroutine, count bytes
// atomically, and optionally fire a per-second tick callback.
//
// bufferHTTPBodyForMatch* are kept next to mitmHTTPS — they exist
// solely to feed the matcher with a capped prefix of the request
// body before forwarding the original stream untouched.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/facet"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func pipeProgress(a, b net.Conn, onTick func(rx, tx int64)) (rx, tx int64) {
	var rxC, txC atomic.Int64
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 256<<10)
		_, _ = io.CopyBuffer(&countWriter{Writer: b, n: &txC}, a, buf)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 256<<10)
		_, _ = io.CopyBuffer(&countWriter{Writer: a, n: &rxC}, b, buf)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	stop := make(chan struct{})
	if onTick != nil {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					onTick(rxC.Load(), txC.Load())
				}
			}
		}()
	}
	<-done
	<-done
	close(stop)
	return rxC.Load(), txC.Load()
}

// countWriter wraps an io.Writer and atomically tallies bytes written
// so a concurrent ticker can read in-flight progress.
type countWriter struct {
	io.Writer
	n *atomic.Int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.n.Add(int64(n))
	}
	return n, err
}

const maxHTTPMatchBody = 1 << 20

func bufferHTTPBodyForMatch(req *http.Request) []byte {
	b, _ := bufferHTTPBodyForMatchTruncated(req)
	return b
}

// bufferHTTPBodyForMatchTruncated is bufferHTTPBodyForMatch with the
// overflow signal exposed: it reads one byte past the cap to detect
// truncation, then re-attaches whatever it pulled (cap + 1 byte) in
// front of the original stream so upstream still receives the body
// byte-for-byte. truncated is true iff the body extended beyond
// maxHTTPMatchBody; callers stash this on match.Request.Truncated so
// the dispatcher can fail-close rules that read http.body /
// http.body_json.
func bufferHTTPBodyForMatchTruncated(req *http.Request) (body []byte, truncated bool) {
	if req.Body == nil {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, maxHTTPMatchBody+1))
	if err != nil {
		return nil, false
	}
	if len(b) > maxHTTPMatchBody {
		// Pulled one byte past the cap — body is over-sized. Keep
		// the cap-sized prefix as the matcher's view; re-attach the
		// full read (including the probe byte) in front of the
		// remaining stream so the upstream forward stays byte-exact.
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), req.Body))
		return b[:maxHTTPMatchBody], true
	}
	// Body fit inside the cap (or was exactly cap bytes). Re-attach
	// what we read — req.Body may still hold bytes past it on a
	// chunked / unknown-length stream that just hadn't surfaced
	// before the ReadAll returned.
	req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), req.Body))
	return b, false
}

// mitmHTTPS handles an SNI-matched TLS connection for an HTTPS-family
// endpoint (https, kubernetes). It mints a leaf cert, terminates TLS,
// then loops reading HTTP requests and dispatching each through the
// compiled policy: runtime.MatchRequest picks the rule, the rule's
// Outcome decides verdict / approve. Allowed requests forward upstream
// over plain TLS with credential injection applied by the credential
// plugin's HTTPCredentialRuntime / HTTPRequestSigner / WebSocket hooks.
func (g *Gateway) mitmHTTPS(c net.Conn, host string, ep *config.CompiledEndpoint) {
	agentAddr := peerIP(c)
	profile := g.profileFor(agentAddr)
	agentAddr = g.agentIPFor(c)
	cert, err := g.certs.mint(host)
	if err != nil {
		log.Printf("mint %s: %v", host, err)
		return
	}
	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("mitm tls handshake %s: %v", host, err)
		return
	}
	defer func() { _ = tc.Close() }()

	// transport is shared across all requests for this endpoint.
	// Old path allocated a fresh http.Transport per mitmHTTPS call,
	// which threw away the idle-conn pool and racked up ~10KB of
	// internal map allocations per request. Per-endpoint cache lets
	// repeat requests to the same upstream reuse keep-alives.
	transport := g.transportFor(ep)

	br := bufio.NewReader(tc)
	for {
		_ = tc.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("mitm read req %s: %v", host, err)
			}
			return
		}
		_ = tc.SetReadDeadline(time.Time{})

		start := time.Now()
		pip := peerIP(c)

		// Body buffering. Any rule with a `body_json` or
		// `body_contains` match facet needs the body up-front; we
		// don't know which yet, so for any POST/PUT/PATCH with a
		// body we read up to 1 MiB and re-attach. Retry-grant
		// requests additionally buffer regardless of method: the
		// one-shot grant fingerprint is a same-request check, so a
		// body-bearing DELETE/GET must bind the exact bytes that will
		// continue to upstream. Reads beyond 1 MiB stream through
		// unbuffered (rare for agent traffic) but surface as
		// Truncated=true so the dispatcher/retry relay can fail-close
		// any path that needed the complete body.
		var matchBody []byte
		var truncated bool
		retryOperationID := strings.TrimSpace(req.Header.Get(hitlRetryOperationHeader))
		if req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" || retryOperationID != "" {
			matchBody, truncated = bufferHTTPBodyForMatchTruncated(req)
		}

		mreq := &match.Request{
			Family:    ep.Family,
			Method:    req.Method,
			URL:       req.URL,
			Headers:   req.Header,
			Body:      matchBody,
			PeerIP:    pip,
			Truncated: truncated,
		}
		// clickhouse_https carries the agent-declared database in
		// `?database=` or `X-ClickHouse-Database` (query wins). Other
		// HTTPS-family endpoints don't have a database concept; leave
		// mreq.Database empty for them.
		if ep.Plugin != nil && ep.Plugin.Type == "clickhouse_https" {
			mreq.Database = endpoints.ClickhouseHTTPSDatabaseFromRequest(req)
		}
		fac := facet.Lookup(ep.Family)
		if fac != nil {
			fac.PrepareRequest(mreq)
		}

		ev := Event{
			ID:     newReqID(),
			Mode:   "mitm",
			Family: ep.Family,
			Host:   host,
			Method: req.Method, Path: req.URL.Path,
			AgentIP:  agentAddr,
			Endpoint: ep.Name,
		}
		if fac != nil {
			ev.Facets = fac.Report(mreq)
		}
		// Emit start event so the dashboard renders the request as
		// in-flight immediately. The end event with the same ID
		// arrives when resp.Write finishes — long-poll / SSE / WS
		// requests no longer wait for connection close to surface.
		startEv := ev
		startEv.Phase = "start"
		startEv.Action = "in_flight"
		g.emit(startEv)

		cr := runtime.MatchRequest(ep, mreq)
		if cr != nil {
			ev.Rule = cr.Name
		}

		hitlRetryBypassedApproval := false
		var hitlRetryConsumedOperation *HITLOperation
		if retryOperationID != "" {
			principalID := hitlPeerPrincipalID(agentAddr)
			consumed, err := g.consumeHITLRetryGrantForRequest(req.Context(), hitlRetryRelayInput{
				OperationID: retryOperationID,
				ProfileID:   profile,
				PrincipalID: principalID,
				Endpoint:    ep,
				Rule:        cr,
				MatchReq:    mreq,
				HTTPRequest: req,
				RawBody:     matchBody,
				Truncated:   truncated,
			})
			if err != nil {
				status, contentType, body := hitlRetryRelayFailure(err)
				log.Printf("hitl retry rejected %s %s %s operation %q: %v", host, req.Method, req.URL.Path, retryOperationID, err)
				_, _ = fmt.Fprintf(tc, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), contentType, len(body), body)
				ev.Status = status
				ev.Action = "hitl_retry_rejected"
				ev.Reason = hitlRetryMismatchErrorValue
				if status == http.StatusNotFound {
					ev.Reason = hitlOperationNotFoundErrorValue
				}
				ev.Ms = time.Since(start).Milliseconds()
				g.emitEnd(ev)
				return
			}
			hitlRetryConsumedOperation = &consumed
			hitlRetryBypassedApproval = true
			ev.Action = "hitl_retry_approved"
			log.Printf("hitl retry approved %s %s %s operation %q by %s", host, req.Method, req.URL.Path, retryOperationID, principalID)
		}

		// Approve chain — dispatch each stage to its approver
		// runtime (config/plugins/approvers). All stages must
		// allow; first deny short-circuits.
		var asyncOp HITLOperation
		var asyncSyncWait time.Duration
		if cr != nil && len(cr.Outcome.Approve) > 0 && !hitlRetryBypassedApproval {
			if approverID, asyncApprover, ok := g.asyncHumanApproverFor(cr.Outcome.Approve); ok {
				start, started, err := g.maybeStartAsyncHITLOperation(req.Context(), hitlAsyncOperationInput{
					ProfileID:   profile,
					PrincipalID: hitlPeerPrincipalID(agentAddr),
					Endpoint:    ep,
					Rule:        cr,
					ApproverID:  approverID,
					Approver:    asyncApprover,
					MatchReq:    mreq,
					HTTPRequest: req,
					RawBody:     matchBody,
					Truncated:   truncated,
					Now:         time.Now().UTC(),
				})
				if err != nil {
					log.Printf("hitl async operation start %s %s: %v", host, req.URL.Path, err)
				} else if started {
					asyncOp = start.Operation
					asyncSyncWait = start.SyncWaitTimeout
				}
			}
			v := g.runApproveChain(req.Context(), cr.Outcome.Approve, runApproveCtx{
				AgentIP: agentAddr, Host: host, Method: req.Method, Path: req.URL.RequestURI(),
				UA: req.Header.Get("User-Agent"), BodySample: string(matchBody), Reason: cr.Outcome.Reason,
				ThreadTS: req.Header.Get("X-HITL-Thread-TS"),
				Endpoint: ep, Rule: cr, Profile: profile, Request: mreq,
				AsyncOperationID: asyncOp.ID, AsyncPendingOnSyncTimeout: asyncOp.ID != "", AsyncSyncWaitTimeout: asyncSyncWait,
			})
			if v.Decision != "allow" {
				if v.Decision == runtime.ApproveDecisionAsyncPending && asyncOp.ID != "" {
					updated, err := g.transitionAsyncHITLOperation(req.Context(), asyncOp, HITLOperationStatePendingApproval, "")
					if err != nil {
						log.Printf("hitl async operation pending %s: %v", asyncOp.ID, err)
					} else {
						asyncOp = updated
					}
					_ = tc.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if err := writeHITLOperationAcceptedToConn(tc, asyncOp, g.cfg.PublicURL()); err != nil {
						log.Printf("hitl async pending response write %s: %v", asyncOp.ID, err)
					}
					_ = tc.SetWriteDeadline(time.Time{})
					ev.Status = http.StatusAccepted
					ev.Action = "hitl_async_pending"
					ev.Approver = v.ApproverName
					ev.ApproverType = v.ApproverType
					ev.ApproverBy = v.By
					ev.Reason = v.Reason
					ev.Ms = time.Since(start).Milliseconds()
					g.emitEnd(ev)
					return
				}
				if asyncOp.ID != "" {
					if _, err := g.transitionAsyncHITLOperation(req.Context(), asyncOp, HITLOperationStateDenied, v.Reason); err != nil {
						log.Printf("hitl async operation deny %s: %v", asyncOp.ID, err)
					}
				}
				reason := v.Reason
				if reason == "" {
					reason = "denied by approver"
				}
				log.Printf("denied %s %s %s: %s (by %s/%s/%s)",
					host, req.Method, req.URL.Path, reason, v.ApproverType, v.ApproverName, v.By)
				_, _ = fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reason), reason)
				ev.Status = 403
				ev.Action = "denied"
				ev.Approver = v.ApproverName
				ev.ApproverType = v.ApproverType
				ev.ApproverBy = v.By
				ev.Reason = reason
				ev.Ms = time.Since(start).Milliseconds()
				g.emitEnd(ev)
				return
			}
			if asyncOp.ID != "" {
				if updated, err := g.transitionAsyncHITLOperation(req.Context(), asyncOp, HITLOperationStateExecutingUpstream, ""); err != nil {
					log.Printf("hitl async operation executing %s: %v", asyncOp.ID, err)
				} else {
					asyncOp = updated
				}
			}
			log.Printf("approved %s %s %s by %s/%s/%s",
				host, req.Method, req.URL.Path, v.ApproverType, v.ApproverName, v.By)
			ev.Action = "approved"
			ev.Approver = v.ApproverName
			ev.ApproverType = v.ApproverType
			ev.ApproverBy = v.By
		}

		// Verdict.
		if cr != nil && cr.Outcome.Verdict == "deny" {
			reason := cr.Outcome.Reason
			if reason == "" {
				reason = "denied by policy"
			}
			log.Printf("deny %s %s %s: %s (rule %q)", host, req.Method, req.URL.Path, reason, cr.Name)
			if hitlRetryConsumedOperation != nil {
				if err := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, HITLOperationStateUpstreamFailed, reason); err != nil {
					log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, HITLOperationStateUpstreamFailed, err)
				}
			}
			_, _ = fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reason), reason)
			ev.Status = 403
			ev.Action = "deny"
			ev.Reason = reason
			ev.Ms = time.Since(start).Milliseconds()
			g.emitEnd(ev)
			return
		}

		// Forward upstream. Hop-by-hop / proxy-leak headers stripped
		// per RFC 7230 §6.1 plus chatgpt.com / Cloudflare flagged set.
		// WS upgrade requests skip this strip block — Connection +
		// Upgrade are part of the handshake (codex hits chatgpt.com
		// /backend-api/codex/responses as a WS upgrade and the server
		// flags requests with Sec-Websocket-* but no Upgrade as
		// "Attack detected"). isWSUpgrade is checked again below to
		// route through handleWSUpgrade after credential injection.
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.Host = host
		req.RequestURI = ""
		req.Header.Del(hitlRetryOperationHeader)
		if !isWSUpgrade(req) {
			for _, h := range []string{
				"Connection", "Keep-Alive", "Proxy-Authenticate",
				"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
				"Cf-Worker", "Cf-Ray", "Cf-Ew-Via", "Cf-Connecting-Ip", "Cdn-Loop",
				"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Via",
				"X-HITL-Thread-TS",
			} {
				req.Header.Del(h)
			}
		}

		// Endpoint-level synthetic-response hook. The endpoint
		// plugin's runtime can short-circuit specific paths and
		// return a clawpatrol-generated response without forwarding
		// upstream — used by openai_codex_https to serve the JWKS +
		// agent-task-register stubs that anchor codex's Agent
		// Identity flow on hosts we MITM. Endpoints without a
		// responder (the default https plugin) fall through.
		if responder, ok := ep.Plugin.Runtime.(runtime.HTTPSyntheticResponder); ok {
			if r, handled, err := responder.RespondHTTP(req.Context(), req); err != nil {
				log.Printf("respond %s: %v", ep.Name, err)
			} else if handled {
				if r.Body != nil {
					defer func() { _ = r.Body.Close() }()
				}
				ev.Status = r.StatusCode
				ev.Action = "synth"
				// Synthetic responses are clawpatrol-generated, so the
				// stock plugins don't set auth-bearing headers — but
				// the no-injected-credential-reaches-the-agent guarantee
				// shouldn't rely on plugin authors remembering that.
				// Strip the same list as the upstream-forwarded path
				// so a future plugin that mirrors response headers from
				// an upstream lookup can't accidentally leak them.
				stripAuthResponseHeaders(r.Header)
				stripAuthResponseHeaders(r.Trailer)
				writeErr := r.Write(tc)
				if hitlRetryConsumedOperation != nil {
					toState := HITLOperationStateUpstreamSucceeded
					lastErr := ""
					if writeErr != nil {
						toState = HITLOperationStateUpstreamFailed
						lastErr = writeErr.Error()
					}
					if err := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, toState, lastErr); err != nil {
						log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, toState, err)
					}
				}
				if writeErr != nil {
					log.Printf("synth write %s %s: %v", host, req.URL.Path, writeErr)
				}
				ev.Ms = time.Since(start).Milliseconds()
				g.emitEnd(ev)
				continue
			}
		}

		// Credential injection. Pick the credential entry that
		// applies to this request (singular binding short-circuits;
		// multi-credential dispatch asks the endpoint plugin's
		// PlaceholderDetector which placeholder the agent sent),
		// fetch the secret bytes from the configured store, and
		// hand both to the credential plugin's request-time runtime hooks
		// to stamp HTTP auth or rewrite server-bound WS token placeholders.
		// Schema-only credential types leave Runtime nil; we pass through
		// verbatim and rely on policy alone.
		var rewriteWSPayload wsPayloadRewriter
		var reqBodySecretRedactions []string
		if cc := runtime.ResolveCredential(g.Policy(), profile, ep, mreq); cc != nil {
			// Plugin.Runtime is a typed-nil sentinel used only for
			// interface-compliance assertions; the actual decoded HCL
			// values (BearerToken.IdempotencyKey, PostgresCredential.User,
			// etc.) live on Body. Invoke methods through Body so the
			// receiver is the real instance.
			injector, wantsHTTP := cc.Credential.Body.(runtime.HTTPCredentialRuntime)
			signer, wantsSign := cc.Credential.Body.(runtime.HTTPRequestSigner)
			wsRewriter, wantsWS := cc.Credential.Body.(runtime.WebSocketCredentialRuntime)
			if wantsHTTP || wantsSign || (wantsWS && isWSUpgrade(req)) {
				sec, err := g.secrets.Get(cc.Credential.Symbol.Name)
				if err != nil {
					log.Printf("secret %s: %v — forwarding without injection", cc.Credential.Symbol.Name, err)
				} else if len(sec.Bytes) == 0 && len(sec.Extras) == 0 {
					log.Printf("secret %s: not configured (set CLAWPATROL_SECRET_%s)", cc.Credential.Symbol.Name, secretEnvName(cc.Credential.Symbol.Name))
				} else {
					// SignHTTPRequest takes precedence over InjectHTTP:
					// signing schemes (SigV4) read the endpoint to
					// pick up service/region, span the whole request,
					// and replace any auth headers the agent stamped.
					// No built-in credential implements both, but the
					// branch is harmless if one ever does.
					switch {
					case wantsSign:
						reqBodySecretRedactions = appendCredentialSecretRedactions(reqBodySecretRedactions, sec)
						if err := signer.SignHTTPRequest(req.Context(), req, sec, ep.Body); err != nil {
							log.Printf("sign %s: %v", cc.Credential.Symbol.Name, err)
						}
					case wantsHTTP:
						reqBodySecretRedactions = appendCredentialSecretRedactions(reqBodySecretRedactions, sec)
						if err := injector.InjectHTTP(req.Context(), req, sec); err != nil {
							log.Printf("inject %s: %v", cc.Credential.Symbol.Name, err)
						}
					}
					if wantsWS && isWSUpgrade(req) {
						wsSec := sec
						rewriteWSPayload = func(payload []byte) ([]byte, bool, error) {
							return wsRewriter.RewriteWebSocketPayload(req.Context(), payload, wsSec)
						}
					}
				}
			}
		}

		// WebSocket upgrade. http.Transport.RoundTrip mangles the
		// 101 response and Cloudflare's WAF rejects unexpectedly modified
		// frames, so we hand off to a raw byte bridge. Frames remain
		// byte-faithful unless the selected credential provides an explicit
		// WS token-placeholder rewriter (for example Discord Gateway
		// IDENTIFY). The handler runs until either side closes — when it
		// returns, the caller's request loop ends naturally.
		if isWSUpgrade(req) {
			log.Printf("ws-upgrade %s %s", host, req.URL.Path)
			ev.Action = "ws"
			// Frame-level observability: handleWSUpgrade emits one
			// frame event per WS message in either direction so the
			// dashboard can render them like pg queries instead of
			// surfacing a single "ws" row at session close. Carries
			// the same request ID as the upgrade so the dashboard
			// nests them under the parent row.
			frameEmit := func(direction string, sample string) {
				g.sink.Emit(Event{
					Ts:        time.Now().UTC(),
					ID:        ev.ID,
					Phase:     "frame",
					Mode:      "mitm",
					Host:      host,
					Method:    "WS",
					Path:      req.URL.Path,
					AgentIP:   ev.AgentIP,
					Frame:     sample,
					Direction: direction,
				})
			}
			g.handleWSUpgrade(tc, br, req, host, frameEmit, ep, profile, rewriteWSPayload)
			if hitlRetryConsumedOperation != nil {
				if err := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, HITLOperationStateUpstreamSucceeded, ""); err != nil {
					log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, HITLOperationStateUpstreamSucceeded, err)
				}
			}
			ev.Status = 101
			ev.Ms = time.Since(start).Milliseconds()
			g.emitEnd(ev)
			return
		}

		trackKind := trackKindFor(host)
		var trackedReqBody []byte
		if trackKind != "" {
			trackedReqBody = bufferHTTPBodyForMatch(req)
		}
		// Pre-create session from the request body so streaming SSE
		// responses (codex /backend-api/codex/responses, anthropic
		// /v1/messages with stream:true) surface in the dashboard at
		// turn-start, not at turn-end. trackLLMUsage below runs after
		// resp.Write completes — which for codex can be minutes. WS
		// reports per-frame; HTTP needs this kickoff so it doesn't lag.
		sessionHint := req.Header.Get("Session_id")
		if sessionHint == "" {
			sessionHint = req.Header.Get("Session-Id")
		}
		if trackKind != "" && len(trackedReqBody) > 0 && g.agents != nil {
			g.preCreateLLMSession(c, trackKind, req.URL.Path, trackedReqBody, sessionHint)
		}
		reqS := newSampler(4096)
		if req.Body != nil {
			req.Body = wrapBodySampler(req.Body, reqS)
		}

		rtStart := time.Now()
		resp, err := transport.RoundTrip(req.WithContext(context.WithValue(req.Context(), profileCtxKey{}, profile)))
		rtDur := time.Since(rtStart)
		if err != nil {
			if asyncOp.ID != "" {
				if _, trErr := g.transitionAsyncHITLOperation(req.Context(), asyncOp, HITLOperationStateUpstreamFailed, hitlAsyncFailureReason(err)); trErr != nil {
					log.Printf("hitl async operation upstream failed %s: %v", asyncOp.ID, trErr)
				}
			}
			log.Printf("mitm upstream %s %s: %v", host, req.URL.Path, err)
			if hitlRetryConsumedOperation != nil {
				if transitionErr := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, HITLOperationStateUpstreamFailed, err.Error()); transitionErr != nil {
					log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, HITLOperationStateUpstreamFailed, transitionErr)
				}
			}
			_, _ = fmt.Fprintf(tc, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			ev.Status = 502
			ev.Action = "error"
			ev.Reason = err.Error()
			ev.Ms = time.Since(start).Milliseconds()
			ev.ReqSha = reqS.sha()
			ev.ReqBody = redactCredentialSample(reqS.sample(req.Header.Get("Content-Encoding")), reqBodySecretRedactions)
			ev.In = reqS.n
			g.emitEnd(ev)
			return
		}
		var trackBuf *bytes.Buffer
		if trackKind != "" && resp.StatusCode == 200 {
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "json") || strings.Contains(ct, "event-stream") {
				trackBuf = &bytes.Buffer{}
				resp.Body = io.NopCloser(io.TeeReader(resp.Body, trackBuf))
			}
		}
		respS := newSampler(4096)
		resp.Body = wrapBodySampler(resp.Body, respS)
		// Close-delimited responses (no Content-Length, no Transfer-
		// Encoding) come from h2 upstreams that we forced to http/1.1
		// via ALPN — Go's transport leaves cl=-1 and te=[] in that
		// case. Without an explicit terminator, peers (curl, browsers)
		// idle until the conn closes, which the 60s ReadRequest
		// deadline then triggers — a ~60s perceived delay per request.
		// Re-frame as chunked so the peer sees a proper end-of-body.
		if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 && !resp.Close {
			resp.TransferEncoding = []string{"chunked"}
		}
		// Snapshot the upstream's response headers for the audit log
		// before stripping credential-bearing ones — the dashboard
		// still wants to show what the upstream actually sent.
		ev.RespHeaders = flatHeaders(resp.Header)
		stripAuthResponseHeaders(resp.Header)
		// Trailers fall outside resp.Header — Go's http.Transport
		// surfaces them on resp.Trailer and http.Response.Write
		// emits them after the chunked body. RFC 9110 §6.5.1 bans
		// Set-Cookie / auth fields in trailers, but a hostile or
		// buggy upstream can still try it, so we strip the same
		// list off the trailer block before resp.Write streams it.
		stripAuthResponseHeaders(resp.Trailer)
		writeErr := resp.Write(tc)
		_ = rtDur
		_ = resp.Body.Close()
		if trackBuf != nil && g.agents != nil {
			body := trackBuf.Bytes()
			if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
				if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
					if d, err := io.ReadAll(zr); err == nil {
						body = d
					}
					_ = zr.Close()
				}
			}
			g.trackLLMUsage(c, trackKind, req.URL.Path, trackedReqBody, body, sessionHint)
		}

		if hitlRetryConsumedOperation != nil {
			toState := HITLOperationStateUpstreamSucceeded
			lastErr := ""
			if writeErr != nil {
				toState = HITLOperationStateUpstreamFailed
				lastErr = writeErr.Error()
			}
			if err := g.transitionConsumedHITLRetryGrant(context.Background(), *hitlRetryConsumedOperation, toState, lastErr); err != nil {
				log.Printf("hitl retry transition %s to %s: %v", hitlRetryConsumedOperation.ID, toState, err)
			}
		}

		if ev.Action == "" {
			ev.Action = "allow"
		}
		if asyncOp.ID != "" {
			to := HITLOperationStateUpstreamSucceeded
			lastErr := ""
			if writeErr != nil {
				to = HITLOperationStateUpstreamFailed
				lastErr = hitlAsyncFailureReason(writeErr)
			}
			if _, err := g.transitionAsyncHITLOperation(req.Context(), asyncOp, to, lastErr); err != nil {
				log.Printf("hitl async operation upstream terminal %s: %v", asyncOp.ID, err)
			}
		}
		ev.Status = resp.StatusCode
		ev.ReqHeaders = flatHeaders(req.Header)
		ev.In = reqS.n
		ev.Out = respS.n
		ev.ReqSha = reqS.sha()
		ev.ReqBody = redactCredentialSample(reqS.sample(req.Header.Get("Content-Encoding")), reqBodySecretRedactions)
		ev.RespSha = respS.sha()
		ev.RespBody = respS.sample(resp.Header.Get("Content-Encoding"))
		ev.Ms = time.Since(start).Milliseconds()
		g.emitEnd(ev)
		if g.agents != nil && agentAddr != "" {
			g.agents.trackUA(agentAddr, host, req.UserAgent(), reqS.n, respS.n)
		}

		if writeErr != nil {
			log.Printf("mitm resp write %s: %v", host, writeErr)
			return
		}
		if req.Close || resp.Close {
			return
		}
	}
}

// secretEnvName mirrors EnvSecretStore's lookup key derivation so log
// messages can hint at the exact var name an operator should set.
// Uppercase, hyphens → underscores.
func secretEnvName(credName string) string {
	return strings.ToUpper(strings.ReplaceAll(credName, "-", "_"))
}
