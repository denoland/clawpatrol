package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// applyRequestMiddleware runs an endpoint's ordered middleware chain
// against the request body. It is called from the HTTPS dispatcher
// after credential injection and before the upstream forward: each
// middleware sees the output of the previous one, so the chain composes
// in declared order.
//
// The request body is read in full and the returned bytes are what the
// caller forwards upstream (the caller re-attaches them and fixes
// Content-Length). A middleware that returns an error aborts the chain;
// the error is returned here and the caller fails the request closed
// (502, no upstream call). Middleware entries whose runtime doesn't
// implement runtime.HTTPMiddleware are skipped — a schema-only
// middleware is inert rather than fatal.
//
// Callers should only invoke this when mws is non-empty; the body read
// is unconditional otherwise.
func applyRequestMiddleware(req *http.Request, mws []*config.CompiledMiddleware) ([]byte, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		body = b
	}
	for _, mw := range mws {
		r, ok := mw.Body.(runtime.HTTPMiddleware)
		if !ok {
			continue
		}
		out, err := r.RewriteHTTPRequest(req.Context(), req, body)
		if err != nil {
			return nil, fmt.Errorf("middleware %s: %w", mw.Name, err)
		}
		body = out
	}
	return body, nil
}
