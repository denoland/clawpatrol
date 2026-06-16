package extplugin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// transformHTTPWithExternalCredential runs the streaming credential
// transform for an http_transform credential. It streams the request body
// to the plugin, applies the returned head (header / method / URL
// mutations) before the request is forwarded, and replaces the request
// body with the plugin's transformed stream.
//
// On any error it returns without leaving a usable request: the body has
// been streamed to the plugin (consumed), so the caller must fail closed
// rather than forward a half-transformed request — see
// dynamicCredentialBody.RewritesHTTPRequest and the gateway call site.
//
// Trailers: the request's trailers (e.g. gRPC's) are conveyed to the
// plugin for inspection and pass through to the upstream unchanged
// (req.Trailer is left in place).
func transformHTTPWithExternalCredential(ctx context.Context, body *dynamicCredentialBody, req *http.Request, sec runtime.Secret) (err error) {
	if body.adapter == nil || body.adapter.client == nil || body.adapter.client.credential == nil {
		return fmt.Errorf("extplugin: credential %q TransformHTTP unavailable: plugin client is not connected", body.instanceName)
	}

	// The stream runs under a cancelable context. On any error return we
	// cancel — tearing down the gRPC stream and the up-pump goroutine. On
	// success the down-pump goroutine owns the context and cancels once the
	// transformed body is fully delivered (or the stream errors), which
	// also stops the up-pump. Without this a stuck plugin would leak both
	// goroutines and the stream (the request context is never canceled).
	streamCtx, cancel := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			cancel()
		}
	}()

	stream, serr := body.adapter.client.credential.TransformHTTP(streamCtx)
	if serr != nil {
		return fmt.Errorf("extplugin: credential %s.%s TransformHTTP: %w", body.adapter.typeName, body.instanceName, serr)
	}
	if serr := stream.Send(&pb.TransformHTTPUp{Kind: &pb.TransformHTTPUp_Init{Init: &pb.TransformHTTPInit{
		CredentialTypeName:      body.adapter.typeName,
		CredentialInstance:      body.instanceName,
		CredentialCanonicalJson: body.canonicalJSON,
		CredentialSecret:        sec.Bytes,
		CredentialExtras:        sec.Extras,
		Method:                  req.Method,
		Url:                     req.URL.String(),
		Host:                    req.Host,
		Headers:                 headersToProto(req.Header),
	}}}); serr != nil {
		return fmt.Errorf("extplugin: credential %s.%s TransformHTTP send init: %w", body.adapter.typeName, body.instanceName, serr)
	}

	// Up-pump: stream the request body to the plugin, then an eof frame
	// carrying the request trailers (populated once the body is fully
	// read). Closes the original body and half-closes the send direction
	// when done; exits if the stream is canceled mid-send.
	origBody := req.Body
	go func() {
		defer func() {
			if origBody != nil {
				_ = origBody.Close()
			}
			_ = stream.CloseSend()
		}()
		if origBody != nil {
			buf := make([]byte, brokeredDialChunk)
			for {
				n, rerr := origBody.Read(buf)
				if n > 0 {
					if serr := stream.Send(&pb.TransformHTTPUp{Kind: &pb.TransformHTTPUp_Body{
						Body: &pb.HTTPBodyChunk{Data: append([]byte(nil), buf[:n]...)},
					}}); serr != nil {
						return
					}
				}
				if rerr != nil {
					break
				}
			}
		}
		eof := &pb.HTTPBodyChunk{Eof: true}
		if len(req.Trailer) > 0 {
			eof.Trailers = headersToProto(req.Trailer)
		}
		_ = stream.Send(&pb.TransformHTTPUp{Kind: &pb.TransformHTTPUp_Body{Body: eof}})
	}()

	// The head must arrive before we forward — a body-derived header (a
	// SigV4 signature) is finalized here. Bound the wait: a buggy plugin
	// that never sends the head must not hang the request. The timer fires
	// cancel(), which unblocks the Recv with a context error.
	headTimer := time.AfterFunc(injectHTTPTimeout, cancel)
	first, rerr := stream.Recv()
	headTimer.Stop()
	if rerr != nil {
		return fmt.Errorf("extplugin: credential %s.%s TransformHTTP recv head: %w", body.adapter.typeName, body.instanceName, rerr)
	}
	headMsg, ok := first.GetKind().(*pb.TransformHTTPDown_Head)
	if !ok || headMsg.Head == nil {
		return fmt.Errorf("extplugin: credential %s.%s TransformHTTP: first reply must be the head", body.adapter.typeName, body.instanceName)
	}
	head := headMsg.Head
	applyHeaderMutations(req.Header, head.Headers)
	if m := head.GetMethod(); m != "" {
		req.Method = m
	}
	if u := head.GetUrl(); u != "" {
		parsed, perr := url.Parse(u)
		if perr != nil {
			return fmt.Errorf("extplugin: credential %s.%s returned invalid url %q: %w", body.adapter.typeName, body.instanceName, u, perr)
		}
		req.URL = parsed
	}
	body.recordHTTPRedactions(req, head.Redactions)
	syncTransformContentLength(req)

	// Down-pump owns the stream now: feed the plugin's transformed body
	// chunks into the pipe that becomes the new req.Body, and cancel() when
	// done (eof, stream error, or the forwarder closing pr) so the up-pump
	// and stream are torn down. Trailers on the plugin's eof frame are
	// accepted but not applied to req in v1 (request trailers pass through
	// unchanged); see the doc comment.
	pr, pw := io.Pipe()
	req.Body = pr
	go func() {
		defer cancel()
		for {
			msg, mrerr := stream.Recv()
			if mrerr != nil {
				_ = pw.CloseWithError(mrerr)
				return
			}
			b, ok := msg.GetKind().(*pb.TransformHTTPDown_Body)
			if !ok || b.Body == nil {
				continue
			}
			if len(b.Body.Data) > 0 {
				if _, werr := pw.Write(b.Body.Data); werr != nil {
					return
				}
			}
			if b.Body.Eof {
				_ = pw.Close()
				return
			}
		}
	}()
	return nil
}

// syncTransformContentLength sets req.ContentLength from a Content-Length
// header the transform credential supplied (it knows the new body length),
// or marks the length unknown so the forwarder uses chunked transfer. A
// credential that changes the body length but leaves a stale Content-Length
// would corrupt the upstream write — it must update or drop the header.
func syncTransformContentLength(req *http.Request) {
	if cl := req.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n >= 0 {
			req.ContentLength = n
			return
		}
	}
	req.ContentLength = -1
	req.Header.Del("Content-Length")
}
