package extplugin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// transformHTTPWithExternalCredential runs the streaming credential
// transform for an http_transform credential. It streams the request body
// to the plugin, applies the returned head (header / method / URL
// mutations) before the request is forwarded, and replaces the request
// body with the plugin's transformed stream.
//
// Trailers: the request's trailers (e.g. gRPC's) are conveyed to the
// plugin for inspection and pass through to the upstream unchanged
// (req.Trailer is left in place). Plugin-rewritten request trailers are a
// follow-up — rewriting them safely across the body swap is non-trivial
// (Go populates req.Trailer from the original body read).
func transformHTTPWithExternalCredential(ctx context.Context, body *dynamicCredentialBody, req *http.Request, sec runtime.Secret) error {
	if body.adapter == nil || body.adapter.client == nil || body.adapter.client.credential == nil {
		return fmt.Errorf("extplugin: credential %q TransformHTTP unavailable: plugin client is not connected", body.instanceName)
	}
	stream, err := body.adapter.client.credential.TransformHTTP(ctx)
	if err != nil {
		return fmt.Errorf("extplugin: credential %s.%s TransformHTTP: %w", body.adapter.typeName, body.instanceName, err)
	}

	if err := stream.Send(&pb.TransformHTTPUp{Kind: &pb.TransformHTTPUp_Init{Init: &pb.TransformHTTPInit{
		CredentialTypeName:      body.adapter.typeName,
		CredentialInstance:      body.instanceName,
		CredentialCanonicalJson: body.canonicalJSON,
		CredentialSecret:        sec.Bytes,
		CredentialExtras:        sec.Extras,
		Method:                  req.Method,
		Url:                     req.URL.String(),
		Host:                    req.Host,
		Headers:                 headersToProto(req.Header),
	}}}); err != nil {
		return fmt.Errorf("extplugin: credential %s.%s TransformHTTP send init: %w", body.adapter.typeName, body.instanceName, err)
	}

	// Up-pump: stream the request body to the plugin, then an eof frame
	// carrying the request trailers (populated once the body is fully
	// read). req.Trailer is read here, by this goroutine, right after the
	// body EOFs — and otherwise only by the forwarder after the swapped
	// body EOFs (which is strictly later), so no concurrent access.
	origBody := req.Body
	go func() {
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
			_ = origBody.Close()
		}
		eof := &pb.HTTPBodyChunk{Eof: true}
		if len(req.Trailer) > 0 {
			eof.Trailers = headersToProto(req.Trailer)
		}
		_ = stream.Send(&pb.TransformHTTPUp{Kind: &pb.TransformHTTPUp_Body{Body: eof}})
	}()

	// Receive the head — it must arrive before we forward, since a
	// body-derived header (a SigV4 signature) is finalized here.
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("extplugin: credential %s.%s TransformHTTP recv head: %w", body.adapter.typeName, body.instanceName, err)
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

	// Down-pump: feed the plugin's transformed body chunks into a pipe
	// that becomes the new req.Body. Trailers on the plugin's eof frame
	// are accepted but not applied to req in v1 (see the doc comment).
	pr, pw := io.Pipe()
	req.Body = pr
	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				_ = pw.CloseWithError(rerr)
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
// or marks the length unknown so the forwarder uses chunked transfer.
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
