package pluginsdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

// TransformHTTP serves the streaming credential-transform RPC for
// HTTPTransform credentials. The gateway sends an init then streams the
// request body; the plugin's callback receives the body as an io.Reader,
// returns the head mutations plus the outgoing body, and the SDK streams
// that back. See the proto for the framing and CredentialDef.TransformHTTP
// for the plugin contract.
func (s *server) TransformHTTP(stream pb.Credential_TransformHTTPServer) error {
	ctx := stream.Context()

	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("pluginsdk TransformHTTP: recv init: %w", err)
	}
	initMsg, ok := first.GetKind().(*pb.TransformHTTPUp_Init)
	if !ok || initMsg.Init == nil {
		return errors.New("pluginsdk TransformHTTP: first message must be init")
	}
	in := initMsg.Init
	def, ok := s.credentials[in.CredentialTypeName]
	if !ok {
		return fmt.Errorf("%w: credential %q", ErrNoSuchType, in.CredentialTypeName)
	}
	if def.TransformHTTP == nil {
		return fmt.Errorf("pluginsdk: credential %q has no TransformHTTP callback", in.CredentialTypeName)
	}

	// A goroutine receives the request body chunks into a pipe the plugin
	// reads as req.Body. Request trailers arrive on the eof frame; they
	// are filled into reqTrailers before the pipe is closed, so a plugin
	// that reads them after Body hits EOF sees them (the pipe's close /
	// read ordering provides the happens-before).
	pr, pw := io.Pipe()
	reqTrailers := http.Header{}
	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				_ = pw.CloseWithError(rerr)
				return
			}
			b, ok := msg.GetKind().(*pb.TransformHTTPUp_Body)
			if !ok || b.Body == nil {
				continue
			}
			if len(b.Body.Data) > 0 {
				if _, werr := pw.Write(b.Body.Data); werr != nil {
					return
				}
			}
			if b.Body.Eof {
				copyHeader(reqTrailers, headersFromProto(b.Body.Trailers))
				_ = pw.Close()
				return
			}
		}
	}()

	req := HTTPTransformRequest{
		CredentialTypeName:        in.CredentialTypeName,
		CredentialInstance:        in.CredentialInstance,
		CredentialCanonicalConfig: in.CredentialCanonicalJson,
		CredentialSecret:          in.CredentialSecret,
		CredentialExtras:          in.CredentialExtras,
		Method:                    in.Method,
		URL:                       in.Url,
		Host:                      in.Host,
		Headers:                   headersFromProto(in.Headers),
		Body:                      pr,
		Trailers:                  reqTrailers,
	}

	resp, err := invokeTransformHTTP(ctx, in.CredentialTypeName, in.CredentialInstance, def.TransformHTTP, req)
	if err != nil {
		_ = pr.CloseWithError(err) // unblock the recv goroutine's pipe writes
		return err
	}
	if resp == nil {
		resp = &HTTPTransformResponse{}
	}

	head := &pb.TransformHTTPHead{
		Headers:    headerMutationsToProto(resp.Headers),
		Redactions: append([]string(nil), resp.Redactions...),
	}
	if resp.Method != "" {
		head.Method = &resp.Method
	}
	if resp.URL != "" {
		head.Url = &resp.URL
	}
	if err := stream.Send(&pb.TransformHTTPDown{Kind: &pb.TransformHTTPDown_Head{Head: head}}); err != nil {
		return err
	}

	// Stream the outgoing body.
	out := resp.Body
	if out == nil {
		out = bytes.NewReader(nil)
	}
	buf := make([]byte, 32*1024)
	for {
		n, rerr := out.Read(buf)
		if n > 0 {
			if serr := stream.Send(&pb.TransformHTTPDown{Kind: &pb.TransformHTTPDown_Body{
				Body: &pb.HTTPBodyChunk{Data: append([]byte(nil), buf[:n]...)},
			}}); serr != nil {
				return serr
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return fmt.Errorf("pluginsdk TransformHTTP: read transformed body: %w", rerr)
		}
	}

	// Outgoing trailers: the plugin's explicit set, else the request's
	// trailers passed through. reqTrailers is safe to read here — the body
	// loop above drained the input pipe to EOF, which is ordered after the
	// recv goroutine filled the trailers and closed the pipe.
	outT := resp.Trailers
	if outT == nil {
		outT = reqTrailers
	}
	eof := &pb.HTTPBodyChunk{Eof: true}
	if len(outT) > 0 {
		eof.Trailers = headersToProtoMap(outT)
	}
	return stream.Send(&pb.TransformHTTPDown{Kind: &pb.TransformHTTPDown_Body{Body: eof}})
}

func invokeTransformHTTP(ctx context.Context, typeName, instanceName string, fn func(context.Context, HTTPTransformRequest) (*HTTPTransformResponse, error), req HTTPTransformRequest) (out *HTTPTransformResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = callbackPanicError(fmt.Sprintf("credential.%s %q TransformHTTP", typeName, instanceName), r)
		}
	}()
	return fn(ctx, req)
}

// copyHeader merges src into dst in place.
func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}
}

func headersToProtoMap(in http.Header) map[string]*pb.HTTPHeaderValues {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*pb.HTTPHeaderValues, len(in))
	for k, vs := range in {
		out[k] = &pb.HTTPHeaderValues{Values: append([]string(nil), vs...)}
	}
	return out
}

func headerMutationsToProto(in []HeaderMutation) []*pb.HeaderMutation {
	if len(in) == 0 {
		return nil
	}
	out := make([]*pb.HeaderMutation, 0, len(in))
	for _, h := range in {
		op := pb.HeaderMutation_SET
		switch h.Op {
		case HeaderAdd:
			op = pb.HeaderMutation_ADD
		case HeaderDel:
			op = pb.HeaderMutation_DEL
		}
		out = append(out, &pb.HeaderMutation{
			Op:     op,
			Name:   h.Name,
			Values: append([]string(nil), h.Values...),
		})
	}
	return out
}
