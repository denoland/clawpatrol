package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/denoland/clawpatrol/pluginsdk"
)

// demoHTTPS is the example plugin's HTTPS endpoint. The gateway
// terminates TLS on the agent side and hands the plaintext bytes to
// the plugin. For each HTTP request, the plugin asks the gateway for
// a verdict via Conn.Evaluate using the built-in `http` facet — so
// rules can write the same `http.method` / `http.path` /
// `http.body_json.<field>` predicates they'd write against any other
// HTTPS endpoint, with no plugin-specific schema. On allow the
// plugin forwards upstream, injects the magic header, and rewrites
// the response body by appending "bye!".
type demoHTTPS struct {
	// Upstream is a full URL: e.g. "http://127.0.0.1:8000". The
	// plugin dials its host:port for every request.
	Upstream string `json:"upstream"`
}

func demoHTTPSDef() pluginsdk.EndpointDef {
	return pluginsdk.EndpointDef{
		TypeName:    "demo_https",
		Family:      "http", // bind to the built-in http facet
		TLSMode:     pluginsdk.TLSTerminate,
		RequiresVIP: true,
		Schema: pluginsdk.Schema{Fields: []pluginsdk.SchemaField{
			{Name: "upstream", TypeString: "string", Required: true},
		}},
		Build: func(req pluginsdk.BuildRequest) (any, error) {
			var e demoHTTPS
			if err := req.Decode(&e); err != nil {
				return nil, err
			}
			if e.Upstream == "" {
				return nil, errors.New("demo_https: upstream is required")
			}
			if _, err := url.Parse(e.Upstream); err != nil {
				return nil, fmt.Errorf("demo_https: upstream %q invalid: %w", e.Upstream, err)
			}
			return e, nil
		},
		HandleConn: handleDemoHTTPS,
	}
}

func handleDemoHTTPS(ctx context.Context, conn *pluginsdk.Conn) error {
	var ep demoHTTPS
	if err := json.Unmarshal(conn.EndpointCanonicalConfig, &ep); err != nil {
		return fmt.Errorf("decode endpoint config: %w", err)
	}
	upstreamURL, err := url.Parse(ep.Upstream)
	if err != nil {
		return fmt.Errorf("parse upstream: %w", err)
	}

	headerName := "X-Magic"
	if len(conn.CredentialCanonicalConfig) > 0 {
		var c magicToken
		if err := json.Unmarshal(conn.CredentialCanonicalConfig, &c); err == nil && c.HeaderName != "" {
			headerName = c.HeaderName
		}
	}
	tokenValue := string(conn.CredentialSecret)

	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read request: %w", err)
		}

		// Buffer the body so the gateway can pull it lazily as a
		// stream while we still have it available for the upstream
		// forward. Real-world plugins handling large bodies would
		// use a tee-reader pattern; for the demo, ReadAll is
		// adequate and the streaming protocol still lets the
		// gateway decide whether to copy the bytes over IPC.
		body, berr := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if berr != nil {
			return fmt.Errorf("read request body: %w", berr)
		}

		// Action keys mirror the built-in http facet's CEL surface:
		// http.method, http.path, http.headers, http.body. The
		// gateway adapter maps these onto the typed match.Request
		// fields the built-in matcher reads — so a rule like
		// `http.method == "GET"` works identically to a rule
		// against the gateway's own HTTPS pipeline.
		headers := map[string][]string(req.Header)
		hdrAny := make(map[string]any, len(headers))
		for k, v := range headers {
			hdrAny[k] = v
		}
		action := map[string]any{
			"method":  req.Method,
			"path":    req.URL.RequestURI(),
			"headers": hdrAny,
			"body":    pluginsdk.Stream(bytes.NewReader(body)),
		}
		summary := req.Method + " " + req.URL.RequestURI()
		v, err := conn.Evaluate(ctx, "http", action, summary)
		if err != nil {
			return fmt.Errorf("evaluate %s: %w", summary, err)
		}

		switch v.Action {
		case "allow", "hitl_allow":
			// proceed
		default:
			if werr := writeDenyResponse(conn, req, v.Reason); werr != nil {
				return fmt.Errorf("write deny: %w", werr)
			}
			if req.Close {
				return nil
			}
			continue
		}

		req.Body = io.NopCloser(bytes.NewReader(body))
		resp, ferr := forwardOneHTTPS(ctx, req, upstreamURL, headerName, tokenValue)
		if ferr != nil {
			// Operational failure (couldn't reach upstream / parse
			// response). Not a verdict, but worth logging — the
			// plugin tells the gateway via a non-policy audit emit.
			conn.Emit(pluginsdk.ConnEvent{
				Action:  "error",
				Reason:  ferr.Error(),
				Verb:    req.Method,
				Summary: summary,
			})
			return fmt.Errorf("forward: %w", ferr)
		}

		if err := writeMutatedResponse(conn, resp); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
		if req.Close || resp.Close {
			return nil
		}
	}
}

func writeDenyResponse(w io.Writer, req *http.Request, reason string) error {
	if reason == "" {
		reason = "policy denied"
	}
	body := []byte(reason + "\n")
	resp := &http.Response{
		Status:        "403 Forbidden",
		StatusCode:    http.StatusForbidden,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	return resp.Write(w)
}

func forwardOneHTTPS(ctx context.Context, req *http.Request, upstream *url.URL, headerName, headerValue string) (*http.Response, error) {
	host := upstream.Host
	if !strings.Contains(host, ":") {
		switch upstream.Scheme {
		case "https":
			host += ":443"
		default:
			host += ":80"
		}
	}

	var (
		c   net.Conn
		err error
	)
	dialer := &net.Dialer{}
	if upstream.Scheme == "https" {
		c, err = tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true, ServerName: stripPort(upstream.Host)})
	} else {
		c, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", host, err)
	}

	out := req.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme = upstream.Scheme
	out.URL.Host = upstream.Host
	out.Host = upstream.Host
	out.Header.Set(headerName, headerValue)

	if err := out.Write(c); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("write upstream request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), out)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("read upstream response: %w", err)
	}
	resp.Body = &closingBody{ReadCloser: resp.Body, after: c.Close}
	return resp, nil
}

// writeMutatedResponse appends "\nbye!\n" to the response body and
// writes the result back to the agent connection. Forces chunked
// transfer encoding because the appended bytes invalidate any
// upstream Content-Length.
func writeMutatedResponse(w io.Writer, resp *http.Response) error {
	resp.Body = io.NopCloser(io.MultiReader(resp.Body, strings.NewReader("\nbye!\n")))
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	resp.TransferEncoding = []string{"chunked"}
	return resp.Write(w)
}

type closingBody struct {
	io.ReadCloser
	after func() error
}

func (c *closingBody) Close() error {
	err := c.ReadCloser.Close()
	if c.after != nil {
		_ = c.after()
	}
	return err
}

func stripPort(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[:i]
	}
	return hostport
}
