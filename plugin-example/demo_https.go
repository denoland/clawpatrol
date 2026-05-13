package main

import (
	"bufio"
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

// demoHTTPS is the example plugin's HTTPS endpoint: gateway terminates
// TLS on the agent side, hands plaintext bytes to the plugin, the
// plugin parses HTTP, mutates the request (adds the magic-token
// header upstream), forwards to the configured upstream, then
// rewrites the response body by appending "bye!" before sending
// back to the agent.
type demoHTTPS struct {
	// Upstream is a full URL: e.g. "http://127.0.0.1:8000". The
	// plugin dials its host:port for every request and rewrites the
	// outgoing request line accordingly.
	Upstream string `json:"upstream"`
}

func demoHTTPSDef() pluginsdk.EndpointDef {
	return pluginsdk.EndpointDef{
		TypeName:    "demo_https",
		Family:      "stream",
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

	// Recover the credential's HCL header_name + the secret value.
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

		resp, ferr := forwardOneHTTPS(ctx, req, upstreamURL, headerName, tokenValue)
		if ferr != nil {
			conn.Emit(pluginsdk.ConnEvent{
				Action:  "error",
				Reason:  ferr.Error(),
				Verb:    req.Method,
				Summary: req.Method + " " + req.URL.RequestURI(),
			})
			return fmt.Errorf("forward: %w", ferr)
		}
		conn.Emit(pluginsdk.ConnEvent{
			Action:  "allow",
			Verb:    req.Method,
			Summary: req.Method + " " + req.URL.RequestURI(),
		})

		// Append "bye!" to the response body before writing back.
		if err := writeMutatedResponse(conn, resp); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
		if req.Close || resp.Close {
			return nil
		}
	}
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

	// Rewrite request: target = upstream.Host, add magic header,
	// drop hop-by-hop. Strip RequestURI (http.Request.Write uses URL
	// when RequestURI is empty).
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
	// Wrap body so it closes the upstream conn when drained.
	resp.Body = &closingBody{ReadCloser: resp.Body, after: c.Close}
	return resp, nil
}

// writeMutatedResponse appends "\nbye!\n" to the response body and
// writes the result back to the agent connection. We force chunked
// transfer encoding because we don't know the final length upfront
// (the upstream might have used chunked or a fixed Content-Length;
// either way our body is now longer).
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
