package main

// WebSocket bridging for the new policy. RFC 6455 frames pass
// through verbatim — placeholder substitution is gone with the
// legacy Swap field, so the bridge is just byte-faithful in both
// directions. Text frames going server-bound get observed (decoded
// + permessage-deflate inflated) for codex-WS token-usage tracking
// when the host matches; nothing is mutated on the wire.
//
// Why a separate bridge instead of letting http.Transport.RoundTrip
// handle the 101 Switching Protocols: Cloudflare's WAF on
// chatgpt.com closes the connection with 1007 ("invalid frame
// payload data") if forwarded frames don't byte-match what the
// client sent, and Go's http.Response.Write mangles hop-by-hop
// headers (Connection / Upgrade) on 101 responses, breaking the
// handshake on the client side. Forwarding bytes verbatim like
// unclaw does is the only thing that works against Cloudflare-
// fronted WS endpoints.

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	wsOpText  = 0x1
	wsOpClose = 0x8
	wsRSV1    = 0x40
	wsMaskBit = 0x80
)

// permessage-deflate trailer to append before flate-decoding a frame.
var deflateTrailer = []byte{0x00, 0x00, 0xff, 0xff}

type wsParams struct {
	deflate          bool
	clientNoTakeover bool // client_no_context_takeover
	serverNoTakeover bool // server_no_context_takeover
}

func parseWSExtensions(headerVal string) wsParams {
	var p wsParams
	for _, ext := range strings.Split(headerVal, ",") {
		ext = strings.TrimSpace(ext)
		fields := strings.Split(ext, ";")
		if strings.TrimSpace(fields[0]) != "permessage-deflate" {
			continue
		}
		p.deflate = true
		for _, f := range fields[1:] {
			switch strings.TrimSpace(f) {
			case "client_no_context_takeover":
				p.clientNoTakeover = true
			case "server_no_context_takeover":
				p.serverNoTakeover = true
			}
		}
	}
	return p
}

// isWSUpgrade returns true iff req is an HTTP/1.1 WebSocket upgrade
// (RFC 6455 §4.1: `Upgrade: websocket` + `Connection: upgrade`).
func isWSUpgrade(req *http.Request) bool {
	conn := strings.ToLower(req.Header.Get("Connection"))
	upg := strings.ToLower(req.Header.Get("Upgrade"))
	return strings.Contains(conn, "upgrade") && upg == "websocket"
}

// handleWSUpgrade swaps the http.Transport-driven request loop for a
// raw byte bridge once the agent's request looks like a WS upgrade.
// The connection stays alive until either side closes; pumpWS
// observes text frames for codex usage tracking when applicable.
func (g *Gateway) handleWSUpgrade(client *tls.Conn, br *bufio.Reader, req *http.Request, upstream string, frameEmit func(direction, sample string)) {
	agentAddr := peerIP(client) // capture before netstack races to nil

	// Cloudflare flags non-browser TLS fingerprints on WS handshakes
	// to chatgpt.com with "Attack attempt detected". Use uTLS Chrome
	// fingerprint for every WS upstream — cheap, and only WS
	// upgrades hit this path.
	up, err := dialBrowserTLS(context.Background(), "tcp", net.JoinHostPort(upstream, "443"), upstream)
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		log.Printf("ws dial %s: %v", upstream, err)
		return
	}
	defer up.Close()

	// Build raw HTTP/1.1 upgrade request — Go's http.Request.Write +
	// http.ReadResponse + http.Response.Write round-trip mangles
	// Connection / Upgrade on 101 responses, which breaks the WS
	// handshake on the client side. Forward bytes verbatim.
	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	host := req.Host
	if host == "" {
		host = upstream
	}
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", host)
	for name, values := range req.Header {
		if strings.EqualFold(name, "Host") {
			continue
		}
		for _, v := range values {
			fmt.Fprintf(&reqBuf, "%s: %s\r\n", name, v)
		}
	}
	reqBuf.WriteString("\r\n")
	if _, err := up.Write(reqBuf.Bytes()); err != nil {
		log.Printf("ws req write: %v", err)
		return
	}

	// Read upstream response headers raw (until "\r\n\r\n"). Anything
	// past the terminator is the start of the WS frame stream and
	// must reach the client BEFORE we hand off to pumpWS.
	upBR := bufio.NewReader(up)
	headerBytes, err := readHTTPHeader(upBR)
	if err != nil {
		log.Printf("ws read resp: %v", err)
		return
	}
	statusLine := ""
	if i := bytes.Index(headerBytes, []byte("\r\n")); i >= 0 {
		statusLine = string(headerBytes[:i])
	}
	respHeaders := parseRespHeaders(headerBytes)
	if !strings.Contains(statusLine, " 101 ") {
		log.Printf("ws upgrade non-101 host=%s status=%q", upstream, statusLine)
		body, _ := io.ReadAll(io.LimitReader(upBR, 2048))
		client.Write(headerBytes)
		client.Write(body)
		return
	}
	if _, err := client.Write(headerBytes); err != nil {
		log.Printf("ws resp.Write: %v", err)
		return
	}

	params := parseWSExtensions(respHeaders.Get("Sec-WebSocket-Extensions"))

	// Codex / chatgpt.com WS sends agent prompt + usage envelopes
	// inside text frames. trackKindFor returns "codex_ws_usage" for
	// hosts that need this; the inspector decodes (unmasks +
	// inflates) frame text without modifying the on-wire bytes.
	var onPayload func([]byte)
	if trackKindFor(upstream) == "codex_ws_usage" {
		onPayload = func(text []byte) {
			g.trackCodexWSUsage(agentAddr, text)
		}
	}

	const wsFrameSampleCap = 512
	wrapPayload := func(direction string, base func([]byte)) func([]byte) {
		return func(text []byte) {
			if base != nil {
				base(text)
			}
			if frameEmit != nil {
				s := text
				if len(s) > wsFrameSampleCap {
					s = s[:wsFrameSampleCap]
				}
				frameEmit(direction, string(s))
			}
		}
	}
	clientToServer := wrapPayload("c→s", onPayload)
	serverToClient := wrapPayload("s→c", onPayload)

	done := make(chan struct{}, 2)
	// client → server (frames are masked on this side)
	go func() {
		_ = pumpWS(br, up, params, true, clientToServer)
		done <- struct{}{}
	}()
	// server → client (frames are NOT masked)
	go func() {
		_ = pumpWS(upBR, client, params, false, serverToClient)
		done <- struct{}{}
	}()
	<-done
}

// readHTTPHeader reads bytes from br up to and including "\r\n\r\n".
// Used to forward a 101 response to the client byte-verbatim.
func readHTTPHeader(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			return buf.Bytes(), nil
		}
		if buf.Len() > 64*1024 {
			return nil, fmt.Errorf("ws: response header too large")
		}
	}
}

func parseRespHeaders(raw []byte) http.Header {
	h := http.Header{}
	lines := bytes.Split(raw, []byte("\r\n"))
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		k := string(bytes.TrimSpace(line[:i]))
		v := string(bytes.TrimSpace(line[i+1:]))
		h.Add(k, v)
	}
	return h
}

// pumpWS reads frames from src and forwards bytes verbatim to dst.
// For text frames, a COPY of the payload is unmasked + decompressed
// (if RSV1 set and deflate negotiated) and passed to onPayload for
// inspection. We do NOT modify or re-mask frames — Cloudflare's WAF
// on chatgpt.com closes the connection with 1007 ("invalid frame
// payload data") if forwarded frames don't byte-match what the
// client sent.
//
// fromClient controls which deflate context-takeover state to use.
func pumpWS(src *bufio.Reader, dst io.Writer, params wsParams, fromClient bool, onPayload func([]byte)) error {
	noTakeover := params.serverNoTakeover
	if fromClient {
		noTakeover = params.clientNoTakeover
	}
	infl := &wsInflater{}
	for {
		raw, _, op, compressed, masked, maskKey, payload, err := readFrameRaw(src)
		if err != nil {
			return err
		}
		if _, werr := dst.Write(raw); werr != nil {
			return werr
		}
		if op == wsOpText && onPayload != nil {
			plain := payload
			if masked {
				plain = make([]byte, len(payload))
				for i := range payload {
					plain[i] = payload[i] ^ maskKey[i%4]
				}
			}
			if compressed && params.deflate {
				if dec := infl.decompress(plain, noTakeover); dec != nil {
					plain = dec
				}
			}
			onPayload(plain)
		}
		if op == wsOpClose {
			return nil
		}
	}
}

// wsInflater handles permessage-deflate decompression with optional
// LZ77 context-takeover across messages (RFC 7692 §7.2.3.1). When
// takeover is in effect the LZ77 sliding window from message N is
// the initial dictionary for message N+1; we save the trailing 32KB
// of decoded output and replay it as a dict for the next message.
type wsInflater struct {
	dict []byte
}

func (w *wsInflater) decompress(payload []byte, noTakeover bool) []byte {
	dict := w.dict
	if noTakeover {
		dict = nil
	}
	var src bytes.Buffer
	src.Write(payload)
	src.Write(deflateTrailer)
	fr := flate.NewReaderDict(&src, dict)
	defer fr.Close()
	out, err := io.ReadAll(fr)
	// io.ErrUnexpectedEOF is expected — permessage-deflate's trailer
	// (00 00 ff ff) is a non-final SYNC block, so flate never sees a
	// real EOF marker. We accept the bytes decoded up to that point.
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil
	}
	if !noTakeover && len(out) > 0 {
		combined := append(w.dict, out...)
		if len(combined) > 32*1024 {
			combined = combined[len(combined)-32*1024:]
		}
		w.dict = combined
	}
	return out
}

// readFrameRaw reads one WebSocket frame, returning both the
// verbatim bytes (for forwarding) and parsed components (for
// inspection).
func readFrameRaw(br *bufio.Reader) (raw []byte, b0 byte, op byte, compressed, masked bool, maskKey [4]byte, payload []byte, err error) {
	var rawBuf bytes.Buffer
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(br, hdr); err != nil {
		return
	}
	rawBuf.Write(hdr)
	b0 = hdr[0]
	op = b0 & 0x0f
	compressed = b0&wsRSV1 != 0
	masked = hdr[1]&wsMaskBit != 0
	plen := int64(hdr[1] & 0x7f)
	switch plen {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(br, ext); err != nil {
			return
		}
		rawBuf.Write(ext)
		plen = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(br, ext); err != nil {
			return
		}
		rawBuf.Write(ext)
		plen = int64(binary.BigEndian.Uint64(ext))
	}
	if masked {
		if _, err = io.ReadFull(br, maskKey[:]); err != nil {
			return
		}
		rawBuf.Write(maskKey[:])
	}
	if plen < 0 || plen > 1<<24 {
		err = fmt.Errorf("ws: payload too large or negative: %d", plen)
		return
	}
	payload = make([]byte, plen)
	if _, err = io.ReadFull(br, payload); err != nil {
		return
	}
	rawBuf.Write(payload)
	raw = rawBuf.Bytes()
	return
}
