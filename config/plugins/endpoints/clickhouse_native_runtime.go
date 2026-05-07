package endpoints

// Per-connection runtime for the clickhouse_native endpoint. Schema
// and registration live in clickhouse_native.go.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	chgoproto "github.com/ClickHouse/ch-go/proto"
	"github.com/ClickHouse/clickhouse-go/v2/lib/cityhash102"
	chproto "github.com/ClickHouse/clickhouse-go/v2/lib/proto"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/match"
	"github.com/denoland/clawpatrol/config/runtime"
)

// chMaxCompressionBuffer caps the per-frame compressed-payload size the
// probe accepts. clickhouse-go's writer flushes a chunk every 10 MiB
// by default; 16 MiB gives us headroom for clients that bump the
// option without weakening the discriminator at the size-range gate.
const chMaxCompressionBuffer = 16 * 1024 * 1024

// chProbeSlowPathDeadline bounds how long the probe's slow path is
// willing to wait for the rest of a candidate frame header. Real frame
// bytes follow the leading byte in the same TCP burst (the
// agent-side LZ4/ZSTD writer flushes a frame as one buffer); when 24
// more bytes don't arrive within this window we treat the leading
// byte as the start of the next packet and rewind. This is what
// rescues headerless 1-byte packets (Ping = 4, Cancel = 3) that sit
// directly after a compressed Data block — without it the probe
// blocks forever while the agent waits for the Pong / cancellation
// reply, eventually times out client-side and tears the connection
// down. 200ms is generous on a wireguard tunnel (single-digit ms RTT)
// while still well under any client-side Pong timeout we've seen.
const chProbeSlowPathDeadline = 200 * time.Millisecond

// chCompressedFrameHeader = 16-byte CityHash128 checksum + 1B method +
// 4B compressed_size + 4B decompressed_size. The compressed_size field
// includes the 9-byte sub-header itself (so payload bytes after the
// header = compressed_size - 9, total wire bytes = compressed_size + 16).
const chCompressedFrameHeader = 25

// chValidClientCode is the discriminator used by the compressed-Data
// probe. Any byte outside this set on the next-byte read MUST be a
// frame checksum byte (since a valid stream alternates frames within a
// Data block); anything inside this set is ambiguous and demands a
// full frame parse + CityHash check.
//
// Mirrors the codes ch-go's protocol enum knows about; new ones land
// here as ClickHouse adds them.
func chValidClientCode(b byte) bool {
	switch chgoproto.ClientCode(b) {
	case chgoproto.ClientCodeHello,
		chgoproto.ClientCodeQuery,
		chgoproto.ClientCodeData,
		chgoproto.ClientCodeCancel,
		chgoproto.ClientCodePing,
		chgoproto.ClientTablesStatusRequest,
		chgoproto.ClientCodeSSHChallengeRequest,
		chgoproto.ClientCodeSSHChallengeResponse:
		return true
	}
	return false
}

// chValidCompressedMethod is the second discriminator gate: a real
// frame's method byte is one of LZ4 (0x82, also LZ4HC) or ZSTD (0x90).
// Uncompressed (0x02) is intentionally excluded — agents that
// negotiated compression=Enabled and then sent a None-coded frame are
// mis-framed regardless, and accepting None here would weaken the
// false-positive rate on the probe (0x02 is also ClientCodeData).
func chValidCompressedMethod(b byte) bool {
	return b == 0x82 || b == 0x90
}

// HandleConn services one inbound native-protocol connection.
//
// Flow:
//
//  1. Read the agent's first packet, parse Hello.
//  2. Resolve the bound credential, fetch its secret. Swap any
//     placeholder substring inside Hello.username / Hello.password.
//  3. Dial upstream (TLS or plain), send the (possibly modified) Hello.
//  4. Emit one ConnEvent describing the session.
//  5. Read the server Hello (forwarded back to the agent), capture
//     the negotiated revision, then run an agent → server pump that
//     decodes every client packet via ch-go / lib/proto: Query packets
//     feed the SQL matcher with the agent's compression preference
//     preserved verbatim, uncompressed Data blocks decode through
//     lib/proto.Block, compressed Data blocks walk the frame chain
//     opaquely with a CityHash-discriminator probe (no LZ4/ZSTD on
//     the path). Cancel/Ping forward as-is. Server → agent stays a
//     pure copy past the Hello.
func (ClickhouseNativeEndpointRuntime) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	defer ch.Conn.Close()
	if ch.Endpoint == nil || ch.Endpoint.Family != "sql" {
		err := fmt.Errorf("clickhouse_native runtime invoked on non-sql endpoint %v", ch.Endpoint)
		chEmitError(ch, "wrong-family", "")
		return err
	}
	chEp, ok := ch.Endpoint.Body.(*ClickhouseNativeEndpoint)
	if !ok {
		err := fmt.Errorf("clickhouse_native runtime invoked on non-native endpoint %v", ch.Endpoint)
		chEmitError(ch, "wrong-endpoint-type", ch.Endpoint.Name)
		return err
	}
	upstreamAddr := chPickUpstream(ch.Endpoint.Hosts, ch.UpstreamHost, ch.DstPort, chEp.port())
	if upstreamAddr == "" {
		chEmitError(ch, "no-host", ch.Endpoint.Name)
		return fmt.Errorf("clickhouse_native endpoint %q has no host", ch.Endpoint.Name)
	}

	// Inbound TLS termination. The wrapped agent (clickhouse-client
	// --secure, etc.) speaks native-over-TLS exactly as it would
	// against the real upstream; we terminate here using a leaf
	// minted off the gateway CA so the SAN matches whatever SNI the
	// agent sent. Agents already trust the gateway CA via the
	// SSL_CERT_FILE env-var pushdown that `clawpatrol run` stamps,
	// so verification passes without any client-side opt-out.
	if chEp.TLS && ch.MintCert != nil {
		fallback := ch.UpstreamHost
		if fallback == "" {
			h, _ := chHostPort(upstreamAddr)
			fallback = h
		}
		mint := ch.MintCert
		tc := tls.Server(ch.Conn, &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				host := chi.ServerName
				if host == "" {
					host = fallback
				}
				return mint(host)
			},
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			chEmitError(ch, "inbound-tls-handshake", err.Error())
			return fmt.Errorf("inbound tls: %w", err)
		}
		ch.Conn = tc
	}

	// Step 1: read agent Hello. Once the conn is wrapped in a
	// chgoproto.Reader the underlying bytes are buffered; subsequent
	// agent → server packets must transcode through that reader.
	hello, agentReader, err := chReadHello(ch.Conn)
	if err != nil {
		chEmitError(ch, "read-hello", err.Error())
		return fmt.Errorf("read hello: %w", err)
	}

	// Step 2: resolve credential and inject. Single-credential native
	// endpoints today; multi-credential dispatch via placeholder lands
	// when SQL parsing does in iter 2.
	claimedUser := hello.Username
	injected := false
	credName := ""
	if cc := chPickCredential(ch.Endpoint); cc != nil {
		credName = cc.Credential.Symbol.Name
		auth, ok := cc.Credential.Body.(runtime.ClickhouseAuthCredential)
		if !ok {
			chEmitError(ch, "credential-not-clickhouse-auth", cc.Credential.Symbol.Name)
			return fmt.Errorf("clickhouse_native: credential %q does not implement ClickhouseAuthCredential",
				cc.Credential.Symbol.Name)
		}
		sec, secErr := ch.Secrets.Get(cc.Credential.Symbol.Name, ch.Profile)
		if secErr != nil {
			chEmitError(ch, "secret-fetch", fmt.Sprintf("%s: %v", cc.Credential.Symbol.Name, secErr))
			return fmt.Errorf("clickhouse_native: fetch secret %q: %w", cc.Credential.Symbol.Name, secErr)
		}
		realUser, realPassword := auth.ClickhouseAuth(sec)
		if realUser == "" || realPassword == "" {
			chEmitError(ch, "secret-empty", cc.Credential.Symbol.Name)
			return fmt.Errorf("clickhouse_native: credential %q produced empty user or password",
				cc.Credential.Symbol.Name)
		}
		before := hello.Username + "\x00" + hello.Password
		hello.Username = realUser
		hello.Password = realPassword
		if hello.Username+"\x00"+hello.Password != before {
			injected = true
		}
	}

	// Step 3: dial upstream + send hello.
	upstream, err := ch.DialUpstream(ctx, "tcp", upstreamAddr)
	if err != nil {
		chEmitError(ch, "dial-upstream", fmt.Sprintf("%s: %v", upstreamAddr, err))
		return fmt.Errorf("dial upstream %s: %w", upstreamAddr, err)
	}
	defer upstream.Close()

	if chEp.TLS {
		host := upstreamAddr
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		tc := tls.Client(upstream, chUpstreamTLSConfig(host, chEp.AcceptInvalidCertificate))
		if err := tc.HandshakeContext(ctx); err != nil {
			chEmitError(ch, "tls-handshake", err.Error())
			return fmt.Errorf("upstream tls: %w", err)
		}
		upstream = tc
	}

	if _, err := upstream.Write(chEncodeHello(hello)); err != nil {
		chEmitError(ch, "send-hello", err.Error())
		return fmt.Errorf("send hello: %w", err)
	}

	// Step 4: emit the connection event. One event per TCP session —
	// per-Query events come from the agent → server pump below.
	database := hello.Database
	if database == "" {
		database = "default"
	}
	host, port := chHostPort(upstreamAddr)
	summary := fmt.Sprintf("%s@%s:%d/%s", hello.Username, host, port, database)
	if injected {
		summary += " (placeholder injected)"
	}
	if ch.Emit != nil {
		ch.Emit(runtime.ConnEvent{
			Action:  "allow",
			Verb:    "connect",
			Summary: summary,
		})
	}
	log.Printf("clickhouse_native %s: connect user=%q claimed=%q db=%q client=%q rev=%d injected=%v",
		ch.Endpoint.Name, hello.Username, claimedUser, database,
		hello.ClientName, hello.ProtocolRevision, injected)

	// Step 5: post-handshake bidirectional shuttle. Server → agent
	// stays a pure copy (decoded only far enough to forward the
	// ServerHello and capture the revision). Agent → server is fully
	// transcoded.
	chRunSession(ctx, ch, agentReader, upstream, hello.ProtocolRevision, credName)
	return nil
}

// chUpstreamTLSConfig builds the upstream tls.Config from the
// endpoint's AcceptInvalidCertificate flag. False (default) keeps the
// public-roots, hostname-matched check. True disables both —
// necessary for self-hosted ClickHouse fronted by a private CA, at
// the cost of trusting whatever cert the upstream presents (MITM
// exposure on the wg→clickhouse hop). Operators opt in per endpoint;
// the default stays safe.
func chUpstreamTLSConfig(host string, acceptInvalidCert bool) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: acceptInvalidCert,
	}
}

// chRunSession orchestrates the post-Hello exchange. Reads the
// server Hello (forwarded verbatim to the agent), captures the
// negotiated revision, then runs agent → server through the Query /
// Data inspector while server → agent stays a pure passthrough.
func chRunSession(ctx context.Context, ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream net.Conn, clientRev int, credName string) {
	upstreamReader := chgoproto.NewReader(upstream)
	negotiatedRev, err := chReadAndForwardServerHello(upstreamReader, ch.Conn, clientRev)
	if err != nil {
		chEmitError(ch, "server-hello", err.Error())
		return
	}

	// Server → agent: pure copy via the wrapped reader. Started BEFORE
	// the synchronous addendum read so any post-ServerHello bytes the
	// upstream emits (which the agent waits on before sending its own
	// addendum) can flow through without deadlocking. With the rev
	// clamped to chMaxProtocolRev there shouldn't be any such tail
	// today, but keeping the goroutine first is the safe ordering for
	// future protocol additions.
	srvDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(ch.Conn, upstreamReader)
		if cw, ok := ch.Conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(srvDone)
	}()

	if err := chForwardClientAddendum(agentReader, upstream, negotiatedRev); err != nil {
		chEmitError(ch, "client-addendum", err.Error())
		return
	}

	chAgentToServer(ctx, ch, agentReader, upstream, negotiatedRev, credName)

	if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	<-srvDone
}

// chAgentToServer is the agent → server transcoding pump. Each
// iteration reads one packet code off the agent reader, dispatches
// to a per-packet handler that decodes the body, and writes the
// (possibly re-encoded) packet to upstream. On policy deny the
// handler writes a server Exception to the agent and the loop
// continues — mirroring postgres' pgWriteDeny + ReadyForQuery so a
// session can't smuggle a denied statement past an allowed one (or
// vice versa). Every Query for the lifetime of the connection is
// re-evaluated; there is no per-session "already inspected" flag.
//
// Compression: the agent's `compression` flag on the Query packet
// is forwarded verbatim and tracked here so subsequent Data packets
// take the right code path — uncompressed blocks round-trip through
// lib/proto.Block.Decode/Encode, compressed blocks walk frame bytes
// opaquely with an optimistic CityHash-discriminator probe (no
// decompression library on the path). A denied Query does not advance
// the compression state — the next Data packet (if any) framing
// depends on the most recent ALLOWED Query.
//
// Probe-and-rewind: the compressed Data handler owns the next-byte
// read past the last frame. When that byte turns out to be the start
// of the next packet (probe rejects), the handler returns a fresh
// chgoproto.Reader pre-fed with the look-ahead bytes via
// io.MultiReader. The pump swaps it in-place and dispatches as usual,
// so the code-loop here doesn't need its own buffered-byte rewind
// channel.
func chAgentToServer(ctx context.Context, ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream io.Writer, revision int, credName string) {
	compression := chgoproto.CompressionDisabled
	for {
		code, err := agentReader.UInt8()
		if err != nil {
			return
		}
		switch chgoproto.ClientCode(code) {
		case chgoproto.ClientCodeQuery:
			next, ok, fatal := chHandleQuery(ctx, ch, agentReader, upstream, revision, credName)
			if fatal {
				return
			}
			if ok {
				compression = next
			}
		case chgoproto.ClientCodeData:
			rewound, ok := chHandleData(ch, agentReader, upstream, revision, compression)
			if !ok {
				return
			}
			if rewound != nil {
				agentReader = rewound
			}
		case chgoproto.ClientCodeCancel, chgoproto.ClientCodePing:
			// Headerless packets — single byte, forward verbatim.
			if _, werr := upstream.Write([]byte{code}); werr != nil {
				return
			}
		default:
			// Unknown / future packet type — log and stop. We can't
			// safely forward an unknown packet because we don't know
			// its body length to skip past it.
			chEmitError(ch, "unknown-client-packet", strconv.Itoa(int(code)))
			return
		}
	}
}

// chHandleQuery decodes one client Query packet, runs the SQL through
// the matcher, and either forwards the re-encoded packet to upstream
// (allow) or writes a server Exception to the agent (deny). The
// agent's `compression` choice is preserved on the wire — the
// gateway used to override it to Disabled, which silently corrupted
// blocks from agents that originated with compression on.
//
// Returns:
//
//	(comp, true,  false) — allow: caller updates session compression to comp.
//	(_,    false, false) — deny:  caller leaves session state alone and
//	                              keeps the loop alive (the agent can issue
//	                              another Query after seeing the Exception).
//	(_,    _,     true)  — fatal: caller tears the connection down (decode
//	                              error or upstream/agent transport failed).
func chHandleQuery(ctx context.Context, ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream io.Writer, revision int, credName string) (chgoproto.Compression, bool, bool) {
	var q chgoproto.Query
	if err := q.DecodeAware(agentReader, revision); err != nil {
		chEmitError(ch, "query-decode", err.Error())
		return chgoproto.CompressionDisabled, false, true
	}
	verdict, reason := chEvaluateSQL(ctx, ch, q.Body, credName)
	if verdict == "deny" {
		if _, werr := ch.Conn.Write(chEncodeException(reason)); werr != nil {
			// Agent gone — there's nothing left to keep alive.
			return chgoproto.CompressionDisabled, false, true
		}
		log.Printf("clickhouse_native %s deny %s: %s",
			ch.Endpoint.Name, ch.PeerIP, reason)
		return chgoproto.CompressionDisabled, false, false
	}

	var b chgoproto.Buffer
	q.EncodeAware(&b, revision)
	if _, werr := upstream.Write(b.Buf); werr != nil {
		return chgoproto.CompressionDisabled, false, true
	}
	return q.Compression, true, false
}

// chHandleData decodes one client Data packet (table-name header +
// Block) and forwards it to upstream. Two paths depending on the
// session's negotiated compression:
//
//   - Disabled: full Block.Decode → Block.Encode round-trip. The
//     gateway sees columns it can later route to a block-aware
//     matcher and re-emits a wire-equivalent block.
//
//   - Enabled: an optimistic CityHash-discriminator probe walks the
//     compressed frame chain opaquely. Each iteration reads the next
//     byte; if it can't be a client packet code it must be a frame
//     checksum byte, so we forward the whole frame verbatim. If it
//     could be either, we pull the candidate header, sanity-check
//     the method byte and size, then verify the checksum over
//     [method | comp_size | decomp_size | payload]. On match it's a
//     frame; on any rejection the byte was the start of the NEXT
//     packet — we hand a rewound reader back to the caller so the
//     pump dispatches it without rereading.
//
// Returns (rewound, ok):
//
//	(nil,    true)  — Data packet fully consumed; pump reads the next
//	                  packet code from agentReader as usual.
//	(reader, true)  — probe rejected; caller MUST swap agentReader for
//	                  reader before its next read, since the look-ahead
//	                  byte (and any candidate frame bytes that came
//	                  with it) are buffered inside reader.
//	(_,      false) — fatal: tear the connection down.
func chHandleData(ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream io.Writer, revision int, compression chgoproto.Compression) (*chgoproto.Reader, bool) {
	var hdr chgoproto.ClientData
	if err := hdr.DecodeAware(agentReader, revision); err != nil {
		chEmitError(ch, "data-header-decode", err.Error())
		return nil, false
	}
	var headBuf chgoproto.Buffer
	headBuf.PutByte(byte(chgoproto.ClientCodeData))
	hdr.EncodeAware(&headBuf, revision)
	if _, werr := upstream.Write(headBuf.Buf); werr != nil {
		return nil, false
	}

	if compression == chgoproto.CompressionEnabled {
		return chProbeCompressedData(ch, agentReader, upstream, hdr.TableName)
	}

	block := chproto.NewBlock()
	if err := block.Decode(agentReader, uint64(revision)); err != nil {
		chEmitError(ch, "data-block-decode", err.Error())
		return nil, false
	}
	if ch.Emit != nil {
		summary := fmt.Sprintf("data table=%q rows=%d cols=%d", hdr.TableName, block.Rows(), len(block.Columns))
		ch.Emit(runtime.ConnEvent{Action: "allow", Verb: "data", Summary: summary})
	}
	var b chgoproto.Buffer
	if err := block.Encode(&b, uint64(revision)); err != nil {
		chEmitError(ch, "data-block-encode", err.Error())
		return nil, false
	}
	if _, werr := upstream.Write(b.Buf); werr != nil {
		return nil, false
	}
	return nil, true
}

// chProbeCompressedData walks the compressed frame chain that follows
// a ClientData header. It owns the next-byte read past every frame —
// the byte that, on rejection, turns out to be the leading code of
// the next packet. When that happens we wrap the candidate bytes
// (look-ahead code + whatever else we'd pulled trying to validate the
// frame header) into a MultiReader-backed chgoproto.Reader and hand
// it back so the pump dispatches as usual. No bytes are dropped: the
// old chgoproto.Reader is the second source of the multi-reader, so
// any bytes its bufio had pre-fetched are still drained on demand.
//
// Forwarding semantics: every byte that belongs to a real frame goes
// to upstream verbatim; nothing is decompressed or re-encoded. The
// per-Data event drops the rows/cols counts the old Block.Decode path
// produced (we don't materialize columns here on purpose) — the
// summary carries forwarded byte count + table name + (compressed).
func chProbeCompressedData(ch *runtime.ConnHandle, agentReader *chgoproto.Reader, upstream io.Writer, tableName string) (*chgoproto.Reader, bool) {
	var totalBytes int64
	emit := func() {
		if ch.Emit == nil {
			return
		}
		ch.Emit(runtime.ConnEvent{
			Action: "allow", Verb: "data",
			Summary: fmt.Sprintf("data table=%q bytes=%d (compressed)", tableName, totalBytes),
		})
	}

	for {
		x, err := agentReader.UInt8()
		if err != nil {
			// EOF (or transport error) at a clean inter-frame boundary.
			// Surface the data event we accumulated and let the pump
			// see EOF on its next read.
			if totalBytes > 0 {
				emit()
			}
			return nil, true
		}

		if !chValidClientCode(x) {
			// Fast path — x is a checksum byte, no rewind risk. Read
			// the rest of the frame header to learn payload size and
			// stream the payload through. We still range-check the
			// header so a corrupt stream is rejected before we hand
			// io.CopyN a multi-gigabyte size to chase.
			var rest [chCompressedFrameHeader - 1]byte
			if err := agentReader.ReadFull(rest[:]); err != nil {
				chEmitError(ch, "data-frame-header", err.Error())
				return nil, false
			}
			method := rest[15]
			compSize := binary.LittleEndian.Uint32(rest[16:20])
			if !chValidCompressedMethod(method) ||
				compSize < 9 || compSize > chMaxCompressionBuffer+9 {
				chEmitError(ch, "data-frame-corrupt",
					fmt.Sprintf("method=0x%02x comp_size=%d", method, compSize))
				return nil, false
			}
			payloadLen := int64(compSize) - 9
			if _, werr := upstream.Write([]byte{x}); werr != nil {
				return nil, false
			}
			if _, werr := upstream.Write(rest[:]); werr != nil {
				return nil, false
			}
			if _, werr := io.CopyN(upstream, agentReader, payloadLen); werr != nil {
				return nil, false
			}
			totalBytes += int64(chCompressedFrameHeader) + payloadLen
			continue
		}

		// Slow path — x could be a checksum byte OR the leading code
		// of the next packet. Pull the candidate header and run the
		// discriminators in cheapest-first order; on any rejection,
		// rewind everything we've buffered as the next packet's bytes.
		//
		// A read deadline here is critical for headerless 1-byte
		// packets (Ping / Cancel): they don't carry 24 more bytes, so
		// without a deadline the ReadFull blocks until the agent
		// gives up and closes — driving per-query reconnects and
		// multi-second latency.
		_ = ch.Conn.SetReadDeadline(time.Now().Add(chProbeSlowPathDeadline))
		var rest [chCompressedFrameHeader - 1]byte
		n, err := io.ReadFull(agentReader, rest[:])
		_ = ch.Conn.SetReadDeadline(time.Time{})
		if err != nil {
			// EOF or timeout before we filled the candidate header:
			// x was a packet code with a short / no body (Cancel,
			// Ping, end-of-stream). Rewind whatever we managed to
			// read and let the pump dispatch x; only non-timeout,
			// non-EOF errors are fatal.
			var nerr net.Error
			isTimeout := errors.As(err, &nerr) && nerr.Timeout()
			if isTimeout || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if totalBytes > 0 {
					emit()
				}
				rewind := make([]byte, 0, 1+n)
				rewind = append(rewind, x)
				rewind = append(rewind, rest[:n]...)
				return chRewindReader(rewind, agentReader), true
			}
			chEmitError(ch, "data-frame-header", err.Error())
			return nil, false
		}
		method := rest[15]
		compSize := binary.LittleEndian.Uint32(rest[16:20])
		if !chValidCompressedMethod(method) ||
			compSize < 9 || compSize > chMaxCompressionBuffer+9 {
			// x was a packet code; rest is the start of its body.
			if totalBytes > 0 {
				emit()
			}
			rewind := make([]byte, 0, chCompressedFrameHeader)
			rewind = append(rewind, x)
			rewind = append(rewind, rest[:]...)
			return chRewindReader(rewind, agentReader), true
		}

		payloadLen := int(compSize) - 9
		body := make([]byte, payloadLen)
		bn, err := io.ReadFull(agentReader, body)
		if err != nil {
			// Same edge as above, deeper into the candidate frame:
			// the bytes that "looked like" a frame are actually a
			// packet body that ended sooner. Rewind everything.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if totalBytes > 0 {
					emit()
				}
				rewind := make([]byte, 0, chCompressedFrameHeader+bn)
				rewind = append(rewind, x)
				rewind = append(rewind, rest[:]...)
				rewind = append(rewind, body[:bn]...)
				return chRewindReader(rewind, agentReader), true
			}
			chEmitError(ch, "data-frame-payload", err.Error())
			return nil, false
		}

		hashed := make([]byte, 0, 9+payloadLen)
		hashed = append(hashed, rest[15:24]...)
		hashed = append(hashed, body...)
		got := cityhash102.CityHash128(hashed, uint32(len(hashed)))
		candLow := uint64(x) |
			uint64(rest[0])<<8 | uint64(rest[1])<<16 |
			uint64(rest[2])<<24 | uint64(rest[3])<<32 |
			uint64(rest[4])<<40 | uint64(rest[5])<<48 |
			uint64(rest[6])<<56
		candHigh := binary.LittleEndian.Uint64(rest[7:15])
		if got.Lower64() != candLow || got.Higher64() != candHigh {
			// Hash mismatch — x was a packet code; everything we read
			// (header + payload-shaped body) is the start of that
			// packet's body.
			if totalBytes > 0 {
				emit()
			}
			rewind := make([]byte, 0, chCompressedFrameHeader+payloadLen)
			rewind = append(rewind, x)
			rewind = append(rewind, rest[:]...)
			rewind = append(rewind, body...)
			return chRewindReader(rewind, agentReader), true
		}

		// Frame verified by checksum — forward all bytes verbatim.
		if _, werr := upstream.Write([]byte{x}); werr != nil {
			return nil, false
		}
		if _, werr := upstream.Write(rest[:]); werr != nil {
			return nil, false
		}
		if _, werr := upstream.Write(body); werr != nil {
			return nil, false
		}
		totalBytes += int64(chCompressedFrameHeader) + int64(payloadLen)
	}
}

// chRewindReader builds a fresh chgoproto.Reader whose stream starts
// with `head` and then continues from the existing agent reader. It's
// the prepend-buffer wrapper for the probe's rewind: the look-ahead
// bytes the probe pulled trying to validate a frame become the first
// reads of the new reader, with the underlying chgoproto.Reader as
// the second source so any bytes its bufio still holds are not lost.
func chRewindReader(head []byte, tail *chgoproto.Reader) *chgoproto.Reader {
	return chgoproto.NewReader(io.MultiReader(bytes.NewReader(head), tail))
}

// chEvaluateSQL runs SQL through the endpoint's compiled rules. The
// shape mirrors pgEvaluate so the SQL family rule semantics stay
// consistent across plugins — same Match.Request fields, same allow /
// deny / approve verdicts.
//
// Returns:
//
//	("deny", reason) — matched rule denies, or approve rejected.
//	("", "")         — no rule fires, or the matched rule allows.
func chEvaluateSQL(ctx context.Context, ch *runtime.ConnHandle, sql, credName string) (string, string) {
	info := parseChSQL(sql)
	mreq := &match.Request{
		Family:     "sql",
		PeerIP:     ch.PeerIP,
		Credential: credName,
		SQL: &match.SQLMeta{
			Verb:      info.Verb,
			Tables:    info.Tables,
			Functions: info.Functions,
			Statement: info.Statement,
		},
	}
	cr := runtime.MatchRequest(ch.Endpoint, mreq)
	if cr == nil {
		chEmit(ch, runtime.ConnEvent{
			Action: "allow", Verb: info.Verb, Summary: chSummary(info),
		})
		return "", ""
	}
	summary := chSummary(info)

	if len(cr.Outcome.Approve) > 0 {
		if ch.Approve == nil {
			chEmit(ch, runtime.ConnEvent{
				Action: "deny", Reason: "HITL not configured",
				Verb: info.Verb, Summary: summary,
			})
			return "deny", "approval required but HITL is not configured"
		}
		v := ch.Approve(runtime.ApproveCallRequest{
			Stages: cr.Outcome.Approve, Verb: info.Verb,
			Summary: summary, Rule: cr,
		})
		if v.Decision != "allow" {
			reason := v.Reason
			if reason == "" {
				reason = "denied by approver"
			}
			chEmit(ch, runtime.ConnEvent{
				Action: "hitl_deny", Reason: reason,
				Verb: info.Verb, Summary: summary,
			})
			return "deny", reason
		}
		chEmit(ch, runtime.ConnEvent{
			Action: "hitl_allow", Verb: info.Verb, Summary: summary,
		})
		return "", ""
	}

	if cr.Outcome.Verdict == "deny" {
		reason := cr.Outcome.Reason
		if reason == "" {
			reason = "denied by policy"
		}
		chEmit(ch, runtime.ConnEvent{
			Action: "deny", Reason: reason,
			Verb: info.Verb, Summary: summary,
		})
		return "deny", reason
	}
	chEmit(ch, runtime.ConnEvent{
		Action: "allow", Verb: info.Verb, Summary: summary,
	})
	_ = ctx
	return "", ""
}

func chEmit(ch *runtime.ConnHandle, ev runtime.ConnEvent) {
	if ch != nil && ch.Emit != nil {
		ch.Emit(ev)
	}
}

// chEmitError emits a structured error ConnEvent if the host wired
// an emit callback. Reason is a stable short tag, Detail is free
// form (error message, name, etc.) — keep the dashboard's filter
// surface narrow.
func chEmitError(ch *runtime.ConnHandle, reason, detail string) {
	if ch == nil || ch.Emit == nil {
		return
	}
	summary := reason
	if detail != "" {
		summary = reason + ": " + detail
	}
	ch.Emit(runtime.ConnEvent{
		Action:  "error",
		Verb:    "connect",
		Reason:  reason,
		Summary: summary,
	})
}

// chPickCredential returns the (only) credential bound to the
// endpoint, or nil. Multi-credential dispatch by placeholder will
// move into the SQL-parsing iteration.
func chPickCredential(ep *config.CompiledEndpoint) *config.CompiledCredential {
	if ep == nil || len(ep.Credentials) == 0 {
		return nil
	}
	return ep.Credentials[0]
}

// chPickUpstream resolves the upstream addr the plugin should dial.
//
// Preference order:
//
//  1. (upstreamHost, dstPort) — VIP-dispatched conns: the agent
//     dialed a specific hostname which dnsvip mapped to a VIP plus
//     the matched port; that pair is the canonical upstream.
//  2. host whose declared port equals dstPort — disambiguates
//     multi-host endpoints where each member runs on a different
//     port (rare but legal).
//  3. first non-empty host — single-host endpoint, or the operator
//     just declared one.
func chPickUpstream(hosts []string, upstreamHost string, dstPort uint16, defaultPort int) string {
	if upstreamHost != "" && dstPort != 0 {
		return net.JoinHostPort(upstreamHost, strconv.Itoa(int(dstPort)))
	}
	if dstPort != 0 {
		want := strconv.Itoa(int(dstPort))
		for _, h := range hosts {
			if h == "" {
				continue
			}
			if _, p, err := net.SplitHostPort(h); err == nil && p == want {
				return h
			}
		}
	}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err == nil {
			return h
		}
		return net.JoinHostPort(h, strconv.Itoa(defaultPort))
	}
	return ""
}

func chHostPort(addr string) (string, int) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return h, 0
	}
	return h, port
}
