package endpoints

// Thin wrappers over ch-go/proto + clickhouse-go/v2/lib/proto for the
// clickhouse_native runtime. The native protocol's wire codec lives
// in those upstream packages — this file holds the small handful of
// gateway-specific operations: read a client Hello off a connection,
// rewrite it with injected credentials, read the server Hello to
// extract the negotiated revision, and synthesize an Exception
// packet when policy denies a Query.
//
// The runtime side is a packet-aware pump on agent → server: it
// decodes each client packet (Hello, Query, Data, Cancel, Ping) for
// inspection. Query packets are re-encoded with the agent's
// `compression` choice preserved. Data blocks branch on that flag —
// uncompressed blocks round-trip through `lib/proto.Block.Decode`
// and `Block.Encode`, compressed blocks walk the frame chain
// verbatim with a CityHash-discriminator probe that detects the
// next packet boundary without decompressing column data. Net
// effect: LZ4/ZSTD stays out of the gateway entirely.

import (
	"errors"
	"fmt"
	"io"

	chgoproto "github.com/ClickHouse/ch-go/proto"
)

// Local aliases of the ch-go packet codes — keeps the runtime's
// switch statements readable without leaking the dependency name
// everywhere.
const (
	chClientPacketHello  = chgoproto.ClientCodeHello
	chClientPacketQuery  = chgoproto.ClientCodeQuery
	chClientPacketData   = chgoproto.ClientCodeData
	chClientPacketCancel = chgoproto.ClientCodeCancel
	chClientPacketPing   = chgoproto.ClientCodePing

	chServerPacketHello     = chgoproto.ServerCodeHello
	chServerPacketException = chgoproto.ServerCodeException
)

// chMaxProtocolRev caps the protocol revision the gateway is willing
// to negotiate on either leg. It's pinned to ch-go's own max
// (`proto.Version`) so every packet the runtime decodes / re-encodes
// uses a field set ch-go actually models. Beyond this rev ClickHouse
// adds addendum extensions (chunked-protocol negotiation, password
// complexity rules, …) the vendored proto package doesn't know how
// to read or write — letting peers negotiate up there silently desyncs
// the wire (server's tail bytes go unread, client's addendum has
// extra fields the gateway parses as packet codes). Clamping both
// directions to chgoproto.Version keeps the addendum at exactly one
// quota_key string, which chForwardClientAddendum handles cleanly.
const chMaxProtocolRev = chgoproto.Version

// ChHello mirrors the subset of the ClientHello fields the gateway
// inspects or rewrites: client identification (forwarded as-is),
// negotiated protocol revision (drives field-set decisions
// downstream), and (database, username, password) — username and
// password are swapped for the credential's real values before
// forwarding.
type ChHello struct {
	ClientName       string
	VersionMajor     int
	VersionMinor     int
	ProtocolRevision int
	Database         string
	Username         string
	Password         string
}

// chReadHello reads + decodes the agent's first packet, expecting a
// ClientHello (code 0). Returns the decoded hello plus the underlying
// proto.Reader, which subsequent packet decodes pull from. The
// reader buffers internally — once a connection has been wrapped, it
// can no longer be read raw, so the runtime transcodes everything
// from this point.
func chReadHello(r io.Reader) (ChHello, *chgoproto.Reader, error) {
	pr := chgoproto.NewReader(r)
	code, err := pr.UInt8()
	if err != nil {
		return ChHello{}, nil, fmt.Errorf("read packet code: %w", err)
	}
	if chgoproto.ClientCode(code) != chgoproto.ClientCodeHello {
		return ChHello{}, nil, fmt.Errorf("clickhouse: not a Hello packet (code=%d)", code)
	}
	var raw chgoproto.ClientHello
	if err := raw.Decode(pr); err != nil {
		return ChHello{}, nil, fmt.Errorf("decode client hello: %w", err)
	}
	rev := raw.ProtocolVersion
	if rev > chMaxProtocolRev {
		rev = chMaxProtocolRev
	}
	return ChHello{
		ClientName:       raw.Name,
		VersionMajor:     raw.Major,
		VersionMinor:     raw.Minor,
		ProtocolRevision: rev,
		Database:         raw.Database,
		Username:         raw.User,
		Password:         raw.Password,
	}, pr, nil
}

// chEncodeHello serializes a (possibly credential-rewritten) Hello to
// the wire bytes the upstream server expects.
func chEncodeHello(h ChHello) []byte {
	var b chgoproto.Buffer
	hello := chgoproto.ClientHello{
		Name:            h.ClientName,
		Major:           h.VersionMajor,
		Minor:           h.VersionMinor,
		ProtocolVersion: h.ProtocolRevision,
		Database:        h.Database,
		User:            h.Username,
		Password:        h.Password,
	}
	hello.Encode(&b)
	return b.Buf
}

// chReadAndForwardServerHello pulls the server's Hello off the
// upstream reader, forwards the re-encoded packet to the agent
// verbatim (modulo serializer normalization — same fields, same
// values), and returns the negotiated protocol revision the
// agent → server inspector should use for subsequent packet decode.
//
// The upstream reader stays live after this call: subsequent server
// packets (Data, Progress, Log, EndOfStream, …) flow agent-ward via
// io.Copy on the same reader, which delegates to its buffered source
// past the bytes the Hello consumed.
func chReadAndForwardServerHello(upstream *chgoproto.Reader, agent io.Writer, clientRev int) (int, error) {
	code, err := upstream.UInt8()
	if err != nil {
		return 0, fmt.Errorf("read server packet code: %w", err)
	}
	switch chgoproto.ServerCode(code) {
	case chgoproto.ServerCodeException:
		// The server rejected the Hello (e.g. bad creds). Forward the
		// Exception payload verbatim so the agent surfaces the upstream
		// error message instead of an opaque close.
		var exc chgoproto.Exception
		if err := exc.DecodeAware(upstream, clientRev); err != nil {
			return 0, fmt.Errorf("decode server exception: %w", err)
		}
		var b chgoproto.Buffer
		b.PutByte(byte(chgoproto.ServerCodeException))
		exc.EncodeAware(&b, clientRev)
		if _, werr := agent.Write(b.Buf); werr != nil {
			return 0, fmt.Errorf("forward server exception: %w", werr)
		}
		return 0, fmt.Errorf("server returned exception: %s", exc.Message)
	case chgoproto.ServerCodeHello:
		// Decode with the client's revision — that's the upper bound
		// on the field set the server will have used to encode (it's
		// gated by min(client_rev, server_rev), and the server hasn't
		// learned our revision yet from the addendum either). clientRev
		// is already clamped to chMaxProtocolRev by chReadHello, so the
		// upstream — which negotiated against our forwarded ClientHello
		// — hasn't sent any post-rev features ch-go can't model.
		var srv chgoproto.ServerHello
		if err := srv.DecodeAware(upstream, clientRev); err != nil {
			return 0, fmt.Errorf("decode server hello: %w", err)
		}
		// Clamp the revision the agent sees so its negotiated rev
		// matches the upstream's. Without this the agent could think
		// the session is at a higher rev than the upstream actually
		// agreed to, leading both sides to disagree on addendum /
		// query schema.
		if srv.Revision > chMaxProtocolRev {
			srv.Revision = chMaxProtocolRev
		}
		var b chgoproto.Buffer
		srv.EncodeAware(&b, clientRev)
		if _, werr := agent.Write(b.Buf); werr != nil {
			return 0, fmt.Errorf("forward server hello: %w", werr)
		}
		negotiated := clientRev
		if srv.Revision < negotiated {
			negotiated = srv.Revision
		}
		return negotiated, nil
	default:
		return 0, fmt.Errorf("clickhouse: unexpected server packet code %d during handshake", code)
	}
}

// chForwardClientAddendum reads and forwards the post-ServerHello
// ClientHelloAddendum that modern clients send when the negotiated
// protocol revision is at FeatureAddendum (54458) or higher. The
// addendum is not a packet — it's a bare `quota_key` string written
// straight after the client receives the ServerHello, and the
// upstream server reads it before the first Query. Skipping it on
// rev<54458 connections is safe (the wire carries nothing extra
// there); failing to forward it on rev>=54458 desyncs both sides:
// the upstream blocks waiting for the string, and the agent → server
// pump misreads the addendum's first byte (often 0x00 for an empty
// quota_key) as a client packet code, returns "unknown-client-packet"
// and closes — which surfaces agent-side as ATTEMPT_TO_READ_AFTER_EOF
// on the next server read.
func chForwardClientAddendum(agent *chgoproto.Reader, upstream io.Writer, negotiatedRev int) error {
	if !chgoproto.FeatureAddendum.In(negotiatedRev) {
		return nil
	}
	quotaKey, err := agent.Str()
	if err != nil {
		return fmt.Errorf("read client addendum quota_key: %w", err)
	}
	var b chgoproto.Buffer
	b.PutString(quotaKey)
	if _, werr := upstream.Write(b.Buf); werr != nil {
		return fmt.Errorf("forward client addendum: %w", werr)
	}
	return nil
}

// chEncodeException builds a server Exception packet (code 2) the
// runtime sends when policy denies a Query. ClickHouse clients
// surface the display text as
// "DB::Exception: ACCESS_DENIED: <reason>" and (for clickhouse-client)
// re-prompt for the next statement.
func chEncodeException(displayText string) []byte {
	exc := chgoproto.Exception{
		Code:    chgoproto.ErrAccessDenied,
		Name:    "DB::Exception",
		Message: displayText,
	}
	var b chgoproto.Buffer
	b.PutByte(byte(chgoproto.ServerCodeException))
	exc.EncodeAware(&b, 0)
	return b.Buf
}

// chErrShortBuffer is returned by helpers that try-decode out of a
// fixed buffer. With ch-go/proto the runtime always reads from a live
// io.Reader so this surfaces only from buffer-backed unit tests.
var chErrShortBuffer = errors.New("clickhouse: short buffer")
