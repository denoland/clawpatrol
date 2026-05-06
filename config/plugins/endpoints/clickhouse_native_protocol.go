package endpoints

// ClickHouse native-protocol Hello packet parser/serializer.
//
// Wire format mirrors what clickhouse-server expects on a fresh
// connection: VarUInt packet type (0 = Hello) followed by a sequence
// of VarUInt + length-prefixed UTF-8 strings:
//
//	type=0 | client_name | major | minor | revision | database | user | password
//
// Past the password, newer clients may send addendum bytes
// (interserver secret, quota key, etc.); we preserve them verbatim.
//
// Mirrors the unclaw plugin's protocol.ts so the two stay easy to
// cross-reference. See denoland/unclaw, refinery/rig/src/plugins/
// clickhouse/protocol.ts.

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// errChShortBuffer surfaces from the parsers when the buffer is
// exhausted mid-packet. Callers use it to drive an
// "accumulate-and-retry" read loop.
var errChShortBuffer = errors.New("clickhouse: short buffer")

// ChHello is the decoded client Hello.
//
// Trailing carries any bytes after the password — addendum data,
// inline post-Hello pipelining — preserved so the rewritten packet
// is byte-identical for fields we don't touch.
//
// VarUInt fields are typed as uint64 to match the ClickHouse wire
// spec (LEB128-encoded uint64). Current revisions fit in int but
// future revisions or non-Hello packets carrying e.g. block sizes
// are immune to overflow.
type ChHello struct {
	PacketType       uint64
	ClientName       string
	VersionMajor     uint64
	VersionMinor     uint64
	ProtocolRevision uint64
	Database         string
	Username         string
	Password         string
	Trailing         []byte
}

// ParseChHello reads a Hello from buf. Returns the decoded packet,
// the number of bytes consumed (excluding Trailing — Trailing is
// caller-owned bytes past the password), and any error. Returns
// errChShortBuffer when buf is incomplete and a retry-with-more-bytes
// could succeed.
func ParseChHello(buf []byte) (ChHello, int, error) {
	off := 0

	pktType, n, err := readChVarUInt(buf, off)
	if err != nil {
		return ChHello{}, 0, err
	}
	off += n
	if pktType != 0 {
		return ChHello{}, 0, errors.New("clickhouse: not a Hello packet")
	}

	clientName, n, err := readChString(buf, off)
	if err != nil {
		return ChHello{}, 0, err
	}
	off += n

	major, n, err := readChVarUInt(buf, off)
	if err != nil {
		return ChHello{}, 0, err
	}
	off += n

	minor, n, err := readChVarUInt(buf, off)
	if err != nil {
		return ChHello{}, 0, err
	}
	off += n

	rev, n, err := readChVarUInt(buf, off)
	if err != nil {
		return ChHello{}, 0, err
	}
	off += n

	database, n, err := readChString(buf, off)
	if err != nil {
		return ChHello{}, 0, err
	}
	off += n

	user, n, err := readChString(buf, off)
	if err != nil {
		return ChHello{}, 0, err
	}
	off += n

	pass, n, err := readChString(buf, off)
	if err != nil {
		return ChHello{}, 0, err
	}
	off += n

	return ChHello{
		PacketType:       pktType,
		ClientName:       clientName,
		VersionMajor:     major,
		VersionMinor:     minor,
		ProtocolRevision: rev,
		Database:         database,
		Username:         user,
		Password:         pass,
	}, off, nil
}

// SerializeChHello rewrites a Hello back to wire bytes. Trailing
// bytes (parsed by the caller out of band, then attached to h) are
// appended as-is.
func SerializeChHello(h ChHello) []byte {
	out := make([]byte, 0, 64+len(h.ClientName)+len(h.Database)+len(h.Username)+len(h.Password)+len(h.Trailing))
	out = appendChVarUInt(out, h.PacketType)
	out = appendChString(out, h.ClientName)
	out = appendChVarUInt(out, h.VersionMajor)
	out = appendChVarUInt(out, h.VersionMinor)
	out = appendChVarUInt(out, h.ProtocolRevision)
	out = appendChString(out, h.Database)
	out = appendChString(out, h.Username)
	out = appendChString(out, h.Password)
	out = append(out, h.Trailing...)
	return out
}

// readChVarUInt decodes a LEB128-encoded uint64 (the ClickHouse
// VarUInt). Returns the decoded value, the number of bytes
// consumed, and any error.
func readChVarUInt(buf []byte, off int) (uint64, int, error) {
	var value uint64
	shift := uint(0)
	i := off
	for {
		if i >= len(buf) {
			return 0, 0, errChShortBuffer
		}
		b := buf[i]
		value |= uint64(b&0x7f) << shift
		i++
		if b&0x80 == 0 {
			return value, i - off, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, 0, errors.New("clickhouse: varuint too long")
		}
	}
}

// appendChVarUInt encodes value as LEB128 and appends to dst.
func appendChVarUInt(dst []byte, value uint64) []byte {
	for value > 0x7f {
		dst = append(dst, byte(0x80|(value&0x7f)))
		value >>= 7
	}
	dst = append(dst, byte(value&0x7f))
	return dst
}

// readChString decodes a VarUInt-prefixed UTF-8 string. Rejects
// malformed UTF-8 to keep arbitrary peer bytes out of downstream
// loggers / renderers.
func readChString(buf []byte, off int) (string, int, error) {
	length, ln, err := readChVarUInt(buf, off)
	if err != nil {
		return "", 0, err
	}
	if length > uint64(len(buf)-off-ln) {
		// Either truncated or the length claims more than the
		// remaining buffer can ever hold (length doesn't fit in int).
		// Both are "need more bytes" from the read loop's POV; the
		// 1 MiB cap in chReadHello catches a malicious huge length.
		return "", 0, errChShortBuffer
	}
	start := off + ln
	end := start + int(length)
	s := string(buf[start:end])
	if !utf8.ValidString(s) {
		return "", 0, errors.New("clickhouse: invalid UTF-8 in string")
	}
	return s, ln + int(length), nil
}

// appendChString encodes a length-prefixed string.
func appendChString(dst []byte, s string) []byte {
	dst = appendChVarUInt(dst, uint64(len(s)))
	dst = append(dst, s...)
	return dst
}

// ── Server Hello + Query packet parsing for iter 2 ────────────────────

// Client packet type codes (subset; see ClickHouse Protocol.h).
const (
	chClientPacketHello  = 0
	chClientPacketQuery  = 1
	chClientPacketData   = 2
	chClientPacketCancel = 3
	chClientPacketPing   = 4
)

// Server packet type codes (subset).
const (
	chServerPacketHello       = 0
	chServerPacketException   = 2
	chServerPacketEndOfStream = 5
)

// ClickHouse protocol-revision feature gates. Numbers come from
// clickhouse-server's src/Core/ProtocolDefines.h. Each gate adds one
// or more conditional fields to a packet body, so the parser must
// branch on the negotiated revision (min(client_rev, server_rev)).
const (
	chMinRevWithClientInfo            = 54032
	chMinRevWithQuotaKeyInClientInfo  = 54060
	chMinRevWithVersionPatch          = 54401
	chMinRevWithXForwardedForInClient = 54402
	chMinRevWithSettingsAsStrings     = 54429
	chMinRevWithInterserverSecret     = 54441
	chMinRevWithOpenTelemetry         = 54442
	chMinRevWithParallelReplicas      = 54447
	chMinRevWithDistributedDepth      = 54448
	chMinRevWithInitialQueryStartTime = 54449
	chMinRevWithParameters            = 54459
)

// ClientInfo interface codes — see ClickHouse src/Interpreters/ClientInfo.h.
const (
	chClientInterfaceTCP  = 1
	chClientInterfaceHTTP = 2
)

// ParseChServerHelloRevision reads enough of a server Hello packet to
// extract the negotiated protocol revision. Returns errChShortBuffer
// when buf is incomplete. The runtime forwards the raw bytes to the
// agent verbatim — this helper exists only so the agent→server
// inspector knows which feature gates apply to subsequent Query
// packets.
//
// Server Hello prefix:
//
//	varuint packet_type (0)
//	string  server_name
//	varuint version_major
//	varuint version_minor
//	varuint server_revision  ← what we want
//
// Anything after the revision is revision-conditional and not relevant
// to client→server packet decoding.
func ParseChServerHelloRevision(buf []byte) (uint64, error) {
	off := 0
	pktType, n, err := readChVarUInt(buf, off)
	if err != nil {
		return 0, err
	}
	off += n
	if pktType == chServerPacketException {
		return 0, errors.New("clickhouse: server returned Exception during handshake")
	}
	if pktType != chServerPacketHello {
		return 0, errors.New("clickhouse: not a server Hello packet")
	}
	if _, n, err = readChString(buf, off); err != nil {
		return 0, err
	}
	off += n
	if _, n, err = readChVarUInt(buf, off); err != nil {
		return 0, err
	}
	off += n
	if _, n, err = readChVarUInt(buf, off); err != nil {
		return 0, err
	}
	off += n
	rev, _, err := readChVarUInt(buf, off)
	if err != nil {
		return 0, err
	}
	return rev, nil
}

// ChQueryView is the parser's read of a client Query packet:
// the SQL string the agent submitted, plus the byte offset at which
// the packet ends within the input buffer. Trailing bytes (the empty
// external-tables Data block, INSERT data blocks) are caller-handled.
type ChQueryView struct {
	SQL string
	End int
}

// ParseChQuery decodes a client Query packet given the negotiated
// protocol revision. Returns errChShortBuffer when buf doesn't yet
// hold the full packet.
//
// The parser's only goal is locating the SQL string + the packet's
// trailing offset. We don't materialize ClientInfo / Settings — every
// field is consumed and dropped because the runtime forwards the raw
// bytes upstream verbatim.
//
// Revisions older than chMinRevWithSettingsAsStrings (54429) are not
// supported: the legacy "BINARY" Settings format encodes values with
// type-prefixed serializers we'd have to mirror, and that revision
// predates ClickHouse 21 — every supported client lands above the
// gate.
func ParseChQuery(buf []byte, revision uint64) (ChQueryView, error) {
	if revision < chMinRevWithSettingsAsStrings {
		return ChQueryView{}, fmt.Errorf("clickhouse: unsupported protocol revision %d (need >= %d)",
			revision, chMinRevWithSettingsAsStrings)
	}
	off := 0

	pktType, n, err := readChVarUInt(buf, off)
	if err != nil {
		return ChQueryView{}, err
	}
	off += n
	if pktType != chClientPacketQuery {
		return ChQueryView{}, fmt.Errorf("clickhouse: not a Query packet (type=%d)", pktType)
	}

	// query_id
	if _, n, err = readChString(buf, off); err != nil {
		return ChQueryView{}, err
	}
	off += n

	// ClientInfo
	if revision >= chMinRevWithClientInfo {
		var consumed int
		consumed, err = skipChClientInfo(buf, off, revision)
		if err != nil {
			return ChQueryView{}, err
		}
		off += consumed
	}

	// Settings: (key, flags varuint, value) triples terminated by empty key.
	for {
		key, n, err := readChString(buf, off)
		if err != nil {
			return ChQueryView{}, err
		}
		off += n
		if key == "" {
			break
		}
		if _, n, err = readChVarUInt(buf, off); err != nil { // flags
			return ChQueryView{}, err
		}
		off += n
		if _, n, err = readChString(buf, off); err != nil { // value
			return ChQueryView{}, err
		}
		off += n
	}

	// interserver_secret
	if revision >= chMinRevWithInterserverSecret {
		if _, n, err = readChString(buf, off); err != nil {
			return ChQueryView{}, err
		}
		off += n
	}

	// stage, compression
	if _, n, err = readChVarUInt(buf, off); err != nil {
		return ChQueryView{}, err
	}
	off += n
	if _, n, err = readChVarUInt(buf, off); err != nil {
		return ChQueryView{}, err
	}
	off += n

	// query (the SQL)
	sql, n, err := readChString(buf, off)
	if err != nil {
		return ChQueryView{}, err
	}
	off += n

	// parameters block (if present): same shape as Settings.
	if revision >= chMinRevWithParameters {
		for {
			key, n, err := readChString(buf, off)
			if err != nil {
				return ChQueryView{}, err
			}
			off += n
			if key == "" {
				break
			}
			if _, n, err = readChVarUInt(buf, off); err != nil { // flags
				return ChQueryView{}, err
			}
			off += n
			if _, n, err = readChString(buf, off); err != nil { // value
				return ChQueryView{}, err
			}
			off += n
		}
	}

	return ChQueryView{SQL: sql, End: off}, nil
}

// skipChClientInfo walks the ClientInfo block embedded in a Query
// packet body and returns the number of bytes consumed. Pure
// length-counter — no field is materialized.
//
// The block's structure is straight out of ClickHouse's
// src/Interpreters/ClientInfo.cpp::write(). When query_kind == 0
// (NO_QUERY) the body is a single byte; otherwise the block expands
// into a long sequence of revision-gated fields. We only handle the
// TCP and HTTP interfaces; LOCAL/MySQL/Postgres/gRPC interfaces are
// rare enough in real client traffic that we error out and let the
// runtime fall back to verbatim forwarding.
func skipChClientInfo(buf []byte, off int, revision uint64) (int, error) {
	start := off
	if off >= len(buf) {
		return 0, errChShortBuffer
	}
	queryKind := buf[off]
	off++
	if queryKind == 0 {
		return off - start, nil
	}

	// initial_user, initial_query_id, initial_address
	for i := 0; i < 3; i++ {
		_, n, err := readChString(buf, off)
		if err != nil {
			return 0, err
		}
		off += n
	}

	if revision >= chMinRevWithInitialQueryStartTime {
		if off+8 > len(buf) {
			return 0, errChShortBuffer
		}
		off += 8
	}

	if off >= len(buf) {
		return 0, errChShortBuffer
	}
	iface := buf[off]
	off++

	switch iface {
	case chClientInterfaceTCP:
		// os_user, client_hostname, client_name
		for i := 0; i < 3; i++ {
			_, n, err := readChString(buf, off)
			if err != nil {
				return 0, err
			}
			off += n
		}
		// client_version_major, client_version_minor, client_tcp_protocol_version
		for i := 0; i < 3; i++ {
			_, n, err := readChVarUInt(buf, off)
			if err != nil {
				return 0, err
			}
			off += n
		}
	case chClientInterfaceHTTP:
		if off >= len(buf) {
			return 0, errChShortBuffer
		}
		off++ // http_method byte
		// http_user_agent
		if _, n, err := readChString(buf, off); err != nil {
			return 0, err
		} else {
			off += n
		}
		if revision >= chMinRevWithXForwardedForInClient {
			// http_referer, forwarded_for
			for i := 0; i < 2; i++ {
				_, n, err := readChString(buf, off)
				if err != nil {
					return 0, err
				}
				off += n
			}
		}
	default:
		return 0, fmt.Errorf("clickhouse: unsupported client interface %d", iface)
	}

	if revision >= chMinRevWithQuotaKeyInClientInfo {
		_, n, err := readChString(buf, off)
		if err != nil {
			return 0, err
		}
		off += n
	}
	if revision >= chMinRevWithDistributedDepth {
		_, n, err := readChVarUInt(buf, off)
		if err != nil {
			return 0, err
		}
		off += n
	}
	if revision >= chMinRevWithVersionPatch {
		_, n, err := readChVarUInt(buf, off)
		if err != nil {
			return 0, err
		}
		off += n
	}
	if revision >= chMinRevWithOpenTelemetry {
		if off >= len(buf) {
			return 0, errChShortBuffer
		}
		tracePresent := buf[off]
		off++
		if tracePresent == 1 {
			// trace_id (16 bytes), span_id (8 bytes), tracestate (string), trace_flags (1 byte)
			if off+16 > len(buf) {
				return 0, errChShortBuffer
			}
			off += 16
			if off+8 > len(buf) {
				return 0, errChShortBuffer
			}
			off += 8
			_, n, err := readChString(buf, off)
			if err != nil {
				return 0, err
			}
			off += n
			if off >= len(buf) {
				return 0, errChShortBuffer
			}
			off++
		}
	}
	if revision >= chMinRevWithParallelReplicas {
		for i := 0; i < 3; i++ {
			_, n, err := readChVarUInt(buf, off)
			if err != nil {
				return 0, err
			}
			off += n
		}
	}
	return off - start, nil
}

// SerializeChException writes a server-side Exception packet (type 2)
// the runtime sends when a Query is denied. ClickHouse clients render
// the display text and (for clickhouse-client) re-prompt for the next
// query.
//
// Layout (from src/Common/Exception.cpp::writeException):
//
//	varuint packet_type (2)
//	int32 LE error_code
//	string name
//	string display_text
//	string stack_trace (we send "")
//	byte has_nested (0)
//
// errCode 497 (ACCESS_DENIED) is the right code for policy denials —
// it surfaces in the agent's error message as
// "DB::Exception: ACCESS_DENIED: <our reason>".
func SerializeChException(errCode int32, displayText string) []byte {
	const exceptionName = "DB::Exception"
	out := make([]byte, 0, 64+len(displayText)+len(exceptionName))
	out = appendChVarUInt(out, chServerPacketException)
	out = append(out,
		byte(uint32(errCode)),
		byte(uint32(errCode)>>8),
		byte(uint32(errCode)>>16),
		byte(uint32(errCode)>>24),
	)
	out = appendChString(out, exceptionName)
	out = appendChString(out, displayText)
	out = appendChString(out, "")
	out = append(out, 0)
	return out
}
