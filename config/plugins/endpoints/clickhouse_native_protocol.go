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
