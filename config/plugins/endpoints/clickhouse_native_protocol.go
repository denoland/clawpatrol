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

import "errors"

// errChShortBuffer surfaces from the parsers when the buffer is
// exhausted mid-packet. Callers use it to drive an
// "accumulate-and-retry" read loop.
var errChShortBuffer = errors.New("clickhouse: short buffer")

// ChHello is the decoded client Hello.
//
// Trailing carries any bytes after the password — addendum data,
// inline post-Hello pipelining — preserved so the rewritten packet
// is byte-identical for fields we don't touch.
type ChHello struct {
	PacketType       int
	ClientName       string
	VersionMajor     int
	VersionMinor     int
	ProtocolRevision int
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

// readChVarUInt decodes a LEB128-style unsigned varint. ClickHouse
// caps payload sizes well below 2^63 so int is safe; we still bound
// shift to 63 to fail loudly on malformed packets.
func readChVarUInt(buf []byte, off int) (int, int, error) {
	value := 0
	shift := uint(0)
	i := off
	for {
		if i >= len(buf) {
			return 0, 0, errChShortBuffer
		}
		b := buf[i]
		value |= int(b&0x7f) << shift
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
func appendChVarUInt(dst []byte, value int) []byte {
	v := uint64(value)
	for v > 0x7f {
		dst = append(dst, byte(0x80|(v&0x7f)))
		v >>= 7
	}
	dst = append(dst, byte(v&0x7f))
	return dst
}

// readChString decodes a VarUInt-prefixed UTF-8 string.
func readChString(buf []byte, off int) (string, int, error) {
	length, ln, err := readChVarUInt(buf, off)
	if err != nil {
		return "", 0, err
	}
	start := off + ln
	end := start + length
	if end > len(buf) {
		return "", 0, errChShortBuffer
	}
	return string(buf[start:end]), ln + length, nil
}

// appendChString encodes a length-prefixed string.
func appendChString(dst []byte, s string) []byte {
	dst = appendChVarUInt(dst, len(s))
	dst = append(dst, s...)
	return dst
}
