package endpoints

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

type clickhouseHello struct {
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

func chReadVarUInt(buf []byte, offset int) (value uint64, bytesRead int, err error) {
	var shift uint
	for i := offset; i < len(buf); i++ {
		b := buf[i]
		if shift >= 64 {
			return 0, 0, fmt.Errorf("varuint too long")
		}
		value |= uint64(b&0x7f) << shift
		bytesRead++
		if b&0x80 == 0 {
			return value, bytesRead, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("short varuint")
}

func chWriteVarUInt(value uint64) []byte {
	out := make([]byte, 0, 10)
	for value > 0x7f {
		out = append(out, byte(value&0x7f)|0x80)
		value >>= 7
	}
	out = append(out, byte(value))
	return out
}

func chReadString(buf []byte, offset int) (value string, bytesRead int, err error) {
	n, nr, err := chReadVarUInt(buf, offset)
	if err != nil {
		return "", 0, err
	}
	start := offset + nr
	end := start + int(n)
	if n > uint64(len(buf)) || end < start || end > len(buf) {
		return "", 0, fmt.Errorf("string extends beyond buffer")
	}
	raw := buf[start:end]
	if !utf8.Valid(raw) {
		return "", 0, fmt.Errorf("string is not valid utf-8")
	}
	return string(raw), nr + int(n), nil
}

func chWriteString(value string) []byte {
	str := []byte(value)
	out := chWriteVarUInt(uint64(len(str)))
	out = append(out, str...)
	return out
}

func chParseHello(buf []byte) (clickhouseHello, error) {
	var h clickhouseHello
	offset := 0

	v, n, err := chReadVarUInt(buf, offset)
	if err != nil {
		return h, err
	}
	offset += n
	if v != 0 {
		return h, fmt.Errorf("not a Hello packet: type %d", v)
	}
	h.PacketType = v

	if h.ClientName, n, err = chReadString(buf, offset); err != nil {
		return h, err
	}
	offset += n
	if h.VersionMajor, n, err = chReadVarUInt(buf, offset); err != nil {
		return h, err
	}
	offset += n
	if h.VersionMinor, n, err = chReadVarUInt(buf, offset); err != nil {
		return h, err
	}
	offset += n
	if h.ProtocolRevision, n, err = chReadVarUInt(buf, offset); err != nil {
		return h, err
	}
	offset += n
	if h.Database, n, err = chReadString(buf, offset); err != nil {
		return h, err
	}
	offset += n
	if h.Username, n, err = chReadString(buf, offset); err != nil {
		return h, err
	}
	offset += n
	if h.Password, n, err = chReadString(buf, offset); err != nil {
		return h, err
	}
	offset += n
	h.Trailing = append([]byte(nil), buf[offset:]...)
	return h, nil
}

func chSerializeHello(h clickhouseHello) []byte {
	parts := [][]byte{
		chWriteVarUInt(h.PacketType),
		chWriteString(h.ClientName),
		chWriteVarUInt(h.VersionMajor),
		chWriteVarUInt(h.VersionMinor),
		chWriteVarUInt(h.ProtocolRevision),
		chWriteString(h.Database),
		chWriteString(h.Username),
		chWriteString(h.Password),
		h.Trailing,
	}
	return bytes.Join(parts, nil)
}
