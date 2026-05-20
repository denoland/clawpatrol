package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPumpWSRewritesMaskedClientTextPayload(t *testing.T) {
	placeholder := []byte("DISCORD_PLACEHOLDER")
	actual := []byte("real.discord.token")
	originalPayload := []byte(`{"op":2,"d":{"token":"DISCORD_PLACEHOLDER"}}`)

	var src bytes.Buffer
	src.Write(testWSFrame(0x80|wsOpText, true, [4]byte{1, 2, 3, 4}, originalPayload))
	src.Write(testWSFrame(0x80|wsOpClose, true, [4]byte{5, 6, 7, 8}, nil))

	var dst bytes.Buffer
	var observed []byte
	rewrite := func(payload []byte) ([]byte, bool, error) {
		if !bytes.Contains(payload, placeholder) {
			return payload, false, nil
		}
		return bytes.ReplaceAll(payload, placeholder, actual), true, nil
	}
	if err := pumpWS(bufio.NewReader(&src), &dst, wsParams{}, true, func(payload []byte) {
		observed = append([]byte(nil), payload...)
	}, rewrite, nil); err != nil {
		t.Fatalf("pumpWS: %v", err)
	}

	raw, _, op, compressed, masked, maskKey, payload, err := readFrameRaw(bufio.NewReader(bytes.NewReader(dst.Bytes())))
	if err != nil {
		t.Fatalf("read forwarded frame: %v", err)
	}
	if op != wsOpText || compressed || !masked {
		t.Fatalf("forwarded frame metadata op=%d compressed=%v masked=%v raw=%x", op, compressed, masked, raw)
	}
	plain := make([]byte, len(payload))
	for i := range payload {
		plain[i] = payload[i] ^ maskKey[i%4]
	}
	if bytes.Contains(plain, placeholder) {
		t.Fatalf("forwarded payload still contains placeholder: %s", plain)
	}
	if !bytes.Contains(plain, actual) {
		t.Fatalf("forwarded payload missing actual token: %s", plain)
	}
	if !bytes.Contains(observed, placeholder) || bytes.Contains(observed, actual) {
		t.Fatalf("observed payload should keep safe placeholder, got: %s", observed)
	}
}

func testWSFrame(b0 byte, masked bool, key [4]byte, payload []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(b0)
	maskBit := byte(0)
	if masked {
		maskBit = wsMaskBit
	}
	switch n := len(payload); {
	case n < 126:
		out.WriteByte(maskBit | byte(n))
	case n <= 0xffff:
		out.WriteByte(maskBit | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		out.Write(ext[:])
	default:
		out.WriteByte(maskBit | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		out.Write(ext[:])
	}
	if masked {
		out.Write(key[:])
		for i, b := range payload {
			out.WriteByte(b ^ key[i%4])
		}
		return out.Bytes()
	}
	out.Write(payload)
	return out.Bytes()
}
